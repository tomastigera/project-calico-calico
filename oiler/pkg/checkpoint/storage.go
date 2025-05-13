// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package checkpoint

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/flowcontrol"

	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/oiler/pkg/migrator/operator"
)

const (
	checkpointKey = "checkpoint"
	timeOut       = 5 * time.Minute
)

// Storage defined how we write and read migration checkpoints
type Storage interface {
	Read(ctx context.Context) (operator.TimeInterval, error)
	Write(ctx context.Context, checkpoint time.Time) error
}

// ConfigMapStorage is a storage that stores checkpoints
// in a config map
type ConfigMapStorage struct {
	k8sClient kubernetes.Interface
	namespace string
	name      string
	timeout   time.Duration
}

func NewConfigMapStorage(k8sClient kubernetes.Interface, namespace string, name string) Storage {

	return &ConfigMapStorage{k8sClient: k8sClient, namespace: namespace, name: name, timeout: timeOut}
}

func (c ConfigMapStorage) Read(ctx context.Context) (operator.TimeInterval, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	configmap, err := c.k8sClient.CoreV1().ConfigMaps(c.namespace).Get(ctx, c.name, metav1.GetOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return operator.TimeInterval{}, err
	}

	if configmap == nil {
		return operator.TimeInterval{}, nil
	}
	if configmap.Data == nil {
		return operator.TimeInterval{}, nil
	}

	if checkpoint, ok := configmap.Data[checkpointKey]; ok {
		start, err := time.Parse(time.RFC3339, checkpoint)
		if err != nil {
			return operator.TimeInterval{}, err
		}
		return operator.TimeInterval{Start: &start}, nil
	}
	return operator.TimeInterval{}, nil
}

func (c ConfigMapStorage) Write(ctx context.Context, checkpoint time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	configmap, err := c.k8sClient.CoreV1().ConfigMaps(c.namespace).Get(ctx, c.name, metav1.GetOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return err
	}

	if errors.IsNotFound(err) {
		configmap = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      c.name,
				Namespace: c.namespace,
				Labels:    map[string]string{"generated-by": "oiler"},
			},
			Data: map[string]string{checkpointKey: checkpoint.UTC().Format(time.RFC3339)},
		}

		_, err := c.k8sClient.CoreV1().ConfigMaps(c.namespace).Create(ctx, configmap, metav1.CreateOptions{})
		if err != nil {
			return err
		}
	} else {
		if configmap.Data == nil {
			configmap.Data = make(map[string]string)
		}
		configmap.Data[checkpointKey] = checkpoint.UTC().Format(time.RFC3339)
		_, err := c.k8sClient.CoreV1().ConfigMaps(c.namespace).Update(ctx, configmap, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
	}

	return nil
}

// NewRealK8sClient is a helper function that sets up a kubernetes client
func NewRealK8sClient(kubeconfigPath string) (*kubernetes.Clientset, error) {
	var kubeConfig *rest.Config
	var err error
	if kubeconfigPath == "" {
		// creates the in-cluster k8sConfig
		kubeConfig, err = rest.InClusterConfig()
	} else {
		// creates a k8sConfig from supplied kubeconfig
		kubeConfig, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	}
	if err != nil {
		return nil, err
	}
	kubeConfig.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(100, 1000)

	client, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// ConfigMapName is a helper function that creates the name of the config map
func ConfigMapName(dataType bapi.DataType, cluster, tenant string) string {
	normalizedDataType := strings.ReplaceAll(string(dataType), "_", "-")
	if len(tenant) == 0 {
		return fmt.Sprintf("%s-%s", normalizedDataType, cluster)
	}
	return fmt.Sprintf("%s-%s-%s", normalizedDataType, cluster, tenant)
}
