// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package kubernetes

import (
	"context"
	"errors"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8slabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	httpCommon "github.com/projectcalico/calico/es-gateway/pkg/clients/internal/http"
)

// client is a wrapper for the K8s client.
type client struct {
	*kubernetes.Clientset
}

// Client is an interface that exposes the required Kube API operations for ES Gateway.
type Client interface {
	GetSecret(context.Context, string, string) (*v1.Secret, error)
	GetSecretList(context.Context, string, map[string]string) (*v1.SecretList, error)
	GetSecretWatcher(context.Context, string, map[string]string) (watch.Interface, error)
	GetK8sReadyz() error
}

func NewClient(configPath string) (Client, error) {
	// Create a rest.Config. If this runs in k8s, it uses the credentials at fixed locations, otherwise, it
	// uses flags.
	var (
		cfg *rest.Config
		err error
	)

	if len(configPath) == 0 {
		cfg, err = rest.InClusterConfig()
	} else {
		cfg, err = clientcmd.BuildConfigFromFlags("", configPath)
	}

	if err != nil {
		log.Fatalf("Failed to get k8s cfg %s", err)
	}

	// NewK8sClientWithConfig configures K8s client based a rest.Config.
	k8s, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("Failed to configure k8s client %s", err)
	}

	return &client{k8s}, nil
}

// GetSecret attempts to retrieve a K8s secret with the given name, from the given namespace.
func (c *client) GetSecret(ctx context.Context, name, namespace string) (*v1.Secret, error) {
	secret, err := c.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return secret, nil
}

// GetSecretList attempts to retrieve a list of K8s secrets with from the given namespace.
func (c *client) GetSecretList(ctx context.Context, namespace string, labels map[string]string) (*v1.SecretList, error) {
	// Determine whether we need to attach any label selector(s).
	listOptions := metav1.ListOptions{}
	if len(labels) > 0 {
		listOptions.LabelSelector = k8slabels.Set(labels).String()
	}

	secretList, err := c.CoreV1().Secrets(namespace).List(ctx, listOptions)
	if err != nil {
		return nil, err
	}
	return secretList, nil
}

// GetSecretWatcher attempts to setup a watcher for secrets within the provided namespace.
func (c *client) GetSecretWatcher(ctx context.Context, namespace string, labels map[string]string) (watch.Interface, error) {
	api := c.CoreV1().Secrets(namespace)

	// Do a list first to get the resource version.
	secrets, err := api.List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	resourceVersion := secrets.ResourceVersion

	// Determine whether we need to attach any label selector(s).
	listOptions := metav1.ListOptions{ResourceVersion: resourceVersion}
	if len(labels) > 0 {
		listOptions.LabelSelector = k8slabels.Set(labels).String()
	}

	// Set up the watcher with list options.
	watcher, err := api.Watch(ctx, listOptions)
	if err != nil {
		return nil, err
	}
	return watcher, nil
}

// GetK8sReadyz checks the readyz endpoint of the Kube API that the client is connected to.
// If the response is anything other than "ok", then an error is returned.
// Otherwise, we return nil.
// https://kubernetes.io/docs/reference/using-api/health-checks/#api-endpoints-for-health
func (c *client) GetK8sReadyz() error {
	path := "/readyz"
	content, err := c.Discovery().RESTClient().Get().Timeout(httpCommon.HealthCheckTimeout).AbsPath(path).DoRaw(context.TODO())
	if err != nil {
		return err
	}

	contentStr := string(content)
	if contentStr != "ok" {
		return errors.New(contentStr)
	}

	return nil
}
