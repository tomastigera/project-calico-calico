package utils

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-semver/semver"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/worker"
	"github.com/projectcalico/calico/kube-controllers/pkg/resource"
	"github.com/projectcalico/calico/lma/pkg/k8s"
)

const (
	DefaultTigeraOperatorNamespace = "tigera-operator"
)

// FetchOperatorNamespace reads the active operator namespace and returns it.
func FetchOperatorNamespace(c kubernetes.Interface) (string, error) {
	cm, err := c.CoreV1().ConfigMaps("calico-system").Get(context.Background(), "active-operator", metav1.GetOptions{})
	if err != nil {
		// If not found then assume we are looking at a earlier version that did not use
		// the active-operator ConfigMap.
		if errors.IsNotFound(err) {
			return DefaultTigeraOperatorNamespace, nil
		}
		return "", fmt.Errorf("unable to get the active-operator ConfigMap: %w", err)
	} else {
		if ns, ok := cm.Data["active-namespace"]; ok {
			return ns, nil
		} else {
			return "", fmt.Errorf("active-operator ConfigMap does not have the data field 'active-namespace'")
		}
	}
}

func AddWatchForActiveOperator(w worker.Worker, c kubernetes.Interface) {
	w.AddWatch(
		cache.NewListWatchFromClient(c.CoreV1().RESTClient(), "configmaps", resource.CalicoNamespaceName,
			fields.ParseSelectorOrDie(fmt.Sprintf("metadata.name=%s", resource.ActiveOperatorConfigMapName))),
		&corev1.ConfigMap{},
		worker.ResourceWatchUpdate, worker.ResourceWatchDelete, worker.ResourceWatchAdd,
	)
}

func FetchVersionedVoltronLinseedPublicCertName(c k8s.ClientSet) (string, error) {
	mgdClusterInfo, err := c.ProjectcalicoV3().ClusterInformations().Get(context.Background(), "default", metav1.GetOptions{})
	if err != nil {
		log.WithError(err).Warn("Error retrieving managed cluster information, treating as older managed cluster")

		return resource.VoltronLinseedPublicCertOld, nil
	}

	calicoEnterpriseVersion := mgdClusterInfo.Spec.CalicoEnterpriseVersion
	if calicoEnterpriseVersion == "" {
		calicoEnterpriseVersion = mgdClusterInfo.Spec.CNXVersion
	}

	// ignore the prerelease version for semver compare
	version := strings.Split(calicoEnterpriseVersion, "-")
	if len(version) == 0 {
		err = fmt.Errorf("managed cluster version length is zero")
		return "", err
	}

	clusterVersion, err := semver.NewVersion(strings.TrimPrefix(version[0], "v"))
	if err != nil {
		err = fmt.Errorf("failed to parse semantic version %v", version[0])
		return "", err
	}

	featureVersion, _ := semver.NewVersion("3.23.0")
	if clusterVersion.LessThan(*featureVersion) {
		return resource.VoltronLinseedPublicCertOld, nil
	}

	return resource.VoltronLinseedPublicCert, nil
}
