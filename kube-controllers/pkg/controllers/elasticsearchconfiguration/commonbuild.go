package elasticsearchconfiguration

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/kube-controllers/pkg/resource"
)

func (c *reconciler) eeReconcileConfigMap() error {
	configMap, err := c.managementK8sCLI.CoreV1().ConfigMaps(c.managementOperatorNamespace).Get(context.Background(), resource.ElasticsearchConfigMapName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	configMap.Namespace = c.managedOperatorNamespace
	cp := resource.CopyConfigMap(configMap)
	cp.Data["clusterName"] = c.clusterName
	if err := resource.WriteConfigMapToK8s(c.managedK8sCLI, cp); err != nil {
		return err
	}
	return nil
}
