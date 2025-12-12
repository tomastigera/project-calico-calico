// Copyright (c) 2021 Tigera, Inc. All rights reserved.

//go:build !tesla

package elasticsearchconfiguration

// enableElasticsearchWatch enables watching the Elasticsearch CR in the Enterprise variant.
var enableElasticsearchWatch = true

// reconcileConfigMap copies the tigera-secure-elasticsearch ConfigMap in the management cluster to the managed cluster,
// changing the clusterName data value to the cluster name this ConfigMap is being copied to
func (c *reconciler) reconcileConfigMap() error {
	return c.eeReconcileConfigMap()
}
