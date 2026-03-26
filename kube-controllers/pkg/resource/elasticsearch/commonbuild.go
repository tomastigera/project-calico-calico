// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package elasticsearch

import (
	"context"

	esv1 "github.com/elastic/cloud-on-k8s/v3/pkg/apis/elasticsearch/v1"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/utils"
	"github.com/projectcalico/calico/kube-controllers/pkg/resource"
)

// CalculateTigeraElasticsearchHash calculates and returns a hash that can be used to determine if the tigera elasticsearch
// cluster has changed
func (r *restClient) eeCalculateTigeraElasticsearchHash() (string, error) {
	es := &esv1.Elasticsearch{}
	err := r.Get().Resource("elasticsearches").Namespace(resource.TigeraElasticsearchNamespace).Name(resource.DefaultTSEEInstanceName).Do(context.Background()).Into(es)
	if err != nil {
		return "", err
	}

	return utils.GenerateTruncatedHash(es.CreationTimestamp, 24)
}
