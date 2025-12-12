// Copyright (c) 2021 Tigera, Inc. All rights reserved.

//go:build !tesla

package elasticsearch

// CalculateTigeraElasticsearchHash calculates and returns a hash that can be used to determine if the tigera elasticsearch
// cluster has changed
func (r *restClient) CalculateTigeraElasticsearchHash() (string, error) {
	return r.eeCalculateTigeraElasticsearchHash()
}
