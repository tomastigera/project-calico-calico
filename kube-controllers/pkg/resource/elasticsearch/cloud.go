// Copyright (c) 2021 Tigera, Inc. All rights reserved.

//go:build tesla

package elasticsearch

import "os"

var tenantID = os.Getenv("TENANT_ID")

// CalculateTigeraElasticsearchHash for the Cloud/Tesla variant simply returns a string and a nil error
// since the cluster does not contain an Elasticsearch CR.
func (r *restClient) CalculateTigeraElasticsearchHash() (string, error) {
	if tenantID != "" {
		// Returning a non-empty string ensures that we perform a one time creation of Elasticsearch roles.
		return "externalElasticsearch", nil
	}

	return r.eeCalculateTigeraElasticsearchHash()
}
