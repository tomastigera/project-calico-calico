// Copyright (c) 2021 Tigera, Inc. All rights reserved.

//go:build tesla

package main

import (
	"log"
	"os"
	"regexp"

	"github.com/projectcalico/calico/kube-controllers/pkg/config"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/managedcluster"
	"github.com/projectcalico/calico/kube-controllers/pkg/elasticsearch"
	relastic "github.com/projectcalico/calico/kube-controllers/pkg/resource/elasticsearch"
)

// We assume that a tenant ID must obey the following syntax restrictions:
//   - contain at most 63 characters
//   - contain only lowercase alphanumeric characters or '-'
//   - start with an alphanumeric character
//   - end with an alphanumeric character
//
// https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-label-names
var tenantIDSyntax = regexp.MustCompile(`^[a-z0-9]([a-z0-9]|[a-z0-9\-]{0,61}[a-z0-9])?$`)

// ValidateEnvVars performs validation on environment variables that are specific to this variant (Cloud/Tesla).
func ValidateEnvVars() {
	// Including Tenant ID is optional for Cloud/Tesla. It should be enabled when using a multi-tenant setup.
	tenantID := os.Getenv("TENANT_ID")
	if tenantID != "" && !tenantIDSyntax.MatchString(tenantID) {
		log.Fatal("TENANT_ID must consist of only alpha-numeric chars (lowercase) or '-' and be at max 63 chars")
	}
}

func getCloudManagedClusterControllerManagers(esK8sREST relastic.RESTClient, esClientBuilder elasticsearch.ClientBuilder, cfg config.RunConfig) []managedcluster.ControllerManager {
	return []managedcluster.ControllerManager{
		managedcluster.NewElasticsearchController(esK8sREST, esClientBuilder, cfg.Controllers.ManagedCluster.ElasticConfig),
	}
}
