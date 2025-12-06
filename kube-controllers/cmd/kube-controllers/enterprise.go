// Copyright (c) 2021 Tigera, Inc. All rights reserved.

//go:build !tesla

package main

import (
	"github.com/projectcalico/calico/kube-controllers/pkg/config"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/managedcluster"
	"github.com/projectcalico/calico/kube-controllers/pkg/elasticsearch"
	relastic "github.com/projectcalico/calico/kube-controllers/pkg/resource/elasticsearch"
)

// ValidateEnvVars performs validation on environment variables that are specific to this variant Enterprise.
func ValidateEnvVars() {}

func getCloudManagedClusterControllerManagers(esK8sREST relastic.RESTClient, esClientBuilder elasticsearch.ClientBuilder, cfg config.RunConfig) []managedcluster.ControllerManager {
	return []managedcluster.ControllerManager{
		managedcluster.NewElasticsearchController(esK8sREST, esClientBuilder, cfg.Controllers.ManagedCluster.ElasticConfig),
		managedcluster.NewLicensingController(cfg.Controllers.ManagedCluster.LicenseConfig),
	}
}
