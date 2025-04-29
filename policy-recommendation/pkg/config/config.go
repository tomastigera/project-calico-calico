// Copyright (c) 2022-2024 Tigera Inc. All rights reserved.

package config

import (
	"fmt"

	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

type Config struct {
	LogLevel log.Level `envconfig:"LOG_LEVEL" default:"INFO"`

	// Cluster connection type
	ClusterConnectionType string `envconfig:"CLUSTER_CONNECTION_TYPE" default:"standalone"`

	// Linseed parameters
	LinseedURL        string `envconfig:"LINSEED_URL" default:"https://tigera-linseed.tigera-elasticsearch.svc"`
	LinseedCA         string `envconfig:"LINSEED_CA" default:"/etc/pki/tls/certs/tigera-ca-bundle.crt"`
	LinseedClientCert string `envconfig:"LINSEED_CLIENT_CERT" default:"/etc/pki/tls/certs/tigera-ca-bundle.crt"`
	LinseedClientKey  string `envconfig:"LINSEED_CLIENT_KEY"`
	LinseedToken      string `envconfig:"LINSEED_TOKEN" default:"/var/run/secrets/kubernetes.io/serviceaccount/token"`

	// For Calico Cloud, the tenant ID to use.
	TenantID string `envconfig:"TENANT_ID"`

	// This setting is required for es proxy that performs the authentication and authorization for a user.
	EnableMultiClusterClient       bool   `envconfig:"ENABLE_MULTI_CLUSTER_CLIENT" default:"false"`
	MultiClusterForwardingCA       string `envconfig:"MULTI_CLUSTER_FORWARDING_CA" default:"/etc/pki/tls/certs/tigera-ca-bundle.crt"`
	MultiClusterForwardingEndpoint string `envconfig:"MULTI_CLUSTER_FORWARDING_ENDPOINT" default:"https://tigera-manager.tigera-manager.svc:9443"`

	TenantNamespace    string `envconfig:"TENANT_NAMESPACE" default:""`
	ManagedClusterType string `envconfig:"MANAGED_CLUSTER_TYPE" default:"enterprise"`
}

func LoadConfig() (*Config, error) {
	var err error
	config := &Config{}
	err = envconfig.Process("", config)
	if err != nil {
		return nil, err
	}

	if config.TenantNamespace != "" && config.TenantID == "" {
		return nil, fmt.Errorf("cannot define the TenantID without the TenantNamespace")
	}
	return config, nil
}

func (c *Config) InitializeLogging() {
	logutils.ConfigureFormatter("polrec")
	log.SetLevel(c.LogLevel)
}
