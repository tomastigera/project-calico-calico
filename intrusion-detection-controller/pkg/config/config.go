package config

import (
	"errors"

	"github.com/kelseyhightower/envconfig"
)

// Config contains generic configuration for intrusion detection components.
type Config struct {
	// Linseed configuration
	LinseedURL        string `envconfig:"LINSEED_URL" default:"https://tigera-linseed.tigera-elasticsearch.svc"`
	LinseedCA         string `envconfig:"LINSEED_CA" default:"/etc/pki/tls/certs/ca.crt"`
	LinseedClientCert string `envconfig:"LINSEED_CLIENT_CERT" default:"/etc/pki/tls/certs/ca.crt"`
	LinseedClientKey  string `envconfig:"LINSEED_CLIENT_KEY"`
	LinseedToken      string `envconfig:"LINSEED_TOKEN" default:"/var/run/secrets/kubernetes.io/serviceaccount/token"`

	ClusterName string `envconfig:"CLUSTER_NAME" default:""`

	// Tenant configuration for Calico Cloud.
	// If TenantNamespace is set, then TenantID must also be set. This signifies a multi-tenant CC installation.
	// If TenantID is set and no TenantNamespace is set, then this is a single-tenant CC installation.
	TenantID        string `envconfig:"TENANT_ID"`
	TenantNamespace string `envconfig:"TENANT_NAMESPACE" default:""`

	// MCM configuration
	MultiClusterForwardingCA       string `envconfig:"MULTI_CLUSTER_FORWARDING_CA" default:"/manager-tls/cert"`
	MultiClusterForwardingEndpoint string `envconfig:"MULTI_CLUSTER_FORWARDING_ENDPOINT" default:"https://calico-manager.calico-system.svc:9443"`
}

func GetConfig() (*Config, error) {
	cfg := &Config{}
	if err := envconfig.Process("", cfg); err != nil {
		return nil, err
	}
	if cfg.TenantNamespace != "" && cfg.TenantID == "" {
		return nil, errors.New("tenant namespace was provided but TenantID was not")
	}
	return cfg, nil
}

// DashboardInstallerConfig contains configuration specific to the Kibana dashboard installer.
type DashboardInstallerConfig struct {
	KibanaScheme      string `envconfig:"KIBANA_SCHEME" default:"https"`
	KibanaHost        string `envconfig:"KIBANA_HOST"`
	KibanaPort        string `envconfig:"KIBANA_PORT" default:"5601"`
	KibanaCAPath      string `envconfig:"KB_CA_CERT" default:"/etc/pki/tls/certs/ca.crt"`
	KibanaSpaceID     string `envconfig:"KIBANA_SPACE_ID"`
	KibanaMTLSEnabled bool   `envconfig:"KIBANA_MTLS_ENABLED"`
	KibanaClientKey   string `envconfig:"KIBANA_CLIENT_KEY"`
	KibanaClientCert  string `envconfig:"KIBANA_CLIENT_CERT"`

	ElasticUsername string `envconfig:"ELASTIC_USER"`
	ElasticPassword string `envconfig:"ELASTIC_PASSWORD"`
}

func GetDashboardInstallerConfig() (*DashboardInstallerConfig, error) {
	cfg := &DashboardInstallerConfig{}
	if err := envconfig.Process("", cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
