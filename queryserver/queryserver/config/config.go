// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.
package config

import (
	"github.com/projectcalico/calico/linseed/pkg/client"
)

type Config struct {
	// this service will be hosted on this address
	ListenAddr string `envconfig:"LISTEN_ADDR" default:":8080"`

	TLSCert string `envconfig:"TLS_CERT" default:"/calico-apiserver-certs/tls.crt"`
	TLSKey  string `envconfig:"TLS_KEY" default:"/calico-apiserver-certs/tls.key"`

	// OIDC Authentication settings.
	OIDCAuthEnabled        bool   `envconfig:"OIDC_AUTH_ENABLED" default:"false" split_words:"true"`
	OIDCAuthJWKSURL        string `envconfig:"OIDC_AUTH_JWKSURL" default:"https://tigera-dex.tigera-dex.svc.cluster.local:5556/dex/keys" split_words:"true"`
	OIDCAuthIssuer         string `envconfig:"OIDC_AUTH_ISSUER" default:"https://127.0.0.1:5556/dex" split_words:"true"`
	OIDCAuthClientID       string `envconfig:"OIDC_AUTH_CLIENT_ID" default:"tigera-manager" split_words:"true"`
	OIDCAuthUsernameClaim  string `envconfig:"OIDC_AUTH_USERNAME_CLAIM" default:"email" split_words:"true"`
	OIDCAuthUsernamePrefix string `envconfig:"OIDC_AUTH_USERNAME_PREFIX" split_words:"true"`
	OIDCAuthGroupsClaim    string `envconfig:"OIDC_AUTH_GROUPS_CLAIM" default:"groups" split_words:"true"`
	OIDCAuthGroupsPrefix   string `envconfig:"OIDC_AUTH_GROUPS_PREFIX" split_words:"true"`

	PrometheusEndpoint string `default:"https://prometheus-http-api.tigera-prometheus.svc:9090" split_words:"true"`

	// Linseed client configuration for policy activity enrichment.
	LinseedURL        string `envconfig:"LINSEED_URL" default:"https://tigera-linseed.tigera-elasticsearch.svc"`
	LinseedCA         string `envconfig:"LINSEED_CA" default:"/etc/pki/tls/certs/tigera-ca-bundle.crt"`
	LinseedClientCert string `envconfig:"LINSEED_CLIENT_CERT"`
	LinseedClientKey  string `envconfig:"LINSEED_CLIENT_KEY"`
	LinseedToken      string `envconfig:"LINSEED_TOKEN" default:"/var/run/secrets/kubernetes.io/serviceaccount/token"`
	TenantID          string `envconfig:"TENANT_ID"`
	ClusterID         string `envconfig:"CLUSTER_ID" default:"cluster"`

	// K8sClientQPS => rest.Config.QPS
	K8sClientQPS float32 `default:"100.0" split_words:"true"`
	// K8sClientBurst => rest.Config.Burst
	K8sClientBurst int `default:"1000" split_words:"true"`

	// LinseedPolicyActivity is the Linseed client for policy activity enrichment.
	// Set programmatically after constructing the config; not populated by envconfig.
	LinseedPolicyActivity client.PolicyActivityInterface `envconfig:"-"`
}
