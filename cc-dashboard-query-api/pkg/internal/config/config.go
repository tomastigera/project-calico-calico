package config

import "time"

type Config struct {
	LogLevel   string `default:"INFO" split_words:"true"`
	ListenAddr string `default:":8443" split_words:"true"`

	OpenTelemetryEnabled bool `default:"false"`

	Kubeconfig string `default:"" json:"kubeconfig,omitempty"`

	// TenantID is the unique identifier for the tenant this instance is serving.
	TenantID        string `default:"" split_words:"true"`
	TenantNamespace string `default:"" split_words:"true"`

	// CorsOrigins allowed origins for CORS response. Separate multiple origins by a comma (e.g. origin1,origin2,origin3)
	CorsOrigins string `default:"https://www.calicocloud.io" split_words:"true"`

	// HTTPSCert, HTTPSKey - path to a x509 certificate and its private key for the https server
	HTTPSCert string `default:"/certs/https/cert" split_words:"true"`
	HTTPSKey  string `default:"/certs/https/key" split_words:"true"`

	// Linseed configuration
	LinseedURL        string `default:"https://tigera-linseed.tigera-elasticsearch.svc" split_words:"true"`
	LinseedCA         string `default:"/etc/pki/tls/certs/tigera-ca-bundle.crt" split_words:"true"`
	LinseedClientKey  string `default:"" split_words:"true"`
	LinseedClientCert string `default:"" split_words:"true"`
	LinseedToken      string `default:"/var/run/secrets/kubernetes.io/serviceaccount/token" split_words:"true"`

	OIDCAuthIssuer         string `split_words:"true"`
	OIDCAuthClientID       string `split_words:"true"`
	OIDCAuthUsernameClaim  string `split_words:"true"`
	OIDCAuthGroupsClaim    string `split_words:"true"`
	OIDCAuthJWKSURL        string `split_words:"true"`
	OIDCAuthUsernamePrefix string `split_words:"true"`
	OIDCAuthGroupsPrefix   string `split_words:"true"`

	// LMAAuthorizationCacheTTL when >0 this will cache the lma authorization results
	LMAAuthorizationCacheTTL time.Duration `default:"10s" split_words:"true"`

	// Endpoint for authorization requests
	MultiClusterForwardingEndpoint string `default:"https://tigera-manager.tigera-manager.svc:9443" split_words:"true"`
}
