package config

import (
	"time"

	"k8s.io/apimachinery/pkg/util/json"
)

type Config struct {
	LogLevel   string `default:"INFO" split_words:"true"`
	ListenAddr string `default:":8443" split_words:"true"`
	HealthPort int    `default:"8080" split_words:"true"`

	OpenTelemetryEnabled bool `default:"false"`

	Kubeconfig string `default:"" json:"kubeconfig,omitempty"`

	// TenantID is the unique identifier for the tenant this instance is serving.
	TenantID        string `default:"" split_words:"true"`
	TenantNamespace string `default:"" split_words:"true"`

	CalicoCloudTenantClaim string `default:"" split_words:"true"`

	// CorsOrigins allowed origins for CORS response. Separate multiple origins by a comma (e.g. origin1,origin2,origin3)
	CorsOrigins string `default:"https://www.calicocloud.io" split_words:"true"`

	// HttpsCert, HttpsKey - path to a x509 certificate and its private key for the https server
	HttpsCert string `default:"" split_words:"true"`
	HttpsKey  string `default:"" split_words:"true"`

	// HttpsCACert Used to verify client certificates for mTLS.
	HttpsCACert string `default:"" split_words:"true"`

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
	MultiClusterForwardingEndpoint string `default:"https://calico-manager.calico-system.svc:9443" split_words:"true"`
	// CA used to verify the forwarding endpoint when contacting voltron (Cloud mode)
	MultiClusterForwardingCA string `default:"/etc/pki/tls/certs/tigera-ca-bundle.crt" split_words:"true"`

	// MaxRequestFilters limits the number of filters on query requests
	MaxRequestFilters int `default:"10" split_words:"true"`

	// MaxRequestAggregations limits the number of aggregations on query requests
	MaxRequestAggregations int `default:"5" split_words:"true"`

	// MetadataAPIEndpoint is the endpoint for the metadata service that is used to store dashboards if
	// ProductMode is set to "cloud". If ProductMode is set to "enterprise", this is ignored.
	MetadataAPIEndpoint string `default:"https://api2.tesla.tigera.io/orgs/dashboards" split_words:"true"`

	// Metrics endpoint configurations.
	EnableMetrics bool   `default:"false" split_words:"true"`
	MetricsAddr   string `default:":9095" split_words:"true"`

	// Certificates used to secure metrics endpoint via TLS
	MetricsCert string `default:"/certs/https/tls.crt" split_words:"true"`
	MetricsKey  string `default:"/certs/https/tls.key" split_words:"true"`

	// DisabledCollections is a comma separated list of collections to be disabled e.g.: waf,dns
	DisabledCollections string `split_words:"true"`

	ProductMode string `default:"enterprise" split_words:"true"`
}

var (
	ProductModeEnterprise = "enterprise"
	ProductModeCloud      = "cloud"
)

func (c Config) String() string {
	c2 := c
	if c2.OIDCAuthClientID != "" {
		c2.OIDCAuthClientID = "<redacted>"
	}

	data, err := json.Marshal(c2)
	if err != nil {
		return "{}"
	}
	return string(data)
}
