// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package server

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

const (
	defaultCertFileName = "cert"
	defaultKeyFileName  = "key"
)

// Config stores various configuration information for the ui-apis
// server.
type Config struct {
	// ListenAddr is the address and port that the server will listen
	// on for proxying requests. The format is similar to the address
	// parameter of net.Listen
	ListenAddr string `envconfig:"LISTEN_ADDR" default:"127.0.0.1:8443"`

	// Paths to files containing certificate and matching private key
	// for serving requests over TLS.
	CertFile string `envconfig:"CERT_FILE_PATH"`
	KeyFile  string `envconfig:"KEY_FILE_PATH"`

	// If specific a CertFile and KeyFile are not provided this is the
	// location to autogenerate the files
	DefaultSSLPath string `envconfig:"KEY_CERT_GEN_PATH" default:"/etc/ui-apis/ssl/"`
	// Default cert and key file paths calculated from the DefaultSSLPath
	DefaultCertFile string `envconfig:"-"`
	DefaultKeyFile  string `envconfig:"-"`

	LinseedURL        string `envconfig:"LINSEED_URL" default:"https://tigera-linseed.tigera-elasticsearch.svc"`
	LinseedCA         string `envconfig:"LINSEED_CA" default:"/etc/pki/tls/certs/ca.crt"`
	LinseedClientCert string `envconfig:"LINSEED_CLIENT_CERT" default:"/etc/pki/tls/certs/ca.crt"`
	LinseedClientKey  string `envconfig:"LINSEED_CLIENT_KEY"`
	LinseedToken      string `envconfig:"LINSEED_TOKEN" default:"/var/run/secrets/kubernetes.io/serviceaccount/token"`

	ExcludeDryRuns bool `envconfig:"EXCLUDE_DRYRUNS" default:"true"`

	// QueryServer Config
	QueryServerEndpoint string `envconfig:"QUEYRSERVER_ENDPOINT" default:"https://calico-api.calico-system.svc:8080"`
	QueryServerURL      string `envconfig:"QUERYSERVER_URL" default:"/api/v1/namespaces/calico-system/services/https:calico-api:8080/proxy"`
	QueryServerCA       string `envconfig:"QUERYSERVER_CA" default:"/etc/pki/tls/certs/ca.crt"`
	QueryServerToken    string `envconfig:"QUSERYSERVER_TOKEN" default:"/var/run/secrets/kubernetes.io/serviceaccount/token"`

	// TenantID is the unique identifier for the tenant this instance is serving. If left blank, this is a
	// zero-tenant (enterprise) instance. If set and TENANT_NAMESPACE is empty, this is a single-tenant management cluster.
	// If set and TENANT_NAMESPACE is set, this is a multi-tenant management cluster.
	TenantID        string `envconfig:"TENANT_ID"`
	TenantNamespace string `envconfig:"TENANT_NAMESPACE"`

	// Whether or not Guardian in managed clusters supports impersonation.
	Impersonate bool `envconfig:"IMPERSONATE" default:"true"`

	// Configuration for connection to Kibana.
	ElasticLicenseType    string `envconfig:"ELASTIC_LICENSE_TYPE"`
	ElasticKibanaEndpoint string `envconfig:"ELASTIC_KIBANA_ENDPOINT" default:"https://tigera-secure-kb-http.tigera-kibana.svc:5601"`
	ElasticKibanaDisabled bool   `envconfig:"ELASTIC_KIBANA_DISABLED"`

	// If multi-cluster management is used inside the cluster, this CA
	// is necessary for establishing a connection with Voltron, when
	// accessing other clusters.
	VoltronCAPath string `envconfig:"VOLTRON_CA_PATH" default:"/manager-tls/cert"`

	// Location of the Voltron service.
	VoltronURL string `envconfig:"VOLTRON_URL" default:"https://localhost:9443"`

	// Whether or not Goldmane is enabled in managed clusters.
	GoldmaneEnabled bool `envconfig:"GOLDMANE_ENABLED" default:"false"`

	// Dex settings for authentication.
	OIDCAuthEnabled        bool   `envconfig:"OIDC_AUTH_ENABLED" default:"false"`
	OIDCAuthIssuer         string `envconfig:"OIDC_AUTH_ISSUER"`
	OIDCAuthClientID       string `envconfig:"OIDC_AUTH_CLIENT_ID"`
	OIDCAuthJWKSURL        string `envconfig:"OIDC_AUTH_JWKSURL" default:"https://tigera-dex.tigera-dex.svc.cluster.local:5556/dex/keys"`
	OIDCAuthUsernameClaim  string `envconfig:"OIDC_AUTH_USERNAME_CLAIM" default:"email"`
	OIDCAuthGroupsClaim    string `envconfig:"OIDC_AUTH_GROUPS_CLAIM"`
	OIDCAuthUsernamePrefix string `envconfig:"OIDC_AUTH_USERNAME_PREFIX"`
	OIDCAuthGroupsPrefix   string `envconfig:"OIDC_AUTH_GROUPS_PREFIX"`

	// Service graph settings.  See servicegraph.Config for details.
	ServiceGraphCacheMaxEntries           int           `envconfig:"SERVICE_GRAPH_CACHE_MAX_ENTRIES" default:"10"`
	ServiceGraphCacheMaxBucketsPerQuery   int           `envconfig:"SERVICE_GRAPH_CACHE_MAX_BUCKETS_PER_QUERY" default:"1000"`
	ServiceGraphCacheMaxAggregatedRecords int           `envconfig:"SERVICE_GRAPH_CACHE_MAX_AGGREGATED_RECORDS" default:"100000"`
	ServiceGraphCachePolledEntryAgeOut    time.Duration `envconfig:"SERVICE_GRAPH_CACHE_POLLED_ENTRY_AGE_OUT" default:"1h"`
	ServiceGraphCacheSlowQueryEntryAgeOut time.Duration `envconfig:"SERVICE_GRAPH_CACHE_SLOW_QUERY_ENTRY_AGE_OUT" default:"5m"`
	ServiceGraphCachePollLoopInterval     time.Duration `envconfig:"SERVICE_GRAPH_CACHE_POLL_LOOP_INTERVAL" default:"5m"`
	ServiceGraphCachePollQueryInterval    time.Duration `envconfig:"SERVICE_GRAPH_CACHE_POLL_QUERY_INTERVAL" default:"3s"`
	ServiceGraphCacheDataSettleTime       time.Duration `envconfig:"SERVICE_GRAPH_CACHE_DATA_SETTLE_TIME" default:"15m"`
	ServiceGraphCacheDataPrefetch         bool          `envconfig:"SERVICE_GRAPH_CACHE_DATA_PREFETCH" default:"true"`

	// Enable querying for L7,DNS logs and events in Linseed. At the moment, used only for ServiceGraph
	// They are disabled in free tier setup
	L7LogsEnabled  bool `envconfig:"L7_LOGS_ENABLED" default:"true"`
	DNSLogsEnabled bool `envconfig:"DNS_LOGS_ENABLED" default:"true"`
	EventsEnabled  bool `envconfig:"EVENTS_ENABLED" default:"true"`

	ParallelGraphStatsFetch     bool  `envconfig:"PARALLEL_GRAPH_STATS_FETCH" default:"true"`
	GraphStatsRequestLogging    bool  `envconfig:"GRAPH_STATS_REQUEST_LOGGING" default:"false"`
	XLargeFlowLogScaleThreshold int64 `envconfig:"XLARGE_FLOW_LOG_SCALE_THRESHOLD" default:"10000000"`
	LargeFlowLogScaleThreshold  int64 `envconfig:"LARGE_FLOW_LOG_SCALE_THRESHOLD" default:"1000000"`
	LargeL3FlowScaleThreshold   int64 `envconfig:"LARGE_L3_FLOW_SCALE_THRESHOLD" default:"2000"`
	GlobalStatsTimeoutSeconds   int   `envconfig:"GLOBAL_STATS_TIMEOUT_SECONDS" default:"3"`
}

func NewConfigFromEnv() (*Config, error) {
	config := &Config{}

	// Load config from environments.
	err := envconfig.Process("", config)
	if err != nil {
		return nil, err
	}

	// Calculate the default cert and key file from the directory.
	config.DefaultKeyFile = config.DefaultSSLPath + defaultKeyFileName
	config.DefaultCertFile = config.DefaultSSLPath + defaultCertFileName

	return config, nil
}
