// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package config

import (
	"errors"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/json"
)

const (
	// EnvConfigPrefix represents the prefix used to load ENV variables required for startup
	EnvConfigPrefix = "LINSEED"
)

// Config defines the parameters of the application
type Config struct {
	Port     int `default:"8444" split_words:"true"`
	Host     string
	LogLevel string `default:"INFO" split_words:"true"`

	Kubeconfig string `envconfig:"KUBECONFIG"`

	// Certificate presented to the client for TLS verification.
	HTTPSCert string `default:"/certs/https/tls.crt" split_words:"true"`
	HTTPSKey  string `default:"/certs/https/tls.key" split_words:"true"`

	// Metrics endpoint configurations.
	EnableMetrics bool `default:"false" split_words:"true"`
	MetricsPort   int  `default:"9095" split_words:"true"`

	// Certificates used to secure metrics endpoint via TLS
	MetricsCert string `default:"/certs/https/tls.crt" split_words:"true"`
	MetricsKey  string `default:"/certs/https/tls.key" split_words:"true"`

	// Key used for generation and verification of access tokens.
	TokenKey string `default:"/certs/https/tokens.key" split_words:"true"`

	// Used to verify client certificates for mTLS.
	CACert string `default:"/certs/https/client.crt" split_words:"true"`

	// ExpectedTenantID will be verified against x-tenant-id header for all API calls
	// in a multi-tenant environment. If left empty, Linseed will not require the x-tenant-id
	// header to be set on incoming requests. Note that ExpectedTenantID is set for both single-tenant management clusters in CC,
	// as well as multi-tenant management clusters; except when a single tenant CC management
	// cluster has Elastic running inside the management cluster, AKA "internal ES".
	ExpectedTenantID string `default:"" split_words:"true"`

	// TenantNamespace indicates the namespace in which this Linseed's tenant resides. If set, this means
	// Linseed is running within a multi-tenant management cluster. If left empty, this means Linseed is either running in a
	// single-tenant management cluster or a zero-tenant management cluster (depending on the value of ExpectedTenantID).
	TenantNamespace string `envconfig:"TENANT_NAMESPACE" default:""`

	// ManagementOperatorNamespace is the namespace in the management cluster in which the tigera-operator is running.
	ManagementOperatorNamespace string `envconfig:"MANAGEMENT_OPERATOR_NS" default:""`

	// Whether or not to run the token controller. This must be true for management clusters.
	TokenControllerEnabled bool `envconfig:"TOKEN_CONTROLLER_ENABLED" default:"false"`

	// Configuration for Voltron access.
	MultiClusterForwardingEndpoint string `default:"https://calico-manager.calico-system.svc:9443" split_words:"true"`
	MultiClusterForwardingCA       string `default:"/etc/pki/tls/certs/ca.crt" split_words:"true"`

	// Configuration for health port.
	HealthPort int `default:"8080" split_words:"true"`

	// Elastic configuration
	ElasticClientConfig *ElasticClientConfig

	// Configures which backend mode to use.
	Backend BackendType `envconfig:"BACKEND" default:"elastic-multi-index"`

	// SingleIndexIndicesCreationEnabled will configure index templates, write aliases and
	// create boostrap indices at runtime from the request received
	SingleIndexIndicesCreationEnabled bool `envconfig:"ELASTIC_SINGLE_INDEX_INDICES_CREATION_ENABLED"`

	// ProductVariant informs linseed which product variant it is running under so that
	// linseed can restrict functionality accordingly, for example by disabling
	// api's that are not used in oss.
	ProductVariant ProductVariant `envconfig:"PRODUCT_VARIANT" default:"TigeraSecureEnterprise"`

	// PolicyActivityCacheCleanupInterval controls how often the in-memory deduplication cache is scanned for expired policy activity records.
	PolicyActivityCacheCleanupInterval time.Duration `envconfig:"POLICY_ACTIVITY_CACHE_CLEANUP_INTERVAL" default:"10m"`
	// PolicyActivityCacheCleanupTTL defines the max age of a cache entry and should slightly exceed the deduplication window for policy activity.
	PolicyActivityCacheCleanupTTL time.Duration `envconfig:"POLICY_ACTIVITY_CACHE_CLEANUP_TTL" default:"2h"`
}

// ElasticClientConfig represents the elastic configuration
type ElasticClientConfig struct {
	ElasticScheme               string `envconfig:"ELASTIC_SCHEME" default:"https"`
	ElasticHost                 string `envconfig:"ELASTIC_HOST" default:"tigera-secure-es-http.tigera-elasticsearch.svc"`
	ElasticPort                 string `envconfig:"ELASTIC_PORT" default:"9200"`
	ElasticUsername             string `envconfig:"ELASTIC_USERNAME" default:""`
	ElasticPassword             string `envconfig:"ELASTIC_PASSWORD" default:"" json:",omitempty"`
	ElasticCA                   string `envconfig:"ELASTIC_CA" default:"/certs/elasticsearch/tls.crt"`
	ElasticClientKey            string `envconfig:"ELASTIC_CLIENT_KEY" default:"/certs/elasticsearch/client.key"`
	ElasticClientCert           string `envconfig:"ELASTIC_CLIENT_CERT" default:"/certs/elasticsearch/client.crt"`
	ElasticGZIPEnabled          bool   `envconfig:"ELASTIC_GZIP_ENABLED" default:"false"`
	ElasticMTLSEnabled          bool   `envconfig:"ELASTIC_MTLS_ENABLED" default:"false"`
	ElasticSniffingEnabled      bool   `envconfig:"ELASTIC_SNIFFING_ENABLED" default:"false"`
	ElasticIndexMaxResultWindow int64  `envconfig:"ELASTIC_INDEX_MAX_RESULT_WINDOW" default:"10000"`

	// Default value for replicas and shards
	ElasticReplicas int `envconfig:"ELASTIC_REPLICAS" default:"0"`
	ElasticShards   int `envconfig:"ELASTIC_SHARDS" default:"1"`

	// Replicas and flows for flows
	ElasticFlowReplicas int `envconfig:"ELASTIC_FLOWS_INDEX_REPLICAS" default:"0"`
	ElasticFlowShards   int `envconfig:"ELASTIC_FLOWS_INDEX_SHARDS" default:"1"`

	// Replicas and flows for DNS
	ElasticDNSReplicas int `envconfig:"ELASTIC_DNS_INDEX_REPLICAS" default:"0"`
	ElasticDNSShards   int `envconfig:"ELASTIC_DNS_INDEX_SHARDS" default:"1"`

	// Replicas and flows for Audit
	ElasticAuditReplicas int `envconfig:"ELASTIC_AUDIT_INDEX_REPLICAS" default:"0"`
	ElasticAuditShards   int `envconfig:"ELASTIC_AUDIT_INDEX_SHARDS" default:"1"`

	// Replicas and flows for BGP
	ElasticBGPReplicas int `envconfig:"ELASTIC_BGP_INDEX_REPLICAS" default:"0"`
	ElasticBGPShards   int `envconfig:"ELASTIC_BGP_INDEX_SHARDS" default:"1"`

	// Replicas and flows for WAF
	ElasticWAFReplicas int `envconfig:"ELASTIC_WAF_INDEX_REPLICAS" default:"0"`
	ElasticWAFShards   int `envconfig:"ELASTIC_WAF_INDEX_SHARDS" default:"1"`

	// Replicas and flows for L7
	ElasticL7Replicas int `envconfig:"ELASTIC_L7_INDEX_REPLICAS" default:"0"`
	ElasticL7Shards   int `envconfig:"ELASTIC_L7_INDEX_SHARDS" default:"1"`

	// Replicas and flows for Runtime
	ElasticRuntimeReplicas int `envconfig:"ELASTIC_RUNTIME_INDEX_REPLICAS" default:"0"`
	ElasticRuntimeShards   int `envconfig:"ELASTIC_RUNTIME_INDEX_SHARDS" default:"1"`

	// Replicas and flows for PolicyActivity
	ElasticPolicyActivityReplicas int `envconfig:"ELASTIC_POLICY_ACTIVITY_INDEX_REPLICAS" default:"0"`
	ElasticPolicyActivityShards   int `envconfig:"ELASTIC_POLICY_ACTIVITY_INDEX_SHARDS" default:"1"`

	// These environment variables allow overriding the index names to use for this Linseed.
	// They are only supported when running in single-index mode. If unset, defaults will be used instead
	ElasticAlertsBaseIndexName               string `envconfig:"ELASTIC_ALERTS_BASE_INDEX_NAME" default:"calico_alerts"`
	ElasticAlertsPolicyName                  string `envconfig:"ELASTIC_ALERTS_POLICY_NAME" default:"tigera_secure_ee_events_policy"`
	ElasticAuditLogsBaseIndexName            string `envconfig:"ELASTIC_AUDIT_LOGS_BASE_INDEX_NAME" default:"calico_auditlogs"`
	ElasticAuditLogsPolicyName               string `envconfig:"ELASTIC_AUDIT_LOGS_POLICY_NAME" default:"tigera_secure_ee_audit_ee_policy"`
	ElasticBGPLogsBaseIndexName              string `envconfig:"ELASTIC_BGP_LOGS_BASE_INDEX_NAME" default:"calico_bgplogs"`
	ElasticBGPLogsPolicyName                 string `envconfig:"ELASTIC_BGP_LOGS_POLICY_NAME" default:"tigera_secure_ee_bgp_policy"`
	ElasticComplianceBenchmarksBaseIndexName string `envconfig:"ELASTIC_COMPLIANCE_BENCHMARKS_BASE_INDEX_NAME" default:"calico_compliance_benchmark_results"`
	ElasticComplianceBenchmarksPolicyName    string `envconfig:"ELASTIC_COMPLIANCE_BENCHMARKS_POLICY_NAME" default:"tigera_secure_ee_benchmark_results_policy"`
	ElasticComplianceReportsBaseIndexName    string `envconfig:"ELASTIC_COMPLIANCE_REPORTS_BASE_INDEX_NAME" default:"calico_compliance_reports"`
	ElasticComplianceReportsPolicyName       string `envconfig:"ELASTIC_COMPLIANCE_REPORTS_POLICY_NAME" default:"tigera_secure_ee_compliance_reports_policy"`
	ElasticComplianceSnapshotsBaseIndexName  string `envconfig:"ELASTIC_COMPLIANCE_SNAPSHOTS_BASE_INDEX_NAME" default:"calico_compliance_snapshots"`
	ElasticComplianceSnapshotsPolicyName     string `envconfig:"ELASTIC_COMPLIANCE_SNAPSHOTS_POLICY_NAME" default:"tigera_secure_ee_compliance_snapshots_policy"`
	ElasticDNSLogsBaseIndexName              string `envconfig:"ELASTIC_DNS_LOGS_BASE_INDEX_NAME" default:"calico_dnslogs"`
	ElasticDNSLogsPolicyName                 string `envconfig:"ELASTIC_DNS_LOGS_POLICY_NAME" default:"tigera_secure_ee_dns_policy"`
	ElasticFlowLogsBaseIndexName             string `envconfig:"ELASTIC_FLOW_LOGS_BASE_INDEX_NAME" default:"calico_flowlogs"`
	ElasticFlowLogsPolicyName                string `envconfig:"ELASTIC_FLOW_LOGS_POLICY_NAME" default:"tigera_secure_ee_flow_policy"`
	ElasticL7LogsBaseIndexName               string `envconfig:"ELASTIC_L7_LOGS_BASE_INDEX_NAME" default:"calico_l7logs"`
	ElasticL7LogsPolicyName                  string `envconfig:"ELASTIC_L7_LOGS_POLICY_NAME" default:"tigera_secure_ee_l7_policy"`
	ElasticRuntimeReportsBaseIndexName       string `envconfig:"ELASTIC_RUNTIME_REPORTS_BASE_INDEX_NAME" default:"calico_runtime_reports"`
	ElasticRuntimeReportsPolicyName          string `envconfig:"ELASTIC_RUNTIME_REPORTS_POLICY_NAME" default:"tigera_secure_ee_runtime_policy"`
	ElasticThreatFeedsDomainSetBaseIndexName string `envconfig:"ELASTIC_THREAT_FEEDS_DOMAIN_SET_BASE_INDEX_NAME" default:"calico_threatfeeds_domainnameset"`
	ElasticThreatFeedsDomainSetPolicyName    string `envconfig:"ELASTIC_THREAT_FEEDS_DOMAIN_SET_POLICY_NAME" default:"tigera_secure_ee_threatfeeds_domainnameset_policy"`
	ElasticThreatFeedsIPSetBaseIndexName     string `envconfig:"ELASTIC_THREAT_FEEDS_IP_SET_BASE_INDEX_NAME" default:"calico_threatfeeds_ipset"`
	ElasticThreatFeedsIPSetIPolicyName       string `envconfig:"ELASTIC_THREAT_FEEDS_IP_SET_POLICY_NAME" default:"tigera_secure_ee_threatfeeds_domainnameset_policy"`
	ElasticWAFLogsBaseIndexName              string `envconfig:"ELASTIC_WAF_LOGS_BASE_INDEX_NAME" default:"calico_waf"`
	ElasticWAFLogsPolicyName                 string `envconfig:"ELASTIC_WAF_LOGS_POLICY_NAME" default:"tigera_secure_ee_waf_policy"`
	ElasticPolicyActivityBaseIndexName       string `envconfig:"ELASTIC_POLICY_ACTIVITY_BASE_INDEX_NAME" default:"calico_policy_activity"`
	ElasticPolicyActivityPolicyName          string `envconfig:"ELASTIC_POLICY_ACTIVITY_POLICY_NAME" default:"tigera_secure_ee_policy_activity_policy"`
}

type BackendType string

const (
	// BackendTypeMultiIndex is the legacy backend that stores different cluster and tenant data in separate indices.
	BackendTypeMultiIndex BackendType = "elastic-multi-index"

	// BackendTypeSingleIndex is the backend that stores all cluster and tenant data in a single index.
	BackendTypeSingleIndex BackendType = "elastic-single-index"
)

type ProductVariant string

const (
	ProductVariantTigeraSecureEnterprise ProductVariant = "TigeraSecureEnterprise"
	ProductVariantCalico                 ProductVariant = "Calico"
)

// Return a string representation on the Config instance.
func (cfg *Config) String() string {
	data, err := json.Marshal(cfg)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func LoadConfig() (*Config, error) {
	var err error
	config := &Config{}
	if err = envconfig.Process(EnvConfigPrefix, config); err != nil {
		logrus.WithError(err).Fatal("Unable to load envconfig %w", err)
	}

	if config.TenantNamespace != "" && config.ExpectedTenantID == "" {
		return nil, errors.New("tenant namespace was provided but TenantID was not")
	}

	return config, nil
}
