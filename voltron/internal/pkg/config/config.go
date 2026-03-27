// Copyright (c) 2019-2022 Tigera, Inc. All rights reserved.

package config

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
	"time"

	"github.com/kelseyhightower/envconfig"

	"github.com/projectcalico/calico/pkg/buildinfo"
)

const (
	// EnvConfigPrefix represents the prefix used to load ENV variables required for startup
	EnvConfigPrefix = "VOLTRON"
)

var versionFlag = flag.Bool("version", false, "Print version information")

// Config is a configuration used for Voltron
type Config struct {
	Port       int `default:"5555"`
	Host       string
	TunnelPort int    `default:"5566" split_words:"true"`
	TunnelHost string `split_words:"true"`
	TunnelCert string `default:"/certs/tunnel/cert" split_words:"true" json:"-"`
	TunnelKey  string `default:"/certs/tunnel/key" split_words:"true" json:"-"`
	LogLevel   string `default:"INFO"`

	InternalPort int `default:"5557" split_words:"true"`

	// The tenant that this Voltron is serving.
	TenantID string `default:"" split_words:"true"`

	// Certificate and Key to use on inner connections received over the mTLS
	// tunnel for Linseed from managed clusters.
	LinseedServerCert string `default:"" split_words:"true"`
	LinseedServerKey  string `default:"" split_words:"true"`

	// HTTPSCert, HTTPSKey - path to an x509 certificate and its private key used
	// for external communication (Tigera UI <-> Voltron)
	HTTPSCert string `default:"/certs/https/cert" split_words:"true" json:"-"`
	HTTPSKey  string `default:"/certs/https/key" split_words:"true" json:"-"`

	UseHTTPSCertOnTunnel bool `split_words:"true"`

	// InternalHTTPSCert, InternalHTTPSKey - path to an x509 certificate and its private key used
	// for internal communication within the K8S cluster
	InternalHTTPSCert string `default:"/certs/internal/cert" split_words:"true" json:"-"`
	InternalHTTPSKey  string `default:"/certs/internal/key" split_words:"true" json:"-"`

	K8sConfigPath string `split_words:"true"`

	// K8sClientQPS => rest.Config.QPS
	K8sClientQPS float32 `default:"100.0" split_words:"true"`
	// K8sClientBurst => rest.Config.Burst
	K8sClientBurst int `default:"1000" split_words:"true"`

	KeepAliveEnable              bool   `default:"true" split_words:"true"`
	KeepAliveInterval            int    `default:"100" split_words:"true"`
	K8sEndpoint                  string `default:"https://kubernetes.default" split_words:"true"`
	ComplianceEndpoint           string `default:"https://compliance.tigera-compliance.svc.cluster.local" split_words:"true"`
	ComplianceCABundlePath       string `default:"/certs/compliance/tls.crt" split_words:"true"`
	ComplianceInsecureTLS        bool   `default:"false" split_words:"true"`
	EnableCompliance             bool   `default:"true" split_words:"true"`
	EnableNonclusterHost         bool   `default:"false" split_words:"true"`
	UIBackendEndpoint            string `default:"https://127.0.0.1:8443" split_words:"true"`
	NginxEndpoint                string `default:"http://127.0.0.1:8080" split_words:"true"`
	PProf                        bool   `default:"false"`
	EnableMultiClusterManagement bool   `default:"false" split_words:"true"`
	KibanaEndpoint               string `default:"https://tigera-secure-kb-http.tigera-kibana.svc:5601" split_words:"true"`
	KibanaBasePath               string `default:"/tigera-kibana" split_words:"true"`
	KibanaCABundlePath           string `default:"/certs/kibana/tls.crt" split_words:"true"`
	EnterpriseDashboardEndpoint  string `default:"http://127.0.0.1:8444" split_words:"true"`
	EnterpriseDashboardBasePath  string `default:"/dashboards" split_words:"true"`
	PacketCaptureCABundlePath    string `default:"/certs/packetcapture/tls.crt" split_words:"true"`
	PacketCaptureEndpoint        string `default:"https://tigera-packetcapture.tigera-packetcapture.svc" split_words:"true"`
	EnableImageAssurance         bool   `split_words:"true"`
	ImageAssuranceCABundlePath   string `split_words:"true"`
	ImageAssuranceEndpoint       string `split_words:"true"`
	PrometheusCABundlePath       string `default:"/certs/prometheus/tls.crt" split_words:"true"`
	PrometheusPath               string `default:"/api/v1/namespaces/tigera-prometheus/services/calico-node-prometheus:9090/proxy/" split_words:"true"`
	PrometheusEndpoint           string `default:"https://prometheus-http-api.tigera-prometheus.svc:9090" split_words:"true"`
	QueryserverPath              string `default:"/api/v1/namespaces/calico-system/services/https:calico-api:8080/proxy/" split_words:"true"`
	QueryserverEndpoint          string `default:"https://calico-api.calico-system.svc:8080" split_words:"true"`
	QueryserverCABundlePath      string `default:"/etc/pki/tls/certs/ca.crt" split_words:"true"`
	FluentdHTTPPath              string `default:"https://fluentd-http-input.tigera-fluentd.svc.cluster.local:9880" split_words:"true"`
	FluentdCABundlePath          string `default:"/etc/pki/tls/certs/ca.crt" split_words:"true"`
	TigeraIssuerCABundlePath     string `default:"/etc/pki/tls/certs/ca.crt" split_words:"true"`

	LinseedEndpoint     string `default:"https://tigera-linseed.tigera-elasticsearch.svc.cluster.local" split_words:"true"`
	LinseedCABundlePath string `default:"/etc/pki/tls/certs/ca.crt" split_words:"true"`

	EnableCalicoCloudRbacApi       bool   `split_words:"true"`
	CalicoCloudRbacApiCABundlePath string `split_words:"true"`
	CalicoCloudRbacApiEndpoint     string `split_words:"true"`
	CalicoCloudRequireTenantClaim  bool   `split_words:"true"`
	CalicoCloudTenantClaim         string `split_words:"true"`
	CalicoCloudCorsHost            string `split_words:"true"`

	// Dex settings
	DexEnabled      bool   `default:"false" split_words:"true"`
	DexURL          string `default:"https://tigera-dex.tigera-dex.svc.cluster.local:5556/" split_words:"true"`
	DexBasePath     string `default:"/dex/" split_words:"true"`
	DexCABundlePath string `default:"/etc/ssl/certs/tls-dex.crt" split_words:"true"`

	// OIDC Authentication settings.
	OIDCAuthEnabled         bool          `default:"false" split_words:"true"`
	OIDCAuthJWKSURL         string        `default:"https://tigera-dex.tigera-dex.svc.cluster.local:5556/dex/keys" split_words:"true"`
	OIDCAuthIssuer          string        `default:"https://127.0.0.1:5556/dex" split_words:"true"`
	OIDCAuthClientID        string        `default:"tigera-manager" split_words:"true"`
	OIDCAuthUsernameClaim   string        `default:"email" split_words:"true"`
	OIDCAuthUsernamePrefix  string        `split_words:"true"`
	OIDCAuthGroupsClaim     string        `default:"groups" split_words:"true"`
	OIDCAuthGroupsPrefix    string        `split_words:"true"`
	OIDCTokenReviewCacheTTL time.Duration `default:"0" split_words:"true"`

	// This will enable tenant claims check on the Bearer token presented on a request
	// The actual value of the claim is checked against the tenant claim
	RequireTenantClaim bool   `split_words:"true"`
	TenantClaim        string `split_words:"true"`

	// The DefaultForward parameters configure where connections from guardian should be forwarded to by default
	ForwardingEnabled               bool          `default:"true" split_words:"true"`
	DefaultForwardServer            string        `default:"tigera-secure-es-http.tigera-elasticsearch.svc:9200" split_words:"true"`
	DefaultForwardDialRetryAttempts int           `default:"5" split_words:"true"`
	DefaultForwardDialInterval      time.Duration `default:"2s" split_words:"true"`

	// CheckManagedClusterAuthorizationBeforeProxy instructs Voltron
	// to additionally check if the user has 'GET' permissions on the ManagedCluster
	// resource before forwarding a request over the tunnel to that managed cluster.
	// If left disabled, the request is still authorized on the managed cluster once it arrives
	// over the tunnel.
	// Enabling it reduces some load on the managed cluster while also adding a second control
	// of allow / deny based on the ManagedCluster RBAC.
	CheckManagedClusterAuthorizationBeforeProxy bool `default:"false" split_words:"true"`

	// CheckManagedClusterAuthorizationCacheTTL when >0 this will cache the authorization results for CheckManagedClusterAuthorizationBeforeProxy
	//
	// Note that CheckManagedClusterAuthorization uses a different RBACAuthorizer instance than the default auth.NewJWTAuth() instance
	CheckManagedClusterAuthorizationCacheTTL time.Duration `default:"0" split_words:"true"`

	// LMAAuthorizationCacheTTL used to configure authz caching when creating the `lma.auth.NewJWTAuth()` instance.
	LMAAuthorizationCacheTTL time.Duration `default:"20s" split_words:"true"`

	// TargetAuthorizerCacheTTL used to configure authz caching when creating the `lma.auth.NewJWTAuth()` instance.
	TargetAuthorizerCacheTTL time.Duration `default:"20s" split_words:"true"`

	// enable logging of all http requests to the clusterMuxer
	HTTPAccessLoggingEnabled bool `default:"false" split_words:"true"`

	// include the authentication tokens groups claim value in the http access logs, optional and disabled by default as this can be a very large value
	HTTPAccessLoggingIncludeAuthGroups bool `default:"false" split_words:"true"`

	MetricsEnabled bool `default:"false" split_words:"true"`

	// TenantNamespace is the namespace for the tenant specified in the TenantID field. If set, Voltron will use this namespace to query per-tenant
	// information such as ManagedClusters. If unset, and a tenant ID is provided, it will be defaulted based on an auto-detected namespace.
	TenantNamespace string `envconfig:"TENANT_NAMESPACE" default:""`

	// UITlsTerminatedRoutesPath is the file path for tls terminated routes to configure the UI proxy with. If not specified,
	// routes are not loaded from the file.
	UITlsTerminatedRoutesPath *string `split_words:"true"`

	// UpstreamTunnelTLSTerminatedRoutesPath is the file path for tls terminated routes to configure the upstream tunnel
	// routes with (routes for traffic going from the managed cluster to the management cluster). If not specified, routes
	// are not loaded from a file.
	UpstreamTunnelTLSTerminatedRoutesPath *string `split_words:"true"`
	// UpstreamTunnelTLSPassThroughRoutesPath is the file path for tls pass through routes to configure the upstream tunnel
	// routes with (routes for traffic going from the managed cluster to the management cluster). If not specified, routes
	// are not loaded from a file.
	UpstreamTunnelTLSPassThroughRoutesPath *string `split_words:"true"`

	// GoldmaneEnabled indicates whether or not the connected managed cluster is running Goldmane. If true, Voltron
	// will enable forwarding of requests to Goldmane. Additionally, Voltron will use its own serviceacocunt when forwarding
	// requests from managed cluster goldmane instances to Linseed.
	GoldmaneEnabled bool `default:"false" split_words:"true"`

	// GoldmaneEndpoint is the endpoint for the Goldmane service in the local cluster.
	GoldmaneEndpoint     string `default:"https://goldmane.calico-system.svc.cluster.local" split_words:"true"`
	GoldmaneCABundlePath string `default:"/etc/pki/tls/certs/ca.crt" split_words:"true"`

	// Whether or not the managed cluster supports impersonation. If not, Voltron will strip impersonation headers
	// from requests before forwarding them to the managed cluster.
	ManagedClusterSupportsImpersonation bool `default:"true" split_words:"true"`
}

func (cfg Config) String() string {
	// Parse all command-line flags
	flag.Parse()

	// For --version use case
	if *versionFlag {
		buildinfo.PrintVersion()
		os.Exit(0)
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func Parse() (*Config, error) {
	config := Config{}
	if err := envconfig.Process(EnvConfigPrefix, &config); err != nil {
		return nil, err
	}

	if config.TenantNamespace != "" && config.TenantID == "" {
		return nil, errors.New("tenant namespace was provided but TenantID was not")
	}
	return &config, nil
}
