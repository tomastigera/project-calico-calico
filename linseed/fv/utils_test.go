// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package fv_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/onsi/gomega"
	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	"github.com/projectcalico/calico/linseed/pkg/config"
)

// Use a relative path to the client token in the calico-private/linseed/fv directory.
const (
	TokenPath             = "./client-token"
	TokenPathMultiCluster = "./client-token-multi-cluster"
)

func NewLinseedClient(args *RunLinseedArgs, tokenPath string) (client.Client, error) {
	cfg := rest.Config{
		CACertPath:     "cert/RootCA.crt",
		URL:            fmt.Sprintf("https://localhost:%d/", args.Port),
		ClientCertPath: "cert/localhost.crt",
		ClientKeyPath:  "cert/localhost.key",
		ServerName:     "localhost",
	}

	// The token is created as part of FV setup in the Makefile, and mounted into the container that
	// runs the FV binaries.
	return client.NewClient(args.TenantID, cfg, rest.WithTokenPath(tokenPath))
}

func DefaultLinseedArgs() *RunLinseedArgs {
	return &RunLinseedArgs{
		ProductVariant: config.ProductVariantTigeraSecureEnterprise,
		Backend:        config.BackendTypeMultiIndex,
		TenantID:       "tenant-a",
		Port:           8443,
		MetricsPort:    9095,
		HealthPort:     8080,
	}
}

type RunLinseedArgs struct {
	Backend        config.BackendType
	TenantID       string
	Port           int
	MetricsPort    int
	HealthPort     int
	ProductVariant config.ProductVariant
}

func RunLinseed(t *testing.T, args *RunLinseedArgs) *containers.Container {
	// The container library uses gomega, so we need to connect our testing.T to it.
	gomega.RegisterTestingT(t)

	// Get the current working directory, which we expect to by the fv dir.
	cwd, err := os.Getwd()
	require.NoError(t, err)

	// Turn it to an absolute path.
	cwd, err = filepath.Abs(cwd)
	require.NoError(t, err)

	// The certs path is relative to the fv dir.
	certsPath := filepath.Join(cwd, "../../hack/test/certs/")

	dockerArgs := []string{
		"--net=host",
		fmt.Sprintf("--user=%d:%d", os.Getuid(), os.Getgid()),
		"-v", fmt.Sprintf("%s/cert/localhost.crt:/certs/https/tls.crt", cwd),
		"-v", fmt.Sprintf("%s/cert/localhost.key:/certs/https/tls.key", cwd),
		"-v", fmt.Sprintf("%s/cert/RootCA.crt:/certs/https/client.crt", cwd),
		"-v", fmt.Sprintf("%s/linseed-token:/var/run/secrets/kubernetes.io/serviceaccount/token", cwd),
		"-v", fmt.Sprintf("%s/tenant-namespace:/var/run/secrets/kubernetes.io/serviceaccount/namespace", cwd),
		"-v", fmt.Sprintf("%s/ca.pem:/var/run/secrets/kubernetes.io/serviceaccount/ca.crt", certsPath),
		"-e", "KUBERNETES_SERVICE_HOST=127.0.0.1",
		"-e", "KUBERNETES_SERVICE_PORT=6443",
		"-e", "ELASTIC_HOST=localhost",
		"-e", "ELASTIC_SCHEME=http",
		"-e", "LINSEED_LOG_LEVEL=debug",
		"-e", fmt.Sprintf("LINSEED_HEALTH_PORT=%d", args.HealthPort),
		"-e", fmt.Sprintf("LINSEED_ENABLE_METRICS=%t", args.MetricsPort != 0),
		"-e", fmt.Sprintf("LINSEED_METRICS_PORT=%d", args.MetricsPort),
		"-e", fmt.Sprintf("LINSEED_PORT=%d", args.Port),
		"-e", fmt.Sprintf("LINSEED_BACKEND=%s", args.Backend),
		"-e", fmt.Sprintf("LINSEED_EXPECTED_TENANT_ID=%s", args.TenantID),
		"-e", fmt.Sprintf("LINSEED_PRODUCT_VARIANT=%s", args.ProductVariant),
		"tigera/linseed:latest",
	}

	name := "tigera-linseed-fv"
	if args.TenantID != "" {
		name += "-" + args.TenantID
	}

	c := containers.Run(name, containers.RunOpts{AutoRemove: true, OutputWriter: logutils.TestingTWriter{T: t}}, dockerArgs...)
	c.StopLogs()
	return c
}

type RunConfigureElasticArgs struct {
	AlertBaseIndexName string
	AlertPolicyName    string

	AuditBaseIndexName string
	AuditPolicyName    string
	AuditReplicas      string
	AuditShards        string

	BGPBaseIndexName string
	BGPPolicyName    string
	BGPReplicas      string
	BGPShards        string

	ComplianceBenchmarksBaseIndexName string
	ComplianceBenchmarksPolicyName    string
	ComplianceReportsBaseIndexName    string
	ComplianceReportsPolicyName       string
	ComplianceSnapshotsBaseIndexName  string
	ComplianceSnapshotsPolicyName     string

	DNSBaseIndexName string
	DNSPolicyName    string
	DNSReplicas      string
	DNSShards        string

	FlowBaseIndexName string
	FlowPolicyName    string
	FlowReplicas      string
	FlowShards        string

	L7BaseIndexName string
	L7PolicyName    string
	L7Replicas      string
	L7Shards        string

	RuntimeReportsBaseIndexName string
	RuntimeReportsPolicyName    string
	RuntimeReplicas             string
	RuntimeShards               string

	ThreatFeedsIPSetBaseIndexName     string
	ThreatFeedsIPSetPolicyName        string
	ThreatFeedsDomainSetBaseIndexName string
	ThreatFeedsDomainSetPolicyName    string

	WAFBaseIndexName string
	WAFPolicyName    string
	WAFReplicas      string
	WAFShards        string

	PolicyActivityBaseIndexName string
	PolicyActivityPolicyName    string
	PolicyActivityReplicas      string
	PolicyActivityShards        string

	ElasticReplicas string
	ElasticShards   string
}

func RunConfigureElasticLinseed(t *testing.T, args *RunConfigureElasticArgs) {
	// The container library uses gomega, so we need to connect our testing.T to it.
	gomega.RegisterTestingT(t)

	dockerArgs := []string{
		"--net=host",
		fmt.Sprintf("--user=%d:%d", os.Getuid(), os.Getgid()),
		"-e", "ELASTIC_HOST=localhost",
		"-e", "ELASTIC_SCHEME=http",
		"-e", "LINSEED_LOG_LEVEL=debug",
		"-e", fmt.Sprintf("LINSEED_BACKEND=%s", config.BackendTypeSingleIndex),
		"-e", fmt.Sprintf("ELASTIC_ALERTS_BASE_INDEX_NAME=%s", args.AlertBaseIndexName),
		"-e", fmt.Sprintf("ELASTIC_ALERTS_POLICY_NAME=%s", args.AlertPolicyName),
		"-e", fmt.Sprintf("ELASTIC_AUDIT_LOGS_BASE_INDEX_NAME=%s", args.AuditBaseIndexName),
		"-e", fmt.Sprintf("ELASTIC_AUDIT_LOGS_POLICY_NAME=%s", args.AuditPolicyName),
		"-e", fmt.Sprintf("ELASTIC_BGP_LOGS_BASE_INDEX_NAME=%s", args.BGPBaseIndexName),
		"-e", fmt.Sprintf("ELASTIC_BGP_LOGS_POLICY_NAME=%s", args.BGPPolicyName),
		"-e", fmt.Sprintf("ELASTIC_COMPLIANCE_BENCHMARKS_BASE_INDEX_NAME=%s", args.ComplianceBenchmarksBaseIndexName),
		"-e", fmt.Sprintf("ELASTIC_COMPLIANCE_BENCHMARKS_POLICY_NAME=%s", args.ComplianceBenchmarksPolicyName),
		"-e", fmt.Sprintf("ELASTIC_COMPLIANCE_REPORTS_BASE_INDEX_NAME=%s", args.ComplianceReportsBaseIndexName),
		"-e", fmt.Sprintf("ELASTIC_COMPLIANCE_REPORTS_POLICY_NAME=%s", args.ComplianceReportsPolicyName),
		"-e", fmt.Sprintf("ELASTIC_COMPLIANCE_SNAPSHOTS_BASE_INDEX_NAME=%s", args.ComplianceSnapshotsBaseIndexName),
		"-e", fmt.Sprintf("ELASTIC_COMPLIANCE_SNAPSHOTS_POLICY_NAME=%s", args.ComplianceSnapshotsPolicyName),
		"-e", fmt.Sprintf("ELASTIC_DNS_LOGS_BASE_INDEX_NAME=%s", args.DNSBaseIndexName),
		"-e", fmt.Sprintf("ELASTIC_DNS_LOGS_POLICY_NAME=%s", args.DNSPolicyName),
		"-e", fmt.Sprintf("ELASTIC_FLOW_LOGS_BASE_INDEX_NAME=%s", args.FlowBaseIndexName),
		"-e", fmt.Sprintf("ELASTIC_FLOW_LOGS_POLICY_NAME=%s", args.FlowPolicyName),
		"-e", fmt.Sprintf("ELASTIC_L7_LOGS_BASE_INDEX_NAME=%s", args.L7BaseIndexName),
		"-e", fmt.Sprintf("ELASTIC_L7_LOGS_POLICY_NAME=%s", args.L7PolicyName),
		"-e", fmt.Sprintf("ELASTIC_RUNTIME_REPORTS_BASE_INDEX_NAME=%s", args.RuntimeReportsBaseIndexName),
		"-e", fmt.Sprintf("ELASTIC_RUNTIME_REPORTS_POLICY_NAME=%s", args.RuntimeReportsPolicyName),
		"-e", fmt.Sprintf("ELASTIC_THREAT_FEEDS_DOMAIN_SET_BASE_INDEX_NAME=%s", args.ThreatFeedsDomainSetBaseIndexName),
		"-e", fmt.Sprintf("ELASTIC_THREAT_FEEDS_DOMAIN_SET_POLICY_NAME=%s", args.ThreatFeedsDomainSetPolicyName),
		"-e", fmt.Sprintf("ELASTIC_THREAT_FEEDS_IP_SET_BASE_INDEX_NAME=%s", args.ThreatFeedsIPSetBaseIndexName),
		"-e", fmt.Sprintf("ELASTIC_THREAT_FEEDS_IP_SET_POLICY_NAME=%s", args.ThreatFeedsIPSetPolicyName),
		"-e", fmt.Sprintf("ELASTIC_WAF_LOGS_BASE_INDEX_NAME=%s", args.WAFBaseIndexName),
		"-e", fmt.Sprintf("ELASTIC_WAF_LOGS_POLICY_NAME=%s", args.WAFPolicyName),
	}

	dockerArgs = updateDockerArgs(dockerArgs, args)

	dockerArgs = append(dockerArgs, "tigera/linseed:latest",
		"-configure-elastic-indices",
	)

	name := "tigera-configure-elastic-linseed-fv"

	c := containers.Run(name, containers.RunOpts{RunAndExit: true, AutoRemove: true, OutputWriter: logutils.TestingTWriter{T: t}}, dockerArgs...)
	c.StopLogs()
	if c.ListedInDockerPS() {
		c.Stop()
	}
}

func updateDockerArgs(dockerArgs []string, args *RunConfigureElasticArgs) []string {
	addEnvVarIfNotEmpty := func(key, value string) {
		if len(value) > 0 {
			dockerArgs = append(dockerArgs, "-e", fmt.Sprintf("%s=%s", key, value))
		}
	}

	addEnvVarIfNotEmpty("ELASTIC_DNS_INDEX_REPLICAS", args.DNSReplicas)
	addEnvVarIfNotEmpty("ELASTIC_DNS_INDEX_SHARDS", args.DNSShards)

	addEnvVarIfNotEmpty("ELASTIC_FLOWS_INDEX_REPLICAS", args.FlowReplicas)
	addEnvVarIfNotEmpty("ELASTIC_FLOWS_INDEX_SHARDS", args.FlowShards)

	addEnvVarIfNotEmpty("ELASTIC_AUDIT_INDEX_REPLICAS", args.AuditReplicas)
	addEnvVarIfNotEmpty("ELASTIC_AUDIT_INDEX_SHARDS", args.AuditShards)

	addEnvVarIfNotEmpty("ELASTIC_L7_INDEX_REPLICAS", args.L7Replicas)
	addEnvVarIfNotEmpty("ELASTIC_L7_INDEX_SHARDS", args.L7Shards)

	addEnvVarIfNotEmpty("ELASTIC_BGP_INDEX_REPLICAS", args.BGPReplicas)
	addEnvVarIfNotEmpty("ELASTIC_BGP_INDEX_SHARDS", args.BGPShards)

	addEnvVarIfNotEmpty("ELASTIC_RUNTIME_INDEX_REPLICAS", args.RuntimeReplicas)
	addEnvVarIfNotEmpty("ELASTIC_RUNTIME_INDEX_SHARDS", args.RuntimeShards)

	addEnvVarIfNotEmpty("ELASTIC_WAF_INDEX_REPLICAS", args.WAFReplicas)
	addEnvVarIfNotEmpty("ELASTIC_WAF_INDEX_SHARDS", args.WAFShards)

	addEnvVarIfNotEmpty("ELASTIC_POLICY_ACTIVITY_INDEX_REPLICAS", args.PolicyActivityReplicas)
	addEnvVarIfNotEmpty("ELASTIC_POLICY_ACTIVITY_INDEX_SHARDS", args.PolicyActivityShards)

	addEnvVarIfNotEmpty("ELASTIC_REPLICAS", args.ElasticReplicas)
	addEnvVarIfNotEmpty("ELASTIC_SHARDS", args.ElasticShards)

	return dockerArgs
}
