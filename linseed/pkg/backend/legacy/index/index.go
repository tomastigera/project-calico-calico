// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package index

import (
	"fmt"
	"strings"

	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
)

// Legacy indices - these all use multiple indices per-cluster and per-tenant.
var (
	ThreatfeedsDomainMultiIndex   bapi.Index = multiIndex{baseName: "tigera_secure_ee_threatfeeds_domainnameset", dataType: bapi.DomainNameSet, hasLifeCycleEnabled: false}
	ThreatfeedsIPSetMultiIndex    bapi.Index = multiIndex{baseName: "tigera_secure_ee_threatfeeds_ipset", dataType: bapi.IPSet, hasLifeCycleEnabled: false}
	EventsMultiIndex              bapi.Index = multiIndex{baseName: "tigera_secure_ee_events", dataType: bapi.Events, hasLifeCycleEnabled: true}
	ComplianceSnapshotMultiIndex  bapi.Index = multiIndex{baseName: "tigera_secure_ee_snapshots", dataType: bapi.Snapshots, hasLifeCycleEnabled: true}
	ComplianceBenchmarkMultiIndex bapi.Index = multiIndex{baseName: "tigera_secure_ee_benchmark_results", dataType: bapi.Benchmarks, hasLifeCycleEnabled: true}
	ComplianceReportMultiIndex    bapi.Index = multiIndex{baseName: "tigera_secure_ee_compliance_reports", dataType: bapi.ReportData, hasLifeCycleEnabled: true}
	WAFLogMultiIndex              bapi.Index = multiIndex{baseName: "tigera_secure_ee_waf", dataType: bapi.WAFLogs, hasLifeCycleEnabled: true}
	L7LogMultiIndex               bapi.Index = multiIndex{baseName: "tigera_secure_ee_l7", dataType: bapi.L7Logs, hasLifeCycleEnabled: true}
	BGPLogMultiIndex              bapi.Index = multiIndex{baseName: "tigera_secure_ee_bgp", dataType: bapi.BGPLogs, hasLifeCycleEnabled: true}
	AuditLogEEMultiIndex          bapi.Index = multiIndex{baseName: "tigera_secure_ee_audit_ee", dataType: bapi.AuditEELogs, hasLifeCycleEnabled: true}
	AuditLogKubeMultiIndex        bapi.Index = multiIndex{baseName: "tigera_secure_ee_audit_kube", dataType: bapi.AuditKubeLogs, hasLifeCycleEnabled: true}
	DNSLogMultiIndex              bapi.Index = multiIndex{baseName: "tigera_secure_ee_dns", dataType: bapi.DNSLogs, hasLifeCycleEnabled: true}
	FlowLogMultiIndex             bapi.Index = multiIndex{baseName: "tigera_secure_ee_flows", dataType: bapi.FlowLogs, hasLifeCycleEnabled: true}
	RuntimeReportMultiIndex       bapi.Index = multiIndex{baseName: "tigera_secure_ee_runtime", dataType: bapi.RuntimeReports, hasLifeCycleEnabled: true}
)

// Single index - these all use a single index for all clusters and tenants.

type Option func(index *singleIndex)

func WithBaseIndexName(name string) Option {
	return func(index *singleIndex) {
		index.name = name
	}
}

func WithILMPolicyName(name string) Option {
	return func(index *singleIndex) {
		index.policyName = name
	}
}

func AlertsIndex(options ...Option) bapi.Index {
	index := singleIndex{
		name:                "calico_alerts",
		policyName:          "tigera_secure_ee_events_policy",
		dataType:            bapi.Events,
		hasLifeCycleEnabled: true,
	}
	for _, opt := range options {
		opt(&index)
	}

	return &index
}

func AuditLogIndex(options ...Option) bapi.Index {
	// The AuditLogIndex uses data type AuditEELogs, but it's actually used for both AuditEELogs and AuditKubeLogs.
	// This is OK because our code for initializing indices treats these the same anyway.
	index := singleIndex{
		name:                "calico_auditlogs",
		policyName:          "tigera_secure_ee_audit_ee_policy",
		dataType:            bapi.AuditEELogs,
		hasLifeCycleEnabled: true}
	for _, opt := range options {
		opt(&index)
	}

	return &index
}

func BGPLogIndex(options ...Option) bapi.Index {
	index := singleIndex{
		name:                "calico_bgplogs",
		policyName:          "tigera_secure_ee_bgp_policy",
		dataType:            bapi.BGPLogs,
		hasLifeCycleEnabled: true}
	for _, opt := range options {
		opt(&index)
	}

	return &index
}

func ComplianceBenchmarksIndex(options ...Option) bapi.Index {
	index := singleIndex{
		name:                "calico_compliance_benchmark_results",
		policyName:          "tigera_secure_ee_benchmark_results_policy",
		dataType:            bapi.Benchmarks,
		hasLifeCycleEnabled: true,
	}
	for _, opt := range options {
		opt(&index)
	}

	return &index
}

func ComplianceReportsIndex(options ...Option) bapi.Index {
	index := singleIndex{
		name:                "calico_compliance_reports",
		policyName:          "tigera_secure_ee_compliance_reports_policy",
		dataType:            bapi.ReportData,
		hasLifeCycleEnabled: true,
	}
	for _, opt := range options {
		opt(&index)
	}

	return &index
}

func ComplianceSnapshotsIndex(options ...Option) bapi.Index {
	index := singleIndex{
		name:                "calico_compliance_snapshots",
		policyName:          "tigera_secure_ee_snapshots_policy",
		dataType:            bapi.Snapshots,
		hasLifeCycleEnabled: true,
	}
	for _, opt := range options {
		opt(&index)
	}

	return &index
}
func DNSLogIndex(options ...Option) bapi.Index {
	index := singleIndex{
		name:                "calico_dnslogs",
		policyName:          "tigera_secure_ee_dns_policy",
		dataType:            bapi.DNSLogs,
		hasLifeCycleEnabled: true,
	}
	for _, opt := range options {
		opt(&index)
	}

	return &index
}

func FlowLogIndex(options ...Option) bapi.Index {
	index := singleIndex{
		name:                "calico_flowlogs",
		policyName:          "tigera_secure_ee_flows_policy",
		dataType:            bapi.FlowLogs,
		hasLifeCycleEnabled: true,
	}
	for _, opt := range options {
		opt(&index)
	}

	return &index
}

func L7LogIndex(options ...Option) bapi.Index {
	index := singleIndex{
		name:                "calico_l7logs",
		policyName:          "tigera_secure_ee_l7_policy",
		dataType:            bapi.L7Logs,
		hasLifeCycleEnabled: true,
	}
	for _, opt := range options {
		opt(&index)
	}

	return &index
}

func RuntimeReportsIndex(options ...Option) bapi.Index {
	index := singleIndex{
		name:                "calico_runtime_reports",
		policyName:          "tigera_secure_ee_runtime_policy",
		dataType:            bapi.RuntimeReports,
		hasLifeCycleEnabled: true,
	}
	for _, opt := range options {
		opt(&index)
	}

	return &index
}

func ThreatFeedsIPSetIndex(options ...Option) bapi.Index {
	index := singleIndex{
		name:                "calico_threatfeeds_ipset",
		dataType:            bapi.IPSet,
		hasLifeCycleEnabled: false,
	}
	for _, opt := range options {
		opt(&index)
	}

	return &index
}

func ThreatFeedsDomainSetIndex(options ...Option) bapi.Index {
	index := singleIndex{
		name:                "calico_threatfeeds_domainnameset",
		dataType:            bapi.DomainNameSet,
		hasLifeCycleEnabled: false,
	}
	for _, opt := range options {
		opt(&index)
	}

	return &index
}

func WAFLogIndex(options ...Option) bapi.Index {
	index := singleIndex{
		name:                "calico_waf",
		policyName:          "tigera_secure_ee_waf_policy",
		dataType:            bapi.WAFLogs,
		hasLifeCycleEnabled: true,
	}

	for _, opt := range options {
		opt(&index)
	}

	return &index
}

func PolicyActivityIndex(options ...Option) bapi.Index {
	index := singleIndex{
		name:                "calico_policy_activity",
		dataType:            bapi.PolicyActivity,
		hasLifeCycleEnabled: false,
	}
	for _, opt := range options {
		opt(&index)
	}
	return &index
}

// singleIndex implements the Index interface for an index mode that uses a single index
// to store data for multiple clusters and tenants.
type singleIndex struct {
	name                string
	policyName          string
	hasLifeCycleEnabled bool
	dataType            bapi.DataType
}

func (i singleIndex) HasLifecycleEnabled() bool {
	return i.hasLifeCycleEnabled
}

func (i singleIndex) Name(info bapi.ClusterInfo) string {
	return i.name
}

func (i singleIndex) BootstrapIndexName(info bapi.ClusterInfo) string {
	pattern := "<%s.linseed-{now/s{yyyyMMdd}}-000001>"
	return fmt.Sprintf(pattern, i.name)
}

func (i singleIndex) Index(info bapi.ClusterInfo) string {
	return fmt.Sprintf("%s.*", i.name)
}

func (i singleIndex) Alias(info bapi.ClusterInfo) string {
	return fmt.Sprintf("%s.", i.name)
}

func (i singleIndex) IndexTemplateName(info bapi.ClusterInfo) string {
	return fmt.Sprintf("%s.", i.name)
}

func (i singleIndex) IsSingleIndex() bool {
	return true
}

func (i singleIndex) DataType() bapi.DataType {
	return i.dataType
}

func (i singleIndex) ILMPolicyName() string {
	return i.policyName
}

func NewMultiIndex(baseName string, dataType bapi.DataType) bapi.Index {
	return multiIndex{baseName: baseName, dataType: dataType}
}

// multiIndex implements the Index interface for an index mode that uses multiple
// indices to store data for multiple clusters and tenants.
type multiIndex struct {
	baseName            string
	dataType            bapi.DataType
	hasLifeCycleEnabled bool
}

func (i multiIndex) HasLifecycleEnabled() bool {
	return i.hasLifeCycleEnabled
}

func (i multiIndex) DataType() bapi.DataType {
	return i.dataType
}

func (i multiIndex) Name(info bapi.ClusterInfo) string {
	if info.Tenant == "" {
		return fmt.Sprintf("%s-%s", strings.ToLower(string(i.dataType)), info.Cluster)
	}

	return fmt.Sprintf("%s-%s-%s", strings.ToLower(string(i.dataType)), info.Cluster, info.Tenant)
}

func (i multiIndex) BootstrapIndexName(info bapi.ClusterInfo) string {
	template, ok := BootstrapIndexPatternLookup[i.DataType()]
	if !ok {
		panic("bootstrap index name for log type not implemented")
	}
	if info.Tenant == "" {
		return fmt.Sprintf(template, info.Cluster)
	}

	return fmt.Sprintf(template, fmt.Sprintf("%s.%s", info.Tenant, info.Cluster))
}

func (i multiIndex) Index(info bapi.ClusterInfo) string {
	if info.IsQueryMultipleClusters() {
		// drop the cluster suffix, cluster filtering is handled at the query level
		if info.Tenant != "" {
			// If a tenant is provided, then we must include it in the index.
			return fmt.Sprintf("%s.%s.*", i.baseName, info.Tenant)
		} else {
			return fmt.Sprintf("%s.*", i.baseName)
		}
	}

	if info.Tenant != "" {
		// If a tenant is provided, then we must include it in the index.
		return fmt.Sprintf("%s.%s.%s.*", i.baseName, info.Tenant, info.Cluster)
	}
	// Otherwise, this is a single-tenant cluster and we only need the cluster.
	return fmt.Sprintf("%s.%s.*", i.baseName, info.Cluster)
}

func (i multiIndex) Alias(info bapi.ClusterInfo) string {
	if info.Tenant == "" {
		return fmt.Sprintf("%s.%s.", i.baseName, info.Cluster)
	}
	return fmt.Sprintf("%s.%s.%s.", i.baseName, info.Tenant, info.Cluster)
}

func (i multiIndex) IndexTemplateName(info bapi.ClusterInfo) string {
	template, ok := TemplateNamePatternLookup[i.DataType()]
	if !ok {
		panic("template name for log type not implemented")
	}
	if info.Tenant == "" {
		return fmt.Sprintf(template, info.Cluster)
	}

	return fmt.Sprintf(template, fmt.Sprintf("%s.%s", info.Tenant, info.Cluster))
}

func (i multiIndex) IsSingleIndex() bool {
	return false
}

func (i multiIndex) ILMPolicyName() string {
	return fmt.Sprintf("tigera_secure_ee_%s_policy", i.DataType())
}
