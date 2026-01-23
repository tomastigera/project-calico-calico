// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package templates

import (
	_ "embed"

	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
)

//go:embed flowlog_mappings.json
var FlowLogMappings string

//go:embed l7log_mappings.json
var L7LogMappings string

//go:embed dnslog_mappings.json
var DNSLogMappings string

//go:embed dnslog_settings.json
var DNSLogSettings string

//go:embed audit_mappings.json
var AuditMappings string

//go:embed bgp_mappings.json
var BGPMappings string

//go:embed events_mappings.json
var EventsMappings string

//go:embed event_settings.json
var EventSettings string

//go:embed waf_mappings.json
var WAFMappings string

//go:embed report_mappings.json
var ReportMappings string

//go:embed benchmarks_mappings.json
var BenchmarksMappings string

//go:embed snapshots_mappings.json
var SnapshotMappings string

//go:embed runtime_mappings.json
var RuntimeReportsMappings string

//go:embed ipset_mappings.json
var IPSetMappings string

//go:embed policy_activity_mapping.json
var PolicyActivityMappings string

//go:embed domainset_mappings.json
var DomainSetMappings string

// SettingsLookup will keep track if an index requires special settings, add its settings template to the map.
var SettingsLookup = map[bapi.DataType]string{
	bapi.DNSLogs: DNSLogSettings,
	bapi.Events:  EventSettings,
}

// LifeCycleEnabledLookup will keep track if ILM policy needs to be enabled or not
var LifeCycleEnabledLookup = map[bapi.DataType]bool{
	bapi.AuditEELogs:    true,
	bapi.AuditKubeLogs:  true,
	bapi.BGPLogs:        true,
	bapi.FlowLogs:       true,
	bapi.L7Logs:         true,
	bapi.DNSLogs:        true,
	bapi.Events:         true,
	bapi.WAFLogs:        true,
	bapi.RuntimeReports: true,
	bapi.ReportData:     true,
	bapi.Benchmarks:     true,
	bapi.Snapshots:      true,
	bapi.IPSet:          false,
	bapi.DomainNameSet:  false,
	bapi.PolicyActivity: true,
}
