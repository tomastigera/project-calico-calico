package index

import (
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
)

// TemplateNamePatternLookup will keep track of the template names created
var TemplateNamePatternLookup = map[bapi.DataType]string{
	bapi.AuditEELogs:    "tigera_secure_ee_audit_ee.%s.",
	bapi.AuditKubeLogs:  "tigera_secure_ee_audit_kube.%s.",
	bapi.BGPLogs:        "tigera_secure_ee_bgp.%s.",
	bapi.FlowLogs:       "tigera_secure_ee_flows.%s.",
	bapi.L7Logs:         "tigera_secure_ee_l7.%s.",
	bapi.DNSLogs:        "tigera_secure_ee_dns.%s.",
	bapi.Events:         "tigera_secure_ee_events.%s",
	bapi.WAFLogs:        "tigera_secure_ee_waf.%s.",
	bapi.RuntimeReports: "tigera_secure_ee_runtime.%s.",
	bapi.ReportData:     "tigera_secure_ee_compliance_reports.%s",
	bapi.Benchmarks:     "tigera_secure_ee_benchmark_results.%s",
	bapi.Snapshots:      "tigera_secure_ee_snapshots.%s",
	bapi.IPSet:          "tigera_secure_ee_threatfeeds_ipset.%s",
	bapi.DomainNameSet:  "tigera_secure_ee_threatfeeds_domainnameset.%s",
}

// BootstrapIndexPatternLookup will keep track of the boostrap indices that will be created
var BootstrapIndexPatternLookup = map[bapi.DataType]string{
	bapi.AuditEELogs:    "<tigera_secure_ee_audit_ee.%s.fluentd-{now/s{yyyyMMdd}}-000001>",
	bapi.AuditKubeLogs:  "<tigera_secure_ee_audit_kube.%s.fluentd-{now/s{yyyyMMdd}}-000001>",
	bapi.BGPLogs:        "<tigera_secure_ee_bgp.%s.fluentd-{now/s{yyyyMMdd}}-000001>",
	bapi.FlowLogs:       "<tigera_secure_ee_flows.%s.fluentd-{now/s{yyyyMMdd}}-000001>",
	bapi.L7Logs:         "<tigera_secure_ee_l7.%s.fluentd-{now/s{yyyyMMdd}}-000001>",
	bapi.DNSLogs:        "<tigera_secure_ee_dns.%s.fluentd-{now/s{yyyyMMdd}}-000001>",
	bapi.Events:         "<tigera_secure_ee_events.%s.lma-{now/s{yyyyMMdd}}-000000>",
	bapi.WAFLogs:        "<tigera_secure_ee_waf.%s.fluentd-{now/s{yyyyMMdd}}-000001>",
	bapi.RuntimeReports: "<tigera_secure_ee_runtime.%s.fluentd-{now/s{yyyyMMdd}}-000001>",
	bapi.ReportData:     "<tigera_secure_ee_compliance_reports.%s.lma-{now/s{yyyyMMdd}}-000000>",
	bapi.Benchmarks:     "<tigera_secure_ee_benchmark_results.%s.lma-{now/s{yyyyMMdd}}-000000>",
	bapi.Snapshots:      "<tigera_secure_ee_snapshots.%s.lma-{now/s{yyyyMMdd}}-000000>",
	bapi.IPSet:          "<tigera_secure_ee_threatfeeds_ipset.%s.linseed-{now/s{yyyyMMdd}}-000001>",
	bapi.DomainNameSet:  "<tigera_secure_ee_threatfeeds_domainnameset.%s.linseed-{now/s{yyyyMMdd}}-000001>",
}
