// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package fv_test

import _ "embed"

// flowLogs is a sample flow logs to be ingested for testing purposes
//
//go:embed testdata/backend/flow_logs_legacy.txt
var flowLogs string

// dnsLogs is a sample flow logs to be ingested for testing purposes
//
//go:embed testdata/backend/dns_logs_legacy.txt
var dnsLogs string

// l7Logs is a sample l7 logs to be ingested for testing purposes
//
//go:embed testdata/backend/l7_logs_legacy.txt
var l7Logs string

// l7LogsGatewayCollector is a sample l7 logs with gateway collector fields for testing purposes
//
//go:embed testdata/backend/l7_logs_gateway_collector.txt
var l7LogsGatewayCollector string

// eeAuditLogs is a sample ee audit logs to be ingested for testing purposes
//
//go:embed testdata/backend/ee_audit_logs_legacy.txt
var eeAuditLogs string

// kubeAuditLogs is a sample kube audit logs to be ingested for testing purposes
//
//go:embed testdata/backend/kube_audit_logs_legacy.txt
var kubeAuditLogs string

// bgpLogs is a sample bgp logs to be ingested for testing purposes
//
//go:embed testdata/backend/bgp_logs_legacy.txt
var bgpLogs string

// wafLogs is a sample waf logs to be ingested for testing purposes
//
//go:embed testdata/backend/waf_logs_legacy.txt
var wafLogs string

// runtimeReports is a sample runtime reports to be ingested for testing purposes
//
//go:embed testdata/backend/runtime_reports_legacy.txt
var runtimeReports string

// truncatedFlowLogs is a sample flow logs with a malformed first line to test partial ingestion
//
//go:embed testdata/backend/truncated_flowlogs.txt
var truncatedFlowLogs string

// anomalyDetectionEvent is a sample alert produced by anomaly detection to be ingested for testing purposes
//
//go:embed testdata/backend/anomaly_detection_event.json
var anomalyDetectionEvent string
