// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package v1

import (
	"encoding/json"
	"net"
	"time"
)

// FlowLogParams define querying parameters to retrieve flow logs
type FlowLogParams struct {
	QueryParams        `json:",inline" validate:"required"`
	QuerySortParams    `json:",inline"`
	LogSelectionParams `json:",inline"`

	IPMatches []IPMatch `json:"ip_matches" validate:"omitempty"`

	// PolicyMatches selects flowlogs based on whether an action is taken on the flowlog
	// by the provided tier.
	// For example, return flowlogs which are allowed by the default tier.
	// If multiple PolicyMatches are provided, they are combined with a logical OR.
	PolicyMatches []PolicyMatch `json:"policy_matches" validate:"dive"`

	// EnforcedPolicyMatches selects flowlogs based on whether an action is taken on the flowlog
	// by the provided tier, in the enforced trace.
	// For example, return flowlogs which are allowed by the default tier.
	// If multiple EnforcedPolicyMatches are provided, they are combined with a logical OR.
	EnforcedPolicyMatches []PolicyMatch `json:"enforced_policy_matches" validate:"dive"`

	// PendingPolicyMatches selects flowlogs based on whether an action is taken on the flowlog
	// by the provided tier, in the pending trace.
	// For example, return flowlogs which are allowed by the default tier.
	// If multiple PendingPolicyMatches are provided, they are combined with a logical OR.
	PendingPolicyMatches []PolicyMatch `json:"pending_policy_matches" validate:"dive"`

	// TransitPolicyMatches selects flowlogs based on whether an action is taken on the flowlog
	// by the provided tier, in the transit trace.
	// For example, return flowlogs which are allowed by the default tier.
	// If multiple TransitPolicyMatches are provided, they are combined with a logical OR.
	TransitPolicyMatches []PolicyMatch `json:"transit_policy_matches" validate:"dive"`
}

type IPMatch struct {
	// Whether to match against the source ip, destination ip
	// or either source ip or destination name ip
	Type MatchType `json:"type"`

	// Any log with a matching ip will be included. If multiple are provided,
	// they are combined using a logical OR.
	IPs []string `json:"ips"`
}

type FlowLogAggregationParams struct {
	// Inherit all the normal flow log selection parameters.
	FlowLogParams `json:",inline"`
	Aggregations  map[string]json.RawMessage `json:"aggregations"`
	NumBuckets    int                        `json:"num_buckets"`
}

// FlowLog is the input format to ingest flow logs
// Some empty values should be json marshalled as null and NOT with golang null values such as "" for
// an empty string
// Having such values as pointers ensures that json marshalling will render it as such.
type FlowLog struct {
	StartTime int64 `json:"start_time"`
	EndTime   int64 `json:"end_time"`

	// Source fields.
	SourceIP         *string        `json:"source_ip"`
	SourceName       string         `json:"source_name"`
	SourceNameAggr   string         `json:"source_name_aggr"`
	SourceNamespace  string         `json:"source_namespace"`
	NatOutgoingPorts []int          `json:"nat_outgoing_ports"`
	SourcePort       *int64         `json:"source_port"`
	SourceType       string         `json:"source_type"`
	SourceLabels     *FlowLogLabels `json:"source_labels"`

	// Destination fields.
	DestIP               *string        `json:"dest_ip"`
	DestName             string         `json:"dest_name"`
	DestNameAggr         string         `json:"dest_name_aggr"`
	DestNamespace        string         `json:"dest_namespace"`
	DestPort             *int64         `json:"dest_port"`
	DestType             string         `json:"dest_type"`
	DestLabels           *FlowLogLabels `json:"dest_labels"`
	DestServiceNamespace string         `json:"dest_service_namespace"`
	DestServiceName      string         `json:"dest_service_name"`
	DestServicePortName  string         `json:"dest_service_port"`
	DestServicePortNum   *int64         `json:"dest_service_port_num"`
	DestDomains          []string       `json:"dest_domains"`

	// Reporter is src or dest - the location where this flowlog was generated.
	Protocol string         `json:"proto"`
	Action   string         `json:"action"`
	Reporter string         `json:"reporter"`
	Policies *FlowLogPolicy `json:"policies"`

	// Traffic stats.
	BytesIn         int64 `json:"bytes_in"`
	BytesOut        int64 `json:"bytes_out"`
	TransitBytesIn  int64 `json:"transit_bytes_in"`
	TransitBytesOut int64 `json:"transit_bytes_out"`

	// Stats from the original logs used to generate this flow log.
	// Felix aggregates multiple flow logs into a single FlowLog.
	NumFlows          int64 `json:"num_flows"`
	NumFlowsStarted   int64 `json:"num_flows_started"`
	NumFlowsCompleted int64 `json:"num_flows_completed"`

	// Traffic stats.
	PacketsIn         int64 `json:"packets_in"`
	PacketsOut        int64 `json:"packets_out"`
	TransitPacketsIn  int64 `json:"transit_packets_in"`
	TransitPacketsOut int64 `json:"transit_packets_out"`

	// HTTP fields.
	HTTPRequestsAllowedIn int64 `json:"http_requests_allowed_in"`
	HTTPRequestsDeniedIn  int64 `json:"http_requests_denied_in"`

	// Process stats.
	ProcessName     string   `json:"process_name"`
	NumProcessNames int64    `json:"num_process_names"`
	ProcessID       string   `json:"process_id"`
	NumProcessIDs   int64    `json:"num_process_ids"`
	ProcessArgs     []string `json:"process_args"`
	NumProcessArgs  int64    `json:"num_process_args"`

	OrigSourceIPs    []net.IP `json:"original_source_ips"`
	NumOrigSourceIPs int64    `json:"num_original_source_ips"`

	// TCP stats.
	TCPMeanSendCongestionWindow int64 `json:"tcp_mean_send_congestion_window"`
	TCPMinSendCongestionWindow  int64 `json:"tcp_min_send_congestion_window"`
	TCPMeanSmoothRTT            int64 `json:"tcp_mean_smooth_rtt"`
	TCPMaxSmoothRTT             int64 `json:"tcp_max_smooth_rtt"`
	TCPMeanMinRTT               int64 `json:"tcp_mean_min_rtt"`
	TCPMaxMinRTT                int64 `json:"tcp_max_min_rtt"`
	TCPMeanMSS                  int64 `json:"tcp_mean_mss"`
	TCPMinMSS                   int64 `json:"tcp_min_mss"`
	TCPTotalRetransmissions     int64 `json:"tcp_total_retransmissions"`
	TCPLostPackets              int64 `json:"tcp_lost_packets"`
	TCPUnrecoveredTo            int64 `json:"tcp_unrecovered_to"`

	Host      string `json:"host"`
	Timestamp int64  `json:"@timestamp"`
	ID        string `json:"id,omitempty"`

	// Cluster is populated by linseed from the request context.
	Cluster string `json:"cluster,omitempty"`
	// GeneratedTime is populated by Linseed when ingesting data to Elasticsearch
	GeneratedTime *time.Time `json:"generated_time,omitempty"`
}

type FlowLogPolicy struct {
	AllPolicies      []string `json:"all_policies,omitempty"`
	EnforcedPolicies []string `json:"enforced_policies"`
	PendingPolicies  []string `json:"pending_policies"`
	TransitPolicies  []string `json:"transit_policies"`
}

type FlowLogLabels struct {
	Labels []string `json:"labels"`
}
