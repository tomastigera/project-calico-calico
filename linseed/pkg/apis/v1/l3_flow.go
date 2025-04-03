// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package v1

// StatsType is different types of stats available for querying on an L3 flow.
type StatsType string

const (
	StatsTypeTraffic StatsType = "traffic"
	StatsTypeTCP     StatsType = "tcp"
	StatsTypeFlowLog StatsType = "flow"
	StatsTypeProcess StatsType = "process"
)

type FlowAction string

const (
	FlowActionUnknown       FlowAction = "unknown"
	FlowActionAllow         FlowAction = "allow"
	FlowActionDeny          FlowAction = "deny"
	FlowActionPass          FlowAction = "pass"
	FlowActionLog           FlowAction = "log"
	FlowActionEndOfTierDeny FlowAction = "eot-deny"
)

type FlowReporter string

const (
	FlowReporterSource FlowReporter = "src"
	FlowReporterDest   FlowReporter = "dst"
)

// L3FlowParams define querying parameters to retrieve L3 Flows
type L3FlowParams struct {
	QueryParams `json:",inline" validate:"required"`

	// Actions limits returned flows to only those with the given actions.
	// If multiple actions are provided, they are combined with a logical OR.
	Actions []FlowAction `json:"actions" validate:"omitempty"`

	// SourceTypes limits the returned flows to only those originating
	// from one of the specified types.
	// If multiple types are provided, they are combined with a logical OR.
	SourceTypes []EndpointType `json:"source_types"`

	// DestinationTypes limits the returned flows to only those destined
	// to one of the specified types.
	// If multiple types are provided, they are combined with a logical OR.
	DestinationTypes []EndpointType `json:"destination_types"`

	// SourceSelectors are a list of label selectors to use
	// to select the source in flow queries.
	// If multiple selectors are provided, they are combined with a logical AND.
	SourceSelectors []LabelSelector `json:"source_selectors"`

	// DestinationSelectors are a list of label selectors to use
	// to select the destination in flow queries.
	// If multiple selectors are provided, they are combined with a logical AND.
	DestinationSelectors []LabelSelector `json:"destination_selectors"`

	// Select flows that match these namespace criteria.
	// If multiple matches are provided, they are combined with a logical AND.
	NamespaceMatches []NamespaceMatch `json:"namespace_matches"`

	// Select flows based on aggregated name.
	// If multiple matches are provided, they are combined with a logical AND.
	NameAggrMatches []NameMatch `json:"name_aggr_matches"`

	// PolicyMatches selects flows based on whether an action is taken on the flow
	// by the provided tier.
	// For example, return flows which are allowed by the default tier.
	// If multiple PolicyMatches are provided, they are combined with a logical OR.
	PolicyMatches []PolicyMatch `json:"policy_matches" validate:"dive"`

	// EnforcedPolicyMatches selects flows based on whether an action is taken on the flow
	// by the provided tier, based on the enforced trace.
	// For example, return flows which are allowed by the default tier.
	// If multiple EnforcedPolicyMatches are provided, they are combined with a logical OR.
	EnforcedPolicyMatches []PolicyMatch `json:"enforced_policy_matches" validate:"dive"`

	// PendingPolicyMatches selects flows based on whether an action is taken on the flow
	// by the provided tier, based on the pending trace.
	// For example, return flows which are allowed by the default tier.
	// If multiple PendingPolicyMatches are provided, they are combined with a logical OR.
	PendingPolicyMatches []PolicyMatch `json:"pending_policy_matches" validate:"dive"`

	// Statistics will include different metrics for the L3 flows that are queried
	// The following metrics can be extracted: connection, tcp, flow and process
	// If missing, only flow metrics will be generated
	Statistics []StatsType `json:"statistics" validate:"omitempty,dive,oneof=tcp connection flow process"`
}

// PolicyMatch allows matching on a policy when querying flow logs.
type PolicyMatch struct {
	// Type of the policy: knp: KubernetesNetworkPolicy, anp: AdminNetworkPolicy
	Type PolicyType `json:"type,omitempty" validate:"omitempty,oneof=knp kanp kbanp"`

	// Staged is a boolean that indicates matching for staged policies.
	Staged bool `json:"staged,omitempty"`

	// Tier for the policy.
	Tier string `json:"tier,omitempty" validate:"omitempty,excludesall=.:/"`

	// The action taken by the policy.
	Action *FlowAction `json:"action,omitempty" validate:"omitempty"`

	// Namespace and name of the policy.
	Namespace *string `json:"namespace,omitempty" validate:"omitempty,excludesall=.:/"`
	Name      *string `json:"name,omitempty" validate:"omitempty,excludesall=.:/"`
}

type PolicyType string

const (
	KNP   PolicyType = "knp"
	KANP  PolicyType = "kanp"
	KBANP PolicyType = "kbanp"
)

type MatchType string

const (
	MatchTypeSource MatchType = "src"
	MatchTypeDest   MatchType = "dst"
	MatchTypeAny    MatchType = "any"
)

type NamespaceMatch struct {
	// Whether to match against the source namespace, destination namespace,
	// or either namespace.
	Type MatchType `json:"type"`

	// List of namespaces to match against. Any flow which has a matching namespace
	// will be included. If multiple are provided, they are combined using a logical OR.
	Namespaces []string `json:"namespaces"`
}

type NameMatch struct {
	// Whether to match against the source name, destination name,
	// or either source or destination name.
	Type MatchType `json:"type"`

	// Any flow with a matching name will be included. If multiple are provided,
	// they are combined using a logical OR.
	Names []string `json:"names"`
}

// L3FlowKey represents the identifiers for an L3 Flow.
type L3FlowKey struct {
	// Common fields
	Action   FlowAction   `json:"action"`
	Reporter FlowReporter `json:"reporter"`
	Protocol string       `json:"protocol"` // TODO: Do we support int values?

	// Source and destination information.
	Source      Endpoint `json:"source"`
	Destination Endpoint `json:"destination"`

	Cluster string `json:"cluster"`
}

// L3Flow represents a summary of connection and traffic information between two
// endpoints over a given period of time, as reported by one of said endpoints.
type L3Flow struct {
	// Key contains the identifying information for this L3 Flow.
	Key L3FlowKey `json:"key"`

	Process *Process `json:"process,omitempty"`
	Service *Service `json:"dest_service,omitempty"`

	// Policies applied to this flow, in order.
	Policies         []Policy `json:"policies,omitempty"`
	EnforcedPolicies []Policy `json:"enforced_policies,omitempty"`
	PendingPolicies  []Policy `json:"pending_policies,omitempty"`

	// DestDomains are the destination domains of this flow
	DestDomains []string `json:"dest_domains,omitempty"`

	SourceIPs      []string `json:"source_ips,omitempty"`
	DestinationIPs []string `json:"destination_ips,omitempty"`

	// DestinationLabels are the labels applied to the destination during the lifetime
	// of this flow. Note that a single label may have had multiple values throughout this flow's life.
	DestinationLabels []FlowLabels `json:"destination_labels,omitempty"`

	// SourceLabels are the labels applied to the source during the lifetime
	// of this flow. Note that a single label may have had multiple values throughout this flow's life.
	SourceLabels []FlowLabels `json:"source_labels,omitempty"`

	// TrafficStats contains summarized traffic stats for this flow.
	TrafficStats *TrafficStats `json:"connection_stats,omitempty"`

	// TCPStats are aggregated TCP metrics generated from the traffic described by the L3 flow
	TCPStats *TCPStats `json:"tcp_stats,omitempty"`

	// HTTPStats are aggregated HTTP metrics generated from the traffic described by the L3 flow
	HTTPStats *HTTPStats `json:"http_stats,omitempty"`

	// LogStats are aggregated metrics about the underlying flow logs used to generate this flow.
	LogStats *LogStats `json:"log_stats,omitempty"`

	// ProcessStats are process aggregated metrics generated from the traffic described by the L3 flows.
	ProcessStats *ProcessStats `json:"process_stats,omitempty"`
}

type Policy struct {
	Tier         string `json:"tier"`
	Namespace    string `json:"namespace"`
	Name         string `json:"name"`
	Action       string `json:"action"`
	IsStaged     bool   `json:"is_staged"`
	IsKubernetes bool   `json:"is_kubernetes"`
	IsProfile    bool   `json:"is_profile"`
	Count        int64  `json:"count"`
	RuleID       *int   `json:"rule_id"`
}

// FlowLabels represents a single label and all of its seen values over the course of
// a flow's life.
type FlowLabels struct {
	Key    string           `json:"key"`
	Values []FlowLabelValue `json:"values"`
}

type FlowLabelValue struct {
	// The value for this label.
	Value string `json:"value"`

	// The number of individual flow logs that had this label value.
	Count int64 `json:"count"`
}

// LogStats represent the number of flows aggregated into this entry
type LogStats struct {
	// LogCount is the total number of raw flow logs - prior to client-side aggregation - that were
	// aggregated into this entry. This is in contrast to FlowLogCount, which is the number of
	// flow log entries from Elasticsearch used to generate this flow.
	LogCount int64 `json:"count"`

	// FlowLogCount is the number of flow logs in Elasticsearch used to generate this flow.
	FlowLogCount int64 `json:"flowLogCount"`

	// Completed is the number of flow logs that finished and aggregated into during this entry.
	Completed int64 `json:"completed"`

	// Started is the number of flow logs that started and aggregated into during this entry.
	Started int64 `json:"started"`
}

// ProcessStats represent the number of processes aggregated into this entry
type ProcessStats struct {
	MinNumNamesPerFlow int `json:"min_num_names_per_flow"`
	MaxNumNamesPerFlow int `json:"max_num_names_per_flow"`
	MinNumIDsPerFlow   int `json:"min_num_ids_per_flow"`
	MaxNumIDsPerFlow   int `json:"max_num_ids_per_flow"`
}

// TrafficStats represent L3 metrics aggregated from flows into this entry
type TrafficStats struct {
	// PacketsIn is the total number of incoming packets aggregated into this entry
	PacketsIn int64 `json:"packets_in"`

	// PacketsOut is the total number of outgoing packets aggregated into this entry
	PacketsOut int64 `json:"packets_out"`

	// BytesIn is the total number of incoming packets aggregated into this entry
	BytesIn int64 `json:"bytes_in"`

	// BytesOut is the total number of outgoing packets aggregated into this entry
	BytesOut int64 `json:"bytes_out"`
}

// HTTPStats represent HTTP metrics aggregated from flows into this entry
type HTTPStats struct {
	AllowedIn int64 `json:"allowed_in"`
	DeniedIn  int64 `json:"denied_in"`
}

// TCPStats represent TCP metrics aggregated from flows into this entry
type TCPStats struct {
	// LostPackets is the total number of lost TCP packets aggregated into this entry
	LostPackets int64 `json:"lost_packets"`

	// MaxMinRTT is the maximum value of the lower Round Trip Time for TCP packets aggregated into this entry
	MaxMinRTT float64 `json:"max_min_rtt"`

	// MaxSmoothRTT is the maximum value of the Smoothed Round Trip Time for TCP packets aggregated into this entry
	MaxSmoothRTT float64 `json:"max_smooth_rtt"`

	// MeanMinRTT is the mean value of the lower Round Trip Time for TCP packets aggregated into this entry
	MeanMinRTT float64 `json:"mean_min_rtt"`

	// MeanMSS is the mean value of the Maximum Segment Size for a TCP packet aggregated into this entry
	MeanMSS float64 `json:"mean_mss"`

	// MeanSendCongestionWindow is the mean value of SendCongestionWindow for TCP packets aggregated into this entry
	MeanSendCongestionWindow float64 `json:"mean_send_congestion_window"`

	// MeanSmoothRTT is the mean value of the Smoothed Round Trip Time for TCP packets aggregated into this entry
	MeanSmoothRTT float64 `json:"mean_smooth_rtt"`

	// MinMSS is the min value of the Maximum Segment Size for a TCP packet aggregated into this entry
	MinMSS float64 `json:"min_mss"`

	// MinSendCongestionWindow is the min value of SendCongestionWindow for TCP packets aggregated into this entry
	MinSendCongestionWindow float64 `json:"min_send_congestion_window"`

	// UnrecoveredTo
	UnrecoveredTo int64 `json:"unrecovered_to"`

	// TotalRetransmissions is the total number of retransmitted TCP packets that were lost
	TotalRetransmissions int64 `json:"total_retransmissions"`
}

type Process struct {
	Name string `json:"name"`
}

type Service struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Port      int64  `json:"port"`
	PortName  string `json:"port_name"`
}

// EndpointType is different types of endpoints present in log data.
type EndpointType string

const (
	WEP        EndpointType = "wep"
	HEP        EndpointType = "hep"
	Network    EndpointType = "net"
	NetworkSet EndpointType = "ns"
)

type Endpoint struct {
	Type           EndpointType `json:"type" validate:"omitempty,oneof=wep hep net ns"`
	Name           string       `json:"name" validate:"omitempty"`
	AggregatedName string       `json:"aggregated_name" validate:"omitempty"`
	Namespace      string       `json:"namespace" validate:"omitempty"`
	Port           int64        `json:"port" validate:"omitempty"`
}

type EndpointMatch struct {
	AggregatedName string `json:"aggregated_name" validate:"omitempty"`
	Namespace      string `json:"namespace" validate:"omitempty"`
	Port           int64  `json:"port" validate:"omitempty"`
}

type LabelSelector struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}
