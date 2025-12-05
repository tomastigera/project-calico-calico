// Copyright (c) 2025 Tigera, Inc. All rights reserved.
package v1

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
)

type ServiceGraphStatsRequest struct {
	// The cluster name. Defaults to "cluster".
	Cluster string `json:"cluster" validate:"omitempty"`

	// Time range.
	TimeRange *lmav1.TimeRange `json:"time_range" validate:"required"`

	// Timeout for the request. Defaults to 60s.
	Timeout v1.Duration `json:"timeout" validate:"omitempty"`

	// Include detailed information on how the topology and namespace stats were constructed.
	IncludeDeveloperStats bool `json:"include_developer_stats" validate:"omitempty"`
}

type ServiceGraphStatsResponse struct {
	// Scale determinations for the global service graph.
	TopologyStatistics TopologyStatistics `json:"topology_stats"`

	// Scale determinations for the service graph on a per-namespace basis.
	// Namespaces will always be included in the slice, but scale determinations on each namespace are optional.
	NamespacesStatistics []NamespaceStatistics `json:"namespaces_statistics"`

	// Detailed information on how the topology and namespace stats were constructed.
	DeveloperStatistics *DeveloperStatistics `json:"developer_stats,omitempty"`
}

type TopologyStatistics struct {
	HighVolume bool `json:"high_volume"`
	NumEdges   *int `json:"num_edges,omitempty"`
}

type NamespaceStatistics struct {
	Namespace  string `json:"namespace"`
	HighVolume *bool  `json:"high_volume,omitempty"`
}

type DeveloperStatistics struct {
	Counts          TopologyCounts  `json:"counts"`
	NamespaceCounts NamespaceCounts `json:"namespace_counts"`
	Cancellations   Operations      `json:"cancellations"`
	Truncations     Operations      `json:"truncations"`
}

type TopologyCounts struct {
	NumFlowLogs int64 `json:"num_flow_logs"`
	NumL3Flows  int64 `json:"num_l3_flows"`
}

type NamespaceCounts struct {
	NumFlowLogs map[string]int64 `json:"num_flow_logs"`
	NumL3Flows  map[string]int64 `json:"num_l3_flows"`
}

type Operations struct {
	NamespacedFlowLogCounts bool `json:"namespaced_flow_log_counts"`
	L3FlowCounts            bool `json:"l3_flow_counts"`
}
