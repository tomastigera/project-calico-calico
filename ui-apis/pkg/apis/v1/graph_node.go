// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package v1

import (
	"fmt"
)

type GraphNodeType string

const (
	GraphNodeTypeNamespace    GraphNodeType = "namespace"
	GraphNodeTypeLayer        GraphNodeType = "layer"
	GraphNodeTypeServiceGroup GraphNodeType = "svcgp"
	GraphNodeTypeService      GraphNodeType = "svc"
	GraphNodeTypeServicePort  GraphNodeType = "svcport"
	GraphNodeTypeReplicaSet   GraphNodeType = "rep"
	GraphNodeTypeWorkload     GraphNodeType = "wep"
	GraphNodeTypeClusterNodes GraphNodeType = "clusternodes"
	GraphNodeTypeClusterNode  GraphNodeType = "clusternode"
	GraphNodeTypeHosts        GraphNodeType = "hosts"
	GraphNodeTypeHost         GraphNodeType = "host"
	GraphNodeTypeHostEndpoint GraphNodeType = "hep" // Never exposed over the API, we expose these as Host or ClusterNode
	GraphNodeTypeNetwork      GraphNodeType = "net"
	GraphNodeTypeNetworkSet   GraphNodeType = "ns"
	GraphNodeTypePort         GraphNodeType = "port"
	GraphNodeTypeUnknown      GraphNodeType = ""
)

type GraphNodeID string

type GraphNode struct {
	// The ID of this graph node. See doc file in /pkg/apis/es for details on the node ID construction.
	ID GraphNodeID `json:"id"`

	// The parent (or outer) node.
	ParentID GraphNodeID `json:"parent_id,omitempty"`

	// Node metadata.
	Type      GraphNodeType `json:"type"`
	Namespace string        `json:"namespace,omitempty"`
	Name      string        `json:"name,omitempty"`
	Protocol  string        `json:"protocol,omitempty"`
	Port      int           `json:"port,omitempty"`

	// The service ports contained within this group.
	ServicePorts ServicePorts `json:"service_ports,omitempty"`

	// Aggregated protocol and port information for this node. Protocols and ports that are explicitly included in the
	// graph because they are part of an expanded service are not included in this aggregated set.
	AggregatedProtoPorts *AggregatedProtoPorts `json:"aggregated_proto_ports,omitempty"`

	// Stats for packets flowing between endpoints within this graph node. Each entry corresponds to a time slice as
	// specified in the main response object.
	StatsWithin []GraphStats `json:"stats_within,omitempty"`

	// Stats for packets flowing between endpoints for ingress connections to this graph node. Each entry corresponds
	// to a time slice as specified in the main response object
	StatsIngress []GraphStats `json:"stats_ingress,omitempty"`

	// Stats for packets flowing between endpoints for egress connections from this graph node. Each entry corresponds
	// to a time slice as specified in the main response object
	StatsEgress []GraphStats `json:"stats_egress,omitempty"`

	// Whether this node is further expandable. In other words if this node is added as an `Expanded` node to
	// the `GraphView` then the results may return additional nodes and edges.
	Expandable bool `json:"expandable,omitempty"`

	// Whether this node is expanded.
	Expanded bool `json:"expanded,omitempty"`

	// Whether this node may be further followed in the egress connection direction or ingress connection direction.
	// If true, this node can be added to FollowedEgress or FollowedIngress in the `GraphView` to return additional
	// nodes and edges.
	FollowEgress  bool `json:"follow_egress,omitempty"`
	FollowIngress bool `json:"follow_ingress,omitempty"`

	// The selectors provide the set of selector expressions used to access the raw data that corresponds to this
	// graph node.
	Selectors GraphSelectors `json:"selectors"`

	// The number of events correlated to this node.
	EventsCount int `json:"events_count,omitempty"`
}

func (n *GraphNode) IncludeStatsWithin(ts []GraphStats) {
	if n.StatsWithin == nil {
		n.StatsWithin = append([]GraphStats(nil), ts...)
	} else if ts != nil {
		for i := range n.StatsWithin {
			n.StatsWithin[i] = n.StatsWithin[i].Combine(ts[i])
		}
	}
}

func (n *GraphNode) IncludeStatsIngress(ts []GraphStats) {
	if n.StatsIngress == nil {
		n.StatsIngress = append([]GraphStats(nil), ts...)
	} else if ts != nil {
		for i := range n.StatsIngress {
			n.StatsIngress[i] = n.StatsIngress[i].Combine(ts[i])
		}
	}
}

func (n *GraphNode) IncludeStatsEgress(ts []GraphStats) {
	if n.StatsEgress == nil {
		n.StatsEgress = append([]GraphStats(nil), ts...)
	} else if ts != nil {
		for i := range n.StatsEgress {
			n.StatsEgress[i] = n.StatsEgress[i].Combine(ts[i])
		}
	}
}

func (n *GraphNode) IncludeAggregatedProtoPorts(p *AggregatedProtoPorts) {
	n.AggregatedProtoPorts = n.AggregatedProtoPorts.Combine(p)
}

func (n *GraphNode) IncludeServicePort(s ServicePort) {
	if n.ServicePorts == nil {
		n.ServicePorts = make(ServicePorts)
	}
	n.ServicePorts[s] = struct{}{}
}

func (n *GraphNode) String() string {
	if n.ParentID == "" {
		return fmt.Sprintf("Node(%s; expandable=%v)", n.ID, n.Expandable)
	}
	return fmt.Sprintf("Node(%s; parent=%s; expandable=%v)", n.ID, n.ParentID, n.Expandable)
}
