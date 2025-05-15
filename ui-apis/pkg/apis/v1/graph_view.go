// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package v1

import (
	"encoding/json"
	"fmt"

	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/lma/pkg/httputils"
)

// GraphView provides the configuration for what is included in the service graph response.
//
// The flows are aggregated based on the layers and expanded nodes defined in this view. The graph is then pruned
// based on the focus and followed-nodes. A graph node is included if any of the following is true:
//   - the node (or one of its child nodes) is in-focus
//   - the node (or one of its child nodes) is connected directly to an in-focus node (in either connection Direction)
//   - the node (or one of its child nodes) is connected indirectly to an in-focus node, respecting the Direction
//     of the connection and FollowConnectionDirection is true (*)
//   - the node (or one of its child nodes) is directly connected to an "included" node whose connections are being
//     explicitly "followed" in the appropriate connection Direction via FollowedEgress or FollowedIngress params (*)
//
// (*) Suppose you have nodes A, B, C, D, E; C is directly in focus
//
//	If connections are: A-->B-->C-->D-->E then: B, C and D will be included by default.
//	                                            A, B, C, D and E will all be included if FollowConnectionDirection is true
//	If connections are: A<--B-->C-->D<--E then: B, C and D will be included in the view, and
//	                                            A will be included iff the egress connections for B are being followed
//	                                            E will be included iff the ingress connections for D are being followed
type GraphView struct {
	// The view is the set of nodes that are the focus of the graph. All nodes returned by the service graph query
	// will be connected to at least one of these nodes. If this is empty, then all nodes will be returned.
	Focus []GraphNodeID `json:"focus,omitempty" validate:"omitempty"`

	// Expanded nodes.
	Expanded []GraphNodeID `json:"expanded,omitempty" validate:"omitempty"`

	// Whether expanded service groups are expanded down to the port level.
	ExpandPorts bool `json:"expand_ports" validate:"omitempty"`

	// Whether or not to automatically follow directly connected nodes.
	FollowConnectionDirection bool `json:"follow_connection_direction" validate:"omitempty"`

	// Whether to split HostEndpoints, NetworkSets and Networks into separate ingress and egress nodes or to combine
	// them. In a service-centric view, splitting these makes the graph clearer. This never splits pods which represent
	// a true microservice which has ingress and egress connections.
	SplitIngressEgress bool `json:"split_ingress_egress" validate:"omitempty"`

	// The set of selectors used to aggregate hosts (Kubernetes nodes).
	HostAggregationSelectors []NamedSelector `json:"host_aggregation_selectors,omitempty" validate:"omitempty"`

	// Followed nodes. These are nodes on the periphery of the graph that we follow further out of the scope of the
	// graph focus. For example a Node N may have egress connections to X and Y, but neither X nor Y are displayed in
	// the graph because they are not explicitly in focus. The service graph response will indicate that Node N has
	// egress connections that may be followed.  If Node N is added to this "FollowedEgress" then the response will
	// include the egress connections to X and Y.
	FollowedEgress  []GraphNodeID `json:"followed_egress,omitempty" validate:"omitempty"`
	FollowedIngress []GraphNodeID `json:"followed_ingress,omitempty" validate:"omitempty"`

	// The layers - this is the set of nodes that will be aggregated into a single layer. If a layer is also
	// flagged as "expanded" then the nodes will not be aggregated into the layer, but the nodes will be flagged as
	// being contained in the layer.
	Layers []Layer `json:"layers,omitempty" validate:"omitempty"`
}

type Layer struct {
	Name  string        `json:"name" validate:"required"`
	Nodes []GraphNodeID `json:"nodes" validate:"required"`
}

type NamedSelector struct {
	Name     string             `json:"name" validate:"required"`
	Selector *selector.Selector `json:"selector" validate:"required"`
}

func (ns *NamedSelector) UnmarshalJSON(b []byte) error {
	// Unmarshal into a map[string]string first
	ss := struct {
		Name     string `json:"name"`
		Selector string `json:"selector"`
	}{}
	if err := json.Unmarshal(b, &ss); err != nil {
		return err
	}

	if sel, err := selector.Parse(ss.Selector); err != nil {
		return httputils.NewHttpStatusErrorBadRequest(
			fmt.Sprintf("Request body contains an invalid selector: %s", ss.Selector), err,
		)
	} else {
		ns.Name = ss.Name
		ns.Selector = sel
		return nil
	}
}
