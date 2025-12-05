// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package servicegraph

import (
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"

	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
	"github.com/projectcalico/calico/ui-apis/pkg/math"
)

// This file provides the final graph construction from a set of correlated (time-series) flows and the parsed view
// IDs.
//
// See v1.GraphView for details on aggregation, and which nodes will be included in the graph.

// K8SAllSelector is used for a namespace service graph node to select all endpoints within that namespace
var K8SAllSelector = "all()"

// GetServiceGraphResponse calculates the service graph from the flow data and parsed view ids.
func GetServiceGraphResponse(sgd *ServiceGraphData, v *ParsedView, constructorOpts ...ServiceGraphConstructorOption) (*v1.ServiceGraphResponse, error) {

	// The bulk of the work is done in the graph constructor.
	s, err := newServiceGraphConstructor(sgd, v, constructorOpts...)
	if err != nil {
		return nil, err
	}

	// Populate the graph construction data by loading the flows.
	s.populate()

	// Prune the graph based on the requested view.
	s.prune()

	// Overlay the events on the in-view nodes.
	s.overlayEvents()

	// Overlay the dns client data on the in-view nodes.
	s.overlayDNS()

	// Overlay the selectors on the in-view nodes and edges.
	s.overlaySelectors()

	// Construct the response.
	return s.getResponse(), nil
}

// trackedGroup is an internal struct used for tracking a node group (i.e. a node in the graph that does not have a
// parent). This is used to simplify the pruning algorithm since we only look at connectivity between these groups
// to determine if the node (and all its children, and its expanded parents) should be included or not.
type trackedGroup struct {
	node             *trackedNode
	parents          []*trackedNode
	children         []*trackedNode
	viewData         NodeViewData
	ingress          map[*trackedGroup]struct{}
	egress           map[*trackedGroup]struct{}
	processedIngress bool
	processedEgress  bool
	followedIngress  bool
	followedEgress   bool
}

// newTrackedGroup creates a new trackedGroup, setting the focus/following info.
func newTrackedGroup(hierarchy []*trackedNode) *trackedGroup {
	node := hierarchy[len(hierarchy)-1]
	parents := hierarchy[:len(hierarchy)-1]
	vd := node.viewData
	for _, parent := range parents {
		vd = vd.Combine(parent.viewData)
	}

	return &trackedGroup{
		node:     node,
		parents:  parents,
		ingress:  make(map[*trackedGroup]struct{}),
		egress:   make(map[*trackedGroup]struct{}),
		viewData: vd,
	}
}

// addChild adds a child node to a tracked group. This updates the groups focus/following info from the child specific
// values - this data is additive.
func (t *trackedGroup) addChild(child *trackedNode) {
	t.children = append(t.children, child)
	t.viewData = t.viewData.Combine(child.viewData)
}

// trackedNode encapsulates details of a node returned by the API, and additional data required to do some post
// graph-construction updates.
type trackedNode struct {
	graphNode v1.GraphNode
	parent    *trackedNode
	selectors SelectorPairs
	viewData  NodeViewData
	// for certain graph node types like host endpoints, even though they are tracked under the same tracked group,
	// we still want to show edges between them. This flag is used to retain edges when we convert raw flow into
	// service graph nodes and edges.
	retainEdges bool
}

func (t *trackedNode) id() v1.GraphNodeID {
	if t == nil {
		return ""
	}
	return t.graphNode.ID
}

func (t *trackedNode) services() []v1.NamespacedName {
	var services []v1.NamespacedName
	if t.graphNode.ServicePorts != nil {
		var set = v1.NamespacedNames{}
		for k := range t.graphNode.ServicePorts {
			set[k.NamespacedName] = struct{}{}
		}

		return set.AsSortedSlice()
	}

	return services
}

// Track the source and dest nodes for each service node. We need to do this to generate the edge selectors for
// edges from the source to service and service to dest.
type serviceEdges struct {
	destNodesBySourceNode map[*trackedNode]map[*trackedNode]struct{}
	sourceNodesByDestNode map[*trackedNode]map[*trackedNode]struct{}
}

func newServiceEdges() *serviceEdges {
	return &serviceEdges{
		destNodesBySourceNode: make(map[*trackedNode]map[*trackedNode]struct{}),
		sourceNodesByDestNode: make(map[*trackedNode]map[*trackedNode]struct{}),
	}
}

func (se *serviceEdges) add(source, dest *trackedNode) {
	if destNodes := se.destNodesBySourceNode[source]; destNodes == nil {
		se.destNodesBySourceNode[source] = map[*trackedNode]struct{}{
			dest: {},
		}
	} else {
		destNodes[dest] = struct{}{}
	}

	if sourceNodes := se.sourceNodesByDestNode[dest]; sourceNodes == nil {
		se.sourceNodesByDestNode[dest] = map[*trackedNode]struct{}{
			source: {},
		}
	} else {
		sourceNodes[source] = struct{}{}
	}
}

// serviceGraphConstructionData is the transient data used to construct the final service graph.
type serviceGraphConstructionData struct {
	// The set of tracked groups keyed of the group node ID.
	groupsMap map[v1.GraphNodeID]*trackedGroup

	// The full set of graph nodes keyed off the node ID.
	nodesMap map[v1.GraphNodeID]*trackedNode

	// The full set of graph edges keyed off the edge ID.
	edgesMap map[v1.GraphEdgeID]*v1.GraphEdge

	// The mapping between service and edges connected to the service.
	serviceEdges map[*trackedNode]*serviceEdges

	// The supplied service graph data.
	sgd *ServiceGraphData

	// The supplied view data.
	view *ParsedView

	// The selector helper used to construct selectors.
	selh *SelectorHelper

	// The view selectors.
	viewSelectors v1.GraphSelectors

	// Whether to exclude stats from flows during graph construction.
	excludeStatsFromFlows bool
}

// ServiceGraphConstructorOption is a functional option for configuring serviceGraphConstructionData.
type ServiceGraphConstructorOption func(*serviceGraphConstructionData) error

// WithExcludeStatsFromFlows configures whether to exclude stats from flows during graph construction.
func WithExcludeStatsFromFlows(exclude bool) ServiceGraphConstructorOption {
	return func(s *serviceGraphConstructionData) error {
		s.excludeStatsFromFlows = exclude
		return nil
	}
}

// newServiceGraphConstructor initializes a new serviceGraphConstructionData.
func newServiceGraphConstructor(sgd *ServiceGraphData, v *ParsedView, opts ...ServiceGraphConstructorOption) (*serviceGraphConstructionData, error) {
	s := &serviceGraphConstructionData{
		groupsMap:             make(map[v1.GraphNodeID]*trackedGroup),
		nodesMap:              make(map[v1.GraphNodeID]*trackedNode),
		edgesMap:              make(map[v1.GraphEdgeID]*v1.GraphEdge),
		serviceEdges:          make(map[*trackedNode]*serviceEdges),
		sgd:                   sgd,
		view:                  v,
		selh:                  NewSelectorHelper(v, sgd.NameHelper, sgd.ServiceGroups),
		excludeStatsFromFlows: false,
	}

	// Apply options
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}

	return s, nil
}

// populate loads the flow data to populate the graph construction data.
func (s *serviceGraphConstructionData) populate() {
	// Iterate through the flows to track the nodes and edges.
	for i := range s.sgd.FilteredFlows {
		if err := s.trackFlow(&s.sgd.FilteredFlows[i]); err != nil {
			log.WithError(err).WithField("flow", s.sgd.FilteredFlows[i]).Errorf("Unable to process flow")
			continue
		}
	}
}

// trackFlow converts a flow into a set of graph nodes and edges. Each flow may be converted into one or more
// nodes (with parent relationships), and either zero, one or two edges.
//
// This tracks the graph node and edge data, aggregating the traffic stats as required. This also tracks connectivity
// between the endpoint groups to simplify graph pruning (we only consider connectivity between groups).
func (s *serviceGraphConstructionData) trackFlow(flow *TimeSeriesFlow) error {
	// Create the source and dest graph nodes. Note that if the source and dest nodes have a common root then add
	// the appropriate intra-node statistics. Note source will not include a service Port since that is an ingress
	// only concept.
	log.Debugf("Processing: %s", flow)

	var egress, ingress Direction
	if s.view.SplitIngressEgress {
		egress, ingress = DirectionEgress, DirectionIngress
	}

	srcGp, srcEpHierarchy, _ := s.trackNodes(flow.Edge.Source, nil, egress)
	dstGp, dstEpHierarchy, servicePortDstHierarchy := s.trackNodes(flow.Edge.Dest, flow.Edge.ServicePort, ingress)

	// Determine the aggregated ports for the destination. We'll add this to the destination node and use it in the
	// edge data.
	var aggProtoPort *v1.AggregatedProtoPorts
	if flow.Edge.Dest.PortNum != 0 {
		aggProtoPort = &v1.AggregatedProtoPorts{
			ProtoPorts: []v1.AggregatedPorts{{
				Protocol: flow.Edge.Dest.Protocol,
				PortRanges: []v1.PortRange{{
					MinPort: flow.Edge.Dest.PortNum, MaxPort: flow.Edge.Dest.PortNum,
				}},
			}},
		}
	} else {
		aggProtoPort = flow.AggregatedProtoPorts
	}

	// If there are any service ports in this flow, include these in the nodes from the service and all its parents.
	// We do not include on the service port since the information is already there.
	if flow.Edge.ServicePort != nil {
		if len(servicePortDstHierarchy) > 0 {
			// We have a service hierarchy, so we must be expanded up to the service or service port. Apply the service
			// port info in the hierarchy up to, but not including the service port.
			for _, t := range servicePortDstHierarchy {
				if t.graphNode.Type == v1.GraphNodeTypeServicePort {
					break
				}
				t.graphNode.IncludeServicePort(*flow.Edge.ServicePort)
			}
		} else {
			// We don't have a service hierarchy, so we cannot be expanded past the service group. Use the endpoint
			// hierarchy and apply the service settings to the full hierarchy.
			for _, t := range dstEpHierarchy {
				t.graphNode.IncludeServicePort(*flow.Edge.ServicePort)
			}
		}
	}

	// Include the aggregated port proto info in the destination endpoint nodes. Apply to all endpoint type nodes in
	// the hierarchy.
	if aggProtoPort != nil {
		for _, t := range dstEpHierarchy {
			if IsEndpointType(t.graphNode.Type) {
				t.graphNode.IncludeAggregatedProtoPorts(aggProtoPort)
			}
		}
	}

	// Apply the stats to the source and dest hierarchies. Each node has three sets of stats for packet flow within
	// the node and packets for ingress and egress connections.
	//
	// Track source and dest from the top of the hiearchy applying to the "within" set when source and dest are the
	// same, but then applying to the relevant ingress or egress set when they become divergent.
	if !s.excludeStatsFromFlows {
		maxIdx := math.MinInt(len(srcEpHierarchy), len(dstEpHierarchy))
		var divergentIdx int
		for divergentIdx = 0; divergentIdx < maxIdx; divergentIdx++ {
			if srcEpHierarchy[divergentIdx] != dstEpHierarchy[divergentIdx] {
				break
			}
			srcEpHierarchy[divergentIdx].graphNode.IncludeStatsWithin(flow.Stats)
		}
		for i := divergentIdx; i < len(srcEpHierarchy); i++ {
			srcEpHierarchy[i].graphNode.IncludeStatsEgress(flow.Stats)
		}
		for i := divergentIdx; i < len(dstEpHierarchy); i++ {
			dstEpHierarchy[i].graphNode.IncludeStatsIngress(flow.Stats)
		}
	}

	// If the source and dest group are the same and the retain edges flags are not set for the nodes,
	// then don't add an edge.
	retainEdges := srcGp.node.retainEdges && dstGp.node.retainEdges
	if srcGp == dstGp && !retainEdges {
		return nil
	}

	// Now track the edge and the edge statistics. Start by determining the final endpoint in each hierarchy. The edges
	// originate and terminate from these most granular endpoints.
	srcEp := srcEpHierarchy[len(srcEpHierarchy)-1]
	dstEp := dstEpHierarchy[len(dstEpHierarchy)-1]

	var servicePortDst *trackedNode
	if servicePortDstHierarchy != nil {
		servicePortDst = servicePortDstHierarchy[len(servicePortDstHierarchy)-1]
	}

	// Stitch together the source and dest nodes going via the service if present.
	if servicePortDst != nil {
		// There is a service port, so we have src->svc->dest
		var sourceEdge, destEdge *v1.GraphEdge
		var ok bool

		id := v1.GraphEdgeID{
			SourceNodeID: srcEp.graphNode.ID,
			DestNodeID:   servicePortDst.graphNode.ID,
		}
		log.Debugf("Tracking: %s", id)
		if sourceEdge, ok = s.edgesMap[id]; ok {
			sourceEdge.IncludeStats(flow.Stats)
			sourceEdge.IncludeServicePort(*flow.Edge.ServicePort)
			sourceEdge.IncludeEndpointProtoPorts(aggProtoPort)
		} else {
			sourceEdge = &v1.GraphEdge{
				ID:                 id,
				Stats:              flow.Stats,
				ServicePorts:       v1.ServicePorts{*flow.Edge.ServicePort: struct{}{}},
				EndpointProtoPorts: aggProtoPort,
			}
			s.edgesMap[id] = sourceEdge
		}

		id = v1.GraphEdgeID{
			SourceNodeID: servicePortDst.graphNode.ID,
			DestNodeID:   dstEp.graphNode.ID,
		}
		log.Debugf("Tracking: %s", id)
		if destEdge, ok = s.edgesMap[id]; ok {
			destEdge.IncludeStats(flow.Stats)
			destEdge.IncludeEndpointProtoPorts(aggProtoPort)
		} else {
			destEdge = &v1.GraphEdge{
				ID:                 id,
				Stats:              flow.Stats,
				EndpointProtoPorts: aggProtoPort,
			}
			s.edgesMap[id] = destEdge
		}

		// Track the edges associated with a service node - we use this to construct selectors.
		se := s.serviceEdges[servicePortDst]
		if se == nil {
			se = newServiceEdges()
			s.serviceEdges[servicePortDst] = se
		}
		se.add(srcEp, dstEp)
	} else {
		// No service port, so direct src->dst
		id := v1.GraphEdgeID{
			SourceNodeID: srcEp.graphNode.ID,
			DestNodeID:   dstEp.graphNode.ID,
		}
		log.Debugf("Tracking: %s", id)
		var edge *v1.GraphEdge
		var ok bool
		if edge, ok = s.edgesMap[id]; ok {
			edge.IncludeStats(flow.Stats)
			edge.IncludeEndpointProtoPorts(aggProtoPort)
		} else {
			edge = &v1.GraphEdge{
				ID:                 id,
				Stats:              flow.Stats,
				EndpointProtoPorts: aggProtoPort,
			}
			s.edgesMap[id] = edge
		}
		if flow.Edge.ServicePort != nil {
			edge.IncludeServicePort(*flow.Edge.ServicePort)
		}
	}

	// Track group interconnectivity for pruning purposes.
	srcGp.egress[dstGp] = struct{}{}
	dstGp.ingress[srcGp] = struct{}{}

	return nil
}

// trackNodes converts a FlowEndpoint and service to a set of hierarchical nodes. This is where we determine whether
// a node is aggregated into a layer, namespace, service group or aggregated endpoint set - only creating the nodes
// required based on the aggregation.
//
// This method updates the groupsMap and nodesMap, and returns the IDs of the group, the endpoint (to which the
// edge is connected) and the service port (which will be an additional hop).
func (s *serviceGraphConstructionData) trackNodes(
	endpoint FlowEndpoint, svc *v1.ServicePort, dir Direction,
) (group *trackedGroup, endpointPortNodes, servicePortNodes []*trackedNode) {
	getEndpointParent := func() *trackedNode {
		if len(endpointPortNodes) == 0 {
			return nil
		}
		return endpointPortNodes[len(endpointPortNodes)-1]
	}
	getServiceParent := func() *trackedNode {
		if len(servicePortNodes) == 0 {
			return nil
		}
		return servicePortNodes[len(servicePortNodes)-1]
	}
	shouldRetainEdges := func(nodeType v1.GraphNodeType) bool {
		switch nodeType {
		case v1.GraphNodeTypeClusterNodes, v1.GraphNodeTypeClusterNode,
			v1.GraphNodeTypeHosts, v1.GraphNodeTypeHost,
			v1.GraphNodeTypeHostEndpoint:
			return true
		default:
			return false
		}
	}

	// Determine if this endpoint is in a layer - most granular wins.
	var sg *ServiceGroup
	if svc != nil {
		sg = s.sgd.ServiceGroups.GetByService(svc.NamespacedName)
	} else {
		sg = s.sgd.ServiceGroups.GetByEndpoint(endpoint)
	}
	// Create an ID handler.
	idi := IDInfo{
		Endpoint:     endpoint,
		ServiceGroup: sg,
		Direction:    dir,
	}
	if svc != nil {
		idi.Service = *svc
	}

	// Determine the group namespace for this node. If this node is part of service group then we use the namespace
	// associated with the service group, otherwise this is just the endpoint namespace. Note that the service group
	// namespace may be an aggregated name - this is fine - in this case the service group does not belong in a single
	// namespace. Layer selection and namespace expansion is based on this group namespace.
	groupNamespace := endpoint.Namespace
	if sg != nil {
		groupNamespace = sg.Namespace
	}

	// Determine the aggregated and full endpoint IDs and check if contained in a layer.
	nonAggrEndpointId := idi.GetEndpointID()
	aggrEndpointId := idi.GetAggrEndpointID()

	// If the endpoint/service group was directly part of a layer, and that layer is expanded then we effectively
	// bypass the namespace grouping. Keep track of whether the namespace layer should be skipped.
	var layerName string
	var skipNamespace bool

	// The parsed layer will only consist of sensible groups of endpoints and will not separate endpoints that cannot
	// be sensibly removed from other groups.
	if nonAggrEndpointId != "" {
		if layerName = s.view.Layers.EndpointToLayer[nonAggrEndpointId]; layerName != "" {
			skipNamespace = true
		}
	}

	if layerName == "" && aggrEndpointId != "" {
		if layerName = s.view.Layers.EndpointToLayer[aggrEndpointId]; layerName != "" {
			skipNamespace = true
		}
	}

	if layerName == "" && sg != nil {
		if layerName = s.view.Layers.ServiceGroupToLayer[sg]; layerName != "" {
			skipNamespace = true
		}
	}

	if layerName == "" && groupNamespace != "" {
		layerName = s.view.Layers.NamespaceToLayer[groupNamespace]
	}

	if layerName != "" {
		idi.Layer = layerName
		layerId := idi.GetLayerID()
		var layer *trackedNode
		if layer = s.nodesMap[layerId]; layer == nil {
			sel := s.selh.GetLayerNodeSelectors(layerName)
			viewData := s.view.NodeViewData[layerId]
			layer = &trackedNode{
				graphNode: v1.GraphNode{
					ID:         layerId,
					Type:       v1.GraphNodeTypeLayer,
					Name:       layerName,
					Expandable: true,
					Expanded:   viewData.Expanded,
				},
				selectors: sel,
				viewData:  viewData,
			}
			s.nodesMap[layerId] = layer
		}
		endpointPortNodes = append(endpointPortNodes, layer)

		if !layer.viewData.Expanded {
			// Layer is not expanded. Track the layer as the group used for graph pruning, and return the layer as
			// both the group and the endpoint.
			if group = s.groupsMap[layerId]; group == nil {
				group = newTrackedGroup(endpointPortNodes)
				s.groupsMap[layerId] = group
			}
			return
		}
	}

	// If there is a namespace and we are not skipping the namespace (because the endpoint or service group are in a
	// layer which has been expanded) then add the namespace.
	if groupNamespace != "" && !skipNamespace {
		namespaceId := idi.GetNamespaceID()
		var namespace *trackedNode
		if namespace = s.nodesMap[namespaceId]; namespace == nil {
			sel := s.selh.GetNamespaceNodeSelectors(groupNamespace)
			viewData := s.view.NodeViewData[namespaceId]
			parent := getEndpointParent()
			namespace = &trackedNode{
				graphNode: v1.GraphNode{
					Type:       v1.GraphNodeTypeNamespace,
					ID:         namespaceId,
					ParentID:   parent.id(),
					Name:       groupNamespace,
					Expandable: true,
					Expanded:   viewData.Expanded,
				},
				parent:    parent,
				selectors: sel,
				viewData:  viewData,
			}
			s.nodesMap[namespaceId] = namespace
		}
		endpointPortNodes = append(endpointPortNodes, namespace)

		if !namespace.viewData.Expanded {
			// Namespace is not expanded. Track the namespace as the group used for graph pruning, and return the
			// namespace as both the group and the endpoint.
			if group = s.groupsMap[namespaceId]; group == nil {
				group = newTrackedGroup(endpointPortNodes)
				s.groupsMap[namespaceId] = group
			}
			return
		}
	}

	// The graph constructor assumes the following are the least divisible units - in that we cannot split out child
	// nodes from these nodes:
	// - Service Group.  If, for example an endpoint is added to a layer, then the whole service group will be added
	//                   to the layer.  The endpoint will never appear as a node without the service group in its
	//                   parentage.
	// - Aggregated Endpoint.  If an endpoint is not associated with a service group, but is part of an aggregated
	//                   endpoint then similar rules apply as per Service Group. If, for example an endpoint is added
	//                   to a layer, then the aggregated endpoint group will be added to the layer.  The endpoint will
	//                   never appear as a node without the aggregated endpoint group in it's parentage.
	//
	// These rules exist to ensure groups of related endpoints are never split up since that would confuse the
	// metrics aggregation and hide important details about endpoint relationship.

	// If there is a service group then add the service group.
	if sg != nil {
		var serviceGroup *trackedNode
		if serviceGroup = s.nodesMap[sg.ID]; serviceGroup == nil {
			sel := s.selh.GetServiceGroupNodeSelectors(sg)
			viewData := s.view.NodeViewData[sg.ID]
			parent := getEndpointParent()
			serviceGroup = &trackedNode{
				graphNode: v1.GraphNode{
					Type:       v1.GraphNodeTypeServiceGroup,
					ID:         sg.ID,
					ParentID:   parent.id(),
					Namespace:  sg.Namespace,
					Name:       sg.Name,
					Expandable: true,
					Expanded:   viewData.Expanded,
				},
				parent:    parent,
				selectors: sel,
				viewData:  viewData,
			}
			s.nodesMap[sg.ID] = serviceGroup
		}
		endpointPortNodes = append(endpointPortNodes, serviceGroup)

		// Since there is a service group - we always track this as the tracking group even if the service group is
		// expanded.
		if group = s.groupsMap[sg.ID]; group == nil {
			group = newTrackedGroup(endpointPortNodes)
			s.groupsMap[sg.ID] = group
		}

		if !serviceGroup.viewData.Expanded {
			// If the service group is not expanded then return this as both the group and the endpoint.
			return
		}

		// If there is a service we will need to add that node and the service port. We return the service port ID since
		// this is an ingress point.
		if svc != nil {
			// Note that the service port hierarchy at this point is the same as the endpoint port hierarchy - so take
			// a copy.
			servicePortNodes = append([]*trackedNode(nil), endpointPortNodes...)
			serviceId := idi.GetServiceID()
			var service *trackedNode
			if service = s.nodesMap[serviceId]; service == nil {
				sel := s.selh.GetServiceNodeSelectors(svc.NamespacedName)
				viewData := s.view.NodeViewData[serviceId]
				parent := getServiceParent()
				// For now, service is not expandable.
				service = &trackedNode{
					graphNode: v1.GraphNode{
						Type:       v1.GraphNodeTypeService,
						ID:         serviceId,
						ParentID:   parent.id(),
						Namespace:  svc.Namespace,
						Name:       svc.Name,
						Expandable: false, // true,
						Expanded:   false, // serviceExpanded,
					},
					parent:    parent,
					selectors: sel,
					viewData:  viewData,
				}
				s.nodesMap[serviceId] = service
				group.addChild(service)
			}
			servicePortNodes = append(servicePortNodes, service)

			// Include the port if known and we are either auto-expanding or the service has been expanded.
			servicePortId := idi.GetServicePortID()
			var servicePortNode *trackedNode
			if servicePortId != "" && s.view.ExpandPorts {
				if servicePortNode = s.nodesMap[servicePortId]; servicePortNode == nil {
					sel := s.selh.GetServicePortNodeSelectors(*svc)
					viewData := s.view.NodeViewData[servicePortId]
					parent := getServiceParent()
					servicePortNode = &trackedNode{
						graphNode: v1.GraphNode{
							Type:     v1.GraphNodeTypeServicePort,
							ID:       servicePortId,
							ParentID: parent.id(),
							Name:     svc.PortName,
							Port:     svc.Port,
							Protocol: svc.Protocol,
						},
						parent:    parent,
						selectors: sel,
						viewData:  viewData,
					}
					s.nodesMap[servicePortId] = servicePortNode
					group.addChild(servicePortNode)
				}
				servicePortNodes = append(servicePortNodes, servicePortNode)
			}
		}
	}

	// Combine the aggregated endpoint node - this should always be available for a flow.
	var aggrEndpoint *trackedNode
	if aggrEndpoint = s.nodesMap[aggrEndpointId]; aggrEndpoint == nil {
		epType := idi.GetAggrEndpointType()
		sel := s.selh.GetEndpointNodeSelectors(
			epType,
			endpoint.Namespace,
			endpoint.Name,
			endpoint.NameAggr,
			NoProto,
			NoPort, idi.Direction,
		)
		viewData := s.view.NodeViewData[aggrEndpointId]
		parent := getEndpointParent()
		expandable := nonAggrEndpointId != ""
		retainEdges := shouldRetainEdges(epType)
		aggrEndpoint = &trackedNode{
			graphNode: v1.GraphNode{
				Type:       epType,
				ID:         aggrEndpointId,
				ParentID:   parent.id(),
				Namespace:  endpoint.Namespace,
				Name:       idi.GetAggrEndpointName(),
				Expandable: expandable,
				Expanded:   expandable && viewData.Expanded,
			},
			parent:      parent,
			selectors:   sel,
			viewData:    viewData,
			retainEdges: retainEdges,
		}
		s.nodesMap[aggrEndpointId] = aggrEndpoint
	}
	endpointPortNodes = append(endpointPortNodes, aggrEndpoint)

	if group == nil {
		// There is no outer group for this aggregated endpoint, so the aggregated endpoint is also the group.
		if group = s.groupsMap[aggrEndpointId]; group == nil {
			group = newTrackedGroup(endpointPortNodes)
			s.groupsMap[aggrEndpointId] = group
		}
	} else {
		// There is an outer group for this aggregated endpoint, so add this endpoint to the group.
		group.addChild(aggrEndpoint)
	}

	// If the endpoint is not expanded then add the port if present.
	if !aggrEndpoint.graphNode.Expanded {
		log.Debugf("Group is not expanded or not expandable: %s; %s, %s", group.node.graphNode.ID, aggrEndpointId, nonAggrEndpointId)

		if s.view.ExpandPorts {
			if aggrEndpointPortId := idi.GetAggrEndpointPortID(); aggrEndpointPortId != "" {
				var aggrEndpointPort *trackedNode
				if aggrEndpointPort = s.nodesMap[aggrEndpointPortId]; aggrEndpointPort == nil {
					sel := s.selh.GetEndpointNodeSelectors(
						idi.GetAggrEndpointType(),
						endpoint.Namespace,
						endpoint.Name,
						endpoint.NameAggr,
						endpoint.Protocol,
						endpoint.PortNum,
						idi.Direction,
					)
					viewData := s.view.NodeViewData[aggrEndpointPortId]
					parent := getEndpointParent()
					aggrEndpointPort = &trackedNode{
						graphNode: v1.GraphNode{
							Type:     v1.GraphNodeTypePort,
							ID:       aggrEndpointPortId,
							ParentID: parent.id(),
							Port:     endpoint.PortNum,
							Protocol: endpoint.Protocol,
						},
						parent:    parent,
						selectors: sel,
						viewData:  viewData,
					}
					s.nodesMap[aggrEndpointPortId] = aggrEndpointPort
					group.addChild(aggrEndpointPort)
				}
				endpointPortNodes = append(endpointPortNodes, aggrEndpointPort)
				return
			}
		}
		return
	}

	// The endpoint is expanded and expandable.
	var nonAggrEndpoint *trackedNode
	if nonAggrEndpoint = s.nodesMap[nonAggrEndpointId]; nonAggrEndpoint == nil {
		sel := s.selh.GetEndpointNodeSelectors(
			idi.Endpoint.Type,
			endpoint.Namespace,
			endpoint.Name,
			endpoint.NameAggr,
			NoProto,
			NoPort,
			idi.Direction,
		)
		viewData := s.view.NodeViewData[nonAggrEndpointId]
		parent := getEndpointParent()
		nonAggrEndpoint = &trackedNode{
			graphNode: v1.GraphNode{
				Type:      idi.Endpoint.Type,
				ID:        nonAggrEndpointId,
				ParentID:  parent.id(),
				Namespace: endpoint.Namespace,
				Name:      endpoint.Name,
			},
			parent:    parent,
			selectors: sel,
			viewData:  viewData,
		}
		s.nodesMap[nonAggrEndpointId] = nonAggrEndpoint
		group.addChild(nonAggrEndpoint)
	}
	endpointPortNodes = append(endpointPortNodes, nonAggrEndpoint)

	if s.view.ExpandPorts {
		if nonAggrEndpointPortId := idi.GetEndpointPortID(); nonAggrEndpointPortId != "" {
			var nonAggrEndpointPort *trackedNode
			if nonAggrEndpointPort = s.nodesMap[nonAggrEndpointId]; nonAggrEndpointPort == nil {
				sel := s.selh.GetEndpointNodeSelectors(
					idi.Endpoint.Type,
					endpoint.Namespace,
					endpoint.Name,
					endpoint.NameAggr,
					endpoint.Protocol,
					endpoint.PortNum,
					idi.Direction,
				)
				viewData := s.view.NodeViewData[nonAggrEndpointPortId]
				parent := getEndpointParent()
				nonAggrEndpointPort = &trackedNode{
					graphNode: v1.GraphNode{
						Type:     v1.GraphNodeTypePort,
						ID:       nonAggrEndpointPortId,
						ParentID: parent.id(),
						Port:     endpoint.PortNum,
						Protocol: endpoint.Protocol,
					},
					parent:    parent,
					selectors: sel,
					viewData:  viewData,
				}
				s.nodesMap[nonAggrEndpointPortId] = nonAggrEndpointPort
				group.addChild(nonAggrEndpointPort)
			}
			endpointPortNodes = append(endpointPortNodes, nonAggrEndpointPort)

			return
		}
	}

	return
}

// getNodeInView determines which nodes are in view. This returns the set of trackedNodes that are in view, and the
// set of parent nodes that are expanded and associated with the in-view children.
//
// This is then used to select the final set of nodes and edges for the service graph.
func (s *serviceGraphConstructionData) prune() {
	// Special case when focus is empty - this indicates full view when everything is visible.
	if s.view.EmptyFocus {
		log.Debug("No view selected - include all nodes and edges")
		return
	}

	// Keep expanding until we have processed all groups that are in-view.  There are three parts to this expansion:
	// - Expand the in-focus nodes in both directions
	// - If connection direction is being following, carry on expanding ingress and egress directions outwards from
	//   in-focus nodes
	// - If a node connection is being explicitly followed, keep expanding until all expansion points are exhausted.

	log.Debug("Expanding nodes explicitly in view")
	groupsInView := make(map[*trackedGroup]struct{})
	expandIngress := make(map[*trackedGroup]struct{})
	expandEgress := make(map[*trackedGroup]struct{})
	expandFollowing := make(map[*trackedGroup]struct{})
	for id, gp := range s.groupsMap {
		if gp.viewData.InFocus {
			log.Debugf("Expand ingress and egress for in-focus node: %s", id)
			groupsInView[gp] = struct{}{}
			expandIngress[gp] = struct{}{}
			expandEgress[gp] = struct{}{}
		}
	}

	// Expand in-Focus nodes in ingress Direction and possibly follow connection direction.
	for len(expandIngress) > 0 {
		for gp := range expandIngress {
			if gp.processedIngress {
				delete(expandIngress, gp)
				continue
			}

			// Add ingress nodes for this group.
			gp.processedIngress = true
			for connectedGp := range gp.ingress {
				log.Debugf("Including ingress expanded group: %s -> %s", connectedGp.node.graphNode.ID, gp.node.graphNode.ID)
				groupsInView[connectedGp] = struct{}{}
				if s.view.FollowConnectionDirection {
					expandIngress[connectedGp] = struct{}{}
					gp.followedIngress = true
				} else if connectedGp.viewData.FollowedEgress || connectedGp.viewData.FollowedIngress {
					log.Debugf("Following ingress and/or egress direction from: %s", connectedGp.node.graphNode.ID)
					expandFollowing[connectedGp] = struct{}{}
				}
			}

			delete(expandIngress, gp)
		}
	}

	// Expand in-Focus nodes in ingress Direction and possibly follow connection direction.
	for len(expandEgress) > 0 {
		for gp := range expandEgress {
			if gp.processedEgress {
				delete(expandEgress, gp)
				continue
			}

			// Add egress nodes for this group.
			gp.processedEgress = true
			for connectedGp := range gp.egress {
				log.Debugf("Including egress expanded group: %s -> %s", gp.node.graphNode.ID, connectedGp.node.graphNode.ID)
				groupsInView[connectedGp] = struct{}{}

				if s.view.FollowConnectionDirection {
					expandEgress[connectedGp] = struct{}{}
					gp.followedEgress = true
				} else if connectedGp.viewData.FollowedEgress || connectedGp.viewData.FollowedIngress {
					log.Debugf("Following ingress and/or egress direction from: %s", connectedGp.node.graphNode.ID)
					expandFollowing[connectedGp] = struct{}{}
				}
			}

			delete(expandEgress, gp)
		}
	}

	// Expand followed nodes.
	for len(expandFollowing) > 0 {
		for gp := range expandFollowing {
			if gp.viewData.FollowedIngress && !gp.processedIngress {
				gp.processedIngress = true
				gp.followedIngress = true
				for followedGp := range gp.ingress {
					log.Debugf("Following ingress from %s to %s", gp.node.graphNode.ID, followedGp.node.graphNode.ID)
					groupsInView[followedGp] = struct{}{}
					expandFollowing[followedGp] = struct{}{}
				}
			}
			if gp.viewData.FollowedEgress && !gp.processedEgress {
				gp.processedEgress = true
				gp.followedEgress = true
				for followedGp := range gp.egress {
					log.Debugf("Following egress from %s to %s", gp.node.graphNode.ID, followedGp.node.graphNode.ID)
					groupsInView[followedGp] = struct{}{}
					expandFollowing[followedGp] = struct{}{}
				}
			}

			delete(expandFollowing, gp)
		}
	}

	// Create the full set of nodes that are in view and create a filtered groups map.
	nodes := make(map[v1.GraphNodeID]*trackedNode)
	groups := make(map[v1.GraphNodeID]*trackedGroup)
	for gp := range groupsInView {
		nodes[gp.node.graphNode.ID] = gp.node
		for _, child := range gp.children {
			nodes[child.graphNode.ID] = child
		}
		for _, parent := range gp.parents {
			nodes[parent.graphNode.ID] = parent
		}
		groups[gp.node.graphNode.ID] = gp
	}

	// Determine which edges to include.
	edges := make(map[v1.GraphEdgeID]*v1.GraphEdge)
	if len(nodes) > 0 {
		// Copy across edges that are in view, and add the nodes to indicate whether we are truncating the graph (i.e.
		// that the graph can be followed along it's ingress or egress connections).
		for id, edge := range s.edgesMap {
			source := nodes[id.SourceNodeID]
			dest := nodes[id.DestNodeID]
			if source != nil && dest != nil {
				// Source and dest are visible, so include the edge.
				edges[id] = edge
			} else if source != nil {
				// Destination is not in view, but this means the egress can be Expanded for the source node. Mark this
				// on the group rather than the endpoint.
				source.graphNode.FollowEgress = true
			} else if dest != nil {
				// Source is not in view, but this means the ingress can be Expanded for the dest node. Mark this
				// on the group rather than the endpoint.
				dest.graphNode.FollowIngress = true
			}
		}
	}

	// Store the updated nodes, edges and groups maps.
	s.groupsMap = groups
	s.nodesMap = nodes
	s.edgesMap = edges
}

// overlayEvents iterates through all the events and overlays them on the existing graph nodes. This never adds more
// nodes to the graph.
func (s *serviceGraphConstructionData) overlayEvents() {
	if len(s.nodesMap) == 0 {
		return
	}

	eventNodes := make(map[*trackedNode]struct{})

	for _, event := range s.sgd.Events {
		log.Debugf("Checking event %#v", event)
		for _, ep := range event.Endpoints {
			log.Debugf("  - Checking event endpoint: %#v", ep)
			var node *trackedNode
			switch ep.Type {
			case v1.GraphNodeTypeService:
				fep := FlowEndpoint{
					Type:      ep.Type,
					Namespace: ep.Namespace,
				}
				sg := s.sgd.ServiceGroups.GetByService(v1.NamespacedName{
					Namespace: ep.Namespace, Name: ep.Name,
				})
				if node = s.getMostGranularNodeInView(s.nodesMap, fep, sg); node != nil {
					node.graphNode.EventsCount += 1
					eventNodes[node] = struct{}{}
				}
			default:
				sg := s.sgd.ServiceGroups.GetByEndpoint(ep)
				if node = s.getMostGranularNodeInView(s.nodesMap, ep, sg); node != nil {
					node.graphNode.EventsCount += 1
					eventNodes[node] = struct{}{}
				}
			}
		}
	}
}

// overlayDNS iterates through all the DNS logs and overlays them on the existing graph nodes. The stats are added
// to the endpoint and all parent nodes in the hierarchy.
func (s *serviceGraphConstructionData) overlayDNS() {
	if len(s.nodesMap) == 0 {
		return
	}

	for _, dl := range s.sgd.FilteredDNSClientLogs {
		log.Debugf("Checking DNS log for endpoint %#v", dl.Endpoint)
		sg := s.sgd.ServiceGroups.GetByEndpoint(dl.Endpoint)

		for node := s.getMostGranularNodeInView(s.nodesMap, dl.Endpoint, sg); node != nil; node = node.parent {
			node.graphNode.IncludeStatsWithin(dl.Stats)
		}
	}
}

// getMostGranularNodeInView returns the most granular node that is in view for a given endpoint.
//
// Note: This duplicates a lot of the processing in trackNodes, so we might want to think about just using that
//
//	to locate the nodes. This processing is, however, a little more lightweight since it only needs to
//	consider nodes that already exist - and can just track the most granular node visible rather than involved
//	in the node expansion processing.
func (s *serviceGraphConstructionData) getMostGranularNodeInView(
	nodesInView map[v1.GraphNodeID]*trackedNode, ep FlowEndpoint, sg *ServiceGroup,
) *trackedNode {
	idi := IDInfo{
		Endpoint:     ep,
		ServiceGroup: sg,
		Direction:    "",
	}

	// Start with the most granular up to service group.
	// The non-aggregated endpoint.
	nonAggrEndpointId := idi.GetEndpointID()
	if nonAggrEndpointId != "" {
		log.Debugf("Checking if endpoint exists: %s", nonAggrEndpointId)
		if nonAggrEndpoint := nodesInView[nonAggrEndpointId]; nonAggrEndpoint != nil {
			log.Debug("Endpoint exists")
			return nonAggrEndpoint
		}
	}

	// Aggregated endpoint.
	aggrEndpointId := idi.GetAggrEndpointID()
	if aggrEndpointId != "" {
		log.Debugf("Checking if aggr endpoint exists: %s", aggrEndpointId)
		if aggrEndpoint := nodesInView[aggrEndpointId]; aggrEndpoint != nil {
			log.Debug("Aggr endpoint exists")
			return aggrEndpoint
		}
	}

	// Service group.
	if sg != nil {
		log.Debugf("Checking if service group exists: %s", sg.ID)
		if serviceGroup := nodesInView[sg.ID]; serviceGroup != nil {
			log.Debug("Service Group exists")
			return serviceGroup
		}
	}

	// Check layer first - if the endpoint or service group are part of a layer then check if the layer is in view.
	if idi.Layer != "" && nonAggrEndpointId != "" {
		if idi.Layer = s.view.Layers.EndpointToLayer[nonAggrEndpointId]; idi.Layer != "" {
			return nodesInView[idi.GetLayerID()]
		}
	}
	if idi.Layer != "" && aggrEndpointId != "" {
		if idi.Layer = s.view.Layers.EndpointToLayer[aggrEndpointId]; idi.Layer != "" {
			return nodesInView[idi.GetLayerID()]
		}
	}
	if idi.Layer != "" && sg != nil {
		if idi.Layer = s.view.Layers.ServiceGroupToLayer[sg]; idi.Layer != "" {
			return nodesInView[idi.GetLayerID()]
		}
	}

	// Now finally, check if the namespace is in view, and if not in view whether the namespace is part of a layer.
	groupNamespace := idi.GetEffectiveNamespace()
	if groupNamespace == "" {
		return nil
	}

	namespaceId := idi.GetNamespaceID()
	if namespace := nodesInView[namespaceId]; namespace != nil {
		log.Debug("Namespace exists")
		return namespace
	}

	if idi.Layer = s.view.Layers.NamespaceToLayer[groupNamespace]; idi.Layer == "" {
		return nil
	}

	return nodesInView[idi.GetLayerID()]
}

func (s *serviceGraphConstructionData) overlaySelectors() {
	// Overlay the graph node selectors.
	var viewEventsSelector *GraphSelectorConstructor
	for _, node := range s.nodesMap {
		node.graphNode.Selectors = node.selectors.ToNodeSelectors().ToGraphSelectors()

		switch node.graphNode.Type {
		case v1.GraphNodeTypeNamespace:
			node.graphNode.Selectors.PacketCapture = &K8SAllSelector
		case v1.GraphNodeTypeService:
			var svcName = v1.NamespacedName{Namespace: node.graphNode.Namespace, Name: node.graphNode.Name}
			var selector = strings.Join(s.sgd.ServiceLabels[svcName], " && ")
			if len(selector) != 0 {
				node.graphNode.Selectors.PacketCapture = &selector
			}
		case v1.GraphNodeTypeServiceGroup:
			var svcgSelectors = s.serviceGroupSelectors(node.services())
			if len(svcgSelectors) != 0 {
				node.graphNode.Selectors.PacketCapture = &svcgSelectors
			}
		case v1.GraphNodeTypeReplicaSet:
			var rsName = v1.NamespacedName{Namespace: node.graphNode.Namespace,
				Name: strings.TrimSuffix(node.graphNode.Name, "-*")}
			var selector = strings.Join(s.sgd.ResourceLabels[rsName], " && ")
			if len(selector) != 0 {
				node.graphNode.Selectors.PacketCapture = &selector
			}
		}

		// Alerts selection is handled slightly differently for the view - we just combine all of the selectors.
		if node.selectors.Source.Alerts != nil {
			viewEventsSelector = NewGraphSelectorConstructor(v1.OpOr, viewEventsSelector, node.selectors.Source.Alerts)
		}
	}

	// Overlay the edge selectors.
	for id, edge := range s.edgesMap {
		src := s.nodesMap[id.SourceNodeID]
		dest := s.nodesMap[id.DestNodeID]

		if serviceEdges := s.serviceEdges[src]; serviceEdges != nil {
			// The source is a service. Include all of the possible source endpoints for the destination.
			sourceEdgeSelector := GraphSelectorsConstructor{}
			for srcEp := range serviceEdges.sourceNodesByDestNode[dest] {
				sourceEdgeSelector = sourceEdgeSelector.Or(srcEp.selectors.Source)
			}
			edge.Selectors = sourceEdgeSelector.And(dest.selectors.Dest).ToGraphSelectors()
		} else if serviceEdges := s.serviceEdges[dest]; serviceEdges != nil {
			// The dest is a service. Include all of the possible destination endpoints for the source.
			destEdgeSelector := GraphSelectorsConstructor{}

			for dstEp := range serviceEdges.destNodesBySourceNode[src] {
				destEdgeSelector = destEdgeSelector.Or(dstEp.selectors.Dest)
			}
			edge.Selectors = src.selectors.Source.And(destEdgeSelector).ToGraphSelectors()
		} else {
			// The edge does not involve a service port so just AND the source and dest selectors.
			edge.Selectors = src.selectors.Source.And(dest.selectors.Dest).ToGraphSelectors()
		}
	}

	// The view selectors are the ORed set of focus and followed node selectors, plus the nodes that were followed
	// implicitly by FollowConnectionDirection setting.
	if s.view.EmptyFocus {
		all := ""
		s.viewSelectors = v1.GraphSelectors{
			L3Flows: &all,
			L7Flows: &all,
			DNSLogs: &all,
			Alerts:  &all,
		}
	} else {
		viewSelectors := GraphSelectorsConstructor{}
		for id, nodeViewData := range s.view.NodeViewData {
			node := s.nodesMap[id]
			if node == nil {
				continue
			}
			if nodeViewData.InFocus {
				// The node is in-focus, so OR the main selector with this node selector (we calculated this above).
				viewSelectors = viewSelectors.Or(node.selectors.ToNodeSelectors())
			} else {
				// The node may not be in focus, but we may be following the ingress or egress connections from this node.
				if nodeViewData.FollowedEgress {
					viewSelectors = viewSelectors.Or(node.selectors.Source)
				}
				if nodeViewData.FollowedIngress {
					viewSelectors = viewSelectors.Or(node.selectors.Dest)
				}
			}
		}
		for _, group := range s.groupsMap {
			if group.viewData.InFocus {
				// Skip over groups that are explicitly in focus as these will be covered by the view focus.
				continue
			}
			if group.followedEgress && !group.viewData.FollowedEgress {
				// We followed the egress for this group, and it was not an explicit request - so must be part of the
				// connection direction following. Include this group in the selectors.
				viewSelectors = viewSelectors.Or(group.node.selectors.Source)
			}
			if group.followedIngress && !group.viewData.FollowedIngress {
				// We followed the ingress for this group, and it was not an explicit request - so must be part of the
				// connection direction following. Include this group in the selectors.
				viewSelectors = viewSelectors.Or(group.node.selectors.Dest)
			}
		}

		s.viewSelectors = viewSelectors.ToGraphSelectors()

		// Handle alerts by simply having the full set of IDs in the view.
		s.viewSelectors.Alerts = viewEventsSelector.SelectorString()
	}
}

func (s *serviceGraphConstructionData) serviceGroupSelectors(services []v1.NamespacedName) string {
	var selectors []string
	for _, svc := range services {
		var labelsSel = strings.Join(s.sgd.ServiceLabels[svc], " && ")
		if len(labelsSel) != 0 {
			selectors = append(selectors, labelsSel)
		}
	}
	sort.Strings(selectors)

	return strings.Join(selectors, " || ")
}

func (s *serviceGraphConstructionData) getResponse() *v1.ServiceGraphResponse {
	sgr := &v1.ServiceGraphResponse{
		// Response should include the time range actually used to perform these queries.
		TimeIntervals: s.sgd.TimeIntervals,
		Selectors:     s.viewSelectors,
		Truncated:     s.sgd.Truncated,
	}
	for _, node := range s.nodesMap {
		sgr.Nodes = append(sgr.Nodes, node.graphNode)
	}
	for _, edge := range s.edgesMap {
		sgr.Edges = append(sgr.Edges, *edge)
	}

	// Trace out the nodes and edges if the log level is debug.
	if log.IsLevelEnabled(log.DebugLevel) {
		for _, node := range sgr.Nodes {
			log.Debugf("%v", node)
		}
		for _, edge := range sgr.Edges {
			log.Debugf("%v", edge)
		}
	}

	return sgr
}
