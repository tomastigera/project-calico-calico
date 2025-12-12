// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package servicegraph

import (
	"fmt"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
)

const (
	maxSelectorItemsPerGroup = 50
)

// GraphSelectorsConstructor provides selectors used to asynchronously perform associated queries for an edge or a node.
// These selectors are used in the other raw and service graph APIs to look update additional data for an edge or a
// node. The format of these selectors is the Kibana-style selector.  For example,
//
//	source_namespace == "namespace1 || (dest_type == "wep" && dest_namespace == "namespace2")
//
// The JSON formatted output of this is actually a simple set of selector strings for each search option:
//
//	{
//	  "l3_flows": "xx = 'y'",
//	  "l7_flows": "xx = 'y'",
//	  "dns_logs": "xx = 'y'"
//	  "alerts": "_id = 'abcdef'"
//	}
type GraphSelectorsConstructor struct {
	L3Flows *GraphSelectorConstructor
	L7Flows *GraphSelectorConstructor
	DNSLogs *GraphSelectorConstructor
	Alerts  *GraphSelectorConstructor
}

// And combines two sets of selectors by ANDing them together.
func (s GraphSelectorsConstructor) And(s2 GraphSelectorsConstructor) GraphSelectorsConstructor {
	return GraphSelectorsConstructor{
		L3Flows: NewGraphSelectorConstructor(v1.OpAnd, s.L3Flows, s2.L3Flows),
		L7Flows: NewGraphSelectorConstructor(v1.OpAnd, s.L7Flows, s2.L7Flows),
		DNSLogs: NewGraphSelectorConstructor(v1.OpAnd, s.DNSLogs, s2.DNSLogs),
		Alerts:  NewGraphSelectorConstructor(v1.OpAnd, s.Alerts, s2.Alerts),
	}
}

// Or combines two sets of selectors by ORing them together.
func (s GraphSelectorsConstructor) Or(s2 GraphSelectorsConstructor) GraphSelectorsConstructor {
	return GraphSelectorsConstructor{
		L3Flows: NewGraphSelectorConstructor(v1.OpOr, s.L3Flows, s2.L3Flows),
		L7Flows: NewGraphSelectorConstructor(v1.OpOr, s.L7Flows, s2.L7Flows),
		DNSLogs: NewGraphSelectorConstructor(v1.OpOr, s.DNSLogs, s2.DNSLogs),
		Alerts:  NewGraphSelectorConstructor(v1.OpOr, s.Alerts, s2.Alerts),
	}
}

// ToGraphSelectors creates the v1.GraphSelector format.
func (s GraphSelectorsConstructor) ToGraphSelectors() v1.GraphSelectors {
	return v1.GraphSelectors{
		L3Flows: s.L3Flows.SelectorString(),
		L7Flows: s.L7Flows.SelectorString(),
		DNSLogs: s.DNSLogs.SelectorString(),
		Alerts:  s.Alerts.SelectorString(),
	}
}

type GraphSelectorConstructor struct {
	operator v1.GraphSelectorOperator

	// Valid if operator is && or ||
	selectors []*GraphSelectorConstructor

	// Valid if operator is ==, != or IN.  Value is an interface to allow string, numerical and slice values.
	key   string
	value interface{}
}

func (s *GraphSelectorConstructor) SelectorString() *string {
	// Note that only the outer-most selector can have an operator of "no-match" since combining selectors will always
	// swallow any no-match in the parts and propagate to the outermost selector.
	if s == nil || s.operator == v1.OpNoMatch {
		return nil
	}
	ss := s.selectorString(false)
	return &ss
}

func (s *GraphSelectorConstructor) selectorString(nested bool) string {
	sb := strings.Builder{}
	writeKey := func(key string) {
		// The key needs to be quoted if it contains a "."
		if strings.Contains(key, ".") {
			sb.WriteString("\"")
			sb.WriteString(s.key)
			sb.WriteString("\"")
		} else {
			sb.WriteString(s.key)
		}
	}
	switch s.operator {
	case v1.OpAnd, v1.OpOr:
		parts := make(map[string]struct{})
		var ordered []string
		for i := 0; i < len(s.selectors); i++ {
			ss := s.selectors[i].selectorString(true)
			if _, ok := parts[ss]; !ok {
				// Don't include duplicate parts.
				parts[ss] = struct{}{}
				ordered = append(ordered, ss)
			}
		}
		sort.Strings(ordered)
		switch {
		case len(ordered) == 0:
			// Nothing to write when there are no entries.
		case len(ordered) == 1:
			// No additional parens required if there is only one part.
			sb.WriteString(ordered[0])
		default:
			if nested {
				sb.WriteString("(")
			}
			for i := 0; i < len(ordered)-1; i++ {
				sb.WriteString(ordered[i])
				sb.WriteString(string(s.operator))
			}
			sb.WriteString(ordered[len(ordered)-1])
			if nested {
				sb.WriteString(")")
			}
		}
	case v1.OpEqual, v1.OpNotEqual:
		writeKey(s.key)
		sb.WriteString(string(s.operator))
		if _, ok := s.value.(string); ok {
			sb.WriteString(fmt.Sprintf("\"%s\"", s.value))
		} else {
			sb.WriteString(fmt.Sprintf("%v", s.value))
		}
	case v1.OpIn:
		if nested {
			sb.WriteString("(")
		}
		value := s.value.([]string)
		writeKey(s.key)
		sb.WriteString(string(v1.OpEqual))
		sb.WriteString("\"")
		sb.WriteString(value[0])
		sb.WriteString("\"")
		for i := 1; i < len(value); i++ {
			sb.WriteString(string(v1.OpOr))
			sb.WriteString(s.key)
			sb.WriteString(string(v1.OpEqual))
			sb.WriteString("\"")
			sb.WriteString(value[i])
			sb.WriteString("\"")
		}
		if nested {
			sb.WriteString(")")
		}
		/*
			sb.WriteString(s.key)
			sb.WriteString(string(s.operator))
			sb.WriteString(v1.OpInListStart)
			sb.WriteString("\"")
			value := s.value.([]string)
			for i := 0; i < len(value)-1; i++ {
				sb.WriteString(value[i])
				sb.WriteString("\"")
				sb.WriteString(v1.OpInListSep)
				sb.WriteString("\"")
			}
			sb.WriteString(value[len(value)-1])
			sb.WriteString("\"")
			sb.WriteString(v1.OpInListEnd)
		*/
	case v1.OpNoMatch:
		log.Panic("Should not convert no match to string")
	}
	return sb.String()
}

func NewGraphSelectorConstructor(op v1.GraphSelectorOperator, parts ...interface{}) *GraphSelectorConstructor {
	gs := &GraphSelectorConstructor{
		operator: op,
	}
	switch op {
	case v1.OpNoMatch:
		// Nothing to extract for the no-match operator.
	case v1.OpAnd, v1.OpOr:
		// Minor finesse: if any parts are IN operators acting on the same parameter then we can combine these.
		var updated []*GraphSelectorConstructor
		var foundNoMatch bool
		inOpsByParm := make(map[string]*GraphSelectorConstructor)
		for _, part := range parts {
			egs, ok := part.(*GraphSelectorConstructor)
			if egs == nil || !ok {
				continue
			}
			if egs.operator == v1.OpNoMatch {
				if op == v1.OpAnd {
					// This is an AND operator and one of the matches is a no-match - therefore the whole selector
					// is a no match.
					return egs
				}

				// This must be an OR - if all parts are no matches then the whole selector will be a no match.
				foundNoMatch = true
				continue
			} else if egs.operator != v1.OpIn {
				updated = append(updated, egs)
				continue
			}
			inOpsByParm[egs.key] = combineInSelectors(op, inOpsByParm[egs.key], egs)
		}
		for _, sel := range inOpsByParm {
			updated = append(updated, sel)
		}

		if foundNoMatch && len(updated) == 0 {
			// All of the parts were no-matches, so the entire selector is a no match.
			return NewGraphSelectorConstructor(v1.OpNoMatch)
		}

		for _, egs := range updated {
			if egs.operator == op {
				// If same operand, then expand into this selector to reduce nesting.
				gs.selectors = append(gs.selectors, egs.selectors...)
			} else {
				gs.selectors = append(gs.selectors, egs)
			}
		}

		// Special case if we have zero or 1 expressions.
		if len(gs.selectors) == 0 {
			return nil
		} else if len(gs.selectors) == 1 {
			return gs.selectors[0]
		}
	case v1.OpEqual, v1.OpNotEqual:
		gs.key = parts[0].(string)
		gs.value = parts[1]
	case v1.OpIn:
		gs.key = parts[0].(string)

		// At the moment, the only time we use OpIn is for a slice of strings. This may change in the future, but
		// no point handling other types just yet.
		value := parts[1].([]string)
		if len(value) == 0 {
			gs.operator = v1.OpNoMatch
		}
		gs.value = value
	default:
		log.Errorf("Unexpected selector type: %s", op)
	}

	return gs
}

func combineInSelectors(op v1.GraphSelectorOperator, sel1, sel2 *GraphSelectorConstructor) *GraphSelectorConstructor {
	if sel1 == nil {
		return sel2
	} else if sel2 == nil {
		return sel1
	}

	if sel1.key != sel2.key || sel1.operator != v1.OpIn || sel2.operator != v1.OpIn {
		log.Panic("combineInSelectors called with non-matching selector types")
	}

	var vals1, vals2 set.Set[string]
	switch sel1.value.(type) {
	case string:
		vals1 = set.From[string](sel1.value.(string))
	case []string:
		vals1 = set.From[string](sel1.value.([]string)...)
	}

	switch sel2.value.(type) {
	case string:
		vals2 = set.From[string](sel2.value.(string))
	case []string:
		vals2 = set.From[string](sel2.value.([]string)...)
	}

	var combined []string
	switch op {
	case v1.OpAnd:
		// Only include values in both sel1 and sel2
		for item := range vals1.All() {
			if vals2.Contains(item) {
				combined = append(combined, item)
			}
		}
	case v1.OpOr:
		// Take a copy of the selector 2 values.
		combined = append([]string(nil), sel2.value.([]string)...)

		// Add any value from sel1 that was not in selector 2.
		for item := range vals1.All() {
			if !vals2.Contains(item) {
				combined = append(combined, item)
			}
		}
	}
	return NewGraphSelectorConstructor(v1.OpIn, sel1.key, combined)
}

// SelectorPairs contains source and dest pairs of graph node selectors.
// The source selector represents the selector used when an edge originates from that node.
// The dest selector represents the selector used when an edge terminates at that node.
//
// This is a convenience since most of the selectors can be split into source and dest related queries. It is not
// required for the API.
type SelectorPairs struct {
	Source GraphSelectorsConstructor
	Dest   GraphSelectorsConstructor
}

func (s SelectorPairs) ToNodeSelectors() GraphSelectorsConstructor {
	return s.Source.Or(s.Dest)
}

// And combines two sets of selectors by ANDing them together.
func (s SelectorPairs) And(s2 SelectorPairs) SelectorPairs {
	return SelectorPairs{
		Source: s.Source.And(s2.Source),
		Dest:   s.Dest.And(s2.Dest),
	}
}

// Or combines two sets of selectors by ORing them together.
func (s SelectorPairs) Or(s2 SelectorPairs) SelectorPairs {
	return SelectorPairs{
		Source: s.Source.Or(s2.Source),
		Dest:   s.Dest.Or(s2.Dest),
	}
}

func NewSelectorHelper(view *ParsedView, nameHelper NameHelper, sgs ServiceGroups) *SelectorHelper {
	return &SelectorHelper{
		view:          view,
		nameHelper:    nameHelper,
		serviceGroups: sgs,
	}
}

type SelectorHelper struct {
	view          *ParsedView
	nameHelper    NameHelper
	serviceGroups ServiceGroups
}

// GetLayerNodeSelectors returns the selectors for a layer node (as specified on the request).
func (s *SelectorHelper) GetLayerNodeSelectors(layer string) SelectorPairs {
	gs := SelectorPairs{}
	for _, n := range s.view.Layers.LayerToNamespaces[layer] {
		gs = gs.Or(s.GetNamespaceNodeSelectors(n))
	}
	for _, sg := range s.view.Layers.LayerToServiceGroups[layer] {
		gs = gs.Or(s.GetServiceGroupNodeSelectors(sg))
	}
	for _, ep := range s.view.Layers.LayerToEndpoints[layer] {
		gs = gs.Or(s.GetEndpointNodeSelectors(ep.Type, ep.Namespace, ep.Name, ep.NameAggr, ep.Protocol, ep.PortNum, NoDirection))
	}
	return gs
}

// GetNamespaceNodeSelectors returns the selectors for a namespace node.
// TODO(rlb): When multiple services are part of the same group, we'll include these in an aggregated namespaces group
//
//	which is not correctly handled below. However, you really have to go out of your way to have multiple
//	service namespaces in the same group, so ignoring this for now.
func (s *SelectorHelper) GetNamespaceNodeSelectors(namespace string) SelectorPairs {
	return SelectorPairs{
		Source: GraphSelectorsConstructor{
			L3Flows: NewGraphSelectorConstructor(v1.OpEqual, "source_namespace", namespace),
			L7Flows: NewGraphSelectorConstructor(v1.OpEqual, "src_namespace", namespace),
			DNSLogs: NewGraphSelectorConstructor(v1.OpEqual, "client_namespace", namespace),
			Alerts:  NewGraphSelectorConstructor(v1.OpEqual, "source_namespace", namespace),
		},
		Dest: GraphSelectorsConstructor{
			L3Flows: NewGraphSelectorConstructor(v1.OpOr,
				NewGraphSelectorConstructor(v1.OpEqual, "dest_service_namespace", namespace),
				NewGraphSelectorConstructor(v1.OpEqual, "dest_namespace", namespace),
			),
			L7Flows: NewGraphSelectorConstructor(v1.OpOr,
				NewGraphSelectorConstructor(v1.OpEqual, "dest_service_namespace", namespace),
				NewGraphSelectorConstructor(v1.OpEqual, "dest_namespace", namespace),
			),
			DNSLogs: NewGraphSelectorConstructor(v1.OpEqual, "servers.namespace", namespace),
			Alerts:  NewGraphSelectorConstructor(v1.OpEqual, "dest_namespace", namespace),
		},
	}
}

// GetServiceNodeSelectors returns the selectors for a service node.  Service nodes are not directly exposed in the
// API, this is just used for constructing service group selectors and does not need to contain DNS selectors as they
// are handled separately.
func (s *SelectorHelper) GetServiceNodeSelectors(svc v1.NamespacedName) SelectorPairs {
	// Start with the service selector.
	selectors := SelectorPairs{
		Source: GraphSelectorsConstructor{
			// L7 selectors for service are the same for source and dest since we always have the service when it is
			// available.
			L7Flows: NewGraphSelectorConstructor(v1.OpAnd,
				NewGraphSelectorConstructor(v1.OpEqual, "dest_service_namespace", svc.Namespace),
				NewGraphSelectorConstructor(v1.OpEqual, "dest_service_name", svc.Name),
			),
			Alerts: NewGraphSelectorConstructor(v1.OpAnd,
				NewGraphSelectorConstructor(v1.OpEqual, "source_namespace", svc.Namespace),
				NewGraphSelectorConstructor(v1.OpEqual, "source_name", svc.Name),
			),
		},
		Dest: GraphSelectorsConstructor{
			L3Flows: NewGraphSelectorConstructor(v1.OpAnd,
				NewGraphSelectorConstructor(v1.OpEqual, "dest_service_namespace", svc.Namespace),
				NewGraphSelectorConstructor(v1.OpEqual, "dest_service_name", svc.Name),
			),
			L7Flows: NewGraphSelectorConstructor(v1.OpAnd,
				NewGraphSelectorConstructor(v1.OpEqual, "dest_service_namespace", svc.Namespace),
				NewGraphSelectorConstructor(v1.OpEqual, "dest_service_name", svc.Name),
			),
			Alerts: NewGraphSelectorConstructor(v1.OpAnd,
				NewGraphSelectorConstructor(v1.OpEqual, "dest_namespace", svc.Namespace),
				NewGraphSelectorConstructor(v1.OpEqual, "dest_name", svc.Name),
			),
		},
	}

	// Also include the actual service endpoints in the destination selectors. Construct the ORed set of endpoints.
	var epsp SelectorPairs
	allEps := make(map[FlowEndpoint]struct{})
	sg := s.serviceGroups.GetByService(svc)
	if sg != nil {
		for _, spd := range sg.ServicePorts {
			for ep := range spd {
				switch ep.Type {
				case v1.GraphNodeTypeClusterNode, v1.GraphNodeTypeHost, v1.GraphNodeTypeWorkload,
					v1.GraphNodeTypeReplicaSet, v1.GraphNodeTypeNetworkSet:
					// for all the endpoints of type host, wep, rep, ns behind the service node add appropriate selector.
					allEps[ep] = struct{}{}
				default:
					// the types not handled in above are skipped from the service node selector
					log.Debugf(
						"type %v is not included in building service node selector.\nFull flow endpoint = %v",
						ep.Type, ep)
				}
			}
		}
	}
	for ep := range allEps {
		epsp = epsp.Or(s.GetEndpointNodeSelectors(ep.Type, ep.Namespace, ep.Name, ep.NameAggr, NoProto, ep.PortNum, NoDirection))
	}

	// Only include the endpoint dest selectors, not the source.
	selectors.Dest = selectors.Dest.Or(epsp.Dest)

	return selectors
}

// GetServicePortNodeSelectors returns the selectors for a service port node.
func (s *SelectorHelper) GetServicePortNodeSelectors(sp v1.ServicePort) SelectorPairs {
	selectors := SelectorPairs{
		Source: GraphSelectorsConstructor{
			// L7 selectors for service are the same for source and dest since we always have the service when it is
			// available.
			L7Flows: NewGraphSelectorConstructor(v1.OpAnd,
				NewGraphSelectorConstructor(v1.OpEqual, "dest_service_namespace", sp.Namespace),
				NewGraphSelectorConstructor(v1.OpEqual, "dest_service_name", sp.Name),
			),
			Alerts: NewGraphSelectorConstructor(v1.OpAnd,
				NewGraphSelectorConstructor(v1.OpEqual, "source_namespace", sp.Namespace),
				NewGraphSelectorConstructor(v1.OpEqual, "source_name", sp.Name),
			),
		},
		Dest: GraphSelectorsConstructor{
			L3Flows: NewGraphSelectorConstructor(v1.OpAnd,
				NewGraphSelectorConstructor(v1.OpEqual, "dest_service_namespace", sp.Namespace),
				NewGraphSelectorConstructor(v1.OpEqual, "dest_service_name", sp.Name),
			),
			L7Flows: NewGraphSelectorConstructor(v1.OpAnd,
				NewGraphSelectorConstructor(v1.OpEqual, "dest_service_namespace", sp.Namespace),
				NewGraphSelectorConstructor(v1.OpEqual, "dest_service_name", sp.Name),
			),
			Alerts: NewGraphSelectorConstructor(v1.OpAnd,
				NewGraphSelectorConstructor(v1.OpEqual, "dest_namespace", sp.Namespace),
				NewGraphSelectorConstructor(v1.OpEqual, "dest_name", sp.Name),
			),
		},
	}

	if sp.Protocol != "tcp" {
		// L7 flows are TCP only.
		selectors.Source.L7Flows = NewGraphSelectorConstructor(v1.OpNoMatch)
		selectors.Dest.L7Flows = NewGraphSelectorConstructor(v1.OpNoMatch)
	} else {
		selectors.Dest.L7Flows = NewGraphSelectorConstructor(v1.OpAnd,
			selectors.Dest.L7Flows,
			NewGraphSelectorConstructor(v1.OpEqual, "dest_service_port_name", sp.PortName),
			NewGraphSelectorConstructor(v1.OpEqual, "dest_service_port", sp.Port),
		)
	}

	selectors.Dest.L3Flows = NewGraphSelectorConstructor(v1.OpAnd,
		selectors.Dest.L3Flows,
		NewGraphSelectorConstructor(v1.OpEqual, "dest_service_port", sp.PortName),
		NewGraphSelectorConstructor(v1.OpEqual, "dest_service_port_num", sp.Port),
		NewGraphSelectorConstructor(v1.OpEqual, "proto", sp.Protocol),
	)

	// Also include the actual service endpoints in the destination selectors. Construct the ORed set of endpoints.
	var epsp SelectorPairs
	allEps := make(map[FlowEndpoint]struct{})
	sg := s.serviceGroups.GetByService(sp.NamespacedName)
	if sg != nil {
		for ep := range sg.ServicePorts[sp] {
			switch ep.Type {
			case v1.GraphNodeTypeClusterNode, v1.GraphNodeTypeHost, v1.GraphNodeTypeWorkload,
				v1.GraphNodeTypeReplicaSet, v1.GraphNodeTypeNetworkSet:
				// for all the endpoints of type host, wep, rep, ns behind the service port add appropriate selector.
				allEps[ep] = struct{}{}
			default:
				// the types not handled in above are skipped from the service port selector
				log.Debugf(
					"type %v is not included in building serviceport selector.\nFull flow endpoint = %v",
					ep.Type, ep)
			}
		}
	}
	for ep := range allEps {
		epsp = epsp.Or(s.GetEndpointNodeSelectors(ep.Type, ep.Namespace, ep.Name, ep.NameAggr, ep.Protocol, ep.PortNum, NoDirection))
	}

	// Only include the endpoint dest selectors, not the source.
	selectors.Dest = selectors.Dest.Or(epsp.Dest)

	return selectors
}

// GetServiceGroupNodeSelectors returns the selectors for a service group node.
func (s *SelectorHelper) GetServiceGroupNodeSelectors(sg *ServiceGroup) SelectorPairs {
	// Selectors depend on whether the service endpoints record the flow. If only the source records the flow then we
	// limit the search based on the service selectors.
	allSvcs := make(map[v1.NamespacedName]struct{})
	allEps := make(map[FlowEndpoint]struct{})

	for sp, eps := range sg.ServicePorts {
		for ep := range eps {
			switch ep.Type {
			case v1.GraphNodeTypeClusterNode, v1.GraphNodeTypeHost, v1.GraphNodeTypeWorkload,
				v1.GraphNodeTypeReplicaSet:
				// prepare an endpoint-style selector if endpoint type is host, wep, or rep
				allEps[ep] = struct{}{}
			default:
				// prepare a service-style selector if endpoint type is anything other than the types above including
				// but not limited to ns (networkset), svc (service), ...
				allSvcs[sp.NamespacedName] = struct{}{}
			}
		}
	}

	var gs SelectorPairs
	for svc := range allSvcs {
		gs = gs.Or(s.GetServiceNodeSelectors(svc))
	}
	for ep := range allEps {
		gs = gs.Or(s.GetEndpointNodeSelectors(ep.Type, ep.Namespace, ep.Name, ep.NameAggr, NoProto, ep.PortNum, NoDirection))
	}
	return gs
}

// GetEndpointNodeSelectors returns the selectors for an endpoint node.
func (s *SelectorHelper) GetEndpointNodeSelectors(
	epType v1.GraphNodeType, namespace, name, nameAggr, proto string, port int, dir Direction,
) SelectorPairs {
	rawType, isAgg := mapGraphNodeTypeToRawType(epType)
	namespace = blankToSingleDash(namespace)

	var l3Dest, l7Dest, l3Source, l7Source, dnsSource, dnsDest, alertSource, alertDest *GraphSelectorConstructor
	if rawType == "wep" {
		// DNS logs are only recorded for wep types.
		if isAgg {
			dnsSource = NewGraphSelectorConstructor(v1.OpAnd,
				NewGraphSelectorConstructor(v1.OpEqual, "client_namespace", namespace),
				NewGraphSelectorConstructor(v1.OpEqual, "client_name_aggr", nameAggr),
			)
			dnsDest = NewGraphSelectorConstructor(v1.OpAnd,
				NewGraphSelectorConstructor(v1.OpEqual, "servers.namespace", namespace),
				NewGraphSelectorConstructor(v1.OpEqual, "servers.name_aggr", nameAggr),
			)
		} else {
			dnsDest = NewGraphSelectorConstructor(v1.OpAnd,
				NewGraphSelectorConstructor(v1.OpEqual, "servers.namespace", namespace),
				NewGraphSelectorConstructor(v1.OpEqual, "servers.name", name),
			)
		}

		// Similarly, L7 logs are only recorded for wep types and also only with aggregated names. If the protocol is
		// known then only include for TCP.
		if isAgg && (proto == "" || proto == "tcp") {
			l7Source = NewGraphSelectorConstructor(v1.OpAnd,
				NewGraphSelectorConstructor(v1.OpEqual, "src_namespace", namespace),
				NewGraphSelectorConstructor(v1.OpEqual, "src_name_aggr", nameAggr),
			)
			l7Dest = NewGraphSelectorConstructor(v1.OpAnd,
				NewGraphSelectorConstructor(v1.OpEqual, "dest_namespace", namespace),
				NewGraphSelectorConstructor(v1.OpEqual, "dest_name_aggr", nameAggr),
			)
		} else {
			l7Source = NewGraphSelectorConstructor(v1.OpNoMatch)
			l7Dest = NewGraphSelectorConstructor(v1.OpNoMatch)
		}
	} else {
		l7Source = NewGraphSelectorConstructor(v1.OpNoMatch)
		l7Dest = NewGraphSelectorConstructor(v1.OpNoMatch)
		dnsSource = NewGraphSelectorConstructor(v1.OpNoMatch)
		dnsDest = NewGraphSelectorConstructor(v1.OpNoMatch)
	}

	if epType == v1.GraphNodeTypeClusterNodes || epType == v1.GraphNodeTypeHosts {
		// Handle hosts separately. We provide an internal aggregation for these types, so when constructing a selector
		// we have do do a rather brutal list of all host endpoints. We can at least skip namespace since hep types
		// are only non-namespaced.
		hosts := s.nameHelper.GetCompiledHostNamesFromAggregatedName(nameAggr)
		if len(hosts) == 0 || len(hosts) > maxSelectorItemsPerGroup {
			// No individual hosts, or too many individual items. Don't filter on the hosts.
			l3Source = NewGraphSelectorConstructor(v1.OpAnd,
				NewGraphSelectorConstructor(v1.OpEqual, "source_type", rawType),
			)
			l3Dest = NewGraphSelectorConstructor(v1.OpAnd,
				NewGraphSelectorConstructor(v1.OpEqual, "dest_type", rawType),
			)
		} else if len(hosts) == 1 {
			// Only one host, just use equals.
			l3Source = NewGraphSelectorConstructor(v1.OpAnd,
				NewGraphSelectorConstructor(v1.OpEqual, "source_type", rawType),
				NewGraphSelectorConstructor(v1.OpEqual, "source_name_aggr", hosts[0]),
			)
			l3Dest = NewGraphSelectorConstructor(v1.OpAnd,
				NewGraphSelectorConstructor(v1.OpEqual, "dest_type", rawType),
				NewGraphSelectorConstructor(v1.OpEqual, "dest_name_aggr", hosts[0]),
			)
		} else {
			// Multiple host names, use "in" operator.
			sort.Strings(hosts)
			l3Source = NewGraphSelectorConstructor(v1.OpAnd,
				NewGraphSelectorConstructor(v1.OpEqual, "source_type", rawType),
				NewGraphSelectorConstructor(v1.OpIn, "source_name_aggr", hosts),
			)
			l3Dest = NewGraphSelectorConstructor(v1.OpAnd,
				NewGraphSelectorConstructor(v1.OpEqual, "dest_type", rawType),
				NewGraphSelectorConstructor(v1.OpIn, "dest_name_aggr", hosts),
			)
		}
	} else if epType == v1.GraphNodeTypeClusterNode || epType == v1.GraphNodeTypeHost {
		// Handle host separately. We provide an internal aggregation for these types which means we copy
		// the aggregated name into the name and provide a calculated aggregated name.  Make sure we use the non
		// aggregated name but use the aggregated name field for the selector.
		l3Source = NewGraphSelectorConstructor(v1.OpAnd,
			NewGraphSelectorConstructor(v1.OpEqual, "source_type", rawType),
			NewGraphSelectorConstructor(v1.OpEqual, "source_name_aggr", name),
		)
		l3Dest = NewGraphSelectorConstructor(v1.OpAnd,
			NewGraphSelectorConstructor(v1.OpEqual, "dest_type", rawType),
			NewGraphSelectorConstructor(v1.OpEqual, "dest_name_aggr", name),
		)
	} else if isAgg {
		l3Source = NewGraphSelectorConstructor(v1.OpAnd,
			NewGraphSelectorConstructor(v1.OpEqual, "source_type", rawType),
			NewGraphSelectorConstructor(v1.OpEqual, "source_namespace", namespace),
			NewGraphSelectorConstructor(v1.OpEqual, "source_name_aggr", nameAggr),
		)
		l3Dest = NewGraphSelectorConstructor(v1.OpAnd,
			NewGraphSelectorConstructor(v1.OpEqual, "dest_type", rawType),
			NewGraphSelectorConstructor(v1.OpEqual, "dest_namespace", namespace),
			NewGraphSelectorConstructor(v1.OpEqual, "dest_name_aggr", nameAggr),
		)
		alertSource = NewGraphSelectorConstructor(v1.OpAnd,
			NewGraphSelectorConstructor(v1.OpEqual, "source_namespace", namespace),
			NewGraphSelectorConstructor(v1.OpEqual, "source_name_aggr", nameAggr),
		)
		alertDest = NewGraphSelectorConstructor(v1.OpAnd,
			NewGraphSelectorConstructor(v1.OpEqual, "dest_namespace", namespace),
			NewGraphSelectorConstructor(v1.OpEqual, "dest_name_aggr", nameAggr),
		)
	} else {
		l3Source = NewGraphSelectorConstructor(v1.OpAnd,
			NewGraphSelectorConstructor(v1.OpEqual, "source_type", rawType),
			NewGraphSelectorConstructor(v1.OpEqual, "source_namespace", namespace),
			NewGraphSelectorConstructor(v1.OpEqual, "source_name", nameAggr),
		)
		l3Dest = NewGraphSelectorConstructor(v1.OpAnd,
			NewGraphSelectorConstructor(v1.OpEqual, "dest_type", rawType),
			NewGraphSelectorConstructor(v1.OpEqual, "dest_namespace", namespace),
			NewGraphSelectorConstructor(v1.OpEqual, "dest_name", nameAggr),
		)
		alertSource = NewGraphSelectorConstructor(v1.OpAnd,
			NewGraphSelectorConstructor(v1.OpEqual, "source_namespace", namespace),
			NewGraphSelectorConstructor(v1.OpEqual, "source_name", nameAggr),
		)
		alertDest = NewGraphSelectorConstructor(v1.OpAnd,
			NewGraphSelectorConstructor(v1.OpEqual, "dest_namespace", namespace),
			NewGraphSelectorConstructor(v1.OpEqual, "dest_name", nameAggr),
		)
	}
	if port != 0 {
		l3Dest = NewGraphSelectorConstructor(v1.OpAnd,
			NewGraphSelectorConstructor(v1.OpEqual, "dest_port", port),
			l3Dest,
		)
	}
	if proto != NoProto {
		l3Source = NewGraphSelectorConstructor(v1.OpAnd,
			NewGraphSelectorConstructor(v1.OpEqual, "proto", proto),
			l3Source,
		)
		l3Dest = NewGraphSelectorConstructor(v1.OpAnd,
			NewGraphSelectorConstructor(v1.OpEqual, "proto", proto),
			l3Dest,
		)
	}

	gsp := SelectorPairs{
		Source: GraphSelectorsConstructor{},
		Dest:   GraphSelectorsConstructor{},
	}

	// If a direction has been specified then we only include one side of the flow.
	if dir != DirectionIngress {
		gsp.Source = GraphSelectorsConstructor{
			L3Flows: l3Source,
			L7Flows: l7Source,
			DNSLogs: dnsSource,
			Alerts:  alertSource,
		}
	}
	if dir != DirectionEgress {
		gsp.Dest = GraphSelectorsConstructor{
			L3Flows: l3Dest,
			L7Flows: l7Dest,
			DNSLogs: dnsDest,
			Alerts:  alertDest,
		}
	}

	return gsp
}
