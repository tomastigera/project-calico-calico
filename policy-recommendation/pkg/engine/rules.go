// Copyright (c) 2022 Tigera, Inc. All rights reserved.
package engine

import (
	"reflect"
	"slices"
	"strings"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/lma/pkg/api"
	calicores "github.com/projectcalico/calico/policy-recommendation/pkg/calico-resources"
	"github.com/projectcalico/calico/policy-recommendation/pkg/types"
)

type flowType string

const (
	egressToDomainFlowType flowType = "egressToDomainFlowType"
	//nolint
	egressToDomainSetFlowType flowType = "egressToDomainSetFlowType"
	egressToServiceFlowType   flowType = "egressToServiceFlowType"
	namespaceFlowType         flowType = "namespaceFlowType"
	networkSetFlowType        flowType = "networkSetFlowType"
	privateNetworkFlowType    flowType = "privateNetworkFlowType"
	publicNetworkFlowType     flowType = "publicNetworkFlowType"
	suppressedFlowType        flowType = "suppressedFlowType"
	unsupportedFlowType       flowType = "unsupportedFlowType"
)

// engineRules implements the EngineRules interface. It defines the policy recommendation engine
// rules. The following types of rules are recommended by the PRE, and apply to the following flows:
// 1. Egress to domain flows.
// 2. Egress to service flows.
// 3. Namespace flows.
// 4. NetworkSet flows.
// 5. Private network flows.
// 6. Public network flows.
type engineRules struct {
	egressToDomainRules  map[engineRuleKey]*types.FlowLogData
	egressToServiceRules map[engineRuleKey]*types.FlowLogData
	namespaceRules       map[engineRuleKey]*types.FlowLogData
	networkSetRules      map[engineRuleKey]*types.FlowLogData
	privateNetworkRules  map[engineRuleKey]*types.FlowLogData
	publicNetworkRules   map[engineRuleKey]*types.FlowLogData

	size int
}

func NewEngineRules() *engineRules {
	return &engineRules{
		egressToDomainRules:  map[engineRuleKey]*types.FlowLogData{},
		egressToServiceRules: map[engineRuleKey]*types.FlowLogData{},
		namespaceRules:       map[engineRuleKey]*types.FlowLogData{},
		networkSetRules:      map[engineRuleKey]*types.FlowLogData{},
		privateNetworkRules:  map[engineRuleKey]*types.FlowLogData{},
		publicNetworkRules:   map[engineRuleKey]*types.FlowLogData{},
	}
}

type engineRuleKey struct {
	global    bool
	name      string
	namespace string
	protocol  numorstring.Protocol
	port      numorstring.Port
}

// addFlowToEgressToDomainRules updates the ports if a rule already exists, otherwise defines a
// new egressToServiceRule for egress flows, where the remote is to a service (but not a pod).
// If there are > max number of rules in the policy, all egress domains will be included in an
// egress-domains network set.
//
// Only required if the number of rules exceeded its maximum. Domain rules will be contracted to use
// an egress domain NetworkSet specific to the namespace. If a flow is egress to a domain, rule is
// an egress rule to a namespace specific network set that will contain all of the domains.
//
// Namespaced network sets will be created for egress domains:
//
//	Name: "<namespace>-egress-domains"
//	Labels:
//			policyrecommendation.tigera.io/scope = 'Domains'
//	Domains from flow logs
//	OwnerReference will be the PolicyRecommendationScope resource.
//
// Policy rules will be added as follows for each protocol that we need to support:
// Note: The lastUpdated timestamp will be updated if the corresponding NetworkSet is updated to
// include an additional domain, even if the rule itself is unchanged.
func (er *engineRules) addFlowToEgressToDomainRules(direction calicores.DirectionType, flow api.Flow, clock Clock, serviceNameSuffix string) {
	if direction != calicores.EgressTraffic {
		log.WithField("flow", flow).Warn("flow cannot be processed, unsupported traffic direction")
		return
	}

	port, protocol := getPortAndProtocol(flow.Destination.Port, flow.Proto)
	if protocol == nil {
		// No need to add an empty protocol
		log.WithField("flow", flow).Warn("flow cannot be processed, protocol is empty")
		return
	}
	domains := parseDomains(flow.Destination.Domains)
	// All domains containing a local service suffix should be removed. The fact that we've gotten
	// this far means the check in the flow log response indicated at least one domain without the
	// suffix, that should be converted to a rule. Otherwise, the flow would have been deemed as an
	// unsupportedFlowType.
	filteredDomains := []string{}
	for _, domain := range domains {
		if !strings.HasSuffix(domain, serviceNameSuffix) {
			filteredDomains = append(filteredDomains, domain)
		}
	}

	key := engineRuleKey{
		protocol: *protocol,
		port:     port,
	}

	// Update the ports and return if the value already exists
	if v, ok := er.egressToDomainRules[key]; ok {
		for _, domain := range filteredDomains {
			// If no new domains are added then no update to the timestamp will occur
			if !containsDomain(v.Domains, domain) {
				// Timestamp recorded will be that of last update.
				v.Domains = append(v.Domains, domain)
				v.Timestamp = clock.NowRFC3339()
			}
		}

		return
	}

	// The key does not exist, define a new value and add the key-value to the egressToDomain rules
	val := &types.FlowLogData{
		Action:    getAction(false, flow),
		Protocol:  *protocol,
		Ports:     []numorstring.Port{port},
		Timestamp: clock.NowRFC3339(),
	}
	val.Domains = filteredDomains

	// Add the value to the map of egress to domain rules and increment the total engine rules count
	er.egressToDomainRules[key] = val
	er.size++
}

// addFlowToEgressToServiceRules updates the ports if a rule already exists, otherwise defines a
// new egressToDomainRule for egress flows, where the remote is to a domain.
func (er *engineRules) addFlowToEgressToServiceRules(direction calicores.DirectionType, flow api.Flow, pass bool, clock Clock) {
	if direction != calicores.EgressTraffic {
		log.WithField("flow", flow).Warn("flow cannot be processed, unsupported traffic direction")
		return
	}

	port, protocol := getPortAndProtocol(flow.Destination.Port, flow.Proto)
	if protocol == nil {
		// No need to add an empty protocol
		log.WithField("flow", flow).Warn("flow cannot be processed, protocol is empty")
		return
	}

	name := flow.Destination.ServiceName

	key := engineRuleKey{
		name:     name,
		protocol: *protocol,
	}

	// Update the ports and return if the value already exists.
	if v, ok := er.egressToServiceRules[key]; ok {
		if containsPort(v.Ports, port) {
			// no update necessary
			return
		}
		v.Ports = append(v.Ports, port)
		v.Timestamp = clock.NowRFC3339()

		return
	}

	// The key does not exist, define a new value and add the key-value to the egress to service rules.

	val := &types.FlowLogData{
		Action:    getAction(pass, flow),
		Name:      name,
		Protocol:  *protocol,
		Timestamp: clock.NowRFC3339(),
	}
	val.Ports = []numorstring.Port{port}

	// Add the value to the map of egress to service rules and increment the total engine rules count.
	er.egressToServiceRules[key] = val
	er.size++
}

// addFlowToNamespaceRules updates the ports if a rule already exists, otherwise defines a
// new namespaceRule for flows where the remote is a pod. The rule simply selects the pod's
// namespace.
func (er *engineRules) addFlowToNamespaceRules(direction calicores.DirectionType, flow api.Flow, pass bool, clock Clock) {
	port, protocol := getPortAndProtocol(flow.Destination.Port, flow.Proto)
	if protocol == nil {
		// No need to add an empty protocol
		log.WithField("flow", flow).Warn("flow cannot be processed, protocol is empty")
		return
	}

	endpoint, _ := getEndpoint(direction, flow)
	namespace := endpoint.Namespace

	key := engineRuleKey{
		namespace: namespace,
		protocol:  *protocol,
	}

	// Update the ports and return if the value already exists.
	if v, ok := er.namespaceRules[key]; ok {
		if containsPort(v.Ports, port) {
			// no update necessary
			return
		}
		v.Ports = append(v.Ports, port)
		v.Timestamp = clock.NowRFC3339()

		return
	}

	// The key does not exist, define a new value and add the key-value to the egress to service rules.

	val := &types.FlowLogData{
		Action:    getAction(pass, flow),
		Namespace: namespace,
		Protocol:  *protocol,
		Timestamp: clock.NowRFC3339(),
	}
	val.Ports = []numorstring.Port{port}

	// Add the value to the map of egress to service rules and increment the total engine rules count.
	er.namespaceRules[key] = val
	er.size++
}

// addFlowToNetworkSetRules updates the ports if a rule already exists, otherwise defines a
// new networkSetRule for flows where the remote is an existing NetworkSet or GlobalNetworkSet.
// A rule will be added to select the NetworkSet by name - this ensures we don’t require label
// schema knowledge.
func (er *engineRules) addFlowToNetworkSetRules(direction calicores.DirectionType, flow api.Flow, pass bool, clock Clock) {
	port, protocol := getPortAndProtocol(flow.Destination.Port, flow.Proto)
	if protocol == nil {
		// No need to add an empty protocol
		log.WithField("flow", flow).Warn("flow cannot be processed, protocol is empty")
		return
	}

	endpoint, _ := getEndpoint(direction, flow)
	name := endpoint.Name
	namespace := endpoint.Namespace

	gl := namespace == "-" || namespace == ""

	key := engineRuleKey{
		global:    gl,
		name:      name,
		namespace: namespace,
		protocol:  *protocol,
	}

	// Update the ports
	if v, ok := er.networkSetRules[key]; ok {
		if containsPort(v.Ports, port) {
			// port present, no update necessary
			return
		}
		v.Ports = append(v.Ports, port)
		v.Timestamp = clock.NowRFC3339()

		return
	}

	// The key does not exist, add the new key-value rule

	val := &types.FlowLogData{
		Action:    getAction(pass, flow),
		Global:    gl,
		Name:      name,
		Namespace: namespace,
		Protocol:  *protocol,
		Timestamp: clock.NowRFC3339(),
	}
	val.Ports = []numorstring.Port{port}

	// Add the value to the map of egress to service rules and increment the total engine rules count.
	er.networkSetRules[key] = val
	er.size++
}

// addFlowToPrivateNetworkRules updates the ports if a rule already exists, otherwise defines a
// new privateNetworkRule all ingress and egress flows from/to private network CIDRs that are not
// covered by all other categories, except for the public network rules. A global network set will
// be created by the PRE containing private CIDRs.
//
// A global network set will be created by the PRE containing private CIDRs.
//
//	Label:
//			policyrecommendation.tigera.io/scope = 'Private'
//	CIDRs will be defaults to those defined in RFC 1918
//	OwnerReference will be the PolicyRecommendationScope resource.
//
// The set of private CIDRs may/should be updated by the customer to only contain private CIDRs
// specific to the customer network, and should exclude the CIDR ranges used by the cluster for
// nodes and pods (**). The PRE will not update the CIDRs once the network set is created.
func (er *engineRules) addFlowToPrivateNetworkRules(direction calicores.DirectionType, flow api.Flow, clock Clock) {
	port, protocol := getPortAndProtocol(flow.Destination.Port, flow.Proto)
	if protocol == nil {
		// No need to add an empty protocol
		log.WithField("flow", flow).Warn("flow cannot be processed, protocol is empty")
		return
	}

	key := engineRuleKey{
		protocol: *protocol,
	}

	// Update the nets, if the value already exists
	if v, ok := er.privateNetworkRules[key]; ok {
		if containsPort(v.Ports, port) {
			// no update necessary
			return
		}
		v.Ports = append(v.Ports, port)
		v.Timestamp = clock.NowRFC3339()

		return
	}

	// The key does not exist, define a new value and add the key-value to the egress to service rules

	val := &types.FlowLogData{
		Action:    getAction(false, flow),
		Protocol:  *protocol,
		Timestamp: clock.NowRFC3339(),
	}
	val.Ports = []numorstring.Port{port}

	// Add the value to the map of private network rules and increment the total engine rules count
	er.privateNetworkRules[key] = val
	er.size++
}

// addFlowToPublicNetworkRules updates the ports if a rule already exists, otherwise defines a
// new publicNetworkRule covering all ingress and egress flows from/to other CIDRs that are not all
// other categories. It is a mop-up rule that is broad in scope. It covers all remaining flow
// endpoints limited only by port and protocol.
func (er *engineRules) addFlowToPublicNetworkRules(direction calicores.DirectionType, flow api.Flow, clock Clock) {
	port, protocol := getPortAndProtocol(flow.Destination.Port, flow.Proto)
	if protocol == nil {
		// No need to add an empty protocol
		log.WithField("flow", flow).Warn("flow cannot be processed, protocol is empty")
		return
	}

	key := engineRuleKey{
		protocol: *protocol,
	}

	// Update the ports and return if the value already exists
	if v, ok := er.publicNetworkRules[key]; ok {
		if containsPort(v.Ports, port) {
			return
		}
		v.Ports = append(v.Ports, port)
		v.Timestamp = clock.NowRFC3339()

		return
	}

	// The key does not exist, define a new value and add the key-value to the egress to service rules
	val := &types.FlowLogData{
		Action:    getAction(false, flow),
		Protocol:  *protocol,
		Timestamp: clock.NowRFC3339(),
	}
	val.Ports = []numorstring.Port{port}

	// Add the value to the map of egress to service rules and increment the total engine rules count
	er.publicNetworkRules[key] = val
	er.size++
}

// containsDomain returns true if the array contains the domain.
func containsDomain(arr []string, val string) bool {
	return slices.Contains(arr, val)
}

// containsPort returns true if the array contains the port.
func containsPort(arr []numorstring.Port, val numorstring.Port) bool {
	for _, v := range arr {
		if reflect.DeepEqual(v, val) {
			// The value is already present
			return true
		}
	}

	return false
}

// getFlowType returns the engine flow type, or an error if the flow defines unsupported traffic.
func getFlowType(direction calicores.DirectionType, flow api.Flow, serviceNameSuffix string) flowType {
	endpoint, dest := getEndpoint(direction, flow)
	if endpoint.Type == api.FlowLogEndpointTypeNetworkSet {
		return networkSetFlowType
	}

	if endpoint.Type == api.FlowLogEndpointTypeWEP && !undefined(endpoint.Namespace) {
		return namespaceFlowType
	}

	if endpoint.Type == api.EndpointTypeNet {
		name := endpoint.Name
		switch name {
		case api.FlowLogNetworkPrivate:
			return privateNetworkFlowType
		case api.FlowLogNetworkPublic:
			if dest {
				if !undefined(endpoint.Domains) {
					return egressToDomainFlowType
				}
				if !undefined(endpoint.ServiceName) {
					return egressToServiceFlowType
				}
			}
			return publicNetworkFlowType
		default:
			log.Warnf("Unsupported flow type: %s for flow: %#v", endpoint.Type, flow)
			return unsupportedFlowType
		}
	}

	log.Warnf("Unsupported flow type: %s for flow: %#v", endpoint.Type, flow)
	return unsupportedFlowType
}

func getEndpoint(dir calicores.DirectionType, flow api.Flow) (*api.FlowEndpointData, bool) {
	var endpoint *api.FlowEndpointData
	dest := false
	if dir == calicores.EgressTraffic {
		dest = true
		endpoint = &flow.Destination
	} else {
		endpoint = &flow.Source
	}

	return endpoint, dest
}

// getAction returns a PASS action if intra-namespace traffic should be passed to the next tier.
// Otherwise, returns ALLOW.
func getAction(pass bool, flow api.Flow) v3.Action {
	srcNamespace := flow.Source.Namespace
	destNamespace := flow.Destination.Namespace
	if pass && (srcNamespace != "" && destNamespace != "") && (srcNamespace == destNamespace) {
		return v3.Pass
	}

	return v3.Allow
}

// getPortAndProtocol returns the port and protocol as numborstring types. The port is
// empty, if the protocol does not support ports (ex. ICMP).
func getPortAndProtocol(iport *uint16, iprotocol *uint8) (numorstring.Port, *numorstring.Protocol) {
	if iprotocol == nil {
		return numorstring.Port{}, nil
	}

	protocol := api.GetProtocol(*iprotocol)
	if !protocol.SupportsPorts() || iport == nil {
		return numorstring.Port{}, &protocol
	}
	port := numorstring.SinglePort(*iport)

	return port, &protocol
}

// parseDomains separates a comma delimited string into a slice of strings and returns the slice.
func parseDomains(domainsAsStr string) []string {
	domains := strings.Split(domainsAsStr, ",")

	return domains
}

// undefined returns true if the name is empty or a dash.
func undefined(name string) bool {
	return name == "" || name == "-"
}
