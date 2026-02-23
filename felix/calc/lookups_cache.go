// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.

package calc

import (
	"maps"

	kapiv1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/pkg/proxy"

	internalapi "github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// MatchType indicates the namespace scope of a NetworkSet match.
// It is used to choose the best match when multiple NetworkSets cover the same IP.
//
// The values are ordered by priority (higher value = higher priority):
// - MatchSameNamespace (Highest): NetworkSet in the preferred namespace.
// - MatchGlobal (Medium): Global NetworkSet.
// - MatchOtherNamespace (Lowest valid): NetworkSet in a different namespace.
// - MatchNone (Sentinel): No match found (value 0).
//
// This specific ordering is relied upon by collector.go's lookupNetworkSetWithNamespace.
// DO NOT reorder without updating the priority logic in that function.
type MatchType int

const (
	MatchNone           MatchType = iota
	MatchOtherNamespace           // Lowest priority: NetworkSet in a different namespace
	MatchGlobal                   // Medium priority: Global (non-namespaced) NetworkSet
	MatchSameNamespace            // Highest priority: NetworkSet in the same namespace as the endpoint
)

// LookupsCache provides an API to do the following:
// - lookup endpoint information given an IP
// - lookup policy/profile information given the NFLOG prefix
//
// To do this, the LookupsCache uses two caches to hook into the
// calculation graph at various stages
// - EndpointLookupsCache
// - PolicyLookupsCache
type LookupsCache struct {
	polCache *PolicyLookupsCache
	epCache  *EndpointLookupsCache
	nsCache  *NetworkSetLookupsCache
	svcCache *ServiceLookupsCache
}

func NewLookupsCache() *LookupsCache {
	lc := &LookupsCache{
		polCache: NewPolicyLookupsCache(),
		epCache:  NewEndpointLookupsCache(),
		nsCache:  NewNetworkSetLookupsCache(),
		svcCache: NewServiceLookupsCache(),
	}
	return lc
}

// GetEndpoint returns the endpoint data for a given IP address.
func (lc *LookupsCache) GetEndpoint(addr [16]byte) (EndpointData, bool) {
	return lc.epCache.GetEndpoint(addr)
}

// GetHostEndpointFromInterfaceKey returns the endpoint data for a given endpoint key.
func (lc *LookupsCache) GetHostEndpointFromInterfaceKey(key string, addr [16]byte) (EndpointData, bool) {
	return lc.epCache.GetHostEndpointFromInterfaceKey(key, addr)
}

// GetEndpointKeys returns all endpoint keys that the cache is tracking.
// Convenience method only used for testing purposes.
func (lc *LookupsCache) GetEndpointKeys() []model.Key {
	return lc.epCache.GetEndpointKeys()
}

// GetAllEndpointData returns all endpoint data that the cache is tracking.
// Convenience method only used for testing purposes.
func (lc *LookupsCache) GetAllEndpointData() []EndpointData {
	return lc.epCache.GetAllEndpointData()
}

// GetNode returns the node configured with the supplied address. This matches against one of the following:
// - The node IP address
// - The node IPIP tunnel address
// - The node VXLAN tunnel address
// - The node wireguard tunnel address
func (lc *LookupsCache) GetNode(addr [16]byte) (string, bool) {
	return lc.epCache.GetNode(addr)
}

// GetNodeIP returns the node IP address for the supplied node name.
func (lc *LookupsCache) GetNodeIP(name string) (string, bool) {
	return lc.epCache.GetNodeIP(name)
}

// GetNetworkSet returns the networkset information for an address.
// It returns the first networkset it finds that contains the given address.
func (lc *LookupsCache) GetNetworkSet(addr [16]byte) (EndpointData, bool) {
	return lc.nsCache.GetNetworkSetFromIP(addr)
}

// GetNetworkSetWithNamespace returns the NetworkSet information for an address with namespace
// precedence. If preferredNamespace is provided, NetworkSets in that namespace are prioritized.
//
// Returns:
//   - EndpointData: the selected NetworkSet endpoint data, or nil if no match is found.
//   - MatchType:    indicates which priority level produced the match (SameNamespace, Global, or OtherNamespace).
func (lc *LookupsCache) GetNetworkSetWithNamespace(addr [16]byte, preferredNamespace string) (EndpointData, MatchType) {
	return lc.nsCache.GetNetworkSetFromIPWithNamespace(addr, preferredNamespace)
}

// GetNetworkSetFromEgressDomainWithNamespace returns the networkset information for an egress domain with namespace precedence.
// It prioritizes NetworkSets in the preferredNamespace, falling back to global NetworkSets if none found in the preferred namespace.
// If no preferred namespace is provided, it prioritizes global NetworkSets.
//
// Returns:
//   - EndpointData: the selected NetworkSet endpoint data, or nil if no match is found.
//   - MatchType:    indicates which priority level produced the match (SameNamespace, Global, or OtherNamespace).
func (lc *LookupsCache) GetNetworkSetFromEgressDomainWithNamespace(domain string, preferredNamespace string) (EndpointData, MatchType) {
	return lc.nsCache.GetNetworkSetFromEgressDomainWithNamespace(domain, preferredNamespace)
}

// IsEndpointDeleted returns whether the given endpoint is marked for deletion.
func (lc *LookupsCache) IsEndpointDeleted(ep EndpointData) bool {
	return lc.epCache.IsEndpointDeleted(ep)
}

// MarkEndpointDeleted marks an endpoint as deleted for testing purposes.
// This should not be called from any mainline code.
func (lc *LookupsCache) MarkEndpointDeleted(ep EndpointData) {
	lc.epCache.MarkEndpointForDeletion(ep)
}

// GetRuleIDFromNFLOGPrefix returns the RuleID associated with the supplied NFLOG prefix.
func (lc *LookupsCache) GetRuleIDFromNFLOGPrefix(prefix [64]byte) *RuleID {
	return lc.polCache.GetRuleIDFromNFLOGPrefix(prefix)
}

// GetRuleIDFromID64 returns the RuleID associated with the supplied 64bit ID.
func (lc *LookupsCache) GetRuleIDFromID64(id uint64) *RuleID {
	return lc.polCache.GetRuleIDFromID64(id)
}

// GetID64FromNFLOGPrefix returns the 64 bit ID associated with the supplied NFLOG prefix.
func (lc *LookupsCache) GetID64FromNFLOGPrefix(prefix [64]byte) uint64 {
	return lc.polCache.GetID64FromNFLOGPrefix(prefix)
}

// EnableID64 make the PolicyLookupsCache to also generate 64bit IDs for each
// NFLOGPrefix. Once turned on, cannot be turned off.
func (lc *LookupsCache) EnableID64() {
	lc.polCache.SetUseIDs()
}

// GetServiceFromPreNATDest looks up a service by cluster/external IP.
func (lc *LookupsCache) GetServiceFromPreDNATDest(ipPreDNAT [16]byte, portPreDNAT int, proto int) (proxy.ServicePortName, bool) {
	return lc.svcCache.GetServiceFromPreDNATDest(ipPreDNAT, portPreDNAT, proto)
}

// GetServiceFromEndpointAddr looks up a service by endpoint (pod) IP address.
// This is useful for resolving service names from backend pod IPs (e.g., from upstream_host in L7 logs).
func (lc *LookupsCache) GetServiceFromEndpointAddr(ipAddr [16]byte, port int, proto int) (proxy.ServicePortName, bool) {
	return lc.svcCache.GetServiceFromEndpointAddr(ipAddr, port, proto)
}

// GetNodePortService looks up a service by port and protocol (assuming a node IP).
func (lc *LookupsCache) GetNodePortService(port int, proto int) (proxy.ServicePortName, bool) {
	return lc.svcCache.GetNodePortService(port, proto)
}

func (lc *LookupsCache) GetServiceSpecFromResourceKey(key model.ResourceKey) (kapiv1.ServiceSpec, bool) {
	return lc.svcCache.GetServiceSpecFromResourceKey(key)
}

// MockDeleteNetworkSet is a helper for tests to simulate a NetworkSet deletion.
func (lc *LookupsCache) MockDeleteNetworkSet(k model.NetworkSetKey) {
	lc.nsCache.OnUpdate(api.Update{
		KVPair:     model.KVPair{Key: k, Value: nil},
		UpdateType: api.UpdateTypeKVDeleted,
	})
}

// SetMockData fills in some of the data structures for use in the test code. This should not
// be called from any mainline code.
func (lc *LookupsCache) SetMockData(
	em map[[16]byte]EndpointData,
	nm map[[64]byte]*RuleID,
	ns map[model.NetworkSetKey]*model.NetworkSet,
	svcs map[model.ResourceKey]*kapiv1.Service,
	nodes map[string]*internalapi.Node,
	gc map[model.PolicyKey]int64,
) {
	for k, v := range nodes {
		lc.epCache.nodes[k] = v.Spec
	}
	for ip, ed := range em {
		if ed == nil {
			delete(lc.epCache.ipToEndpoints, ip)
		} else {
			lc.epCache.ipToEndpoints[ip] = []endpointData{ed.(endpointData)}
		}
	}
	for id, rid := range nm {
		if rid == nil {
			delete(lc.polCache.nflogPrefixHash, id)
		} else {
			lc.polCache.nflogPrefixHash[id] = pcRuleID{ruleID: rid}
		}
	}
	for k, v := range ns {
		lc.nsCache.OnUpdate(api.Update{KVPair: model.KVPair{Key: k, Value: v}})
	}
	for k, v := range svcs {
		lc.svcCache.OnResourceUpdate(api.Update{KVPair: model.KVPair{Key: k, Value: v}})
	}
	maps.Copy(lc.polCache.generationCache, gc)
}

func (lc *LookupsCache) GetGeneration(key model.PolicyKey) int64 {
	return lc.polCache.GetGeneration(key)
}
