// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.

package calc

import (
	"net"
	"reflect"
	"slices"
	"strings"
	"sync"
	"unique"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var (
	gaugeNetworkSetCacheLength = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_collector_lookupcache_networksets",
		Help: "Total number of entries currently residing in the network set lookup cache.",
	})
)

func init() {
	prometheus.MustRegister(gaugeNetworkSetCacheLength)
}

type networkSetData struct {
	cidrs                set.Set[ip.CIDR]
	allowedEgressDomains set.Set[string]
	key                  model.NetworkSetKey
	labels               uniquelabels.Map
}

func (n networkSetData) IsLocal() bool {
	return false
}

func (n networkSetData) IngressMatchData() *MatchData {
	return nil
}

func (n networkSetData) EgressMatchData() *MatchData {
	return nil
}

func (n networkSetData) IsHostEndpoint() bool {
	return false
}

func (n networkSetData) IsNetworkSet() bool {
	return true
}

func (n networkSetData) Key() model.Key {
	return n.key
}

func (n networkSetData) Labels() uniquelabels.Map {
	return n.labels
}

func (n networkSetData) GenerateName() string {
	return ""
}

func (n networkSetData) InterfaceName() string {
	// NetworkSet does not have an interface name.
	return ""
}

var _ EndpointData = &networkSetData{}

// Networkset data is stored in the EndpointData object for easier type processing for flow logs.
type NetworkSetLookupsCache struct {
	nsMutex sync.RWMutex

	networkSets map[model.Key]*networkSetData
	ipTree      *IpTrie

	// Maps domain -> list of NetworkSetKey handles
	domainToNetworksets map[string][]unique.Handle[model.NetworkSetKey]
}

func NewNetworkSetLookupsCache() *NetworkSetLookupsCache {
	nc := &NetworkSetLookupsCache{
		nsMutex: sync.RWMutex{},

		// NetworkSet data.
		networkSets: make(map[model.Key]*networkSetData),

		// Reverse lookups by CIDR and egress domain.
		ipTree:              NewIpTrie(),
		domainToNetworksets: make(map[string][]unique.Handle[model.NetworkSetKey]),
	}

	return nc
}

func (nc *NetworkSetLookupsCache) RegisterWith(allUpdateDispatcher *dispatcher.Dispatcher) {
	allUpdateDispatcher.Register(model.NetworkSetKey{}, nc.OnUpdate)
}

// OnUpdate is the callback method registered with the AllUpdatesDispatcher for
// the NetworkSet type. This method updates the mapping between networkSets
// and the corresponding CIDRs that they contain.
func (nc *NetworkSetLookupsCache) OnUpdate(nsUpdate api.Update) (_ bool) {
	switch k := nsUpdate.Key.(type) {
	case model.NetworkSetKey:
		if nsUpdate.Value == nil {
			nc.removeNetworkSet(k)
		} else {
			networkSet := nsUpdate.Value.(*model.NetworkSet)
			nc.addOrUpdateNetworkSet(&networkSetData{
				key:                  k,
				labels:               networkSet.Labels,
				cidrs:                set.FromArray(ip.CIDRsFromCalicoNets(networkSet.Nets)),
				allowedEgressDomains: set.FromArray(networkSet.AllowedEgressDomains),
			})
		}
	default:
		log.Infof("ignoring unexpected update: %v %#v",
			reflect.TypeOf(nsUpdate.Key), nsUpdate)
		return
	}
	log.Infof("Updating networkset cache with networkset data %v", nsUpdate.Key)
	return
}

// addOrUpdateNetworkSet tracks networkset to CIDR mapping as well as the reverse
// mapping from CIDR to networkset.
func (nc *NetworkSetLookupsCache) addOrUpdateNetworkSet(data *networkSetData) {
	// If the networkset exists, it was updated, then we might have to add or
	// remove CIDRs and allowed egress domains.
	nc.nsMutex.Lock()
	defer nc.nsMutex.Unlock()

	currentData, exists := nc.networkSets[data.key]
	if currentData == nil {
		currentData = &networkSetData{
			cidrs:                set.New[ip.CIDR](),
			allowedEgressDomains: set.New[string](),
		}
	}
	nc.networkSets[data.key] = data

	set.IterDifferences[ip.CIDR](data.cidrs, currentData.cidrs,
		// In new, not current.  Add new entry to mappings.
		func(newCIDR ip.CIDR) error {
			nc.ipTree.InsertKey(newCIDR, data.key)
			return nil
		},
		// In current, not new.  Remove old entry from mappings.
		func(oldCIDR ip.CIDR) error {
			nc.ipTree.DeleteKey(oldCIDR, data.key)
			return nil
		},
	)
	set.IterDifferences[string](data.allowedEgressDomains, currentData.allowedEgressDomains,
		// In new, not current.  Add new entry to mappings.
		func(newDomain string) error {
			nc.addDomainMapping(newDomain, data.key)
			return nil
		},
		// In current, not new.  Remove old entry from mappings.
		func(oldDomain string) error {
			nc.removeDomainMapping(oldDomain, data.key)
			return nil
		},
	)
	if !exists {
		nc.reportNetworksetCacheMetrics()
	}
}

// removeNetworkSet removes the networkset from the NetworksetLookupscache.networkSets map
// and also removes all corresponding CIDR to networkset mappings as well.
// This method should acquire (and release) the NetworkSetLookupsCache.nsMutex before (and after)
// manipulating the maps.
func (nc *NetworkSetLookupsCache) removeNetworkSet(key model.Key) {
	nc.nsMutex.Lock()
	defer nc.nsMutex.Unlock()
	currentData, ok := nc.networkSets[key]
	if !ok {
		// We don't know about this networkset. Nothing to do.
		return
	}
	for oldCIDR := range currentData.cidrs.All() {
		nc.ipTree.DeleteKey(oldCIDR, key)
	}
	for oldDomain := range currentData.allowedEgressDomains.All() {
		nc.removeDomainMapping(oldDomain, key)
	}
	delete(nc.networkSets, key)

	nc.reportNetworksetCacheMetrics()
}

func (nc *NetworkSetLookupsCache) addDomainMapping(domain string, key model.Key) {
	nsKey, ok := key.(model.NetworkSetKey)
	if !ok {
		return
	}

	h := unique.Make(nsKey)

	// Update main map
	handles := nc.domainToNetworksets[domain]

	// Insert handle in sorted order to maintain lexicographic ordering
	idx, found := slices.BinarySearchFunc(handles, nsKey, compareNetworkSetKeys)

	if found {
		return
	}

	// Insert at the correct position
	handles = slices.Insert(handles, idx, h)
	nc.domainToNetworksets[domain] = handles
}

func (nc *NetworkSetLookupsCache) removeDomainMapping(domain string, key model.Key) {
	nsKey, ok := key.(model.NetworkSetKey)
	if !ok {
		return
	}

	handles := nc.domainToNetworksets[domain]
	if len(handles) == 0 {
		return
	}

	idx, found := slices.BinarySearchFunc(handles, nsKey, compareNetworkSetKeys)
	if !found {
		return
	}

	handles = slices.Delete(handles, idx, idx+1)

	if len(handles) == 0 {
		delete(nc.domainToNetworksets, domain)
		return
	}

	nc.domainToNetworksets[domain] = handles
}

func compareNetworkSetKeys(h unique.Handle[model.NetworkSetKey], target model.NetworkSetKey) int {
	val := h.Value()
	nsVal := val.Namespace()
	nsTarget := target.Namespace()
	if c := strings.Compare(nsVal, nsTarget); c != 0 {
		return c
	}
	return strings.Compare(val.Name, target.Name)
}

// GetNetworkSetFromIP finds Longest Prefix Match CIDR from given IP ADDR and return last observed
// Networkset for that CIDR
func (nc *NetworkSetLookupsCache) GetNetworkSetFromIP(addr [16]byte) (ed EndpointData, ok bool) {
	ed, match := nc.GetNetworkSetFromIPWithNamespace(addr, "")
	return ed, match != MatchNone
}

// GetNetworkSetFromIPWithNamespace finds NetworkSet for the Given IP with namespace precedence.
// It prioritizes NetworkSets in the preferredNamespace, falling back to longest prefix match of
// the global networkSets if none found, then the first lexicographically ordered matching
// NetworkSet if no other matches are found. If no preferred namespace is provided, it prioritizes
// global NetworkSets.
func (nc *NetworkSetLookupsCache) GetNetworkSetFromIPWithNamespace(ipAddr [16]byte, preferredNamespace string) (ed EndpointData, matchType MatchType) {
	netIP := net.IP(ipAddr[:])
	addr := ip.FromNetIP(netIP)

	nc.nsMutex.RLock()
	defer nc.nsMutex.RUnlock()

	// Use the namespace isolation lookup from IpTrie for collector use case
	key, matchType := nc.ipTree.GetLongestPrefixCidrWithNamespaceIsolation(addr, preferredNamespace)
	if matchType == MatchNone {
		return nil, MatchNone
	}

	// Get the NetworkSet data for the key
	if ns := nc.networkSets[key]; ns != nil {
		return ns, matchType
	}

	return nil, MatchNone
}

// GetNetworkSetFromEgressDomainWithNamespace returns a NetworkSet that contains the supplied
// egress domain with namespace precedence. It follows a three-tier priority:
// 1. NetworkSets in the preferredNamespace
// 2. Global NetworkSets (if no preferred namespace match)
// 3. NetworkSets in any other namespace (if no global match)
// Returning the lexicographically lowest matching NetworkSet.
func (nc *NetworkSetLookupsCache) GetNetworkSetFromEgressDomainWithNamespace(domain string, preferredNamespace string) (ed EndpointData, matchType MatchType) {
	nc.nsMutex.RLock()
	defer nc.nsMutex.RUnlock()

	handles := nc.domainToNetworksets[domain]
	if len(handles) == 0 {
		return nil, MatchNone
	}

	// Helper to check a specific namespace for the best match among candidates
	checkNamespace := func(ns string) (EndpointData, bool) {
		// The handles are already sorted, so use binary search to find the start of the namespace block.
		start, _ := slices.BinarySearchFunc(handles, ns, func(h unique.Handle[model.NetworkSetKey], targetNs string) int {
			return strings.Compare(h.Value().Namespace(), targetNs)
		})

		if start < len(handles) {
			key := handles[start].Value()
			if key.Namespace() == ns {
				// Since handles are sorted, the first match is the lexicographically first one.
				if nsData := nc.networkSets[key]; nsData != nil {
					return nsData, true
				}
			}
		}
		return nil, false
	}

	// Match against preferred namespace first (only when preferredNamespace is non-empty)
	if preferredNamespace != "" {
		if ed, ok := checkNamespace(preferredNamespace); ok {
			return ed, MatchSameNamespace
		}
	}

	// Match against global namespace
	if ed, ok := checkNamespace(""); ok {
		return ed, MatchGlobal
	}

	// Fallback and return the lexicographically first NetworkSet. Since the list is sorted and
	// Global sets were already checked, the first element is the deterministic default.
	lowestHandle := handles[0]
	lowestKey := model.NetworkSetKey(lowestHandle.Value())
	if nsData := nc.networkSets[lowestKey]; nsData != nil {
		return nsData, MatchOtherNamespace
	}

	return nil, MatchNone
}

func (nc *NetworkSetLookupsCache) DumpNetworksets() string {
	nc.nsMutex.RLock()
	defer nc.nsMutex.RUnlock()
	lines := nc.ipTree.DumpCIDRKeys()
	lines = append(lines, "-------")
	for key, ns := range nc.networkSets {
		cidrStr := []string{}
		for cidr := range ns.cidrs.All() {
			cidrStr = append(cidrStr, cidr.String())
		}
		domainStr := []string{}
		for domain := range ns.allowedEgressDomains.All() {
			domainStr = append(domainStr, domain)
		}
		lines = append(lines,
			key.(model.NetworkSetKey).Name,
			"   cidrs: "+strings.Join(cidrStr, ","),
			" domains: "+strings.Join(domainStr, ","),
		)
	}
	return strings.Join(lines, "\n")
}

// reportNetworksetCacheMetrics reports networkset cache performance metrics to prometheus
func (nc *NetworkSetLookupsCache) reportNetworksetCacheMetrics() {
	gaugeNetworkSetCacheLength.Set(float64(len(nc.networkSets)))
}
