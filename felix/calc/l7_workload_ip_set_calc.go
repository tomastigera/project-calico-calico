// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package calc

import (
	"reflect"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/labelindex/ipsetmember"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/tproxydefs"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// L7WorkloadIPSetCalculator keeps the tproxydefs.ApplicationLayerPolicyIPSet up to date.  The IP set contains
// all the IPs of local workloads that have ALP policy.
//
// To avoid having to deal with label inheritance, L7WorkloadIPSetCalculator uses the
// ActiveRulesCalculator's PolicyMatchListener callback API to stay informed on which
// local endpoints match which policies.  Because not all policies are ALP policies,
// it also tracks which policies have ALP, and it does a second layer of filtering
// when calculating the IP set.
//
// Note: since the ActiveRulesCalculator is registered first with the dispatcher, it
// will often send us updates for policies and endpoints that we haven't heard about
// yet.  We deal with that by caching the information separately and treating
// unknown WEPs/policies as having no IPs/no ALP.  It all comes out in the wash.
type L7WorkloadIPSetCalculator struct {
	// Input caches.
	localWorkloadIPv4s         map[model.WorkloadEndpointKey][]net.IPNet
	ipsChangedSinceFlush       bool
	wepKeyToMatchingPolicyKeys map[model.WorkloadEndpointKey]set.Set[model.PolicyKey]
	policyKeyToMatchingWepKeys map[model.PolicyKey]set.Set[model.WorkloadEndpointKey]
	policiesWithALP            set.Set[model.PolicyKey]

	// WEPs/IPs that we've sent downstream.
	wepsWithALP set.Set[model.WorkloadEndpointKey] // Recalculated on flush.
	sentAddrs   set.Set[ip.Addr]

	// dataplane callbacks
	callbacks ipSetUpdateCallbacks
}

func NewL7WorkloadIPSetCalculator(callbacks ipSetUpdateCallbacks) *L7WorkloadIPSetCalculator {
	w := &L7WorkloadIPSetCalculator{
		localWorkloadIPv4s:         map[model.WorkloadEndpointKey][]net.IPNet{},
		wepKeyToMatchingPolicyKeys: map[model.WorkloadEndpointKey]set.Set[model.PolicyKey]{},
		policyKeyToMatchingWepKeys: map[model.PolicyKey]set.Set[model.WorkloadEndpointKey]{},
		policiesWithALP:            set.New[model.PolicyKey](),
		wepsWithALP:                set.New[model.WorkloadEndpointKey](),
		sentAddrs:                  set.New[ip.Addr](),
		callbacks:                  callbacks,
	}
	w.InitializeIPSet()
	return w
}

func (w *L7WorkloadIPSetCalculator) RegisterWith(allUpdateDisp, localUpdDisp *dispatcher.Dispatcher) {
	allUpdateDisp.Register(model.PolicyKey{}, w.OnResourceUpdate)
	localUpdDisp.Register(model.WorkloadEndpointKey{}, w.OnResourceUpdate)
}

func (w *L7WorkloadIPSetCalculator) InitializeIPSet() {
	w.callbacks.OnIPSetAdded(tproxydefs.ApplicationLayerPolicyIPSet, proto.IPSetUpdate_IP)
}

// PolicyMatchListener callbacks from the ActiveRulesCalculator; we record which local endpoints match
// the policies and then further filter to only ALP policies.

func (w *L7WorkloadIPSetCalculator) OnPolicyMatch(policyKey model.PolicyKey, endpointKey model.EndpointKey) {
	// We only care about workload endpoints (not host endpoints).
	wepKey, ok := endpointKey.(model.WorkloadEndpointKey)
	if !ok {
		return
	}
	log.WithFields(log.Fields{
		"policy":   policyKey,
		"endpoint": endpointKey,
	}).Debug("Recording policy match (start) and checking if it impacts the ALP IP set.")
	// Record the match, even if it's not an ALP policy.  The policy might change to ALP later.
	if w.wepKeyToMatchingPolicyKeys[wepKey] == nil {
		w.wepKeyToMatchingPolicyKeys[wepKey] = set.New[model.PolicyKey]()
	}
	w.wepKeyToMatchingPolicyKeys[wepKey].Add(policyKey)
	if w.policyKeyToMatchingWepKeys[policyKey] == nil {
		w.policyKeyToMatchingWepKeys[policyKey] = set.New[model.WorkloadEndpointKey]()
	}
	w.policyKeyToMatchingWepKeys[policyKey].Add(wepKey)

	if len(w.localWorkloadIPv4s[wepKey]) == 0 {
		// Endpoint has no IPs (yet) so it can't make a contribution to the IP set.
		return
	}
	if !w.policyHasALP(policyKey) {
		// Policy isn't an ALP policy, so it can't cause an endpoint to be added to the IP set.
		return
	}

	// Do a scan to find out if any IPs have changed.
	log.Debugf("Matched policy has ALP and endpoint has IPs, recalculate IP set")
	w.flush()
}

func (w *L7WorkloadIPSetCalculator) OnPolicyMatchStopped(policyKey model.PolicyKey, endpointKey model.EndpointKey) {
	// We only care about workload endpoints, not host endpoints.
	wepKey, ok := endpointKey.(model.WorkloadEndpointKey)
	if !ok {
		return
	}
	log.WithFields(log.Fields{
		"policy":   policyKey,
		"endpoint": endpointKey,
	}).Debug("Recording policy match (end) and checking if it impacts the ALP IP set.")
	w.wepKeyToMatchingPolicyKeys[wepKey].Discard(policyKey)
	if w.wepKeyToMatchingPolicyKeys[wepKey].Len() == 0 {
		delete(w.wepKeyToMatchingPolicyKeys, wepKey)
	}
	w.policyKeyToMatchingWepKeys[policyKey].Discard(wepKey)
	if w.policyKeyToMatchingWepKeys[policyKey].Len() == 0 {
		delete(w.policyKeyToMatchingWepKeys, policyKey)
	}

	if len(w.localWorkloadIPv4s[wepKey]) == 0 {
		// Endpoint has no IPs (yet) so it can't have made a contribution to the IP set.
		return
	}
	if !w.policyHasALP(policyKey) {
		// Policy isn't an ALP policy, so removing the match can't change the ALP status of an endpoint.
		return
	}

	// Do a scan to find out if any IPs have changed.
	log.Debugf("Matched policy had ALP and endpoint has IPs, recalculate IP set")
	w.flush()
}

func (w *L7WorkloadIPSetCalculator) OnComputedSelectorMatch(_ string, _ model.EndpointKey)        {} // Not needed.
func (w *L7WorkloadIPSetCalculator) OnComputedSelectorMatchStopped(_ string, _ model.EndpointKey) {} // Not needed.

func (w *L7WorkloadIPSetCalculator) OnResourceUpdate(update api.Update) (_ bool) {
	switch k := update.Key.(type) {
	case model.PolicyKey:
		// Staged NetworkPolicies/GlobalNetworkPolicies should be
		// skipped
		if model.PolicyIsStaged(k.Name) {
			return
		}
		wasALP := w.policiesWithALP.Contains(k)
		isALP := false
		if update.Value != nil {
			isALP = PolicyHasALP(update.Value.(*model.Policy))
		}
		if wasALP != isALP {
			if isALP {
				log.WithField("policy", k).Debug("Now an ALP policy.")
				w.policiesWithALP.Add(k)
			} else {
				log.WithField("policy", k).Debug("No longer an ALP policy.")
				w.policiesWithALP.Discard(k)
			}
			w.flush()
		}
	case model.WorkloadEndpointKey:
		if update.Value == nil {
			w.handleWEPRemoval(k)
			return
		}
		if v, ok := update.Value.(*model.WorkloadEndpoint); ok {
			if v.ApplicationLayer != nil {
				// skip this workload because it is set to be
				// using sidecars
				return
			}
			w.handleWEPUpdate(k, v)
		}
	}
	return
}

func PolicyHasALP(pol *model.Policy) bool {
	for _, rule := range pol.InboundRules {
		log.Tracef("matching rule %v: %v", rule, rule.HTTPMatch != nil)
		if rule.HTTPMatch != nil {
			return true
		}
	}
	return false
}

func (w *L7WorkloadIPSetCalculator) handleWEPUpdate(k model.WorkloadEndpointKey, v *model.WorkloadEndpoint) {
	log.Debugf("WEP update: %v", k)
	oldIPs := w.localWorkloadIPv4s[k]
	w.localWorkloadIPv4s[k] = v.IPv4Nets

	if w.recalculateWEPHasALP(k) && !reflect.DeepEqual(oldIPs, v.IPv4Nets) {
		// Endpoint is in the IP set and its IPs have changed, need to recalculate it.
		log.Debugf("WEP %v has ALP and new/changed IPs; recalculate", k)
		w.ipsChangedSinceFlush = true
		w.flush()
	}
}

func (w *L7WorkloadIPSetCalculator) handleWEPRemoval(k model.WorkloadEndpointKey) {
	log.Debugf("WEP removed: %v", k)
	needFlush := w.recalculateWEPHasALP(k)
	delete(w.localWorkloadIPv4s, k)

	if needFlush {
		// Defensive: this is unhittable because the ActiveRulesCalculator removes all policy matches
		// before we get the WEP removal.
		log.Debugf("Removed WEP %v had ALP; recalculate", k)
		w.ipsChangedSinceFlush = true
		w.flush()
	}
}

func (w *L7WorkloadIPSetCalculator) recalculateALPWorkloadIPs() set.Set[ip.Addr] {
	res := set.New[ip.Addr]()
	for k := range w.wepsWithALP.All() {
		for _, ip4Net := range w.localWorkloadIPv4s[k] {
			ip4 := ip.CIDRFromCalicoNet(ip4Net)
			res.Add(ip4.Addr())
		}
	}
	return res
}

func (w *L7WorkloadIPSetCalculator) flush() {
	// Update our cache of which WEPs have ALP.
	wepsWithALPChanged := w.recalculateWEPWithALP()
	if !wepsWithALPChanged && !w.ipsChangedSinceFlush {
		// Nothing to do, the set of endpoints with ALP hasn't changed.
		log.Debug("Set of ALP endpoints and IPs didn't change, skipping IP set recalc.")
		return
	}
	w.ipsChangedSinceFlush = false
	log.Debug("Set of ALP endpoints changed, recalculating IP set.")

	// Recalculate the complete set of IPs, this deals with possibility that two workloads have the same IP.
	// Otherwise, we'd need to do ref counting or similar to deal with deletions.
	updatedAddrs := w.recalculateALPWorkloadIPs()
	log.Debugf("Updated set of local WEP IPs with ALP: %v", updatedAddrs)

	// find removals by looking at active ips, see if it's in the new list
	for addr := range w.sentAddrs.All() {
		if !updatedAddrs.Contains(addr) {
			log.Debugf("Local WEP IP no longer active for ALP policy: %v", addr)
			w.callbacks.OnIPSetMemberRemoved(tproxydefs.ApplicationLayerPolicyIPSet, ipsetmember.MakeCIDROrIPOnly(addr.AsCIDR()))
			w.sentAddrs.Discard(addr)
		}
	}

	// find additions by iterating list of possible incoming members then
	// see if it's already in the ipset
	for addr := range updatedAddrs.All() {
		if !w.sentAddrs.Contains(addr) {
			log.Debugf("Local WEP IP now active for ALP policy: %v", addr)
			w.callbacks.OnIPSetMemberAdded(tproxydefs.ApplicationLayerPolicyIPSet, ipsetmember.MakeCIDROrIPOnly(addr.AsCIDR()))
			w.sentAddrs.Add(addr)
		}
	}
}

// recalculateWEPWithALP recalculates the w.wepsWithALP set, which contains the keys of all the endpoints that
// are known to have ALP policies.
func (w *L7WorkloadIPSetCalculator) recalculateWEPWithALP() (alpWEPsChanged bool) {
	oldWEPsWithALP := w.wepsWithALP
	newWEPsWithALP := set.New[model.WorkloadEndpointKey]()
	for wepKey := range w.wepKeyToMatchingPolicyKeys {
		if w.recalculateWEPHasALP(wepKey) {
			newWEPsWithALP.Add(wepKey)
			if oldWEPsWithALP.Contains(wepKey) {
				// Remove the unchanged WEPs from the old set, then if anything is left at the end
				// we know that something has been removed.
				oldWEPsWithALP.Discard(wepKey)
			} else {
				log.Debugf("New WEP with ALP: %v", wepKey)
				alpWEPsChanged = true
			}
		}
	}
	if oldWEPsWithALP.Len() > 0 {
		log.Debugf("Some WEPs no longer have ALP.")
		alpWEPsChanged = true
	}
	w.wepsWithALP = newWEPsWithALP
	return
}

func (w *L7WorkloadIPSetCalculator) policyHasALP(key model.PolicyKey) bool {
	return w.policiesWithALP.Contains(key)
}

func (w *L7WorkloadIPSetCalculator) recalculateWEPHasALP(k model.WorkloadEndpointKey) (hasALP bool) {
	polKeys := w.wepKeyToMatchingPolicyKeys[k]
	if polKeys == nil {
		return false
	}
	for k := range polKeys.All() {
		if w.policiesWithALP.Contains(k) {
			hasALP = true
			break
		}
	}
	return
}

var _ PolicyMatchListener = (*L7WorkloadIPSetCalculator)(nil)
