// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package xrefcache

import (
	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/compliance/pkg/syncer"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// This file implements a RuleSelector cache. This is a pseudo-resource, implemented to allow rule selectors to be
// managed and accessed as if they were a resource type. Creation of these pseudo-resources is managed via the
// NetworkPolicy cache which tracks which selectors need to be created/deleted based on policy configuration events.

var (
	// Internal resource kind to encapsulate a selector. This is a bit of a hack since our label-selector interface
	// assumes all links are resource types, however we want to track selector/netset links so we create a fake
	// selector kind.
	KindSelector = metav1.TypeMeta{
		Kind:       "rule-selector",
		APIVersion: "internal.tigera.io/v1",
	}

	KindsNetworkPolicyRuleSelectors = []metav1.TypeMeta{
		KindSelector,
	}
)

func selectorIDToSelector(id apiv3.ResourceID) string {
	return id.Name
}

func selectorToSelectorID(sel string) apiv3.ResourceID {
	return apiv3.ResourceID{
		TypeMeta: KindSelector,
		Name:     sel,
	}
}

// Fake versioned struct so that the version conversion returns something non-nil.
type VersionedNetworkPolicyRuleSelector struct {
	VersionedResource
}

// CacheEntryNetworkPolicyRuleSelector is a cache entry in the NetworkPolicyRuleSelector cache. Each entry implements
// the CacheEntry interface.
type CacheEntryNetworkPolicyRuleSelector struct {
	// The versioned policy resource.
	VersionedNetworkPolicyRuleSelector

	// The effective NetworkSet CacheEntryFlags (i.e. the combination of the set of selected NetworkSets for this
	// selector.
	NetworkSetFlags CacheEntryFlags

	// Internally managed references.
	NetworkSets set.Typed[apiv3.ResourceID]
	Policies    set.Typed[apiv3.ResourceID]

	// --- Internal data ---
	cacheEntryCommon
	clog *log.Entry
}

// getVersionedResource implements the CacheEntry interface.
func (c *CacheEntryNetworkPolicyRuleSelector) getVersionedResource() VersionedResource {
	return c.VersionedResource
}

// setVersionedResource implements the CacheEntry interface.
func (c *CacheEntryNetworkPolicyRuleSelector) setVersionedResource(r VersionedResource) {
	c.VersionedResource = r
}

// newNetworkPolicyRuleSelectorsEngine creates a new handler used for the NetworkPolicy cache.
func newNetworkPolicyRuleSelectorsEngine() resourceHandler {
	return &networkPolicyRuleSelectorsEngine{}
}

// networkPolicyRuleSelectorsEngine implements the resourceHandler interface for the NetworkPolicy rule selector.
type networkPolicyRuleSelectorsEngine struct {
	CacheAccessor
}

// register implements the resourceHandler interface.
func (c *networkPolicyRuleSelectorsEngine) register(cache CacheAccessor) {
	c.CacheAccessor = cache

	// Register with the netset label selectors for notification of match start/stops.
	c.NetworkSetLabelSelector().RegisterCallbacks(c.kinds(), c.netsetMatchStarted, c.netsetMatchStopped)
	c.NetworkPolicyRuleSelectorManager().RegisterCallbacks(c.policyMatchStarted, c.policyMatchStopped)

	// Register for updates for all NetworkSet events. We don't care about Added/Deleted/Updated events as any changes
	// to the cross-referencing will result in a notification here where we will requeue any changed rule selectors.
	for _, kind := range KindsNetworkSet {
		c.RegisterOnUpdateHandler(
			kind,
			syncer.UpdateType(CacheEntryFlagsNetworkSets),
			c.queueRuleSelectorsForRecalculation,
		)
	}
}

// register implements the resourceHandler interface.
func (c *networkPolicyRuleSelectorsEngine) kinds() []metav1.TypeMeta {
	return KindsNetworkPolicyRuleSelectors
}

// newCacheEntry implements the resourceHandler interface.
func (c *networkPolicyRuleSelectorsEngine) newCacheEntry() CacheEntry {
	return &CacheEntryNetworkPolicyRuleSelector{
		NetworkSets: set.New[apiv3.ResourceID](),
		Policies:    set.New[apiv3.ResourceID](),
	}
}

// resourceAdded implements the resourceHandler interface.
func (c *networkPolicyRuleSelectorsEngine) resourceAdded(id apiv3.ResourceID, entry CacheEntry) {
	// Just call through to our update processsing.
	entry.(*CacheEntryNetworkPolicyRuleSelector).clog = log.WithField("id", id)
	c.resourceUpdated(id, entry, nil)
}

// resourceUpdated implements the resourceHandler interface.
func (c *networkPolicyRuleSelectorsEngine) resourceUpdated(id apiv3.ResourceID, entry CacheEntry, prev VersionedResource) {
	c.NetworkSetLabelSelector().UpdateSelector(id, selectorIDToSelector(id))
}

// resourceDeleted implements the resourceHandler interface.
func (c *networkPolicyRuleSelectorsEngine) resourceDeleted(id apiv3.ResourceID, res CacheEntry) {
	c.NetworkSetLabelSelector().DeleteSelector(id)
}

// recalculate implements the resourceHandler interface.
func (c *networkPolicyRuleSelectorsEngine) recalculate(id apiv3.ResourceID, entry CacheEntry) syncer.UpdateType {
	x := entry.(*CacheEntryNetworkPolicyRuleSelector)

	// Store and clear the effective set of Netset flags.
	oldFlags := x.NetworkSetFlags
	x.NetworkSetFlags = 0
	x.NetworkSets.Iter(func(nsid apiv3.ResourceID) error {
		netset := c.GetFromXrefCache(nsid)
		if netset == nil {
			log.Errorf("Cannot find referenced NetworkSet in cache when recalculating rule selector flags")
			return nil
		}
		x.NetworkSetFlags |= netset.(*CacheEntryNetworkSet).Flags
		return nil
	})

	changed := syncer.UpdateType(oldFlags ^ x.NetworkSetFlags)

	x.clog.Debugf("Recalculated, returning update %d, flags now: %d", changed, x.NetworkSetFlags)
	return changed
}

// convertToVersioned implements the resourceHandler interface.
func (c *networkPolicyRuleSelectorsEngine) convertToVersioned(res resources.Resource) (VersionedResource, error) {
	return &VersionedNetworkPolicyRuleSelector{}, nil
}

func (c *networkPolicyRuleSelectorsEngine) queueRuleSelectorsForRecalculation(update syncer.Update) {
	// We have only registered for notifications from NetworkSets and for changes to configuration that we care about.
	x := update.Resource.(*CacheEntryNetworkSet)

	x.PolicyRuleSelectors.Iter(func(id apiv3.ResourceID) error {
		c.QueueUpdate(id, nil, update.Type)
		return nil
	})
}

func (c *networkPolicyRuleSelectorsEngine) netsetMatchStarted(sel, nsLabels apiv3.ResourceID) {
	x, ok := c.GetFromOurCache(sel).(*CacheEntryNetworkPolicyRuleSelector)
	if !ok {
		log.Errorf("Match started on selector, but selector is not in cache: %s matches %s", sel, nsLabels)
		return
	}
	x.clog.Debugf("Adding %s to networksets for %s", nsLabels, sel)
	x.NetworkSets.Add(nsLabels)
	c.QueueUpdate(sel, nil, EventNetsetMatchStarted)
}

func (c *networkPolicyRuleSelectorsEngine) netsetMatchStopped(sel, nsLabels apiv3.ResourceID) {
	x, ok := c.GetFromOurCache(sel).(*CacheEntryNetworkPolicyRuleSelector)
	if !ok {
		log.Errorf("Match stopped on selector, but selector is not in cache: %s matches %s", sel, nsLabels)
		return
	}
	x.clog.Debugf("Removing %s to networksets for %s", nsLabels, sel)
	x.NetworkSets.Discard(nsLabels)
	c.QueueUpdate(sel, nil, EventNetsetMatchStopped)
}

func (c *networkPolicyRuleSelectorsEngine) policyMatchStarted(pol, sel apiv3.ResourceID) {
	x, ok := c.GetFromOurCache(sel).(*CacheEntryNetworkPolicyRuleSelector)
	if !ok {
		log.Errorf("Match started on selector, but selector is not in cache: %s matches %s", sel, pol)
		return
	}
	x.clog.Debugf("Adding %s to policies for %s", pol, sel)
	x.Policies.Add(pol)
}

func (c *networkPolicyRuleSelectorsEngine) policyMatchStopped(pol, sel apiv3.ResourceID) {
	x, ok := c.GetFromOurCache(sel).(*CacheEntryNetworkPolicyRuleSelector)
	if !ok {
		log.Errorf("Match stopped on selector, but selector is not in cache: %s matches %s", sel, pol)
		return
	}
	x.clog.Debugf("Removing %s from policies for %s", pol, sel)
	x.Policies.Discard(pol)
}
