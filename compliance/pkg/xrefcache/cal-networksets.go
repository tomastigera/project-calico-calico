// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package xrefcache

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/compliance/pkg/internet"
	"github.com/projectcalico/calico/compliance/pkg/syncer"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var (
	KindsNetworkSet = []metav1.TypeMeta{
		resources.TypeCalicoGlobalNetworkSets,
		resources.TypeCalicoNetworkSets,
	}
)

// VersionedNetworkSetResource is an extension to the VersionedResource interface with some NetworkSet specific
// helper methods.
type VersionedNetworkSetResource interface {
	VersionedResource
	GetCalicoV1NetworkSet() *model.NetworkSet
	IsNamespaced() bool
}

// CacheEntryNetworkSet is a cache entry in the network set cache. Each entry implements the CacheEntry
// interface.
type CacheEntryNetworkSet struct {
	// The versioned network set resource.
	VersionedNetworkSetResource

	// Boolean values associated with this NetworkSet. Valid flags defined by CacheEntryFlagsNetworkSet.
	Flags CacheEntryFlags

	// The set of policy (allow) rule selectors that match this network set.
	PolicyRuleSelectors set.Typed[apiv3.ResourceID]

	// --- Internal data ---
	cacheEntryCommon
	clog *log.Entry
}

// getVersionedResource implements the CacheEntry interface.
func (c *CacheEntryNetworkSet) getVersionedResource() VersionedResource {
	return c.VersionedNetworkSetResource
}

// setVersionedResource implements the CacheEntry interface.
func (c *CacheEntryNetworkSet) setVersionedResource(r VersionedResource) {
	c.VersionedNetworkSetResource = r.(VersionedNetworkSetResource)
}

// versionedCalicoGlobalNetworkSet implements the VersionedNetworkSetResource for a Calico GlobalNetworkSet.
type versionedCalicoGlobalNetworkSet struct {
	*apiv3.GlobalNetworkSet
	v1 *model.NetworkSet
}

// GetPrimary implements the VersionedNetworkSetResource interface.
func (v *versionedCalicoGlobalNetworkSet) GetPrimary() resources.Resource {
	return v.GlobalNetworkSet
}

// GetCalicoV3 implements the VersionedNetworkSetResource interface.
func (v *versionedCalicoGlobalNetworkSet) GetCalicoV3() resources.Resource {
	return v.GlobalNetworkSet
}

// getCalicoV1 implements the VersionedNetworkSetResource interface.
func (v *versionedCalicoGlobalNetworkSet) GetCalicoV1() interface{} {
	return v.v1
}

// GetCalicoV1NetworkSet implements the VersionedNetworkSetResource interface.
func (v *versionedCalicoGlobalNetworkSet) GetCalicoV1NetworkSet() *model.NetworkSet {
	return v.v1
}

// IsNamespaced implements the VersionedNetworkSetResource interface.
func (v *versionedCalicoGlobalNetworkSet) IsNamespaced() bool {
	return false
}

// versionedCalicoNetworkSet implements the VersionedNetworkSetResource for a Calico NetworkSet kind.
type versionedCalicoNetworkSet struct {
	*apiv3.NetworkSet
	v1 *model.NetworkSet
}

// GetPrimary implements the VersionedNetworkSetResource interface.
func (v *versionedCalicoNetworkSet) GetPrimary() resources.Resource {
	return v.NetworkSet
}

// GetCalicoV3 implements the VersionedPolicyResource interface.
func (v *versionedCalicoNetworkSet) GetCalicoV3() resources.Resource {
	return v.NetworkSet
}

// getCalicoV1 implements the VersionedPolicyResource interface.
func (v *versionedCalicoNetworkSet) GetCalicoV1() interface{} {
	return v.v1
}

// GetCalicoV1NetworkSet implements the VersionedPolicyResource interface.
func (v *versionedCalicoNetworkSet) GetCalicoV1NetworkSet() *model.NetworkSet {
	return v.v1
}

// IsNamespaced implements the VersionedPolicyResource interface.
func (v *versionedCalicoNetworkSet) IsNamespaced() bool {
	return true
}

// newNetworkSetHandler creates a new handler used for the NetworkSet cache.
func newNetworkSetHandler() resourceHandler {
	return &networkSetHandler{}
}

// networkSetHandler implements the resourceHandler interface for the network set cache.
type networkSetHandler struct {
	CacheAccessor
}

// register implements the resourceHandler interface.
func (c *networkSetHandler) register(cache CacheAccessor) {
	c.CacheAccessor = cache

	// Register with the allow-rule label seletor so that we can track which allow rules are using this NetworkSet.
	c.NetworkSetLabelSelector().RegisterCallbacks(c.kinds(), c.selectorMatchStarted, c.selectorMatchStopped)
}

// kinds implements the resourceHandler interface.
func (c *networkSetHandler) kinds() []metav1.TypeMeta {
	return KindsNetworkSet
}

// newCacheEntry implements the resourceHandler interface.
func (c *networkSetHandler) newCacheEntry() CacheEntry {
	return &CacheEntryNetworkSet{
		PolicyRuleSelectors: set.New[apiv3.ResourceID](),
	}
}

// resourceAdded implements the resourceHandler interface.
func (c *networkSetHandler) resourceAdded(id apiv3.ResourceID, entry CacheEntry) {
	entry.(*CacheEntryNetworkSet).clog = log.WithField("id", id)
	c.resourceUpdated(id, entry, nil)
}

// resourceUpdated implements the resourceHandler interface.
func (c *networkSetHandler) resourceUpdated(id apiv3.ResourceID, entry CacheEntry, prev VersionedResource) {
	// Use the V1 labels to register with the label selection handler.
	x := entry.(*CacheEntryNetworkSet)

	// Update the labels for this network set. Always update the labels first so that each cache can get a view of the
	// links before we start sending updates.
	c.NetworkSetLabelSelector().UpdateLabels(id, x.GetCalicoV1NetworkSet().Labels, nil)
}

// resourceDeleted implements the resourceHandler interface.
func (c *networkSetHandler) resourceDeleted(id apiv3.ResourceID, entry CacheEntry) {
	c.NetworkSetLabelSelector().DeleteLabels(id)
}

// recalculate implements the resourceHandler interface.
func (c *networkSetHandler) recalculate(id apiv3.ResourceID, entry CacheEntry) syncer.UpdateType {
	x := entry.(*CacheEntryNetworkSet)

	// Determine whether this network set contains any internet addresses.
	changed := c.scanNets(x)
	x.clog.Debugf("Recalculated, returning update %d, flags now: %d", changed, x.Flags)
	return changed
}

// convertToVersioned implements the resourceHandler interface.
func (c *networkSetHandler) convertToVersioned(res resources.Resource) (VersionedResource, error) {
	// Accept AAPIS versions of the Calico resources, but convert them to the libcalico-go versions.
	switch tr := res.(type) {
	case *apiv3.GlobalNetworkSet:
		res = &apiv3.GlobalNetworkSet{
			TypeMeta:   tr.TypeMeta,
			ObjectMeta: tr.ObjectMeta,
			Spec:       tr.Spec,
		}
	case *apiv3.NetworkSet:
		res = &apiv3.NetworkSet{
			TypeMeta:   tr.TypeMeta,
			ObjectMeta: tr.ObjectMeta,
			Spec:       tr.Spec,
		}
	}

	switch in := res.(type) {
	case *apiv3.NetworkSet:
		in = res.(*apiv3.NetworkSet)

		v1, err := updateprocessors.ConvertNetworkSetV3ToV1(&model.KVPair{
			Key: model.ResourceKey{
				Kind:      apiv3.KindNetworkSet,
				Name:      in.Name,
				Namespace: in.Namespace,
			},
			Value: in,
		})
		if err != nil {
			return nil, err
		}

		return &versionedCalicoNetworkSet{
			NetworkSet: in,
			v1:         v1.Value.(*model.NetworkSet),
		}, nil
	case *apiv3.GlobalNetworkSet:
		in = res.(*apiv3.GlobalNetworkSet)

		v1, err := updateprocessors.ConvertGlobalNetworkSetV3ToV1(&model.KVPair{
			Key: model.ResourceKey{
				Kind: apiv3.KindGlobalNetworkSet,
				Name: in.Name,
			},
			Value: in,
		})
		if err != nil {
			return nil, err
		}

		return &versionedCalicoGlobalNetworkSet{
			GlobalNetworkSet: in,
			v1:               v1.Value.(*model.NetworkSet),
		}, nil
	}

	return nil, fmt.Errorf("unhandled resource type: %v", res)
}

// scanNets checks the nets in the resource for certain properties (currently just if it contains any non-private
// CIDRs.
func (c *networkSetHandler) scanNets(x *CacheEntryNetworkSet) syncer.UpdateType {
	old := x.Flags
	// Toggle the InternetAddressExposed flag
	x.Flags &^= CacheEntryInternetExposed
	if internet.NetsContainInternetAddr(x.GetCalicoV1NetworkSet().Nets) {
		x.Flags |= CacheEntryInternetExposed
	}

	// Determine flags that have changed, and convert to an update type. See notes in flags.go.
	changed := syncer.UpdateType(old ^ x.Flags)

	// Return which flags have changed and return as an update type. See notes in flags.go.
	return changed
}

// selectorMatchStarted is called synchronously from the rule selector or network set resource update methods when a
// selector<->netset match has started. We update our set of matched selectors.
func (c *networkSetHandler) selectorMatchStarted(selId, netsetId apiv3.ResourceID) {
	x, ok := c.GetFromOurCache(netsetId).(*CacheEntryNetworkSet)
	if !ok {
		// This is called synchronously from the resource update methods, so we don't expect the entries to have been
		// removed from the cache at this point.
		log.Errorf("Match started on NetworkSet, but NetworkSet is not in cache: %s matches %s", selId, netsetId)
		return
	}
	// Update the selector set in our network set data. No need to queue an async recalculation since this won't affect
	// our settings *and* we don't notify the cache listeners about this event type.
	x.clog.Debugf("Adding %s to policyRuleSelectors for %s", selId, netsetId)
	x.PolicyRuleSelectors.Add(selId)
}

// selectorMatchStopped is called synchronously from the rule selector or network set resource update methods when a
// selector<->netset match has stopped. We update our set of matched selectors.
func (c *networkSetHandler) selectorMatchStopped(selId, netsetId apiv3.ResourceID) {
	x, ok := c.GetFromOurCache(netsetId).(*CacheEntryNetworkSet)
	if !ok {
		// This is called synchronously from the resource update methods, so we don't expect the entries to have been
		// removed from the cache at this point.
		log.Errorf("Match started on NetworkSet, but NetworkSet is not in cache: %s matches %s", selId, netsetId)
		return
	}
	// Update the selector set in our network set data. No need to queue an async recalculation since this won't affect
	// our settings *and* we don't notify the cache listeners about this event type.
	x.clog.Debugf("Removing %s from policyRuleSelectors for %s", selId, netsetId)
	x.PolicyRuleSelectors.Discard(selId)
}
