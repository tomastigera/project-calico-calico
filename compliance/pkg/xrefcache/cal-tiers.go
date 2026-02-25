// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package xrefcache

import (
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/compliance/pkg/syncer"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
)

var (
	KindsTier = []metav1.TypeMeta{
		resources.TypeCalicoTiers,
	}
)

type VersionedTierResource interface {
	VersionedResource
	GetCalicoV1Key() model.TierKey
	GetCalicoV1Tier() *model.Tier
}

type CacheEntryTier struct {
	// The versioned network set resource.
	VersionedTierResource

	// --- Internal data ---
	cacheEntryCommon
	policySorter PolicySorter
}

func (c *CacheEntryTier) getVersionedResource() VersionedResource {
	return c.VersionedTierResource
}

func (c *CacheEntryTier) setVersionedResource(r VersionedResource) {
	c.VersionedTierResource = r.(VersionedTierResource)
}

type versionedCalicoTier struct {
	*apiv3.Tier
	v1 *model.Tier
}

// GetPrimary implements the VersionedTierResource interface.
func (v *versionedCalicoTier) GetPrimary() resources.Resource {
	return v.Tier
}

func (v *versionedCalicoTier) GetCalicoV3() resources.Resource {
	return v.Tier
}

func (v *versionedCalicoTier) GetCalicoV1() any {
	return v.v1
}

// GetCalicoV1Key implements the VersionedTierResource interface.
func (v *versionedCalicoTier) GetCalicoV1Key() model.TierKey {
	return model.TierKey{
		Name: v.Name,
	}
}

func (v *versionedCalicoTier) GetCalicoV1Tier() *model.Tier {
	return v.v1
}

func newTierHandler() resourceHandler {
	return &tierHandler{}
}

type tierHandler struct {
	CacheAccessor
}

func (c *tierHandler) register(cache CacheAccessor) {
	c.CacheAccessor = cache
}

func (c *tierHandler) kinds() []metav1.TypeMeta {
	return KindsTier
}

func (c *tierHandler) newCacheEntry() CacheEntry {
	return &CacheEntryTier{
		policySorter: c.PolicySorter(),
	}
}

func (c *tierHandler) resourceAdded(id apiv3.ResourceID, entry CacheEntry) {
	c.resourceUpdated(id, entry, nil)
}

func (c *tierHandler) resourceUpdated(id apiv3.ResourceID, entry CacheEntry, prev VersionedResource) {
	// Update the policy sorter.
	x := entry.(*CacheEntryTier)
	c.PolicySorter().updateTier(x)
}

func (c *tierHandler) resourceDeleted(id apiv3.ResourceID, entry CacheEntry) {
	// Delete the tier from the policy sorter.
	x := entry.(*CacheEntryTier)
	c.PolicySorter().deleteTier(x)
}

// recalculate implements the resourceHandler interface.
func (c *tierHandler) recalculate(podId apiv3.ResourceID, podEntry CacheEntry) syncer.UpdateType {
	// We calculate all state in the resourceUpdated/resourceAdded callbacks.
	return 0
}

func (c *tierHandler) convertToVersioned(res resources.Resource) (VersionedResource, error) {
	// Accept AAPIS versions of the Calico resources, but convert them to the libcalico-go versions.
	switch tr := res.(type) {
	case *apiv3.Tier:
		res = &apiv3.Tier{
			TypeMeta:   tr.TypeMeta,
			ObjectMeta: tr.ObjectMeta,
			Spec:       tr.Spec,
		}
	}

	in := res.(*apiv3.Tier)

	v1, err := updateprocessors.ConvertTierV3ToV1Value(in)
	if err != nil {
		return nil, err
	}

	return &versionedCalicoTier{
		Tier: in,
		v1:   v1.(*model.Tier),
	}, nil
}
