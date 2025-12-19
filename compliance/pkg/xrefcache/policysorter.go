package xrefcache

import (
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

type PolicySorter interface {
	GetOrderedTiersAndPolicies() []*TierWithOrderedPolicies
	sort()
	updatePolicy(resource *CacheEntryNetworkPolicy)
	deletePolicy(resource *CacheEntryNetworkPolicy)
	updateTier(resource *CacheEntryTier)
	deleteTier(resource *CacheEntryTier)
}

// policySorter implements the PolicySorter interface.
type policySorter struct {
	sorter       *calc.PolicySorter
	dirty        bool
	orderedTiers []*TierWithOrderedPolicies

	// Store our own map of tiers and policies keyed off the v1 key. This is required because the felix policy
	// sorter will return a set of ordered v1 tiers and policies and we need to map that to our multi-version
	// representations.
	tiers    map[string]*CacheEntryTier
	policies map[model.PolicyKey]*CacheEntryNetworkPolicy
}

// newPolicySorter creates a new PolicySorter
func newPolicySorter() PolicySorter {
	return &policySorter{
		sorter:   calc.NewPolicySorter(),
		dirty:    true,
		tiers:    make(map[string]*CacheEntryTier),
		policies: make(map[model.PolicyKey]*CacheEntryNetworkPolicy),
	}
}

// GetOrderedTiers returns the ordered list of tiers. Each tier may be queried to obtain the ordered set of policies
// within the tier.
func (p *policySorter) GetOrderedTiersAndPolicies() []*TierWithOrderedPolicies {
	p.sort()
	return p.orderedTiers
}

// sort sorts the tiers and policies within the xrefCache.
func (p *policySorter) sort() {
	if !p.dirty {
		return
	}

	log.Info("Tier/policy ordering needs to be recalculated")
	tierInfos := p.sorter.Sorted()
	p.orderedTiers = make([]*TierWithOrderedPolicies, 0, len(tierInfos))
	for _, t := range tierInfos {
		// Get the tier cache entry for this tier. We have the v1 model to hand, so need to convert this to
		// the v3 ResourceID to lookup our cache entry.
		te := p.tiers[t.Name]
		if te == nil {
			log.WithField("tier", t.Name).Error("Tier is not in cache")
			continue
		}
		twp := &TierWithOrderedPolicies{Tier: te}
		p.orderedTiers = append(p.orderedTiers, twp)

		// Now loop through the policies in the tier and construct the ordered set of network policy cache entries
		// and assign to the tier cache entry.
		twp.OrderedPolicies = make([]*CacheEntryNetworkPolicy, 0, len(t.OrderedPolicies))
		for _, pol := range t.OrderedPolicies {
			entry := p.policies[pol.Key]
			if entry == nil {
				log.WithField("policy", pol.Key).Error("Policy is not in cache")
				continue
			}
			twp.OrderedPolicies = append(twp.OrderedPolicies, entry)
		}
	}
	p.dirty = false
}

// updatePolicy is called when a policy resource is updated.
func (p *policySorter) updatePolicy(entry *CacheEntryNetworkPolicy) {
	v1Key := entry.GetCalicoV1Key()
	dirty := p.sorter.OnUpdate(api.Update{
		UpdateType: api.UpdateTypeKVUpdated,
		KVPair: model.KVPair{
			Key:   v1Key,
			Value: entry.GetCalicoV1Policy(),
		},
	})
	p.policies[v1Key] = entry
	p.dirty = p.dirty || dirty
}

// deletePolicy is called when a policy resource is deleted.
func (p *policySorter) deletePolicy(entry *CacheEntryNetworkPolicy) {
	v1Key := entry.GetCalicoV1Key()
	dirty := p.sorter.OnUpdate(api.Update{
		UpdateType: api.UpdateTypeKVDeleted,
		KVPair: model.KVPair{
			Key: v1Key,
		},
	})
	delete(p.policies, v1Key)
	p.dirty = p.dirty || dirty
}

// updateTier is called when a tier resource is updated.
func (p *policySorter) updateTier(entry *CacheEntryTier) {
	v1Key := entry.GetCalicoV1Key()
	dirty := p.sorter.OnUpdate(api.Update{
		UpdateType: api.UpdateTypeKVUpdated,
		KVPair: model.KVPair{
			Key:   v1Key,
			Value: entry.GetCalicoV1Tier(),
		},
	})
	p.tiers[v1Key.Name] = entry
	p.dirty = p.dirty || dirty
}

// deleteTier is called when a tier resource is deleted.
func (p *policySorter) deleteTier(entry *CacheEntryTier) {
	v1Key := entry.GetCalicoV1Key()
	dirty := p.sorter.OnUpdate(api.Update{
		UpdateType: api.UpdateTypeKVDeleted,
		KVPair: model.KVPair{
			Key: v1Key,
		},
	})
	delete(p.tiers, v1Key.Name)
	p.dirty = p.dirty || dirty
}
