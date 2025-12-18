package policystore

import (
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type DomainIPSetsDataplane struct {
	ipFamily           ipsets.IPFamily
	policyStoreManager PolicyStoreManager
}

func NewDomainIPSetsDataplane(ipFamily ipsets.IPFamily, policyStoreManager PolicyStoreManager) *DomainIPSetsDataplane {
	return &DomainIPSetsDataplane{
		ipFamily:           ipFamily,
		policyStoreManager: policyStoreManager,
	}
}

// AddOrReplaceIPSet adds or replaces an IP set of the policy store with the given members.
func (s *DomainIPSetsDataplane) AddOrReplaceIPSet(setMetadata ipsets.IPSetMetadata, members []string) {
	if setMetadata.UpdateType != proto.IPSetUpdate_DOMAIN {
		// This implementation only supports domain IP sets.
		return
	}

	log.Debugf("Updating domain IP set %v with members: %v", setMetadata.SetID, members)
	s.policyStoreManager.DoWithLock(func(store *PolicyStore) {
		// Get the existing IPSet or create a new one
		ipset, exists := store.IPSetByID[setMetadata.SetID]
		if !exists {
			if ipset = NewIPSet(proto.IPSetUpdate_DOMAIN); ipset == nil {
				log.Errorf("Failed to create IPSet for domain IP set %v", setMetadata.SetID)
				return
			}
			store.IPSetByID[setMetadata.SetID] = ipset
		}

		// Remove members that are not in the new members
		memberSet := set.FromArray(members)
		for _, member := range ipset.Members() {
			if !memberSet.Contains(member) {
				ipset.RemoveString(member)
			} else {
				// The member is already set, no need to add it again later
				memberSet.Discard(member)
			}
		}
		// Add the remaining new members that are not already in ipset
		for member := range memberSet.All() {
			ipset.AddString(member)
		}
	})
}

// AddMembers adds new members to the IP set of the policy store with the given ID.
func (s *DomainIPSetsDataplane) AddMembers(setID string, newMembers []string) {
	log.Debugf("Adding new members to IP set %v: %v", setID, newMembers)
	s.policyStoreManager.DoWithLock(func(store *PolicyStore) {
		if ipset, ok := store.IPSetByID[setID]; ok {
			for _, addr := range newMembers {
				ipset.AddString(addr)
			}
		}
	})
}

// RemoveMembers removes members from the IP set of the policy store with the given ID.
func (s *DomainIPSetsDataplane) RemoveMembers(setID string, removedMembers []string) {
	log.Debugf("Removing members from IP set %v: %v", setID, removedMembers)
	s.policyStoreManager.DoWithLock(func(store *PolicyStore) {
		if ipset, ok := store.IPSetByID[setID]; ok {
			for _, addr := range removedMembers {
				ipset.RemoveString(addr)
			}
		}
	})
}

// RemoveIPSet removes the IP set of the policy store with the given ID.
func (s *DomainIPSetsDataplane) RemoveIPSet(setID string) {
	log.Debugf("Removing IP set %v", setID)
	s.policyStoreManager.DoWithLock(func(store *PolicyStore) {
		delete(store.IPSetByID, setID)
	})
}

// GetIPFamily returns the IP family of the IP set.
func (s *DomainIPSetsDataplane) GetIPFamily() ipsets.IPFamily {
	return s.ipFamily
}

// GetTypeOf returns the type of the IP set with the given ID. This implementation always returns
// IPSetTypeHashIP, corresponding to domain IP sets.
func (s *DomainIPSetsDataplane) GetTypeOf(setID string) (ipsets.IPSetType, error) {
	return ipsets.IPSetTypeHashIP, nil
}
