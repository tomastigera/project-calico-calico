// Copyright (c) 2016-2024 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ipsets

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/dataplane/common"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type BaseIPSetsDataplane interface {
	AddOrReplaceIPSet(setMetadata ipsets.IPSetMetadata, members []string)
	AddMembers(setID string, newMembers []string)
	RemoveMembers(setID string, removedMembers []string)
	RemoveIPSet(setID string)
	GetIPFamily() ipsets.IPFamily
	GetTypeOf(setID string) (ipsets.IPSetType, error)
}

type IPSetsDataplane interface {
	BaseIPSetsDataplane
	GetDesiredMembers(setID string) (set.Set[string], error)
	QueueResync()
	ApplyUpdates(listener UpdateListener)
	ApplyDeletions() (reschedule bool)
	SetFilter(neededIPSets set.Set[string])
}

type UpdateListener = ipsets.UpdateListener

// Except for domain IP sets, IPSetsManager simply passes through IP set updates from the datastore
// to the ipsets.IPSets dataplane layer.  For domain IP sets - which hereafter we'll just call
// "domain sets" - IPSetsManager handles the resolution from domain names to expiring IPs.
type IPSetsManager struct {
	dataplanes []BaseIPSetsDataplane
	maxSize    int
	lg         *log.Entry

	// Provider of domain name to IP information.
	domainInfoStore IPSetsDomainStore

	// Map from each active domain set ID to the IPs that are currently programmed for it and
	// why. The interior map is from each IP to the set of lower case domain names that have resolved to
	// that IP.
	domainSetProgramming map[string]map[string]set.Set[string]

	// Map from each active lower case domain name to the IDs of the domain sets that include that domain
	// name.
	domainSetIds map[string]set.Set[string]

	// IP set IDs that we don't process.
	ignoredSetIds set.Set[string]
	// domainTracker is an optional external component that tracks which domains are part
	// of which ipset.
	domainTracker IPSetsDomainTracker
}

type IPSetsDomainStore interface {
	// Register this IPSets manager as a user of the DomainInfoStore.
	RegisterHandler(common.DomainInfoChangeHandler)
	// Get the IPs for a given domain name.
	GetDomainIPs(domain string) []string
}

type IPSetsDomainTracker interface {
	Add(domain string, setIDs ...string)
	Delete(domain string, setIDs ...string)
	ApplyAllChanges() error
}

func NewIPSetsManager(name string, ipsets_ IPSetsDataplane, maxIPSetSize int,
	domainInfoStore IPSetsDomainStore,
) *IPSetsManager {
	m := &IPSetsManager{
		maxSize:         maxIPSetSize,
		lg:              log.WithField("name", name),
		domainInfoStore: domainInfoStore,

		domainSetProgramming: make(map[string]map[string]set.Set[string]),
		domainSetIds:         make(map[string]set.Set[string]),
		ignoredSetIds:        set.New[string](),
	}

	if ipsets_ != nil {
		m.dataplanes = append(m.dataplanes, ipsets_)
	}

	domainInfoStore.RegisterHandler(m)
	return m
}

func (m *IPSetsManager) AddDataplane(dp BaseIPSetsDataplane) {
	m.dataplanes = append(m.dataplanes, dp)
}

func (m *IPSetsManager) AddDomainTracker(domainTracker IPSetsDomainTracker) {
	m.domainTracker = domainTracker
}

func (m *IPSetsManager) GetIPSetType(setID string) (typ ipsets.IPSetType, err error) {
	for _, dp := range m.dataplanes {
		typ, err = dp.GetTypeOf(setID)
		if err == nil {
			break
		}
	}
	return
}

func (m *IPSetsManager) GetIPSetMembers(setID string) (members set.Set[string], err error) {
	for _, dp := range m.dataplanes {
		if dpWithMembers, ok := dp.(IPSetsDataplane); ok {
			if members, err = dpWithMembers.GetDesiredMembers(setID); err == nil {
				break
			}
		}
	}
	return
}

func (m *IPSetsManager) OnUpdate(msg any) {
	switch msg := msg.(type) {
	// IP set-related messages, these are extremely common.
	case *proto.IPSetDeltaUpdate:
		m.lg.WithField("ipSetId", msg.Id).Debug("IP set delta update")
		if m.domainSetProgramming[msg.Id] != nil {
			// Work needed to resolve domain name deltas against the current ipset
			// programming.  These domain names may be mixed case.
			m.handleDomainIPSetDeltaUpdate(msg.Id, msg.RemovedMembers, msg.AddedMembers)
		} else if !m.ignoredSetIds.Contains(msg.Id) {
			// Pass deltas directly to the ipsets dataplane layer(s).
			for _, dp := range m.dataplanes {
				dp.AddMembers(msg.Id, msg.AddedMembers)
				dp.RemoveMembers(msg.Id, msg.RemovedMembers)
			}
		}
	case *proto.IPSetUpdate:
		m.lg.WithField("ipSetId", msg.Id).Debug("IP set update")
		var setType ipsets.IPSetType
		switch msg.Type {
		case proto.IPSetUpdate_IP:
			setType = ipsets.IPSetTypeHashIP
		case proto.IPSetUpdate_NET:
			setType = ipsets.IPSetTypeHashNet
		case proto.IPSetUpdate_IP_AND_PORT:
			setType = ipsets.IPSetTypeHashIPPort
		case proto.IPSetUpdate_DOMAIN:
			setType = ipsets.IPSetTypeHashIP
		case proto.IPSetUpdate_EGRESS_IP:
			// Ignore this IP set.
			m.ignoredSetIds.Add(msg.Id)
			return
		case proto.IPSetUpdate_NET_NET:
			setType = ipsets.IPSetTypeHashNetNet
		case proto.IPSetUpdate_PORTS:
			setType = ipsets.IPSetTypeBitmapPort
		default:
			m.lg.WithField("type", msg.Type).Panic("Unknown IP set type")
		}

		metadata := ipsets.IPSetMetadata{
			Type:       setType,
			UpdateType: msg.Type,
			SetID:      msg.Id,
			MaxSize:    m.maxSize,
		}
		if setType == ipsets.IPSetTypeBitmapPort {
			metadata.MaxSize = 0
			metadata.RangeMax = 0xffff
		}

		if msg.Type == proto.IPSetUpdate_DOMAIN {
			// Work needed to resolve domain names to expiring IPs.  These domain names may be mixed case.
			m.handleDomainIPSetUpdate(msg, &metadata)
		} else {
			// Pass directly onto the ipsets dataplane layer(s).
			for _, dp := range m.dataplanes {
				dp.AddOrReplaceIPSet(metadata, msg.Members)
			}
		}
	case *proto.IPSetRemove:
		m.lg.WithField("ipSetId", msg.Id).Debug("IP set remove")
		if m.domainSetProgramming[msg.Id] != nil {
			// Remove tracking data for this domain set.
			m.removeDomainIPSetTracking(msg.Id)
		}
		if m.ignoredSetIds.Contains(msg.Id) {
			m.ignoredSetIds.Discard(msg.Id)
			return
		}
		for _, dp := range m.dataplanes {
			dp.RemoveIPSet(msg.Id)
		}
	}
}

func (m *IPSetsManager) CompleteDeferredWork() error {
	if m.domainTracker != nil {
		err := m.domainTracker.ApplyAllChanges()
		if err != nil {
			return fmt.Errorf("failed to apply changes to domain tracker: %w", err)
		}
	}

	return nil
}

func (m *IPSetsManager) domainIncludedInSet(domain string, ipSetId string) {
	if m.domainSetIds[domain] != nil {
		m.domainSetIds[domain].Add(ipSetId)
	} else {
		m.domainSetIds[domain] = set.From(ipSetId)
	}
}

func (m *IPSetsManager) domainRemovedFromSet(domain string, ipSetId string) {
	if m.domainSetIds[domain] != nil {
		m.domainSetIds[domain].Discard(ipSetId)
		if m.domainSetIds[domain].Len() == 0 {
			delete(m.domainSetIds, domain)
		}
	}

	if m.domainTracker != nil {
		m.domainTracker.Delete(domain, ipSetId)
	}
}

func (m *IPSetsManager) handleDomainIPSetUpdate(msg *proto.IPSetUpdate, metadata *ipsets.IPSetMetadata) {
	log.Infof("Update whole domain set: msg=%v metadata=%v", msg, metadata)

	if m.domainSetProgramming[msg.Id] != nil {
		log.Info("IPSetUpdate for existing IP set")
		domainsToAdd := set.New[string]()
		domainsToRemove := set.New[string]()
		for _, mixedCaseMsgDomain := range msg.Members {
			domainsToAdd.Add(mixedCaseMsgDomain)
		}
		for domain, domainSetIds := range m.domainSetIds {
			if domainSetIds.Contains(msg.Id) {
				// Domain set previously included this domain name.
				if domainsToAdd.Contains(domain) {
					// And it still should, so don't re-add it.
					domainsToAdd.Discard(domain)
				} else {
					// And now it doesn't, so remove it.
					domainsToRemove.Add(domain)
				}
			}
		}
		m.handleDomainIPSetDeltaUpdate(msg.Id, domainsToRemove.Slice(), domainsToAdd.Slice())
		return
	}

	// Accumulator for the IPs that we need to program for this domain set.
	ipToDomains := make(map[string]set.Set[string])

	// For each domain name in this set...
	for _, mixedCaseDomain := range msg.Members {
		domain := strings.ToLower(mixedCaseDomain)
		// Update the reverse map that tells us all of the domain sets that include a given
		// domain name.
		m.domainIncludedInSet(domain, msg.Id)

		// Merge the IPs for this domain into the accumulator.
		for _, ip := range m.domainInfoStore.GetDomainIPs(domain) {
			if ipToDomains[ip] == nil {
				ipToDomains[ip] = set.New[string]()
			}
			ipToDomains[ip].Add(domain)
		}
	}

	// Convert that to a list of members for the ipset dataplane layer to program.
	ipMembers := make([]string, 0, len(ipToDomains))
	for ip := range ipToDomains {
		ipMembers = append(ipMembers, ip)
	}
	// Note: no XDP Callbacks here because XDP is for ingress policy only and domain
	// IP sets are egress only.
	for _, dp := range m.dataplanes {
		dp.AddOrReplaceIPSet(*metadata, ipMembers)
	}

	if m.domainTracker != nil {
		// Now that we created the IPsets that possibly did not exists, we can update the
		// tracker so it points to existing sets.
		for _, mixedCaseDomain := range msg.Members {
			domain := strings.ToLower(mixedCaseDomain)
			m.domainTracker.Add(domain, msg.Id)
		}
	}

	// Record the programming that we've asked the dataplane for.
	m.domainSetProgramming[msg.Id] = ipToDomains
}

func (m *IPSetsManager) handleDomainIPSetDeltaUpdate(ipSetId string, domainsRemoved []string, domainsAdded []string) {
	log.Infof("Domain set delta update: id=%v removed=%v added=%v", ipSetId, domainsRemoved, domainsAdded)
	m.handleDomainIPSetDeltaUpdateNoLog(ipSetId, domainsRemoved, domainsAdded)
}

func (m *IPSetsManager) handleDomainIPSetDeltaUpdateNoLog(ipSetId string, domainsRemoved []string, domainsAdded []string) {
	// Get the current programming for this domain set.
	ipToDomains := m.domainSetProgramming[ipSetId]
	if ipToDomains == nil {
		log.Panic("Got IPSetDeltaUpdate for an unknown IP set")
	}

	// Accumulators for the IPs that we need to remove and add.  Do remove processing first, so
	// that it works to process a domain info change by calling this function with the same
	// domain name being removed and then added again.
	ipsToRemove := set.New[string]()
	ipsToAdd := set.New[string]()

	// For each removed domain name...
	for _, mixedCaseDomain := range domainsRemoved {
		// Update the reverse map that tells us all of the domain sets that include a given
		// domain name.
		domain := strings.ToLower(mixedCaseDomain)
		m.domainRemovedFromSet(domain, ipSetId)
	}

	// For each programmed IP...
	for ip, domains := range ipToDomains {
		// Remove the removed domains.
		for _, domain := range domainsRemoved {
			domains.Discard(strings.ToLower(domain))
		}
		if domains.Len() == 0 {
			// We should remove this IP now.
			ipsToRemove.Add(ip)
			delete(ipToDomains, ip)
		}
	}

	// For each new domain name...
	for _, mixedCaseDomain := range domainsAdded {
		domain := strings.ToLower(mixedCaseDomain)
		// Update the reverse map that tells us all of the domain sets that include a given
		// domain name.
		m.domainIncludedInSet(domain, ipSetId)
		if m.domainTracker != nil {
			m.domainTracker.Add(domain, ipSetId)
		}

		// Get the IPs and expiry times for this domain, then merge those into the current
		// programming, noting any updates that we need to send to the dataplane.
		for _, ip := range m.domainInfoStore.GetDomainIPs(domain) {
			if ipToDomains[ip] == nil {
				ipToDomains[ip] = set.New[string]()
				ipsToAdd.Add(ip)
			}
			ipToDomains[ip].Add(domain)
		}
	}

	// If there are any IPs that are now in both ipsToRemove and ipsToAdd, we don't need either
	// to add or remove those IPs.
	for item := range ipsToRemove.All() {
		if ipsToAdd.Contains(item) {
			ipsToAdd.Discard(item)
			ipsToRemove.Discard(item)
		}
	}

	// Pass IP deltas onto the ipsets dataplane layer.  Note: no XDP Callbacks here
	// because XDP is for ingress policy only and domain IP sets are egress only.
	for _, dp := range m.dataplanes {
		dp.RemoveMembers(ipSetId, ipsToRemove.Slice())
		dp.AddMembers(ipSetId, ipsToAdd.Slice())
	}
}

func (m *IPSetsManager) removeDomainIPSetTracking(ipSetId string) {
	log.Infof("Domain set removed: id=%v", ipSetId)
	for domain := range m.domainSetIds {
		m.domainRemovedFromSet(domain, ipSetId)
	}
	delete(m.domainSetProgramming, ipSetId)
}

// This function may be called with a lowercase domain name when the original watch was uppercase.
func (m *IPSetsManager) OnDomainChange(domain string) (dataplaneSyncNeeded bool) {
	log.WithFields(log.Fields{"domain": domain}).Debug("Domain info changed")

	// Find the affected domain sets (note that the domain is always lowercased).
	domainSetIds := m.domainSetIds[domain]
	if domainSetIds != nil {
		// This is a domain name of active interest, so report that a dataplane sync will be
		// needed.
		dataplaneSyncNeeded = true

		// Tell each domain set that includes this domain name to requery the IPs for the
		// domain name and adjust its overall IP set accordingly.
		for item := range domainSetIds.All() {
			// Handle as a delta update where the same domain name is removed and then re-added.
			m.handleDomainIPSetDeltaUpdateNoLog(item, []string{domain}, []string{domain})
		}
	}

	return
}

type IPSetsDomainStoreVoid struct{}

func (*IPSetsDomainStoreVoid) RegisterHandler(common.DomainInfoChangeHandler) {}
func (*IPSetsDomainStoreVoid) GetDomainIPs(domain string) []string            { return nil }
