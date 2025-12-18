//go:build !windows

// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package dnsresolver

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/tchap/go-patricia/v2/patricia"

	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/cachingmap"
	"github.com/projectcalico/calico/felix/idalloc"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// DomainTracker tracks which domains are associated with what ipsets. That is,
// when a domain is resolved to an IP, which ipsets need to be updated with that
// IP. Similarly, when a domain is removed, from which ipsets do we need to
// clear the domains IPs. Since we allow wildcards (in this case only sufix
// wildcards of the for *.com) we need to be able to match the wildcards rather
// than just keep a list of domain->ipsets mappings. To accomodate for the
// matching, BPF code uses trie for longest prefix match. Since the wildcards
// are suffixes, we reverse the string, that is, *.com becomes moc.(*) - the * is
// stripped. However, we cannot just say *.com is in sets x y z when cnn.com is
// in sets v and w. If the bpf code matches cnn.com it must add the IP to any
// ipsets that matches *.com. Similarly. anything that matches *.ubuntu.com,
// must also match *.com but not cnn.com, while news.cnn.com must match both
// *.cnn.com as well as *.com. To accomodate wildcard, the tracker has an
// internal trie which holds all domains and all sets that need to be updated
// when that domain matches.
//
// When we add a domain like news.cnn.com into the trie, we need to walk all the
// shorter wildcard suffixes like *.cnn.com and *.com and add the ipsets
// associated directly (commes straight from policy that refers that domain)
// with the domain. But it must not add those ipsets to any non-wildcard prefx
// like us.news.cnn.com.
//
// When we are adding a wildcard like *.cnn.com, we need to walks all the
// shorter wildcard suffixes like *.com (as above) but we also need to inset it
// into any longer suffixes like new.cnn.com as well as us.new.cnn.com. or
// *.news.cnn.com.
//
// When we are removing an ipset for a non-wildcard domain, we just remove that
// node and all domain-ipset mappings. sets that belong directly to the perfect
// match are not included in any wildcard.
//
// When we remove an ipset from a wildcard domain, we have to walk the subtree
// (only if the same ipset was also accumulated from a shorter wildcard)
// of all longer suffixes and remove the from the accumulated sets unless it
// also directly belongs to it. If it directly belongs to a longer wildcard,
// than we can skip the subtree because it would _also_ get it from the longer
// wildcard.
type DomainTracker struct {
	mPfx          maps.Map
	mSets         maps.Map
	domainIDAlloc *idalloc.IDAllocator
	pfxMap        *cachingmap.CachingMap[DNSPfxKey, DNSPfxValue]
	setsMap       *cachingmap.CachingMap[DNSSetKey, DNSSetValue]
	setsAcc       *patricia.Trie
	strToUin64    func(string) uint64
}

type saItem struct {
	id       uint64
	wildcard bool
	acc      set.Set[uint64] /* accumulated from shorter wildcards */
	sets     set.Set[uint64] /* those sets which directly belong to this domain/wildcard */
}

func CreateBPFMapsForDNS(family int) (maps.Map, maps.Map, error) {
	var mPfx, mSets maps.Map
	switch family {
	case 4:
		mPfx = DNSPrefixMap()
		mSets = DNSSetMap()
	case 6:
		mPfx = DNSPrefixMapV6()
		mSets = DNSSetMapV6()
	default:
		return nil, nil, fmt.Errorf("unknown ip family %d", family)
	}

	err := mPfx.EnsureExists()

	if err != nil {
		return nil, nil, fmt.Errorf("could not create BPF map: %w", err)
	}

	err = mSets.EnsureExists()
	if err != nil {
		return nil, nil, fmt.Errorf("could not create BPF map: %w", err)
	}
	return mPfx, mSets, nil
}

func NewDomainTracker(family int, strToUin64 func(string) uint64) (*DomainTracker, error) {
	mPfx, mSets, err := CreateBPFMapsForDNS(family)
	if err != nil {
		return nil, err
	}
	return NewDomainTrackerWithMaps(strToUin64, mPfx, mSets)
}

func NewDomainTrackerWithMaps(strToUin64 func(string) uint64, mPfx, mSets maps.Map) (*DomainTracker, error) {
	d := &DomainTracker{
		mPfx:          mPfx,
		mSets:         mSets,
		domainIDAlloc: idalloc.New(),
		pfxMap: cachingmap.New[DNSPfxKey, DNSPfxValue](mPfx.GetName(),
			maps.NewTypedMap[DNSPfxKey, DNSPfxValue](
				mPfx.(maps.MapWithExistsCheck), DNSPfxKeyFromBytes, DNSPfxValueFromBytes,
			)),
		setsMap: cachingmap.New[DNSSetKey, DNSSetValue](mSets.GetName(),
			maps.NewTypedMap[DNSSetKey, DNSSetValue](
				mSets.(maps.MapWithExistsCheck), DNSSetKeyFromBytes, DNSSetValueFromBytes,
			)),
		setsAcc:    patricia.NewTrie(),
		strToUin64: strToUin64,
	}

	err := d.pfxMap.LoadCacheFromDataplane()
	if err != nil {
		return nil, fmt.Errorf("could not load data from dataplane: %w", err)
	}

	loglevel := log.GetLevel()

	d.pfxMap.Dataplane().Iter(func(k DNSPfxKey, v DNSPfxValue) {
		domain := k.Domain()
		d.domainIDAlloc.ReserveWellKnownID(domain, uint64(v))
		if loglevel >= log.DebugLevel {
			log.WithFields(log.Fields{
				"domain": domain,
				"id":     uint64(v),
			}).Debug("Reserved id found in dataplane for domain")
		}
	})

	return d, nil
}

func (d *DomainTracker) Add(domain string, setIDs ...string) {
	loglevel := log.GetLevel()

	if loglevel >= log.DebugLevel {
		log.WithFields(log.Fields{
			"domain": domain,
			"setIDs": setIDs,
		}).Debug("Add")
	}

	if len(setIDs) == 0 {
		return
	}

	wildcard := domain == "" || domain[0] == '*'

	k := NewPfxKey(domain)
	log.Debugf("k = %s", k)

	domainID := d.domainIDAlloc.GetOrAlloc(domain)

	v := NewPfxValue(domainID)
	d.pfxMap.Desired().Set(k, v)

	kb := k.LPMDomain()

	var current *saItem

	c := d.setsAcc.Get(kb)
	if c == nil {
		current = &saItem{
			id:       domainID,
			wildcard: wildcard,
			acc:      set.New[uint64](),
			sets:     set.New[uint64](),
		}
		d.setsAcc.Set(kb, current)
	} else {
		current = c.(*saItem)
	}

	for _, si := range setIDs {
		id64 := d.strToUin64(si)
		if id64 == 0 {
			log.Debugf("No uint64 id for domain %s string set id '%s'", domain, si)
			continue
		}

		if current.sets.Contains(id64) {
			log.Debugf("Set %s (0x%x) alredy belongs to domain %s", si, id64, string(kb))
			continue
		}

		current.sets.Add(id64)

		if loglevel >= log.DebugLevel {
			log.Debugf("Adding set %s (0x%x) to domain %s", si, id64, string(kb))
		}
		d.setsMap.Desired().Set(NewDNSSetKey(domainID, id64), DNSSetValueVoid)

		if wildcard {
			// Insert self into everything that is longer, e.g. *.com into
			// xyz.com and a.b.com
			_ = d.setsAcc.VisitSubtree(kb, func(dom patricia.Prefix, item patricia.Item) error {
				if string(kb) != string(dom) {
					if loglevel >= log.DebugLevel {
						log.Debugf("Accumulating set %s (0x%x) to domain %s", si, id64, string(dom))
					}
					i := item.(*saItem)
					i.acc.Add(id64)
					d.setsMap.Desired().Set(NewDNSSetKey(i.id, id64), DNSSetValueVoid)
				}
				return nil
			})
		}
	}

	// Accumulate to self any shorter wildcards, e.g. *.xyz.com and *.com into
	// abc.xyz.com. It does not matter if self is a wildcard or not.
	_ = d.setsAcc.VisitPrefixes(kb, func(pfx patricia.Prefix, item patricia.Item) error {
		i := item.(*saItem)
		if string(kb) != string(pfx) && i.wildcard {
			log.Debugf("Accumultating wildcard %s set %s to domain %s", pfx, i.sets, domain)
			current.acc.AddSet(i.sets)

			for setid := range i.sets.All() {
				d.setsMap.Desired().Set(NewDNSSetKey(domainID, setid), DNSSetValueVoid)
			}
		}
		return nil
	})
}

func (d *DomainTracker) Delete(domain string, setIDs ...string) {
	loglevel := log.GetLevel()

	if loglevel >= log.DebugLevel {
		log.WithFields(log.Fields{
			"domain": domain,
			"setIDs": setIDs,
		}).Debug("Delete")
	}

	wildcard := domain == "" || domain[0] == '*'

	k := NewPfxKey(domain)

	kb := k.LPMDomain()

	c := d.setsAcc.Get(kb)
	if c == nil {
		return
	}
	current := c.(*saItem)

	domainID := d.domainIDAlloc.GetNoAlloc(domain)
	if domainID == 0 {
		return
	}

	for _, si := range setIDs {
		id64 := d.strToUin64(si)
		if id64 == 0 {
			log.Debugf("No uint64 id for domain %s string set id '%s'", domain, si)
			continue
		}

		if !current.sets.Contains(id64) {
			log.Debugf("Set id '%s' does not belong to domain '%s'", si, domain)
			continue
		}

		// If the set is not accumulated from a shorter wildcard (strictly
		// belongs to self), remove it from anything longer that accumulated it
		// from here.
		if wildcard && !current.acc.Contains(id64) {
			_ = d.setsAcc.VisitSubtree(kb, func(dom patricia.Prefix, item patricia.Item) error {
				i := item.(*saItem)

				if i.wildcard {
					if i.sets.Contains(id64) && string(dom) != string(kb) {
						// Anything below (longer) could have equally got it
						// from here so do not descend.
						if loglevel >= log.DebugLevel {
							log.Debugf("Skip subtree for domain %s", string(dom))
						}
						return patricia.SkipSubtree
					}
				}

				if loglevel >= log.DebugLevel {
					log.Debugf("Removing set %s (0x%x) from domain %s", si, id64, string(dom))
				}
				i.acc.Discard(id64)
				if !i.sets.Contains(id64) {
					d.setsMap.Desired().Delete(NewDNSSetKey(i.id, id64))
				}
				return nil
			})
		}

		current.sets.Discard(id64)

		if !current.acc.Contains(id64) {
			if loglevel >= log.DebugLevel {
				log.Debugf("Removing set %s (0x%x) from domain %s", si, id64, domain)
			}
			d.setsMap.Desired().Delete(NewDNSSetKey(domainID, id64))
		}
	}

	if current.sets.Len() == 0 {
		log.Debugf("Removing domain %s without sets", domain)
		_ = d.domainIDAlloc.ReleaseUintID(domainID)
		d.setsAcc.Delete(kb)
		d.pfxMap.Desired().Delete(k)
	}
}

func (d *DomainTracker) ApplyAllChanges() error {
	if err := d.setsMap.ApplyAllChanges(); err != nil {
		return fmt.Errorf("ApplyAllChanges to DNS sets map: %w", err)
	}

	if err := d.pfxMap.ApplyAllChanges(); err != nil {
		return fmt.Errorf("ApplyAllChanges to DNS prefix map: %w", err)
	}

	return nil
}

func (d *DomainTracker) Close() {
	d.mPfx.Close()
	d.mSets.Close()
}

func (d *DomainTracker) Maps() []maps.Map {
	return []maps.Map{d.mPfx, d.mSets}
}
