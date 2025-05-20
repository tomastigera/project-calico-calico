// Copyright (c) 2025 Tigera, Inc. All rights reserved

package dns

import (
	"strings"

	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// DomainIPSetListener is an implementation of ipset.UpdateListener that
// collects updates to domain IP sets only.
type DomainIPSetListener struct {
	// DomainSetUpdates is a set of domain IP set members that have been
	// programmed, or nil if there are none.
	DomainSetUpdates set.Set[string]
}

func NewDomainIPSetListener() *DomainIPSetListener {
	return &DomainIPSetListener{}
}

func (d DomainIPSetListener) CaresAboutIPSet(ipSetName string) bool {
	// Collect only Domain IP set updates so we don't overload the packet processor with irrelevant ips.
	ipSetID := ipsets.StripIPSetNamePrefix(ipSetName)
	return strings.HasPrefix(ipSetID, "d:")
}

func (d DomainIPSetListener) OnMemberProgrammed(rawIPSetMember string) {
	if d.DomainSetUpdates == nil {
		d.DomainSetUpdates = set.New[string]()
	}
	d.DomainSetUpdates.Add(rawIPSetMember)
}
