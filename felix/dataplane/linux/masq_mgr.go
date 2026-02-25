// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.
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

package intdataplane

import (
	"strings"

	log "github.com/sirupsen/logrus"

	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// masqManager manages the ipsets and iptables chains used to implement the "NAT outgoing" or
// "masquerade" feature.  The feature adds a boolean flag to each IPAM pool, which controls how
// outgoing traffic to non-Calico destinations is handled.  If the "masquerade" flag is set,
// outgoing traffic is source-NATted to appear to come from the host's IP address.
//
// The masqManager maintains two CIDR IP sets: one contains the CIDRs for all Calico
// IPAM pools, the other contains only the NAT-enabled pools.
//
// When NAT-enabled pools are present, the masqManager inserts the iptables masquerade rule
// to trigger NAT of outgoing packets from NAT-enabled pools.  Traffic to any Calico-owned
// pool is excluded.
type masqManager struct {
	ipVersion       uint8
	ipsetsDataplane dpsets.IPSetsDataplane
	natTable        Table
	allCIDRs        map[string]*cidrState
	masqPools       set.Set[string]
	dirty           bool
	ruleRenderer    rules.RuleRenderer

	logCxt *log.Entry
}

func newMasqManager(
	ipsetsDataplane dpsets.IPSetsDataplane,
	natTable Table,
	ruleRenderer rules.RuleRenderer,
	maxIPSetSize int,
	ipVersion uint8,
) *masqManager {
	// Make sure our IP sets exist.  We set the contents to empty here
	// but the IPSets object will defer writing the IP sets until we're
	// in sync, by which point we'll have added all our CIDRs into the sets.
	ipsetsDataplane.AddOrReplaceIPSet(ipsets.IPSetMetadata{
		MaxSize: maxIPSetSize,
		SetID:   rules.IPSetIDAllPools,
		Type:    ipsets.IPSetTypeHashNet,
	}, []string{})
	ipsetsDataplane.AddOrReplaceIPSet(ipsets.IPSetMetadata{
		MaxSize: maxIPSetSize,
		SetID:   rules.IPSetIDNATOutgoingMasqPools,
		Type:    ipsets.IPSetTypeHashNet,
	}, []string{})

	return &masqManager{
		ipVersion:       ipVersion,
		ipsetsDataplane: ipsetsDataplane,
		natTable:        natTable,
		allCIDRs:        map[string]*cidrState{},
		masqPools:       set.New[string](),
		dirty:           true,
		ruleRenderer:    ruleRenderer,
		logCxt:          log.WithField("ipVersion", ipVersion),
	}
}

func (d *masqManager) OnUpdate(msg any) {
	var cidrKey string
	var newPool *proto.IPAMPool
	var cluster string

	switch msg := msg.(type) {
	case *proto.IPAMPoolUpdate:
		d.logCxt.WithField("id", msg.Id).Debug("IPAM pool update/create")
		cidrKey = msg.Id
		newPool = msg.Pool
	case *proto.IPAMPoolRemove:
		d.logCxt.WithField("id", msg.Id).Debug("IPAM pool removed")
		cidrKey = msg.Id
	case *proto.RemoteIPAMPoolUpdate:
		if msg.Cluster == "" {
			d.logCxt.Panic("BUG: Cluster not set on RemoteIPAMPoolUpdate")
		}
		d.logCxt.WithField("id", msg.Id).Debug("Remote IPAM pool update/create")
		cidrKey = msg.Id
		newPool = msg.Pool
		cluster = msg.Cluster
	case *proto.RemoteIPAMPoolRemove:
		if msg.Cluster == "" {
			d.logCxt.Panic("BUG: Cluster not set on RemoteIPAMPoolRemove")
		}
		d.logCxt.WithField("id", msg.Id).Debug("Remote IPAM pool removed")
		cidrKey = msg.Id
		cluster = msg.Cluster
	default:
		return
	}

	logCxt := d.logCxt.WithField("cidr", cidrKey)
	oldCIDRState := d.allCIDRs[cidrKey]
	if oldCIDRState != nil {
		// For simplicity (in case of an update to the CIDR, say) always
		// remove the old values from the IP sets.  The IPSets object
		// defers and coalesces the update so removing then adding the
		// same IP is a no-op anyway.
		logCxt.Debug("Removing old pool.")
		oldProgrammablePool, oldPoolIsRemote := oldCIDRState.getProgrammablePool()
		if oldProgrammablePool == nil {
			d.logCxt.Panicf("BUG: Tracking CIDR with no programmable pool.")
		}
		d.ipsetsDataplane.RemoveMembers(rules.IPSetIDAllPools, []string{oldProgrammablePool.Cidr})
		if !oldPoolIsRemote && oldProgrammablePool.Masquerade {
			logCxt.Debug("Masquerade was enabled on pool.")
			d.ipsetsDataplane.RemoveMembers(rules.IPSetIDNATOutgoingMasqPools, []string{oldProgrammablePool.Cidr})
		}
		oldCIDRState.clearPoolForCluster(cluster)
		delete(d.allCIDRs, cidrKey)
		d.masqPools.Discard(cidrKey)
	}

	nextCIDRState := d.getOrCreateNextCIDRState(oldCIDRState)
	nextCIDRState.updateForNewPool(cluster, newPool)
	if nextCIDRState.hasProgrammablePool() {
		// An update/create.
		newProgrammablePool, newProgrammablePoolIsRemote := nextCIDRState.getProgrammablePool()
		newPoolIsV6 := strings.Contains(newProgrammablePool.Cidr, ":")
		weAreV6 := d.ipVersion == 6
		if newPoolIsV6 != weAreV6 {
			logCxt.Debug("Skipping IPAM pool of different version.")
			return
		}

		// Update the IP sets.
		logCxt.Debug("Adding IPAM pool to IP sets.")
		d.ipsetsDataplane.AddMembers(rules.IPSetIDAllPools, []string{newProgrammablePool.Cidr})
		if !newProgrammablePoolIsRemote && newProgrammablePool.Masquerade {
			logCxt.Debug("IPAM has masquerade enabled.")
			d.ipsetsDataplane.AddMembers(rules.IPSetIDNATOutgoingMasqPools, []string{newProgrammablePool.Cidr})
			d.masqPools.Add(cidrKey)
		}
		d.allCIDRs[cidrKey] = nextCIDRState
	}
	d.dirty = true
}

func (m *masqManager) CompleteDeferredWork() error {
	if !m.dirty {
		return nil
	}

	// Refresh the chain in case we've gone from having no masq pools to
	// having some or vice-versa.
	m.logCxt.Info("IPAM pools updated, refreshing iptables rule")
	chain := m.ruleRenderer.NATOutgoingChain(m.masqPools.Len() > 0, m.ipVersion)
	m.natTable.UpdateChain(chain)
	m.dirty = false

	return nil
}

func (m *masqManager) getOrCreateNextCIDRState(currentCIDRState *cidrState) *cidrState {
	if currentCIDRState != nil {
		return currentCIDRState
	} else {
		return &cidrState{
			remoteClusters: set.New[string](),
		}
	}
}

type cidrState struct {
	cidr           string
	localPool      *proto.IPAMPool
	remoteClusters set.Set[string]
}

func (c *cidrState) getProgrammablePool() (pool *proto.IPAMPool, isRemote bool) {
	if c.localPool != nil {
		return c.localPool, false
	}

	if c.remoteClusters.Len() > 0 {
		// For the purposes of programming, remote pools only contribute their CIDR.
		return &proto.IPAMPool{Cidr: c.cidr}, true
	}

	return nil, false
}

func (c *cidrState) hasProgrammablePool() bool {
	return c.localPool != nil || c.remoteClusters.Len() > 0
}

func (c *cidrState) updateForNewPool(cluster string, newPool *proto.IPAMPool) {
	if newPool == nil {
		return
	}

	c.cidr = newPool.Cidr
	if cluster != "" {
		c.remoteClusters.Add(cluster)
	} else {
		c.localPool = newPool
	}
}

func (c *cidrState) clearPoolForCluster(cluster string) {
	if cluster != "" {
		c.remoteClusters.Discard(cluster)
	} else {
		c.localPool = nil
	}
}
