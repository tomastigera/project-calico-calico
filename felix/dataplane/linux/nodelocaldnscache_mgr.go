// Copyright (c) 2023 Tigera, Inc. All rights reserved.
package intdataplane

import (
	"reflect"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const (
	// Network Interface name used by NodeLocalDNS DaemonSet
	NodeLocalDNSNetworkInterfaceName = "nodelocaldns"

	PortDNS = uint16(53)
)

type nodeLocalDNSManager struct {
	ruleRenderer rules.RuleRenderer
	rawTables    Table
	ipVersion    uint8

	nodeLocalDNSCachePresent bool
	nodeLocalAddrs           set.Set[string]
	dirty                    bool
}

func newNodeLocalDNSManager(
	ruleRenderer rules.RuleRenderer,
	ipVersion uint8,
	rawTables Table,
) *nodeLocalDNSManager {
	return &nodeLocalDNSManager{
		ruleRenderer: ruleRenderer,
		ipVersion:    ipVersion,
		rawTables:    rawTables,
		dirty:        true,
	}
}

func (m *nodeLocalDNSManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	case *ifaceStateUpdate:
		// Called when the status update is for the nodelocaldns
		// network interface to check its status and updates the
		// config to indicate the presence of the NodeLocalDNSCache.
		if msg.Name != NodeLocalDNSNetworkInterfaceName {
			return
		}
		present := msg.State != ifacemonitor.StateNotPresent
		if present == m.nodeLocalDNSCachePresent {
			return
		}
		m.nodeLocalDNSCachePresent = present
		m.dirty = true
	case *ifaceAddrsUpdate:
		// connected to the Addr Callback when the interface name is nodelocaldns
		// to retrieve the addresses set for it.
		if msg.Name != NodeLocalDNSNetworkInterfaceName {
			return
		}
		if reflect.DeepEqual(m.nodeLocalAddrs, msg.Addrs) {
			return
		}
		m.nodeLocalAddrs = msg.Addrs
		m.dirty = true
	default:
		return
	}
}

func (m *nodeLocalDNSManager) CompleteDeferredWork() error {
	if !m.dirty {
		return nil
	}
	m.dirty = false

	if !m.nodeLocalDNSCachePresent || m.nodeLocalAddrs == nil || m.nodeLocalAddrs.Len() == 0 {
		log.Info("Node-local DNS cache not detected, disabling iptables rules.")
		m.updateCaliRawChainsWithNodelocalDNSRules(nil)
		return nil
	}

	var dnsServerPorts []config.ServerPort
	for addr := range m.nodeLocalAddrs.All() {
		dnsServerPorts = append(dnsServerPorts, config.ServerPort{
			IP:   addr,
			Port: PortDNS,
		})
	}
	log.WithField("addrs", dnsServerPorts).Info("Node-local DNS cache enabled, enabling iptables rules.")
	m.updateCaliRawChainsWithNodelocalDNSRules(dnsServerPorts)
	return nil
}

func (m *nodeLocalDNSManager) updateCaliRawChainsWithNodelocalDNSRules(dnsServerPorts []config.ServerPort) {
	m.rawTables.UpdateChain(m.ruleRenderer.StaticRawPreroutingChain(m.ipVersion, dnsServerPorts))
	m.rawTables.UpdateChain(m.ruleRenderer.StaticRawOutputChain(0, m.ipVersion, dnsServerPorts))
}
