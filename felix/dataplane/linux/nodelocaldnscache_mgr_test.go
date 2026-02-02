// Copyright (c) 2023 Tigera, Inc. All rights reserved.
package intdataplane

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var _ = Describe("NodeLocalDNSCache", func() {
	var (
		mgr            *nodeLocalDNSManager
		rrConfigNormal rules.Config
		ruleRenderer   rules.RuleRenderer
		rawTable       *mockTable

		nodelocaldnsTestAddrs = []string{"10.96.0.10", "169.254.0.0"}
	)

	BeforeEach(func() {
		rrConfigNormal = rules.Config{
			IPIPEnabled:              true,
			IPIPTunnelAddress:        nil,
			IPSetConfigV4:            ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
			IPSetConfigV6:            ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
			DNSPolicyNfqueueID:       100,
			MarkAccept:               0x8,
			MarkPass:                 0x10,
			MarkScratch0:             0x20,
			MarkScratch1:             0x40,
			MarkEndpoint:             0xff00,
			MarkNonCaliEndpoint:      0x0100,
			MarkDrop:                 0x80,
			MarkDNSPolicy:            0x00001,
			MarkSkipDNSPolicyNfqueue: 0x400000,
			KubeIPVSSupportEnabled:   true,
			WorkloadIfacePrefixes:    []string{"cali", "tap"},
			VXLANPort:                4789,
			VXLANVNI:                 4096,
		}
		ruleRenderer = rules.NewRenderer(rrConfigNormal, false)

		rawTable = newMockTable("raw")

		mgr = newNodeLocalDNSManager(
			ruleRenderer,
			4,
			rawTable,
		)
	})

	expectDefaultRules := func() {
		Expect(rawTable.getCurrentChainByName("cali-PREROUTING").Rules).To(
			ContainElements(ruleRenderer.StaticRawPreroutingChain(mgr.ipVersion, nil).Rules),
		)
		Expect(rawTable.getCurrentChainByName("cali-OUTPUT").Rules).To(
			ContainElements(ruleRenderer.StaticRawOutputChain(uint32(0), mgr.ipVersion, nil).Rules),
		)
	}

	It("ignores messages not interface related", func() {
		msg := &proto.IPAMPoolUpdate{
			Id: "pool-1",
			Pool: &proto.IPAMPool{
				Cidr:       "10.0.0.0/16",
				Masquerade: true,
			},
		}

		mgr.OnUpdate(msg)
		Expect(mgr.CompleteDeferredWork()).NotTo(HaveOccurred())
		Expect(mgr.dirty).To(BeFalse())

		expectDefaultRules()
	})

	It("ignores ifaceupdate messages not for nodelocaldns", func() {
		msg := &ifaceStateUpdate{
			Name: "notnodelocaldns",
		}
		mgr.OnUpdate(msg)
		Expect(mgr.CompleteDeferredWork()).NotTo(HaveOccurred())
		Expect(mgr.dirty).To(BeFalse())

		expectDefaultRules()
	})

	It("ignores ifaceAddrsUpdate messages not for nodelocaldns", func() {
		msg := &ifaceAddrsUpdate{
			Name: "notnodelocaldns",
		}
		mgr.OnUpdate(msg)
		Expect(mgr.CompleteDeferredWork()).NotTo(HaveOccurred())
		Expect(mgr.dirty).To(BeFalse())

		expectDefaultRules()
	})

	It("ifaceUpdate for a present nodelocaldns sets the state", func() {
		msg := &ifaceStateUpdate{
			Name:  "nodelocaldns",
			State: ifacemonitor.StateUp,
		}
		mgr.OnUpdate(msg)
		Expect(mgr.nodeLocalDNSCachePresent).To(BeTrue())
		Expect(mgr.CompleteDeferredWork()).NotTo(HaveOccurred())
		Expect(mgr.dirty).To(BeFalse())

		expectDefaultRules()
	})

	It("ifaceUpdate for a non present nodelocaldns does not set the state and sets the default Raw table", func() {
		msg := &ifaceStateUpdate{
			Name:  "nodelocaldns",
			State: ifacemonitor.StateNotPresent,
		}
		mgr.OnUpdate(msg)
		Expect(mgr.nodeLocalDNSCachePresent).To(BeFalse())
		Expect(mgr.CompleteDeferredWork()).NotTo(HaveOccurred())
		Expect(mgr.dirty).To(BeFalse())

		expectDefaultRules()
	})

	It("ifaceAddrsUpdate when nodelocaldns is present reflects the broadcasted addresses in the ifaceAddrsUpdate message", func() {
		nodelocaldnsMsgAddrs := set.From(nodelocaldnsTestAddrs...)
		var serverPorts []config.ServerPort
		for _, addr := range nodelocaldnsTestAddrs {
			serverPorts = append(serverPorts, config.ServerPort{
				IP:   addr,
				Port: PortDNS,
			})
		}

		msg := &ifaceAddrsUpdate{
			Name:  "nodelocaldns",
			Addrs: nodelocaldnsMsgAddrs,
		}

		mgr.nodeLocalDNSCachePresent = true
		mgr.OnUpdate(msg)
		Expect(mgr.CompleteDeferredWork()).NotTo(HaveOccurred())
		Expect(mgr.dirty).To(BeFalse())

		Expect(rawTable.getCurrentChainByName("cali-PREROUTING").Rules).To(
			ContainElements(ruleRenderer.StaticRawPreroutingChain(mgr.ipVersion, serverPorts).Rules),
		)
		Expect(rawTable.getCurrentChainByName("cali-OUTPUT").Rules).To(
			ContainElements(ruleRenderer.StaticRawOutputChain(uint32(0), mgr.ipVersion, serverPorts).Rules),
		)
	})

	It("ifaceAddrsUpdate when nodelocaldns is NOT present reflects the default Raw table", func() {
		nodelocaldnsMsgAddrs := set.From(nodelocaldnsTestAddrs...)

		msg := &ifaceAddrsUpdate{
			Name:  "nodelocaldns",
			Addrs: nodelocaldnsMsgAddrs,
		}

		mgr.nodeLocalDNSCachePresent = false
		mgr.OnUpdate(msg)
		Expect(mgr.CompleteDeferredWork()).NotTo(HaveOccurred())
		Expect(mgr.dirty).To(BeFalse())

		expectDefaultRules()
	})
})
