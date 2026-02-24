// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.

package calc_test

import (
	"fmt"
	"net"
	"regexp"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	libcaliconet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

const (
	testDeletionDelay = 100 * time.Millisecond
)

var (
	float1_0 = float64(1.0)
	float2_0 = float64(2.0)
)

var _ = Describe("EndpointLookupsCache tests: endpoints", func() {
	var ec *calc.EndpointLookupsCache

	BeforeEach(func() {
		ec = calc.NewEndpointLookupsCache(calc.WithDeletionDelay(testDeletionDelay))
	})

	DescribeTable(
		"Check adding/deleting workload endpoint modifies the cache",
		func(key model.WorkloadEndpointKey, wep *model.WorkloadEndpoint, ipAddr net.IP) {
			c := "WEP(" + key.Hostname + "/" + key.OrchestratorID + "/" + key.WorkloadID + "/" + key.EndpointID + ")"

			// tests adding an endpoint
			update := api.Update{
				KVPair: model.KVPair{
					Key:   key,
					Value: wep,
				},
				UpdateType: api.UpdateTypeKVNew,
			}
			var addrB [16]byte
			copy(addrB[:], ipAddr.To16()[:16])

			ec.OnUpdate(update)

			// test GetEndpointByIP retrieves the endpointData
			ed, ok := ec.GetEndpoint(addrB)
			Expect(ok).To(BeTrue(), c)
			Expect(ed.Key()).To(Equal(key))

			// test GetEndpointKeys
			keys := ec.GetEndpointKeys()
			Expect(len(keys)).To(Equal(1))
			Expect(keys).To(ConsistOf(ed.Key()))

			// test GetAllEndpointData also contains the one
			// retrieved by the IP
			endpoints := ec.GetAllEndpointData()
			Expect(len(endpoints)).To(Equal(1))
			Expect(endpoints).To(ConsistOf(ed))

			// tests deleting an endpoint
			update = api.Update{
				KVPair: model.KVPair{
					Key: key,
				},
				UpdateType: api.UpdateTypeKVDeleted,
			}

			// OnUpdate delays deletion with delay
			ec.OnUpdate(update)
			ed, ok = ec.GetEndpoint(addrB)
			Expect(ok).To(BeTrue(), c)
			Expect(ed.IsLocal()).To(BeFalse())
			Expect(ed.IngressMatchData()).To(BeNil())
			Expect(ed.EgressMatchData()).To(BeNil())

			epExists := func() bool {
				_, ok = ec.GetEndpoint(addrB)
				return ok
			}
			Consistently(epExists, testDeletionDelay*80/100, time.Millisecond).Should(BeTrue())
			Eventually(epExists, testDeletionDelay*40/100, time.Millisecond).Should(BeFalse())

			_, ok = ec.GetEndpoint(addrB)
			Expect(ok).To(BeFalse(), c)

			// test GetEndpointKeys are empty after deletion
			keys = ec.GetEndpointKeys()
			Expect(len(keys)).To(Equal(0))
			Expect(keys).NotTo(ConsistOf(ed.Key()))

			// test GetAllEndpointData are empty after deletion
			endpoints = ec.GetAllEndpointData()
			Expect(len(endpoints)).To(Equal(0))
			Expect(endpoints).NotTo(ConsistOf(ed))
		},
		Entry("remote WEP1 IPv4", remoteWlEpKey1, &remoteWlEp1, remoteWlEp1.IPv4Nets[0].IP),
		Entry("remote WEP1 IPv6", remoteWlEpKey1, &remoteWlEp1, remoteWlEp1.IPv6Nets[0].IP),
	)

	DescribeTable(
		"should cancel a previous endpoint data mark to be deleted and update the endpoint key with data in the new entry",
		func(key model.HostEndpointKey, hep *model.HostEndpoint, ipAddr net.IP) {
			// setup - add entry for key
			c := "HEP(" + key.Hostname + "/" + key.EndpointID + ")"
			update := api.Update{
				KVPair: model.KVPair{
					Key:   key,
					Value: hep,
				},
				UpdateType: api.UpdateTypeKVNew,
			}
			var addrB [16]byte
			copy(addrB[:], ipAddr.To16()[:16])

			ec.OnUpdate(update)
			ed, ok := ec.GetEndpoint(addrB)
			Expect(ok).To(BeTrue(), c)
			Expect(ed.Key()).To(Equal(key))

			// DumpEndpoint is only used for debug, just a basic sanity check.
			Expect(ec.DumpEndpoints()).To(ContainSubstring(ipAddr.String() + ": " + c))
			dumpIPsRegexp := MatchRegexp(regexp.QuoteMeta(c) + ":.*" + regexp.QuoteMeta(ipAddr.String()))
			Expect(ec.DumpEndpoints()).To(dumpIPsRegexp)

			// deletion process
			update = api.Update{
				KVPair: model.KVPair{
					Key: key,
				},
				UpdateType: api.UpdateTypeKVDeleted,
			}
			// OnUpdate delays deletion with time to live
			ec.OnUpdate(update)
			_, ok = ec.GetEndpoint(addrB)
			Expect(ok).To(BeTrue(), c)
			Expect(ec.DumpEndpoints()).To(ContainSubstring(ipAddr.String() + ": " + c))
			Expect(ec.DumpEndpoints()).To(ContainSubstring(c + ": deleted"))

			// re-add entry before the deletion is delegated
			update = api.Update{
				KVPair: model.KVPair{
					Key:   key,
					Value: hep,
				},
				UpdateType: api.UpdateTypeKVNew,
			}
			ec.OnUpdate(update)
			ed, ok = ec.GetEndpoint(addrB)
			Expect(ok).To(BeTrue(), c)
			Expect(ed.Key()).To(Equal(key))

			// Verify that the deletion is cancelled.
			epExists := func() bool {
				_, ok = ec.GetEndpoint(addrB)
				return ok
			}
			Consistently(epExists, testDeletionDelay*120/100, time.Millisecond).Should(BeTrue())
			Expect(ec.DumpEndpoints()).To(ContainSubstring(ipAddr.String() + ": " + c))
			Expect(ec.DumpEndpoints()).To(dumpIPsRegexp)
		},
		Entry("Host Endpoint IPv4", hostEpWithNameKey, &hostEpWithName, hostEpWithName.ExpectedIPv4Addrs[0].IP),
		Entry("Host Endpoint IPv6", hostEpWithNameKey, &hostEpWithName, hostEpWithName.ExpectedIPv6Addrs[0].IP),
	)

	It("should process both workload and host endpoints each with multiple IP addresses", func() {
		By("adding a workload endpoint with multiple ipv4 and ipv6 ip addresses")
		update := api.Update{
			KVPair: model.KVPair{
				Key:   remoteWlEpKey1,
				Value: &remoteWlEp1,
			},
			UpdateType: api.UpdateTypeKVNew,
		}
		origRemoteWepLabels := map[string]string{
			"id": "rem-ep-1",
			"x":  "x",
			"y":  "y",
		}
		ec.OnUpdate(update)

		// take delay with deletion into account
		time.Sleep(testDeletionDelay + 1*time.Second)

		verifyIpToEndpoint := func(key model.Key, ipAddr net.IP, exists bool, labels map[string]string) {
			var name string
			switch k := key.(type) {
			case model.WorkloadEndpointKey:
				name = "WEP(" + k.Hostname + "/" + k.OrchestratorID + "/" + k.WorkloadID + "/" + k.EndpointID + ")"
			case model.HostEndpointKey:
				name = "HEP(" + k.Hostname + "/" + k.EndpointID + ")"
			}

			var addrB [16]byte
			copy(addrB[:], ipAddr.To16()[:16])

			ed, ok := ec.GetEndpoint(addrB)
			if exists {
				Expect(ok).To(BeTrue(), name+"\n"+ec.DumpEndpoints())
				Expect(ed.Key()).To(Equal(key), ec.DumpEndpoints())
				if labels != nil {
					Expect(ed.Labels()).To(Equal(uniquelabels.Make(labels)), ec.DumpEndpoints())
				}
			} else {
				_, ok = ec.GetEndpoint(addrB)
				Expect(ok).To(BeFalse(), name+".\n"+ec.DumpEndpoints())
			}
		}

		By("verifying all IPv4 and IPv6 addresses of the workload endpoint are present in the mapping")
		for _, ipv4 := range remoteWlEp1.IPv4Nets {
			verifyIpToEndpoint(remoteWlEpKey1, ipv4.IP, true, origRemoteWepLabels)
		}
		for _, ipv6 := range remoteWlEp1.IPv6Nets {
			verifyIpToEndpoint(remoteWlEpKey1, ipv6.IP, true, origRemoteWepLabels)
		}

		By("adding a host endpoint with multiple ipv4 and ipv6 ip addresses")
		update = api.Update{
			KVPair: model.KVPair{
				Key:   hostEpWithNameKey,
				Value: &hostEpWithName,
			},
			UpdateType: api.UpdateTypeKVNew,
		}
		hepLabels := map[string]string{
			"id": "loc-ep-1",
			"a":  "a",
			"b":  "b",
		}
		ec.OnUpdate(update)

		By("verifying all IPv4 and IPv6 addresses of the host endpoint are present in the mapping")
		for _, ipv4 := range hostEpWithName.ExpectedIPv4Addrs {
			verifyIpToEndpoint(hostEpWithNameKey, ipv4.IP, true, hepLabels)
		}
		for _, ipv6 := range hostEpWithName.ExpectedIPv6Addrs {
			verifyIpToEndpoint(hostEpWithNameKey, ipv6.IP, true, hepLabels)
		}

		By("deleting the host endpoint")
		update = api.Update{
			KVPair: model.KVPair{
				Key: hostEpWithNameKey,
			},
			UpdateType: api.UpdateTypeKVDeleted,
		}
		ec.OnUpdate(update)

		// delete is delayed
		time.Sleep(testDeletionDelay + 1*time.Second)

		By("verifying all IPv4 and IPv6 addresses of the host endpoint are not present in the mapping")
		for _, ipv4 := range hostEpWithName.ExpectedIPv4Addrs {
			fmt.Println()
			verifyIpToEndpoint(hostEpWithNameKey, ipv4.IP, false, nil)
		}
		for _, ipv6 := range hostEpWithName.ExpectedIPv6Addrs {
			verifyIpToEndpoint(hostEpWithNameKey, ipv6.IP, false, nil)
		}

		By("updating the workload endpoint and adding new labels")
		update = api.Update{
			KVPair: model.KVPair{
				Key:   remoteWlEpKey1,
				Value: &remoteWlEp1UpdatedLabels,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		}
		ec.OnUpdate(update)

		updatedRemoteWepLabels := map[string]string{
			"id": "rem-ep-1",
			"x":  "x",
			"y":  "y",
			"z":  "z",
		}

		By("verifying all IPv4 and IPv6 addresses are present with updated labels")
		// For verification we iterate using the original WEP with IPv6 so that it is easy to
		// get a list of Ipv6 addresses to check against.
		for _, ipv4 := range remoteWlEp1.IPv4Nets {
			verifyIpToEndpoint(remoteWlEpKey1, ipv4.IP, true, updatedRemoteWepLabels)
		}
		for _, ipv6 := range remoteWlEp1.IPv6Nets {
			verifyIpToEndpoint(remoteWlEpKey1, ipv6.IP, true, updatedRemoteWepLabels)
		}

		By("updating the workload endpoint and removing all IPv6 addresses, and reverting labels back to original")
		update = api.Update{
			KVPair: model.KVPair{
				Key:   remoteWlEpKey1,
				Value: &remoteWlEp1NoIpv6,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		}
		ec.OnUpdate(update)

		By("verifying all IPv4 are present and no Ipv6 addresses are present")
		// For verification we iterate using the original WEP with IPv6 so that it is easy to
		// get a list of Ipv6 addresses to check against.
		for _, ipv4 := range remoteWlEp1.IPv4Nets {
			verifyIpToEndpoint(remoteWlEpKey1, ipv4.IP, true, origRemoteWepLabels)
		}
		for _, ipv6 := range remoteWlEp1.IPv6Nets {
			verifyIpToEndpoint(remoteWlEpKey1, ipv6.IP, false, nil)
		}

		By("updating the workload endpoint keeping all the information as before")
		update = api.Update{
			KVPair: model.KVPair{
				Key:   remoteWlEpKey1,
				Value: &remoteWlEp1NoIpv6,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		}
		ec.OnUpdate(update)
		// delete is delayed
		time.Sleep(testDeletionDelay + 1*time.Second)

		By("verifying all IPv4 are present but no Ipv6 addresses are present")
		// For verification we iterate using the original WEP with IPv6 so that it is easy to
		// get a list of Ipv6 addresses to check against.
		for _, ipv4 := range remoteWlEp1.IPv4Nets {
			verifyIpToEndpoint(remoteWlEpKey1, ipv4.IP, true, origRemoteWepLabels)
		}
		for _, ipv6 := range remoteWlEp1.IPv6Nets {
			verifyIpToEndpoint(remoteWlEpKey1, ipv6.IP, false, nil)
		}

		By("finally removing the WEP and no mapping is present")
		update = api.Update{
			KVPair: model.KVPair{
				Key: remoteWlEpKey1,
			},
			UpdateType: api.UpdateTypeKVDeleted,
		}
		ec.OnUpdate(update)
		// delete is delayed
		time.Sleep(testDeletionDelay + 1*time.Second)

		By("verifying all there are no mapping present")
		// For verification we iterate using the original WEP with IPv6 so that it is easy to
		// get a list of Ipv6 addresses to check against.
		for _, ipv4 := range remoteWlEp1.IPv4Nets {
			verifyIpToEndpoint(remoteWlEpKey1, ipv4.IP, false, nil)
		}
		for _, ipv6 := range remoteWlEp1.IPv6Nets {
			verifyIpToEndpoint(remoteWlEpKey1, ipv6.IP, false, nil)
		}
	})

	It("should process local endpoints correctly with no staged policies and one tier per ingress and egress", func() {
		By("adding a host endpoint with ingress policies in tier1 and egress policies in tier default")
		p1k := model.PolicyKey{Name: "tier1.pol1", Kind: v3.KindGlobalNetworkPolicy}
		p1 := &model.Policy{
			Tier:         "tier1",
			Order:        &float1_0,
			Types:        []string{"ingress"},
			InboundRules: []model.Rule{{Action: "next-tier"}, {Action: "allow"}, {Action: "deny"}},
		}
		p1id := calc.PolicyID{Name: "tier1.pol1", Kind: v3.KindGlobalNetworkPolicy}

		p2k := model.PolicyKey{Name: "pol2", Namespace: "ns1", Kind: v3.KindNetworkPolicy}
		p2 := &model.Policy{
			Tier:      "default",
			Namespace: "ns1",
			Order:     &float1_0,
			Types:     []string{"egress"},
		}
		p2id := calc.PolicyID{Name: "pol2", Namespace: "ns1", Kind: v3.KindNetworkPolicy}

		p3k := model.PolicyKey{Name: "pol3", Namespace: "ns1", Kind: v3.KindNetworkPolicy}
		p3 := &model.Policy{
			Tier:      "default",
			Namespace: "ns1",
			Order:     &float2_0,
			Types:     []string{"egress"},
		}
		p3id := calc.PolicyID{Name: "pol3", Namespace: "ns1", Kind: v3.KindNetworkPolicy}

		t1 := calc.NewTierInfo("tier1")
		t1.Order = &float1_0
		t1.Valid = true
		t1.OrderedPolicies = []calc.PolKV{{Key: p1k, Value: policyMetadata(p1)}}

		td := calc.NewTierInfo("default")
		td.Order = &float2_0
		td.Valid = true
		td.OrderedPolicies = []calc.PolKV{
			{Key: p2k, Value: policyMetadata(p2)},
			{Key: p3k, Value: policyMetadata(p3)},
		}

		ts := newTierInfoSlice()
		ts = append(ts, *t1, *td)

		var ed calc.EndpointData = ec.CreateLocalEndpointData(hostEpWithNameKey, &hostEpWithName, ts)

		By("checking endpoint data")
		Expect(ed.Key()).To(Equal(hostEpWithNameKey))
		Expect(ed.IsLocal()).To(BeTrue())
		Expect(ed.IsHostEndpoint()).To(BeTrue())
		Expect(ed.GenerateName()).To(Equal(""))
		Expect(ed.Labels()).To(Equal(hostEpWithName.Labels))
		Expect(ed.IsHostEndpoint()).To(BeTrue())

		By("checking compiled ingress data")
		Expect(ed.IngressMatchData()).ToNot(BeNil())
		Expect(ed.IngressMatchData().PolicyMatches).To(HaveLen(1))
		Expect(ed.IngressMatchData().PolicyMatches).To(HaveKey(p1id))
		Expect(ed.IngressMatchData().PolicyMatches[p1id]).To(Equal(0))
		Expect(ed.IngressMatchData().ProfileMatchIndex).To(Equal(1))
		Expect(ed.IngressMatchData().TierData).To(HaveLen(1))
		Expect(ed.IngressMatchData().TierData).To(HaveKey("tier1"))
		Expect(ed.IngressMatchData().TierData["tier1"]).ToNot(BeNil())
		Expect(ed.IngressMatchData().TierData["tier1"].TierDefaultActionRuleID).To(Equal(
			calc.NewRuleID(v3.KindGlobalNetworkPolicy, "tier1", "tier1.pol1", "", calc.RuleIndexTierDefaultAction, rules.RuleDirIngress, rules.RuleActionDeny)))
		Expect(ed.IngressMatchData().TierData["tier1"].EndOfTierMatchIndex).To(Equal(0))

		By("checking compiled egress data")
		Expect(ed.EgressMatchData()).ToNot(BeNil())
		Expect(ed.EgressMatchData().PolicyMatches).To(HaveLen(2))
		Expect(ed.EgressMatchData().PolicyMatches).To(HaveKey(p2id))
		Expect(ed.EgressMatchData().PolicyMatches[p2id]).To(Equal(0))
		Expect(ed.EgressMatchData().PolicyMatches).To(HaveKey(p3id))
		Expect(ed.EgressMatchData().PolicyMatches[p3id]).To(Equal(0))
		Expect(ed.EgressMatchData().ProfileMatchIndex).To(Equal(1))
		Expect(ed.EgressMatchData().TierData).To(HaveLen(1))
		Expect(ed.EgressMatchData().TierData).To(HaveKey("default"))
		Expect(ed.EgressMatchData().TierData["default"]).ToNot(BeNil())
		Expect(ed.EgressMatchData().TierData["default"].TierDefaultActionRuleID).To(Equal(
			calc.NewRuleID(v3.KindNetworkPolicy, "default", "pol3", "ns1", calc.RuleIndexTierDefaultAction, rules.RuleDirEgress, rules.RuleActionDeny)))
		Expect(ed.EgressMatchData().TierData["default"].EndOfTierMatchIndex).To(Equal(0))
	})

	DescribeTable(
		"should process local endpoints correctly with staged policies and multiple tiers",
		func(ingress bool) {
			var dir string
			if ingress {
				dir = "ingress"
			} else {
				dir = "egress"
			}

			By("adding a workloadendpoint with mixed staged/non-staged policies in tier1")
			sp1k := model.PolicyKey{Name: "pol1", Kind: v3.KindStagedGlobalNetworkPolicy}
			sp1 := &model.Policy{
				Tier:  "tier1",
				Order: &float1_0,
				Types: []string{dir},
			}
			sp1id := calc.PolicyID{Name: "pol1", Kind: v3.KindStagedGlobalNetworkPolicy}

			p1k := model.PolicyKey{Name: "pol1", Kind: v3.KindGlobalNetworkPolicy}
			p1 := &model.Policy{
				Tier:  "tier1",
				Order: &float1_0,
				Types: []string{dir},
			}
			p1id := calc.PolicyID{Name: "pol1", Kind: v3.KindGlobalNetworkPolicy}

			sp2k := model.PolicyKey{Name: "pol2", Namespace: "ns1", Kind: v3.KindStagedNetworkPolicy}
			sp2 := &model.Policy{
				Tier:      "tier1",
				Namespace: "ns1",
				Order:     &float2_0,
				Types:     []string{dir},
			}
			sp2id := calc.PolicyID{Name: "pol2", Namespace: "ns1", Kind: v3.KindStagedNetworkPolicy}

			p2k := model.PolicyKey{Name: "pol2", Namespace: "ns1", Kind: v3.KindNetworkPolicy}
			p2 := &model.Policy{
				Tier:      "tier1",
				Namespace: "ns1",
				Order:     &float2_0,
				Types:     []string{dir},
			}
			p2id := calc.PolicyID{Name: "pol2", Namespace: "ns1", Kind: v3.KindNetworkPolicy}

			t1 := calc.NewTierInfo("tier1")
			t1.Order = &float1_0
			t1.Valid = true
			t1.OrderedPolicies = []calc.PolKV{
				{Key: sp1k, Value: policyMetadata(sp1)},
				{Key: p1k, Value: policyMetadata(p1)},
				{Key: sp2k, Value: policyMetadata(sp2)},
				{Key: p2k, Value: policyMetadata(p2)},
			}

			By("and adding staged policies in tier default")
			sp3k := model.PolicyKey{Name: "knp.default.pol3", Namespace: "ns2", Kind: v3.KindStagedKubernetesNetworkPolicy}
			sp3 := &model.Policy{
				Tier:  "default",
				Order: &float1_0,
				Types: []string{dir},
			}
			sp3id := calc.PolicyID{Name: "knp.default.pol3", Namespace: "ns2", Kind: v3.KindStagedKubernetesNetworkPolicy}

			sp4k := model.PolicyKey{Name: "pol4", Kind: v3.KindStagedGlobalNetworkPolicy}
			sp4 := &model.Policy{
				Tier:  "default",
				Order: &float2_0,
				Types: []string{dir},
			}
			sp4id := calc.PolicyID{Name: "pol4", Kind: v3.KindStagedGlobalNetworkPolicy}

			td := calc.NewTierInfo("default")
			td.Valid = true
			td.OrderedPolicies = []calc.PolKV{
				{Key: sp3k, Value: policyMetadata(sp3)},
				{Key: sp4k, Value: policyMetadata(sp4)},
			}

			By("Creating the endpoint data")
			ts := newTierInfoSlice()
			ts = append(ts, *t1, *td)

			var ed calc.EndpointData = ec.CreateLocalEndpointData(localWlEpKey1, &localWlEp1, ts)

			By("checking endpoint data")
			Expect(ed.Key()).To(Equal(localWlEpKey1))
			Expect(ed.IsLocal()).To(BeTrue())
			Expect(ed.GenerateName()).To(Equal(localWlEp1.GenerateName))
			Expect(ed.Labels()).To(Equal(localWlEp1.Labels))
			Expect(ed.IsHostEndpoint()).To(BeFalse())

			By("checking compiled data size for both tiers")
			var data, other *calc.MatchData
			var ruleDir rules.RuleDir
			if ingress {
				data = ed.IngressMatchData()
				other = ed.EgressMatchData()
				ruleDir = rules.RuleDirIngress
			} else {
				data = ed.EgressMatchData()
				other = ed.IngressMatchData()
				ruleDir = rules.RuleDirEgress
			}

			Expect(data).ToNot(BeNil())
			Expect(data.PolicyMatches).To(HaveLen(6))
			Expect(other.PolicyMatches).To(HaveLen(0))
			Expect(data.TierData).To(HaveLen(2))
			Expect(other.TierData).To(HaveLen(0))
			Expect(data.TierData["tier1"]).ToNot(BeNil())
			Expect(data.TierData["default"]).ToNot(BeNil())

			By("checking compiled match data for tier1")
			// Staged policy increments the next index.
			Expect(data.PolicyMatches).To(HaveKey(sp1id))
			Expect(data.PolicyMatches[sp1id]).To(Equal(0))

			// Enforced policy leaves next index unchanged.
			Expect(data.PolicyMatches).To(HaveKey(p1id))
			Expect(data.PolicyMatches[p1id]).To(Equal(1))

			// Staged policy increments the next index.
			Expect(data.PolicyMatches).To(HaveKey(sp2id))
			Expect(data.PolicyMatches[sp2id]).To(Equal(1))

			// Enforced policy leaves next index unchanged.
			Expect(data.PolicyMatches).To(HaveKey(p2id))
			Expect(data.PolicyMatches[p2id]).To(Equal(2))

			// Tier contains enforced policy, so has a real implicit drop rule ID.
			Expect(data.TierData["tier1"].EndOfTierMatchIndex).To(Equal(2))
			Expect(data.TierData["tier1"].TierDefaultActionRuleID).To(Equal(
				calc.NewRuleID(v3.KindNetworkPolicy, "tier1", "pol2", "ns1", calc.RuleIndexTierDefaultAction, ruleDir, rules.RuleActionDeny)))

			By("checking compiled match data for default tier")
			// Staged policy increments the next index.
			Expect(data.PolicyMatches).To(HaveKey(sp3id))
			Expect(data.PolicyMatches[sp3id]).To(Equal(3))

			// Staged policy increments the next index.
			Expect(data.PolicyMatches).To(HaveKey(sp4id))
			Expect(data.PolicyMatches[sp4id]).To(Equal(4))

			// Tier contains only staged policy so does not contain an implicit drop rule ID.
			Expect(data.TierData["default"].EndOfTierMatchIndex).To(Equal(5))
			Expect(data.TierData["default"].TierDefaultActionRuleID).To(BeNil())

			By("checking profile match index")
			Expect(data.ProfileMatchIndex).To(Equal(6))
			Expect(other.ProfileMatchIndex).To(Equal(0))
		},
		Entry("ingress", true),
		Entry("egress", false),
	)
})

var _ = Describe("EndpointLookupCache tests: Node lookup", func() {
	var elc *calc.EndpointLookupsCache
	var updates []api.Update
	// localIP, _ := IPStringToArray("127.0.0.1")
	nodeIPStr := "100.0.0.0/26"
	nodeIP, _ := calc.IPStringToArray(nodeIPStr)
	nodeIP2Str := "100.0.0.2/26"
	nodeIP2, _ := calc.IPStringToArray(nodeIP2Str)
	nodeIP3Str := "100.0.0.3/26"
	nodeIP3, _ := calc.IPStringToArray(nodeIP3Str)
	nodeIP4Str := "100.0.0.4/26"
	nodeIP4, _ := calc.IPStringToArray(nodeIP4Str)

	BeforeEach(func() {
		elc = calc.NewEndpointLookupsCache()

		By("adding a node and a service")
		updates = []api.Update{{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: internalapi.KindNode, Name: "node1"},
				Value: &internalapi.Node{
					Spec: internalapi.NodeSpec{
						BGP: &internalapi.NodeBGPSpec{
							IPv4Address: nodeIPStr,
						},
					},
				},
			},
			UpdateType: api.UpdateTypeKVNew,
		}}

		for _, u := range updates {
			elc.OnResourceUpdate(u)
		}
	})

	It("Should handle each type of lookup", func() {
		By("checking node IP attributable to one node")
		node, ok := elc.GetNode(nodeIP)
		Expect(ok).To(BeTrue())
		Expect(node).To(Equal("node1"))
	})

	It("Should handle deletion of config", func() {
		By("deleting all resources")
		for _, u := range updates {
			elc.OnResourceUpdate(api.Update{
				KVPair:     model.KVPair{Key: u.Key},
				UpdateType: api.UpdateTypeKVDeleted,
			})
		}

		By("checking nodes return no results")
		_, ok := elc.GetNode(nodeIP)
		Expect(ok).To(BeFalse())
	})

	Describe("It should handle reconfiguring the node resources", func() {
		BeforeEach(func() {
			By("updating the node and adding a new node")
			updates = []api.Update{{
				KVPair: model.KVPair{
					Key: model.ResourceKey{Kind: internalapi.KindNode, Name: "node1"},
					Value: &internalapi.Node{
						Spec: internalapi.NodeSpec{
							BGP: &internalapi.NodeBGPSpec{
								IPv4Address: nodeIPStr,
							},
							IPv4VXLANTunnelAddr: nodeIPStr,
						},
					},
				},
				UpdateType: api.UpdateTypeKVUpdated,
			}, {
				// 2nd node has duplicate main IP and also has other interface IPs assigned
				KVPair: model.KVPair{
					Key: model.ResourceKey{Kind: internalapi.KindNode, Name: "node2"},
					Value: &internalapi.Node{
						Spec: internalapi.NodeSpec{
							BGP: &internalapi.NodeBGPSpec{
								IPv4Address:        nodeIPStr,
								IPv4IPIPTunnelAddr: nodeIP2Str,
							},
							IPv4VXLANTunnelAddr: nodeIP3Str,
							Wireguard: &internalapi.NodeWireguardSpec{
								InterfaceIPv4Address: nodeIP4Str,
							},
						},
					},
				},
				UpdateType: api.UpdateTypeKVNew,
			}}

			for _, u := range updates {
				elc.OnResourceUpdate(u)
			}
		})

		It("should handle multiple assigned IPs to different nodes", func() {
			By("checking nodes return no results for duplicate IP")
			_, ok := elc.GetNode(nodeIP)
			Expect(ok).To(BeFalse())
		})

		It("should handle unique IPs on new node", func() {
			By("checking nodes returns results for unique IP")
			node, ok := elc.GetNode(nodeIP2)
			Expect(ok).To(BeTrue())
			Expect(node).To(Equal("node2"))

			node, ok = elc.GetNode(nodeIP3)
			Expect(ok).To(BeTrue())
			Expect(node).To(Equal("node2"))

			node, ok = elc.GetNode(nodeIP4)
			Expect(ok).To(BeTrue())
			Expect(node).To(Equal("node2"))
		})

		It("should handle reconfiguring node 2 so that node 1 IP is unique again", func() {
			By("Reconfiguring node 2")
			elc.OnResourceUpdate(api.Update{
				KVPair: model.KVPair{
					Key: model.ResourceKey{Kind: internalapi.KindNode, Name: "node2"},
					Value: &internalapi.Node{
						Spec: internalapi.NodeSpec{
							BGP: &internalapi.NodeBGPSpec{
								IPv4Address:        nodeIP2Str,
								IPv4IPIPTunnelAddr: nodeIP2Str,
							},
							IPv4VXLANTunnelAddr: nodeIP3Str,
							Wireguard: &internalapi.NodeWireguardSpec{
								InterfaceIPv4Address: nodeIP4Str,
							},
						},
					},
				},
				UpdateType: api.UpdateTypeKVUpdated,
			})

			By("checking nodes returns results for node 1 unique IP")
			node, ok := elc.GetNode(nodeIP)
			Expect(ok).To(BeTrue())
			Expect(node).To(Equal("node1"))
		})

		It("should handle reconfiguring node 1 so that node 2 IPs are all unique", func() {
			By("Reconfiguring node 1 to remove the main IP")
			elc.OnResourceUpdate(api.Update{
				KVPair: model.KVPair{
					Key: model.ResourceKey{Kind: internalapi.KindNode, Name: "node1"},
					Value: &internalapi.Node{
						Spec: internalapi.NodeSpec{
							BGP: &internalapi.NodeBGPSpec{
								IPv4IPIPTunnelAddr: nodeIPStr,
							},
						},
					},
				},
				UpdateType: api.UpdateTypeKVUpdated,
			})

			By("checking node1 and node 2 still share an IP")
			_, ok := elc.GetNode(nodeIP)
			Expect(ok).To(BeFalse())

			By("Reconfiguring node 1 to remove the remaining IP")
			elc.OnResourceUpdate(api.Update{
				KVPair: model.KVPair{
					Key: model.ResourceKey{Kind: internalapi.KindNode, Name: "node1"},
					Value: &internalapi.Node{
						Spec: internalapi.NodeSpec{},
					},
				},
				UpdateType: api.UpdateTypeKVUpdated,
			})

			By("checking node 2 has unique IPs")
			node, ok := elc.GetNode(nodeIP)
			Expect(ok).To(BeTrue())
			Expect(node).To(Equal("node2"))
		})
	})
})

var _ = Describe("EndpointLookupsCache GetEndpointFromInterfaceKey", func() {
	var cache *calc.EndpointLookupsCache

	ipToAddr := func(ipStr string) [16]byte {
		var addr [16]byte
		ip := net.ParseIP(ipStr)
		Expect(ip).NotTo(BeNil(), "IP address should be valid")
		copy(addr[:], ip.To16())
		return addr
	}

	createWorkloadEndpoint := func(hostname, orchID, workloadID, endpointID, interfaceName, ipStr string) (*model.WorkloadEndpointKey, *model.WorkloadEndpoint) {
		key := model.WorkloadEndpointKey{
			Hostname:       hostname,
			OrchestratorID: orchID,
			WorkloadID:     workloadID,
			EndpointID:     endpointID,
		}

		ip := net.ParseIP(ipStr)
		cidr := net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(32, 32),
		}
		endpoint := &model.WorkloadEndpoint{
			State:      "active",
			Name:       endpointID,
			ProfileIDs: []string{"profile1"},
			IPv4Nets: []libcaliconet.IPNet{
				{IPNet: cidr},
			},
		}

		return &key, endpoint
	}

	createHostEndpoint := func(hostname, endpointID, interfaceName, ipStr string) (*model.HostEndpointKey, *model.HostEndpoint) {
		key := model.HostEndpointKey{
			Hostname:   hostname,
			EndpointID: endpointID,
		}

		ip := net.ParseIP(ipStr)

		endpoint := &model.HostEndpoint{
			Name: interfaceName,
			ExpectedIPv4Addrs: []libcaliconet.IP{
				{IP: ip},
			},
		}

		return &key, endpoint
	}

	BeforeEach(func() {
		cache = calc.NewEndpointLookupsCache()
	})

	Context("with empty interface key", func() {
		It("should delegate to GetEndpoint", func() {
			// Setup - add a single endpoint
			hepKey, hep := createHostEndpoint("test-host", "k8s", "eth0", "192.168.1.1")
			cache.OnEndpointTierUpdate(*hepKey, hep, nil, nil, nil)

			// Test
			addr := ipToAddr("192.168.1.1")
			ep, found := cache.GetHostEndpointFromInterfaceKey("", addr)

			// Verification
			Expect(found).To(BeTrue())
			Expect(ep).NotTo(BeNil())
			Expect(ep.Key().String()).To(Equal(hepKey.String()))
		})
	})

	Context("with exact interface match", func() {
		It("should return endpoint with matching interface name", func() {
			// Setup - add an endpoint with a specific interface name
			hepKey, hep := createHostEndpoint("test-host", "k8s", "eth0", "192.168.1.1")
			cache.OnEndpointTierUpdate(*hepKey, hep, nil, nil, nil)

			// Test
			addr := ipToAddr("192.168.1.1")
			ep, found := cache.GetHostEndpointFromInterfaceKey("eth0", addr)

			// Verification
			Expect(found).To(BeTrue())
			Expect(ep).NotTo(BeNil())
			Expect(ep.Key().String()).To(Equal(hepKey.String()))
		})
	})

	Context("with wildcard interface match", func() {
		It("should return endpoint with matching IP regardless of interface name", func() {
			// Setup - add an endpoint with a specific interface name
			hepKey, hep := createHostEndpoint("test-host", "k8s", "*", "192.168.1.1")
			cache.OnEndpointTierUpdate(*hepKey, hep, nil, nil, nil)

			// Test with wildcard interface name
			addr := ipToAddr("192.168.1.1")
			ep, found := cache.GetHostEndpointFromInterfaceKey("eth0", addr)

			// Verification
			Expect(found).To(BeTrue())
			Expect(ep).NotTo(BeNil())
			Expect(ep.Key().String()).To(Equal(hepKey.String()))
		})
	})

	Context("with multiple endpoints for same IP", func() {
		It("should prioritize exact interface match", func() {
			// Setup - add multiple endpoints with the same IP but different interface names
			hepKey1, hep1 := createHostEndpoint("test-host", "k8s", "eth0", "192.168.1.1")
			hepKey2, hep2 := createHostEndpoint("test-host", "k8s", "eth1", "192.168.1.1")

			cache.OnEndpointTierUpdate(*hepKey1, hep1, nil, nil, nil)
			cache.OnEndpointTierUpdate(*hepKey2, hep2, nil, nil, nil)

			// Test for exact match on eth1
			addr := ipToAddr("192.168.1.1")
			ep, found := cache.GetHostEndpointFromInterfaceKey("eth1", addr)

			// Verification
			Expect(found).To(BeTrue())
			Expect(ep).NotTo(BeNil())
			Expect(ep.Key().String()).To(Equal(hepKey2.String()), "Should return endpoint with matching interface name eth1")
		})
	})

	Context("with no interface match but endpoint without interface", func() {
		It("should return endpoint without interface name", func() {
			// Setup - add endpoint with interface and one without
			hepKey1, hep1 := createHostEndpoint("test-host", "k8s", "eth0", "192.168.1.1")
			hepKey2, hep2 := createHostEndpoint("test-host", "k8s", "eth1", "192.168.1.1")
			hepNoInterface, hep3 := createHostEndpoint("test-host", "k8s", "", "192.168.1.1")

			cache.OnEndpointTierUpdate(*hepKey1, hep1, nil, nil, nil)
			cache.OnEndpointTierUpdate(*hepKey2, hep2, nil, nil, nil)
			cache.OnEndpointTierUpdate(*hepNoInterface, hep3, nil, nil, nil)

			// Test with non-matching interface name
			addr := ipToAddr("192.168.1.1")
			ep, found := cache.GetHostEndpointFromInterfaceKey("nonexistent", addr)

			// Verification
			Expect(found).To(BeTrue())
			Expect(ep).NotTo(BeNil())
			Expect(ep.Key().String()).To(Equal(hepNoInterface.String()), "Should return endpoint without interface name")
		})
	})

	Context("with no endpoints for IP", func() {
		It("should return nil and false", func() {
			// Setup - add endpoint with different IP
			hepKey, hep := createHostEndpoint("test-host", "k8s", "eth0", "192.168.1.1")
			cache.OnEndpointTierUpdate(*hepKey, hep, nil, nil, nil)

			// Test with IP that doesn't match any endpoint
			addr := ipToAddr("192.168.1.2")
			ep, found := cache.GetHostEndpointFromInterfaceKey("eth0", addr)

			// Verification
			Expect(found).To(BeFalse())
			Expect(ep).To(BeNil())
		})
	})

	Context("with both workload and host endpoints", func() {
		It("should find the right endpoint based on interface", func() {
			// Setup - add both workload and host endpoints with same IP
			wepKey, wep := createWorkloadEndpoint("test-host", "k8s", "pod-1", "wep-eth0", "wep-eth0", "192.168.1.1")
			hepKey, hep := createHostEndpoint("test-host", "host-ep", "host-eth0", "192.168.1.1")

			cache.OnEndpointTierUpdate(*wepKey, wep, nil, nil, nil)
			cache.OnEndpointTierUpdate(*hepKey, hep, nil, nil, nil)

			// Test looking for host endpoint
			addr := ipToAddr("192.168.1.1")
			ep, found := cache.GetHostEndpointFromInterfaceKey("host-eth0", addr)

			// Verification
			Expect(found).To(BeTrue())
			Expect(ep).NotTo(BeNil())
			Expect(ep.Key().String()).To(Equal(hepKey.String()), "Should return host endpoint with matching interface name")
		})
	})
})

func TestIsEndpointDeleted(t *testing.T) {
	// Create a cache with a short deletion delay for testing
	cache := calc.NewEndpointLookupsCache(calc.WithDeletionDelay(50 * time.Millisecond))

	// Create a test endpoint key
	key := model.WorkloadEndpointKey{
		Hostname:       "test-node",
		OrchestratorID: "cni",
		WorkloadID:     "test-workload",
		EndpointID:     "eth0",
	}

	// Create endpoint data using the same pattern as existing tests
	ip := net.ParseIP("10.0.0.1")
	cidr := net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(32, 32),
	}

	endpoint := &model.WorkloadEndpoint{
		State:      "active",
		Name:       "test-endpoint",
		ProfileIDs: []string{"test-profile"},
		IPv4Nets:   []libcaliconet.IPNet{{IPNet: cidr}},
	}

	// Add the endpoint to the cache using the correct API pattern
	ed := calc.CalculateRemoteEndpoint(key, endpoint)
	cache.OnUpdate(api.Update{
		UpdateType: api.UpdateTypeKVNew,
		KVPair: model.KVPair{
			Key:   key,
			Value: endpoint,
		},
	})

	// Check if the endpoint is deleted (should be false)
	if cache.IsEndpointDeleted(ed) {
		t.Error("Expected endpoint to not be deleted before deletion")
	}

	// Remove the endpoint (this should mark it for deletion)
	cache.OnUpdate(api.Update{
		UpdateType: api.UpdateTypeKVDeleted,
		KVPair: model.KVPair{
			Key:   key,
			Value: nil,
		},
	})

	// Check if the endpoint is now marked as deleted (should be true)
	if !cache.IsEndpointDeleted(ed) {
		t.Error("Expected endpoint to be marked as deleted after deletion")
	}

	// Wait for the deletion delay to pass
	time.Sleep(100 * time.Millisecond)

	// Check if the endpoint is still marked as deleted (should be false as it's been cleaned up)
	if cache.IsEndpointDeleted(ed) {
		t.Error("Expected endpoint to not be marked as deleted after cleanup")
	}
}

func newTierInfoSlice() []calc.TierInfo {
	return nil
}

func policyMetadata(policy *model.Policy) *calc.PolicyMetadata {
	pm := calc.ExtractPolicyMetadata(policy)
	return &pm
}
