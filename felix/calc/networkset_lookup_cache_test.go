// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.

package calc_test

import (
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	calinet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var _ = Describe("NetworkSetLookupsCache IP tests", func() {
	ec := NewNetworkSetLookupsCache()

	DescribeTable(
		"Check adding/deleting networkset modifies the cache",
		func(key model.NetworkSetKey, netset *model.NetworkSet, ipAddr net.IP) {
			c := "NetworkSet(" + key.Name + ")"
			update := api.Update{
				KVPair: model.KVPair{
					Key:   key,
					Value: netset,
				},
				UpdateType: api.UpdateTypeKVNew,
			}
			var addrB [16]byte
			copy(addrB[:], ipAddr.To16()[:16])
			ec.OnUpdate(update)
			ed, ok := ec.GetNetworkSetFromIP(addrB)
			Expect(ok).To(BeTrue(), c)
			Expect(ed.Key()).To(Equal(key))

			update = api.Update{
				KVPair: model.KVPair{
					Key: key,
				},
				UpdateType: api.UpdateTypeKVDeleted,
			}
			ec.OnUpdate(update)
			_, ok = ec.GetNetworkSetFromIP(addrB)
			Expect(ok).To(BeFalse(), c)
		},
		Entry("networkset with IPv4", netSet1Key, &netSet1, localWlEp1.IPv4Nets[0].IP),
		Entry("networkset with IPv6", netSet1Key, &netSet1, mustParseNet("feed:beef::1/128").IP),
	)

	It("should process networkSets with multiple CIDRs", func() {
		By("adding a networkset with multiple CIDRs")
		update := api.Update{
			KVPair: model.KVPair{
				Key:   netSet1Key,
				Value: &netSet1,
			},
			UpdateType: api.UpdateTypeKVNew,
		}
		origNetSetLabels := map[string]string{
			"a": "b",
		}
		ec.OnUpdate(update)

		verifyIpToNetworkset := func(key model.Key, ipAddr net.IP, exists bool, labels map[string]string) {
			name := "NetworkSet(" + key.(model.NetworkSetKey).Name + ")"
			var addrB [16]byte
			copy(addrB[:], ipAddr.To16()[:16])

			ed, ok := ec.GetNetworkSetFromIP(addrB)
			if exists {
				Expect(ok).To(BeTrue(), name+"\n"+ec.DumpNetworksets())
				Expect(ed.Key()).To(Equal(key), ec.DumpNetworksets())
				if labels != nil {
					Expect(ed.Labels()).To(Equal(uniquelabels.Make(labels)), ec.DumpNetworksets())
				}
			} else {
				Expect(ok).To(BeFalse(), name+".\n"+ec.DumpNetworksets())
			}
		}

		By("verifying all subnets of the networkset are present in the mapping")
		for _, cidr := range netSet1.Nets {
			verifyIpToNetworkset(netSet1Key, cidr.IP, true, origNetSetLabels)
		}

		By("adding networkset2")
		update = api.Update{
			KVPair: model.KVPair{
				Key:   netSet2Key,
				Value: &netSet2,
			},
			UpdateType: api.UpdateTypeKVNew,
		}
		netSet2Labels := map[string]string{
			"a": "b",
		}
		ec.OnUpdate(update)

		By("verifying networkset2 is in the mapping")
		// This check validates that netSet2 is found since one subnet is outside the range of netSet1's subnets.
		for _, cidr := range netSet2.Nets {
			// For overlapping CIDRs (12.0.0.0/24), lowest-lexicographic-name-wins applies
			// netSet1 ("netset-1") comes before netSet2 ("netset-2") lexicographically, so netSet1 wins
			// For unique CIDRs (13.1.0.0/24), netSet2 should still be returned
			var expectedKey model.Key
			var expectedLabels map[string]string
			if cidr.String() == "12.0.0.0/24" {
				// This overlaps with netSet1, so netSet1 should win due to lexicographic ordering
				expectedKey = netSet1Key
				expectedLabels = origNetSetLabels
			} else {
				// This is unique to netSet2
				expectedKey = netSet2Key
				expectedLabels = netSet2Labels
			}
			verifyIpToNetworkset(expectedKey, cidr.IP, true, expectedLabels)
		}

		By("deleting networkset2")
		update = api.Update{
			KVPair: model.KVPair{
				Key: netSet2Key,
			},
			UpdateType: api.UpdateTypeKVDeleted,
		}
		ec.OnUpdate(update)

		By("verifying the unique subnets of networkset2 are not present in the mapping")
		netSet2SubnetLen := len(netSet2.Nets)
		if netSet2SubnetLen > 0 {
			verifyIpToNetworkset(netSet2Key, netSet2.Nets[netSet2SubnetLen-1].IP, false, nil)
		}

		By("updating the networkset and adding new labels")
		update = api.Update{
			KVPair: model.KVPair{
				Key:   netSet1Key,
				Value: &netSet1WithBEqB,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		}
		ec.OnUpdate(update)

		updatedNetSetLabels := map[string]string{
			"foo": "bar",
			"b":   "b",
		}

		By("verifying the subnets are present with the updated labels")
		for _, cidr := range netSet1WithBEqB.Nets {
			verifyIpToNetworkset(netSet1Key, cidr.IP, true, updatedNetSetLabels)
		}

		By("updating the networkset keeping all the information as before")
		update = api.Update{
			KVPair: model.KVPair{
				Key:   netSet1Key,
				Value: &netSet1WithBEqB,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		}
		ec.OnUpdate(update)

		By("verifying the subnets are as they were before")
		for _, cidr := range netSet1WithBEqB.Nets {
			verifyIpToNetworkset(netSet1Key, cidr.IP, true, updatedNetSetLabels)
		}

		By("finally removing the networkset and no mapping is present")
		update = api.Update{
			KVPair: model.KVPair{
				Key: netSet1Key,
			},
			UpdateType: api.UpdateTypeKVDeleted,
		}
		ec.OnUpdate(update)

		By("verifying there is no mapping present")
		for _, cidr := range netSet1.Nets {
			verifyIpToNetworkset(netSet1Key, cidr.IP, false, nil)
		}
	})

	It("should longest prefix match for a given IP from multiple CIDRs", func() {
		By("adding a networkset with multiple overlapping CIDRs")
		update := api.Update{
			KVPair: model.KVPair{
				Key:   netSet3Key,
				Value: &netSet3,
			},
			UpdateType: api.UpdateTypeKVNew,
		}
		ec.OnUpdate(update)
		update = api.Update{
			KVPair: model.KVPair{
				Key:   netSet1Key,
				Value: &netSet1,
			},
			UpdateType: api.UpdateTypeKVNew,
		}
		ec.OnUpdate(update)
		verifyIpInCidrUsingLpm := func(key model.Key, ipAddr net.IP, exists bool) {
			name := "NetworkSet(" + key.(model.NetworkSetKey).Name + ")"
			var addrB [16]byte
			copy(addrB[:], ipAddr.To16()[:16])
			ed, ok := ec.GetNetworkSetFromIP(addrB)
			if exists {
				Expect(ok).To(BeTrue(), name+"\n"+ec.DumpNetworksets())
				Expect(ed.Key()).To(Equal(key))
			} else {
				Expect(ok).To(BeFalse(), name+".\n"+ec.DumpNetworksets())
			}
		}

		By("verifying all subnets of the networkset are present in the mapping")
		verifyIpInCidrUsingLpm(netSet1Key, netset3Ip1a, true)
		verifyIpInCidrUsingLpm(netSet3Key, netset3Ip1b, true)
	})
})

var _ = Describe("NetworkSetLookupsCache Egress domain tests", func() {
	ec := NewNetworkSetLookupsCache()

	DescribeTable(
		"Check adding/deleting networkset modifies the cache",
		func(netset1, netset2 *model.NetworkSet, domain1, domain2 string, before1, before2, after1, after2 bool) {
			update := api.Update{
				KVPair: model.KVPair{
					Key:   netSet1Key,
					Value: netset1,
				},
				UpdateType: api.UpdateTypeKVNew,
			}
			ec.OnUpdate(update)
			ed, match := ec.GetNetworkSetFromEgressDomainWithNamespace(domain1, "")
			Expect(match != MatchNone).To(Equal(before1))
			if match != MatchNone {
				Expect(ed.Key()).To(Equal(netSet1Key))
			}
			ed, match = ec.GetNetworkSetFromEgressDomainWithNamespace(domain2, "")
			Expect(match != MatchNone).To(Equal(before2))
			if match != MatchNone {
				Expect(ed.Key()).To(Equal(netSet1Key))
			}

			update = api.Update{
				KVPair: model.KVPair{
					Key:   netSet1Key,
					Value: netset2,
				},
				UpdateType: api.UpdateTypeKVUpdated,
			}
			ec.OnUpdate(update)
			ed, match = ec.GetNetworkSetFromEgressDomainWithNamespace(domain1, "")
			Expect(match != MatchNone).To(Equal(after1))
			if match != MatchNone {
				Expect(ed.Key()).To(Equal(netSet1Key))
			}
			ed, match = ec.GetNetworkSetFromEgressDomainWithNamespace(domain2, "")
			Expect(match != MatchNone).To(Equal(after2))
			if match != MatchNone {
				Expect(ed.Key()).To(Equal(netSet1Key))
			}

			update = api.Update{
				KVPair: model.KVPair{
					Key: netSet1Key,
				},
				UpdateType: api.UpdateTypeKVDeleted,
			}
			ec.OnUpdate(update)
			ed, match = ec.GetNetworkSetFromEgressDomainWithNamespace(domain1, "")
			Expect(match != MatchNone).To(BeFalse())
			ed, match = ec.GetNetworkSetFromEgressDomainWithNamespace(domain2, "")
			Expect(match != MatchNone).To(BeFalse())
		},
		Entry("none -> tigera+google", &netSet1, &netSet1WithEgressDomains, "tigera.io", "google.com", false, false, true, true),
		Entry("google -> none", &netSet2WithEgressDomains, &netSet1, "tigera.io", "google.com", false, true, false, false),
		Entry("tigera+google -> google", &netSet1WithEgressDomains, &netSet2WithEgressDomains, "tigera.io", "google.com", true, true, false, true),
	)

	DescribeTable(
		"Check adding/deleting multiple networksets with the same domains modifies the cache",
		func(netset1, netset2 *model.NetworkSet, domain1, domain2, domain12 string) {
			// Add networkset 1. Check domain1 and domain12 both return netset1.
			update := api.Update{
				KVPair: model.KVPair{
					Key:   netSet1Key,
					Value: netset1,
				},
				UpdateType: api.UpdateTypeKVNew,
			}
			ec.OnUpdate(update)
			ed, match := ec.GetNetworkSetFromEgressDomainWithNamespace(domain1, "")
			Expect(match != MatchNone).To(BeTrue())
			Expect(ed.Key()).To(Equal(netSet1Key))
			ed, match = ec.GetNetworkSetFromEgressDomainWithNamespace(domain2, "")
			Expect(match != MatchNone).To(BeFalse())
			ed, match = ec.GetNetworkSetFromEgressDomainWithNamespace(domain12, "")
			Expect(match != MatchNone).To(BeTrue())
			Expect(ed.Key()).To(Equal(netSet1Key))

			// Add networkset 2. Check domain1 still returns netset1, domain2 returns netset2 and domain12 returns
			// either networkset.
			update = api.Update{
				KVPair: model.KVPair{
					Key:   netSet2Key,
					Value: netset2,
				},
				UpdateType: api.UpdateTypeKVNew,
			}
			ec.OnUpdate(update)
			ed, match = ec.GetNetworkSetFromEgressDomainWithNamespace(domain1, "")
			Expect(match != MatchNone).To(BeTrue())
			Expect(ed.Key()).To(Equal(netSet1Key))
			ed, match = ec.GetNetworkSetFromEgressDomainWithNamespace(domain2, "")
			Expect(match != MatchNone).To(BeTrue())
			Expect(ed.Key()).To(Equal(netSet2Key))
			ed, match = ec.GetNetworkSetFromEgressDomainWithNamespace(domain12, "")
			Expect(match != MatchNone).To(BeTrue())
			Expect(ed.Key()).To(BeElementOf(netSet1Key, netSet2Key))

			// Delete networkset 1.  Check domain1 is not present and check domain2 and domain12 both return netset2.
			update = api.Update{
				KVPair: model.KVPair{
					Key: netSet1Key,
				},
				UpdateType: api.UpdateTypeKVDeleted,
			}
			ec.OnUpdate(update)
			ed, match = ec.GetNetworkSetFromEgressDomainWithNamespace(domain1, "")
			Expect(match != MatchNone).To(BeFalse())
			ed, match = ec.GetNetworkSetFromEgressDomainWithNamespace(domain2, "")
			Expect(match != MatchNone).To(BeTrue())
			Expect(ed.Key()).To(Equal(netSet2Key))
			ed, match = ec.GetNetworkSetFromEgressDomainWithNamespace(domain12, "")
			Expect(match != MatchNone).To(BeTrue())
			Expect(ed.Key()).To(Equal(netSet2Key))

			// Delete networkset 1.  There should be no domain name mappings now.
			update = api.Update{
				KVPair: model.KVPair{
					Key: netSet2Key,
				},
				UpdateType: api.UpdateTypeKVDeleted,
			}
			ec.OnUpdate(update)
			ed, match = ec.GetNetworkSetFromEgressDomainWithNamespace(domain1, "")
			Expect(match == MatchNone).To(BeTrue())
			ed, match = ec.GetNetworkSetFromEgressDomainWithNamespace(domain2, "")
			Expect(match == MatchNone).To(BeTrue())
			ed, match = ec.GetNetworkSetFromEgressDomainWithNamespace(domain12, "")
			Expect(match == MatchNone).To(BeTrue())
		},
		Entry("tigera+google and projectcalico+google",
			&netSet1WithEgressDomains, &netSet2WithEgressDomains,
			"tigera.io", "projectcalico.org", "google.com",
		),
	)
})

var _ = Describe("NetworkSetLookupsCache namespace precedence tests", func() {
	var ec *NetworkSetLookupsCache

	BeforeEach(func() {
		ec = NewNetworkSetLookupsCache()
	})

	// Helper function to convert IP to [16]byte format expected by the cache
	ipToBytes := func(ip net.IP) [16]byte {
		var addrB [16]byte
		copy(addrB[:], ip.To16()[:16])
		return addrB
	}

	// Test data for namespace precedence
	makeTestNetworkSets := func() (globalKey, ns1Key, ns2Key model.Key, globalNS, ns1NS, ns2NS model.NetworkSet) {
		// Global NetworkSet with broad CIDR
		globalKey = model.NetworkSetKey{Name: "global-netset"}
		globalNS = model.NetworkSet{
			Nets: []calinet.IPNet{
				calinet.MustParseNetwork("10.0.0.0/8"), // Broad CIDR
			},
			Labels: uniquelabels.Make(map[string]string{
				"type": "global",
			}),
		}

		// Namespaced NetworkSet in ns1 with more specific CIDR
		ns1Key = model.NetworkSetKey{Name: "ns1/specific-netset"}
		ns1NS = model.NetworkSet{
			Nets: []calinet.IPNet{
				calinet.MustParseNetwork("10.1.0.0/16"), // More specific than global
			},
			Labels: uniquelabels.Make(map[string]string{
				"type": "namespace-specific",
				"env":  "test",
			}),
		}

		// Namespaced NetworkSet in ns2 with different but overlapping CIDR
		ns2Key = model.NetworkSetKey{Name: "ns2/ns2-netset"}
		ns2NS = model.NetworkSet{
			Nets: []calinet.IPNet{
				calinet.MustParseNetwork("10.2.0.0/16"), // Different from ns1 but within global
			},
			Labels: uniquelabels.Make(map[string]string{
				"type": "namespace-specific",
				"env":  "prod",
			}),
		}

		return
	}

	It("should prioritize namespaced NetworkSet over global when namespace matches", func() {
		globalKey, ns1Key, _, globalNS, ns1NS, _ := makeTestNetworkSets()

		// Add global NetworkSet
		ec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   globalKey,
				Value: &globalNS,
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		// Add namespaced NetworkSet
		ec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   ns1Key,
				Value: &ns1NS,
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		// Test IP that matches both (within ns1 range and global range)
		testIP := ipToBytes(calinet.MustParseNetwork("10.1.1.1/32").IP)

		// Without namespace context - should return longest prefix match (ns1)
		networkSet, ok := ec.GetNetworkSetFromIP(testIP)
		Expect(ok).To(BeTrue())
		Expect(networkSet.Key()).To(Equal(globalKey))

		// With ns1 namespace context - should return ns1 NetworkSet
		networkSet, match := ec.GetNetworkSetFromIPWithNamespace(testIP, "ns1")
		Expect(match).To(Equal(MatchSameNamespace))
		Expect(networkSet.Key()).To(Equal(ns1Key))

		// With different namespace context - should fallback to longest prefix match (ns1)
		networkSet, match = ec.GetNetworkSetFromIPWithNamespace(testIP, "ns2")
		Expect(match).To(Equal(MatchGlobal))
		Expect(networkSet.Key()).To(Equal(globalKey))

		// Test IP that only matches global range
		testIPGlobal := ipToBytes(calinet.MustParseNetwork("10.3.1.1/32").IP)

		// With any namespace context - should return global NetworkSet
		networkSet, match = ec.GetNetworkSetFromIPWithNamespace(testIPGlobal, "ns1")
		Expect(match).To(Equal(MatchGlobal))
		Expect(networkSet.Key()).To(Equal(globalKey))
	})

	It("should return consistent ordering when multiple NetworkSets match but in different namespaces", func() {
		// Create multiple NetworkSets with same CIDR in different namespaces
		ns1Key := model.NetworkSetKey{Name: "ns1/common-name"}
		ns1NS := model.NetworkSet{
			Nets: []calinet.IPNet{
				calinet.MustParseNetwork("172.16.0.0/24"),
			},
			Labels: uniquelabels.Make(map[string]string{"namespace": "ns1"}),
		}

		ns2Key := model.NetworkSetKey{Name: "ns2/common-name"}
		ns2NS := model.NetworkSet{
			Nets: []calinet.IPNet{
				calinet.MustParseNetwork("172.16.0.0/24"), // Same CIDR
			},
			Labels: uniquelabels.Make(map[string]string{"namespace": "ns2"}),
		}

		// Add both NetworkSets
		ec.OnUpdate(api.Update{
			KVPair:     model.KVPair{Key: ns1Key, Value: &ns1NS},
			UpdateType: api.UpdateTypeKVNew,
		})
		ec.OnUpdate(api.Update{
			KVPair:     model.KVPair{Key: ns2Key, Value: &ns2NS},
			UpdateType: api.UpdateTypeKVNew,
		})

		testIP := ipToBytes(calinet.MustParseNetwork("172.16.0.100/32").IP)

		// Test multiple times to ensure consistent ordering
		var firstResult model.Key
		for i := range 1000 {
			networkSet, match := ec.GetNetworkSetFromIPWithNamespace(testIP, "ns1")
			Expect(match).ToNot(Equal(MatchNone))

			if i == 0 {
				firstResult = networkSet.Key()
			} else {
				Expect(networkSet.Key()).To(Equal(firstResult), "Result should be consistent across multiple calls")
			}
		}
	})

	It("should return consistent ordering when multiple NetworkSets match in the same namespace", func() {
		// Create multiple NetworkSets with same CIDR in different namespaces
		ns1Key := model.NetworkSetKey{Name: "ns1/netset1"}
		ns1NS := model.NetworkSet{
			Nets: []calinet.IPNet{
				calinet.MustParseNetwork("172.16.0.0/24"),
			},
			Labels: uniquelabels.Make(map[string]string{"namespace": "ns1"}),
		}

		ns2Key := model.NetworkSetKey{Name: "ns1/netset2"}
		ns2NS := model.NetworkSet{
			Nets: []calinet.IPNet{
				calinet.MustParseNetwork("172.16.0.0/24"), // Same CIDR
			},
			Labels: uniquelabels.Make(map[string]string{"namespace": "ns1"}),
		}

		// Add both NetworkSets
		ec.OnUpdate(api.Update{
			KVPair:     model.KVPair{Key: ns1Key, Value: &ns1NS},
			UpdateType: api.UpdateTypeKVNew,
		})
		ec.OnUpdate(api.Update{
			KVPair:     model.KVPair{Key: ns2Key, Value: &ns2NS},
			UpdateType: api.UpdateTypeKVNew,
		})

		testIP := ipToBytes(calinet.MustParseNetwork("172.16.0.100/32").IP)

		// Test multiple times to ensure consistent ordering
		var firstResult model.Key
		for i := range 1000 {
			networkSet, match := ec.GetNetworkSetFromIPWithNamespace(testIP, "ns1")
			Expect(match).ToNot(Equal(MatchNone))

			if i == 0 {
				firstResult = networkSet.Key()
			} else {
				Expect(networkSet.Key()).To(Equal(firstResult), "Result should be consistent across multiple calls")
			}
		}
	})

	It("should handle complex namespace precedence scenarios", func() {
		globalKey, ns1Key, ns2Key, globalNS, ns1NS, ns2NS := makeTestNetworkSets()

		// Add all NetworkSets
		updates := []api.Update{
			{KVPair: model.KVPair{Key: globalKey, Value: &globalNS}, UpdateType: api.UpdateTypeKVNew},
			{KVPair: model.KVPair{Key: ns1Key, Value: &ns1NS}, UpdateType: api.UpdateTypeKVNew},
			{KVPair: model.KVPair{Key: ns2Key, Value: &ns2NS}, UpdateType: api.UpdateTypeKVNew},
		}
		for _, update := range updates {
			ec.OnUpdate(update)
		}

		// Test cases with different IPs and namespace contexts
		testCases := []struct {
			ip          string
			namespace   string
			expectedKey model.Key
			description string
		}{
			{"10.1.1.1", "ns1", ns1Key, "IP matching ns1 netset and ns1 context should return ns1"},
			{"10.1.1.1", "ns2", globalKey, "IP matching global netset but ns2 context should return global"},
			{"10.1.1.1", "", globalKey, "IP matching global netset with no context should return globalKey"},
			{"10.2.1.1", "ns2", ns2Key, "IP matching ns2 netset and ns2 context should return ns2"},
			{"10.2.1.1", "ns1", globalKey, "IP matching global netset but ns1 context should return global"},
			{"10.3.1.1", "ns1", globalKey, "IP matching global netset but ns1 context should return global"},
			{"10.3.1.1", "ns2", globalKey, "IP matching global netset but ns2 context should return global"},
		}

		for _, tc := range testCases {
			testIP := ipToBytes(calinet.MustParseNetwork(tc.ip + "/32").IP)

			if tc.namespace == "" {
				networkSet, ok := ec.GetNetworkSetFromIP(testIP)
				Expect(ok).To(BeTrue(), tc.description)
				Expect(networkSet.Key()).To(Equal(tc.expectedKey), tc.description)
			} else {
				networkSet, match := ec.GetNetworkSetFromIPWithNamespace(testIP, tc.namespace)
				Expect(match).ToNot(Equal(MatchNone), tc.description)
				Expect(networkSet.Key()).To(Equal(tc.expectedKey), tc.description)
			}
		}
	})
})

var _ = Describe("NetworkSetLookupsCache lexicographic ordering tests", func() {
	var ec *NetworkSetLookupsCache

	BeforeEach(func() {
		ec = NewNetworkSetLookupsCache()
	})

	// Helper function to convert IP to [16]byte format expected by the cache
	ipToBytes := func(ip net.IP) [16]byte {
		var addrB [16]byte
		copy(addrB[:], ip.To16()[:16])
		return addrB
	}

	Describe("GetNetworkSetFromIPWithNamespace lexicographic ordering", func() {
		It("should return lexicographically lowest NetworkSet when multiple global NetworkSets match same CIDR", func() {
			// Create multiple global NetworkSets with identical CIDR
			// Names in lexicographic order: aaa-netset, bbb-netset, zzz-netset
			netsAKey := model.NetworkSetKey{Name: "zzz-netset"}
			netsA := model.NetworkSet{
				Nets: []calinet.IPNet{
					calinet.MustParseNetwork("192.168.1.0/24"),
				},
				Labels: uniquelabels.Make(map[string]string{"name": "zzz"}),
			}

			netsBKey := model.NetworkSetKey{Name: "aaa-netset"}
			netsB := model.NetworkSet{
				Nets: []calinet.IPNet{
					calinet.MustParseNetwork("192.168.1.0/24"),
				},
				Labels: uniquelabels.Make(map[string]string{"name": "aaa"}),
			}

			netsCKey := model.NetworkSetKey{Name: "bbb-netset"}
			netsC := model.NetworkSet{
				Nets: []calinet.IPNet{
					calinet.MustParseNetwork("192.168.1.0/24"),
				},
				Labels: uniquelabels.Make(map[string]string{"name": "bbb"}),
			}

			// Add in non-lexicographic order to ensure ordering is not insertion-based
			ec.OnUpdate(api.Update{
				KVPair:     model.KVPair{Key: netsAKey, Value: &netsA},
				UpdateType: api.UpdateTypeKVNew,
			})
			ec.OnUpdate(api.Update{
				KVPair:     model.KVPair{Key: netsCKey, Value: &netsC},
				UpdateType: api.UpdateTypeKVNew,
			})
			ec.OnUpdate(api.Update{
				KVPair:     model.KVPair{Key: netsBKey, Value: &netsB},
				UpdateType: api.UpdateTypeKVNew,
			})

			testIP := ipToBytes(calinet.MustParseNetwork("192.168.1.100/32").IP)

			// Should always return "aaa-netset" as it's lexicographically lowest
			networkSet, match := ec.GetNetworkSetFromIPWithNamespace(testIP, "")
			Expect(match).ToNot(Equal(MatchNone))
			Expect(networkSet.Key()).To(Equal(netsBKey), "Should return lexicographically lowest global NetworkSet")
			labelValue, labelOk := networkSet.Labels().GetString("name")
			Expect(labelOk).To(BeTrue())
			Expect(labelValue).To(Equal("aaa"))
		})

		It("should return lexicographically lowest NetworkSet when multiple namespaced NetworkSets match same CIDR in same namespace", func() {
			// Create multiple namespaced NetworkSets with identical CIDR in same namespace
			// Names: ns1/zebra-netset, ns1/alpha-netset, ns1/middle-netset
			netsZebraKey := model.NetworkSetKey{Name: "ns1/zebra-netset"}
			netsZebra := model.NetworkSet{
				Nets: []calinet.IPNet{
					calinet.MustParseNetwork("172.20.0.0/24"),
				},
				Labels: uniquelabels.Make(map[string]string{"name": "zebra"}),
			}

			netsAlphaKey := model.NetworkSetKey{Name: "ns1/alpha-netset"}
			netsAlpha := model.NetworkSet{
				Nets: []calinet.IPNet{
					calinet.MustParseNetwork("172.20.0.0/24"),
				},
				Labels: uniquelabels.Make(map[string]string{"name": "alpha"}),
			}

			netsMiddleKey := model.NetworkSetKey{Name: "ns1/middle-netset"}
			netsMiddle := model.NetworkSet{
				Nets: []calinet.IPNet{
					calinet.MustParseNetwork("172.20.0.0/24"),
				},
				Labels: uniquelabels.Make(map[string]string{"name": "middle"}),
			}

			// Add in non-lexicographic order
			ec.OnUpdate(api.Update{
				KVPair:     model.KVPair{Key: netsMiddleKey, Value: &netsMiddle},
				UpdateType: api.UpdateTypeKVNew,
			})
			ec.OnUpdate(api.Update{
				KVPair:     model.KVPair{Key: netsZebraKey, Value: &netsZebra},
				UpdateType: api.UpdateTypeKVNew,
			})
			ec.OnUpdate(api.Update{
				KVPair:     model.KVPair{Key: netsAlphaKey, Value: &netsAlpha},
				UpdateType: api.UpdateTypeKVNew,
			})

			testIP := ipToBytes(calinet.MustParseNetwork("172.20.0.50/32").IP)

			// Should always return "ns1/alpha-netset" when querying with ns1 context
			networkSet, match := ec.GetNetworkSetFromIPWithNamespace(testIP, "ns1")
			Expect(match).ToNot(Equal(MatchNone))
			Expect(networkSet.Key()).To(Equal(netsAlphaKey), "Should return lexicographically lowest namespaced NetworkSet")
			labelValue, labelOk := networkSet.Labels().GetString("name")
			Expect(labelOk).To(BeTrue())
			Expect(labelValue).To(Equal("alpha"))
		})

		It("should prioritize namespaced NetworkSet over global even if global is lexicographically lower", func() {
			// Create global NetworkSet with lexicographically lowest name
			globalKey := model.NetworkSetKey{Name: "aaa-global"}
			globalNS := model.NetworkSet{
				Nets: []calinet.IPNet{
					calinet.MustParseNetwork("10.50.0.0/16"),
				},
				Labels: uniquelabels.Make(map[string]string{"type": "global"}),
			}

			// Create namespaced NetworkSet with lexicographically higher name
			ns1Key := model.NetworkSetKey{Name: "ns1/zzz-namespaced"}
			ns1NS := model.NetworkSet{
				Nets: []calinet.IPNet{
					calinet.MustParseNetwork("10.50.10.0/24"),
				},
				Labels: uniquelabels.Make(map[string]string{"type": "namespaced"}),
			}

			ec.OnUpdate(api.Update{
				KVPair:     model.KVPair{Key: globalKey, Value: &globalNS},
				UpdateType: api.UpdateTypeKVNew,
			})
			ec.OnUpdate(api.Update{
				KVPair:     model.KVPair{Key: ns1Key, Value: &ns1NS},
				UpdateType: api.UpdateTypeKVNew,
			})

			testIP := ipToBytes(calinet.MustParseNetwork("10.50.10.100/32").IP)

			// With ns1 context, should return namespaced NetworkSet despite global being lexicographically lower
			networkSet, match := ec.GetNetworkSetFromIPWithNamespace(testIP, "ns1")
			Expect(match).ToNot(Equal(MatchNone))
			Expect(networkSet.Key()).To(Equal(ns1Key), "Namespace precedence should override lexicographic ordering")
			labelValue, labelOk := networkSet.Labels().GetString("type")
			Expect(labelOk).To(BeTrue())
			Expect(labelValue).To(Equal("namespaced"))
		})

		It("should maintain lexicographic ordering across namespace boundaries when no preferred namespace match", func() {
			// Create global and namespaced NetworkSets with same CIDR
			globalKey := model.NetworkSetKey{Name: "zzz-global"}
			globalNS := model.NetworkSet{
				Nets: []calinet.IPNet{
					calinet.MustParseNetwork("10.60.0.0/24"),
				},
				Labels: uniquelabels.Make(map[string]string{"scope": "global"}),
			}

			ns1Key := model.NetworkSetKey{Name: "ns1/mmm-namespaced"}
			ns1NS := model.NetworkSet{
				Nets: []calinet.IPNet{
					calinet.MustParseNetwork("10.60.0.0/24"),
				},
				Labels: uniquelabels.Make(map[string]string{"scope": "ns1"}),
			}

			ns2Key := model.NetworkSetKey{Name: "ns2/aaa-namespaced"}
			ns2NS := model.NetworkSet{
				Nets: []calinet.IPNet{
					calinet.MustParseNetwork("10.60.0.0/24"),
				},
				Labels: uniquelabels.Make(map[string]string{"scope": "ns2"}),
			}

			ec.OnUpdate(api.Update{
				KVPair:     model.KVPair{Key: globalKey, Value: &globalNS},
				UpdateType: api.UpdateTypeKVNew,
			})
			ec.OnUpdate(api.Update{
				KVPair:     model.KVPair{Key: ns1Key, Value: &ns1NS},
				UpdateType: api.UpdateTypeKVNew,
			})
			ec.OnUpdate(api.Update{
				KVPair:     model.KVPair{Key: ns2Key, Value: &ns2NS},
				UpdateType: api.UpdateTypeKVNew,
			})

			testIP := ipToBytes(calinet.MustParseNetwork("10.60.0.50/32").IP)

			// With ns3 context (no match), should fallback to global
			networkSet, match := ec.GetNetworkSetFromIPWithNamespace(testIP, "ns3")
			Expect(match).ToNot(Equal(MatchNone))
			Expect(networkSet.Key()).To(Equal(globalKey))
			labelValue, labelOk := networkSet.Labels().GetString("scope")
			Expect(labelOk).To(BeTrue())
			Expect(labelValue).To(Equal("global"))
		})

		It("should handle deletion and re-addition maintaining lexicographic ordering", func() {
			// Create multiple NetworkSets
			netsAKey := model.NetworkSetKey{Name: "ccc-netset"}
			netsA := model.NetworkSet{
				Nets:   []calinet.IPNet{calinet.MustParseNetwork("10.70.0.0/24")},
				Labels: uniquelabels.Make(map[string]string{"id": "c"}),
			}

			netsBKey := model.NetworkSetKey{Name: "aaa-netset"}
			netsB := model.NetworkSet{
				Nets:   []calinet.IPNet{calinet.MustParseNetwork("10.70.0.0/24")},
				Labels: uniquelabels.Make(map[string]string{"id": "a"}),
			}

			netsCKey := model.NetworkSetKey{Name: "bbb-netset"}
			netsC := model.NetworkSet{
				Nets:   []calinet.IPNet{calinet.MustParseNetwork("10.70.0.0/24")},
				Labels: uniquelabels.Make(map[string]string{"id": "b"}),
			}

			// Add all
			ec.OnUpdate(api.Update{KVPair: model.KVPair{Key: netsAKey, Value: &netsA}, UpdateType: api.UpdateTypeKVNew})
			ec.OnUpdate(api.Update{KVPair: model.KVPair{Key: netsBKey, Value: &netsB}, UpdateType: api.UpdateTypeKVNew})
			ec.OnUpdate(api.Update{KVPair: model.KVPair{Key: netsCKey, Value: &netsC}, UpdateType: api.UpdateTypeKVNew})

			testIP := ipToBytes(calinet.MustParseNetwork("10.70.0.100/32").IP)

			// Should return "aaa-netset"
			networkSet, match := ec.GetNetworkSetFromIPWithNamespace(testIP, "")
			Expect(match).ToNot(Equal(MatchNone))
			Expect(networkSet.Key()).To(Equal(netsBKey))

			// Delete the lexicographically lowest
			ec.OnUpdate(api.Update{KVPair: model.KVPair{Key: netsBKey}, UpdateType: api.UpdateTypeKVDeleted})

			// Should now return "bbb-netset"
			networkSet, match = ec.GetNetworkSetFromIPWithNamespace(testIP, "")
			Expect(match).ToNot(Equal(MatchNone))
			Expect(networkSet.Key()).To(Equal(netsCKey))

			// Re-add the original lowest
			ec.OnUpdate(api.Update{KVPair: model.KVPair{Key: netsBKey, Value: &netsB}, UpdateType: api.UpdateTypeKVNew})

			// Should return "aaa-netset" again
			networkSet, match = ec.GetNetworkSetFromIPWithNamespace(testIP, "")
			Expect(match).ToNot(Equal(MatchNone))
			Expect(networkSet.Key()).To(Equal(netsBKey))
		})

		It("should use lexicographic ordering as tiebreaker when longest prefix matches are equal", func() {
			// Create NetworkSets with same CIDR prefix length
			netsXKey := model.NetworkSetKey{Name: "xxx-netset"}
			netsX := model.NetworkSet{
				Nets:   []calinet.IPNet{calinet.MustParseNetwork("10.80.0.0/16")},
				Labels: uniquelabels.Make(map[string]string{"name": "x"}),
			}

			netsAKey := model.NetworkSetKey{Name: "aaa-netset"}
			netsA := model.NetworkSet{
				Nets:   []calinet.IPNet{calinet.MustParseNetwork("10.80.0.0/16")},
				Labels: uniquelabels.Make(map[string]string{"name": "a"}),
			}

			netsMKey := model.NetworkSetKey{Name: "mmm-netset"}
			netsM := model.NetworkSet{
				Nets:   []calinet.IPNet{calinet.MustParseNetwork("10.80.0.0/16")},
				Labels: uniquelabels.Make(map[string]string{"name": "m"}),
			}

			// Add in random order
			ec.OnUpdate(api.Update{KVPair: model.KVPair{Key: netsMKey, Value: &netsM}, UpdateType: api.UpdateTypeKVNew})
			ec.OnUpdate(api.Update{KVPair: model.KVPair{Key: netsXKey, Value: &netsX}, UpdateType: api.UpdateTypeKVNew})
			ec.OnUpdate(api.Update{KVPair: model.KVPair{Key: netsAKey, Value: &netsA}, UpdateType: api.UpdateTypeKVNew})

			testIP := ipToBytes(calinet.MustParseNetwork("10.80.50.100/32").IP)

			// All have same prefix length, should use lexicographic ordering
			networkSet, match := ec.GetNetworkSetFromIPWithNamespace(testIP, "")
			Expect(match).ToNot(Equal(MatchNone))
			Expect(networkSet.Key()).To(Equal(netsAKey), "Should use lexicographic ordering when prefix lengths are equal")
		})
	})

	Describe("GetNetworkSetFromEgressDomainWithNamespace lexicographic ordering", func() {
		It("should return lexicographically lowest NetworkSet when multiple global NetworkSets have same egress domain", func() {
			// Create multiple global NetworkSets with same egress domain
			netsZKey := model.NetworkSetKey{Name: "zzz-domain-netset"}
			netsZ := model.NetworkSet{
				AllowedEgressDomains: []string{"example.com"},
				Labels:               uniquelabels.Make(map[string]string{"name": "z"}),
			}

			netsAKey := model.NetworkSetKey{Name: "aaa-domain-netset"}
			netsA := model.NetworkSet{
				AllowedEgressDomains: []string{"example.com"},
				Labels:               uniquelabels.Make(map[string]string{"name": "a"}),
			}

			netsMKey := model.NetworkSetKey{Name: "mmm-domain-netset"}
			netsM := model.NetworkSet{
				AllowedEgressDomains: []string{"example.com"},
				Labels:               uniquelabels.Make(map[string]string{"name": "m"}),
			}

			// Add in non-lexicographic order
			ec.OnUpdate(api.Update{KVPair: model.KVPair{Key: netsZKey, Value: &netsZ}, UpdateType: api.UpdateTypeKVNew})
			ec.OnUpdate(api.Update{KVPair: model.KVPair{Key: netsMKey, Value: &netsM}, UpdateType: api.UpdateTypeKVNew})
			ec.OnUpdate(api.Update{KVPair: model.KVPair{Key: netsAKey, Value: &netsA}, UpdateType: api.UpdateTypeKVNew})

			// Should always return "aaa-domain-netset"
			networkSet, match := ec.GetNetworkSetFromEgressDomainWithNamespace("example.com", "")
			Expect(match).ToNot(Equal(MatchNone))
			Expect(networkSet.Key()).To(Equal(netsAKey), "Should return lexicographically lowest global NetworkSet for egress domain")
			labelValue, labelOk := networkSet.Labels().GetString("name")
			Expect(labelOk).To(BeTrue())
			Expect(labelValue).To(Equal("a"))
		})

		It("should return lexicographically lowest namespaced NetworkSet when multiple in same namespace have same domain", func() {
			// Create multiple namespaced NetworkSets with same domain
			netsYKey := model.NetworkSetKey{Name: "ns1/yyy-netset"}
			netsY := model.NetworkSet{
				AllowedEgressDomains: []string{"test.io"},
				Labels:               uniquelabels.Make(map[string]string{"name": "y"}),
			}

			netsBKey := model.NetworkSetKey{Name: "ns1/bbb-netset"}
			netsB := model.NetworkSet{
				AllowedEgressDomains: []string{"test.io"},
				Labels:               uniquelabels.Make(map[string]string{"name": "b"}),
			}

			netsPKey := model.NetworkSetKey{Name: "ns1/ppp-netset"}
			netsP := model.NetworkSet{
				AllowedEgressDomains: []string{"test.io"},
				Labels:               uniquelabels.Make(map[string]string{"name": "p"}),
			}

			ec.OnUpdate(api.Update{KVPair: model.KVPair{Key: netsYKey, Value: &netsY}, UpdateType: api.UpdateTypeKVNew})
			ec.OnUpdate(api.Update{KVPair: model.KVPair{Key: netsPKey, Value: &netsP}, UpdateType: api.UpdateTypeKVNew})
			ec.OnUpdate(api.Update{KVPair: model.KVPair{Key: netsBKey, Value: &netsB}, UpdateType: api.UpdateTypeKVNew})

			// Should return "ns1/bbb-netset"
			networkSet, match := ec.GetNetworkSetFromEgressDomainWithNamespace("test.io", "ns1")
			Expect(match).ToNot(Equal(MatchNone))
			Expect(networkSet.Key()).To(Equal(netsBKey), "Should return lexicographically lowest namespaced NetworkSet")
			labelValue, labelOk := networkSet.Labels().GetString("name")
			Expect(labelOk).To(BeTrue())
			Expect(labelValue).To(Equal("b"))
		})

		It("should prioritize namespaced over global for egress domains even if global is lexicographically lower", func() {
			// Global with lexicographically lowest name
			globalKey := model.NetworkSetKey{Name: "aaa-global-domain"}
			globalNS := model.NetworkSet{
				AllowedEgressDomains: []string{"priority-test.com"},
				Labels:               uniquelabels.Make(map[string]string{"type": "global"}),
			}

			// Namespaced with higher name
			ns1Key := model.NetworkSetKey{Name: "ns1/zzz-ns-domain"}
			ns1NS := model.NetworkSet{
				AllowedEgressDomains: []string{"priority-test.com"},
				Labels:               uniquelabels.Make(map[string]string{"type": "namespaced"}),
			}

			ec.OnUpdate(api.Update{KVPair: model.KVPair{Key: globalKey, Value: &globalNS}, UpdateType: api.UpdateTypeKVNew})
			ec.OnUpdate(api.Update{KVPair: model.KVPair{Key: ns1Key, Value: &ns1NS}, UpdateType: api.UpdateTypeKVNew})

			// With ns1 context, should prioritize namespaced
			networkSet, match := ec.GetNetworkSetFromEgressDomainWithNamespace("priority-test.com", "ns1")
			Expect(match).To(Equal(MatchSameNamespace))
			Expect(networkSet.Key()).To(Equal(ns1Key), "Namespace precedence should override lexicographic ordering for domains")
			labelValue, labelOk := networkSet.Labels().GetString("type")
			Expect(labelOk).To(BeTrue())
			Expect(labelValue).To(Equal("namespaced"))

			// Without namespace context, should use global
			networkSet, match = ec.GetNetworkSetFromEgressDomainWithNamespace("priority-test.com", "")
			Expect(match).To(Equal(MatchGlobal))
			Expect(networkSet.Key()).To(Equal(globalKey))
			labelValue, labelOk = networkSet.Labels().GetString("type")
			Expect(labelOk).To(BeTrue())
			Expect(labelValue).To(Equal("global"))
		})

		It("should maintain consistent lexicographic ordering across multiple queries for egress domains", func() {
			// Create multiple NetworkSets with same domain
			keys := []model.NetworkSetKey{
				{Name: "ddd-netset"},
				{Name: "ccc-netset"},
				{Name: "bbb-netset"},
				{Name: "aaa-netset"},
				{Name: "eee-netset"},
			}

			for _, key := range keys {
				ns := model.NetworkSet{
					AllowedEgressDomains: []string{"consistent.test"},
					Labels:               uniquelabels.Make(map[string]string{"key": key.Name}),
				}
				ec.OnUpdate(api.Update{
					KVPair:     model.KVPair{Key: key, Value: &ns},
					UpdateType: api.UpdateTypeKVNew,
				})
			}

			// Query multiple times and verify consistency
			var firstResult model.Key
			for i := range 100 {
				networkSet, match := ec.GetNetworkSetFromEgressDomainWithNamespace("consistent.test", "")
				Expect(match).To(Equal(MatchGlobal))

				if i == 0 {
					firstResult = networkSet.Key()
					Expect(firstResult).To(Equal(model.NetworkSetKey{Name: "aaa-netset"}), "First result should be lexicographically lowest")
				} else {
					Expect(networkSet.Key()).To(Equal(firstResult), "Result should be consistent across queries")
				}
			}
		})

		It("should fallback to other namespaces when preferred namespace and global don't match", func() {
			// Create NetworkSets in different namespaces, but NO global NetworkSet
			ns1Key := model.NetworkSetKey{Name: "ns1/alpha-netset"}
			ns1NS := model.NetworkSet{
				AllowedEgressDomains: []string{"fallback-test.com"},
				Labels:               uniquelabels.Make(map[string]string{"namespace": "ns1"}),
			}

			ns2Key := model.NetworkSetKey{Name: "ns2/beta-netset"}
			ns2NS := model.NetworkSet{
				AllowedEgressDomains: []string{"fallback-test.com"},
				Labels:               uniquelabels.Make(map[string]string{"namespace": "ns2"}),
			}

			ns3Key := model.NetworkSetKey{Name: "ns3/gamma-netset"}
			ns3NS := model.NetworkSet{
				AllowedEgressDomains: []string{"fallback-test.com"},
				Labels:               uniquelabels.Make(map[string]string{"namespace": "ns3"}),
			}

			ec.OnUpdate(api.Update{KVPair: model.KVPair{Key: ns1Key, Value: &ns1NS}, UpdateType: api.UpdateTypeKVNew})
			ec.OnUpdate(api.Update{KVPair: model.KVPair{Key: ns2Key, Value: &ns2NS}, UpdateType: api.UpdateTypeKVNew})
			ec.OnUpdate(api.Update{KVPair: model.KVPair{Key: ns3Key, Value: &ns3NS}, UpdateType: api.UpdateTypeKVNew})

			// Request with non-existent namespace - should fallback to lexicographically lowest from other namespaces
			networkSet, match := ec.GetNetworkSetFromEgressDomainWithNamespace("fallback-test.com", "nonexistent-ns")
			Expect(match).To(Equal(MatchOtherNamespace))
			Expect(networkSet.Key()).To(Equal(ns1Key), "Should fallback to lexicographically lowest from other namespaces (ns1/alpha-netset)")

			// Verify it returns the correct label
			labelValue, labelOk := networkSet.Labels().GetString("namespace")
			Expect(labelOk).To(BeTrue())
			Expect(labelValue).To(Equal("ns1"))
		})

		It("should prioritize preferred namespace > global > other namespaces for egress domains", func() {
			// Create NetworkSets in all three categories
			globalKey := model.NetworkSetKey{Name: "global-netset"}
			globalNS := model.NetworkSet{
				AllowedEgressDomains: []string{"priority-test.io"},
				Labels:               uniquelabels.Make(map[string]string{"type": "global"}),
			}

			targetNsKey := model.NetworkSetKey{Name: "target-ns/netset"}
			targetNsNS := model.NetworkSet{
				AllowedEgressDomains: []string{"priority-test.io"},
				Labels:               uniquelabels.Make(map[string]string{"type": "target"}),
			}

			otherNsKey := model.NetworkSetKey{Name: "other-ns/netset"}
			otherNsNS := model.NetworkSet{
				AllowedEgressDomains: []string{"priority-test.io"},
				Labels:               uniquelabels.Make(map[string]string{"type": "other"}),
			}

			ec.OnUpdate(api.Update{KVPair: model.KVPair{Key: globalKey, Value: &globalNS}, UpdateType: api.UpdateTypeKVNew})
			ec.OnUpdate(api.Update{KVPair: model.KVPair{Key: targetNsKey, Value: &targetNsNS}, UpdateType: api.UpdateTypeKVNew})
			ec.OnUpdate(api.Update{KVPair: model.KVPair{Key: otherNsKey, Value: &otherNsNS}, UpdateType: api.UpdateTypeKVNew})

			// Test 1: When preferred namespace exists, it should win
			networkSet, match := ec.GetNetworkSetFromEgressDomainWithNamespace("priority-test.io", "target-ns")
			Expect(match).To(Equal(MatchSameNamespace))
			Expect(networkSet.Key()).To(Equal(targetNsKey), "Preferred namespace should have highest priority")
			labelValue, _ := networkSet.Labels().GetString("type")
			Expect(labelValue).To(Equal("target"))

			// Test 2: When preferred namespace doesn't exist, global should win over other namespaces
			networkSet, match = ec.GetNetworkSetFromEgressDomainWithNamespace("priority-test.io", "nonexistent-ns")
			Expect(match).To(Equal(MatchGlobal))
			Expect(networkSet.Key()).To(Equal(globalKey), "Global should have priority over other namespaces")
			labelValue, _ = networkSet.Labels().GetString("type")
			Expect(labelValue).To(Equal("global"))

			// Test 3: When neither preferred nor global exists, other namespace should be returned
			ec2 := NewNetworkSetLookupsCache()
			ec2.OnUpdate(api.Update{KVPair: model.KVPair{Key: otherNsKey, Value: &otherNsNS}, UpdateType: api.UpdateTypeKVNew})

			networkSet, match = ec2.GetNetworkSetFromEgressDomainWithNamespace("priority-test.io", "nonexistent-ns")
			Expect(match).To(Equal(MatchOtherNamespace))
			Expect(networkSet.Key()).To(Equal(otherNsKey), "Other namespace should be used as last resort")
			labelValue, _ = networkSet.Labels().GetString("type")
			Expect(labelValue).To(Equal("other"))
		})
	})
})
