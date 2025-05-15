// Copyright (c) 2018-2021 Tigera, Inc. All rights reserved.

package calc_test

import (
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	. "github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
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
		for _, cidr = range netSet2.Nets {
			verifyIpToNetworkset(netSet2Key, cidr.IP, true, netSet2Labels)
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
			ed, ok := ec.GetNetworkSetFromEgressDomain(domain1)
			Expect(ok).To(Equal(before1))
			if ok {
				Expect(ed.Key()).To(Equal(netSet1Key))
			}
			ed, ok = ec.GetNetworkSetFromEgressDomain(domain2)
			Expect(ok).To(Equal(before2))
			if ok {
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
			ed, ok = ec.GetNetworkSetFromEgressDomain(domain1)
			Expect(ok).To(Equal(after1))
			if ok {
				Expect(ed.Key()).To(Equal(netSet1Key))
			}
			ed, ok = ec.GetNetworkSetFromEgressDomain(domain2)
			Expect(ok).To(Equal(after2))
			if ok {
				Expect(ed.Key()).To(Equal(netSet1Key))
			}

			update = api.Update{
				KVPair: model.KVPair{
					Key: netSet1Key,
				},
				UpdateType: api.UpdateTypeKVDeleted,
			}
			ec.OnUpdate(update)
			ed, ok = ec.GetNetworkSetFromEgressDomain(domain1)
			Expect(ok).To(BeFalse())
			ed, ok = ec.GetNetworkSetFromEgressDomain(domain2)
			Expect(ok).To(BeFalse())
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
			ed, ok := ec.GetNetworkSetFromEgressDomain(domain1)
			Expect(ok).To(BeTrue())
			Expect(ed.Key()).To(Equal(netSet1Key))
			ed, ok = ec.GetNetworkSetFromEgressDomain(domain2)
			Expect(ok).To(BeFalse())
			ed, ok = ec.GetNetworkSetFromEgressDomain(domain12)
			Expect(ok).To(BeTrue())
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
			ed, ok = ec.GetNetworkSetFromEgressDomain(domain1)
			Expect(ok).To(BeTrue())
			Expect(ed.Key()).To(Equal(netSet1Key))
			ed, ok = ec.GetNetworkSetFromEgressDomain(domain2)
			Expect(ok).To(BeTrue())
			Expect(ed.Key()).To(Equal(netSet2Key))
			ed, ok = ec.GetNetworkSetFromEgressDomain(domain12)
			Expect(ok).To(BeTrue())
			Expect(ed.Key()).To(BeElementOf(netSet1Key, netSet2Key))

			// Delete networkset 1.  Check domain1 is not present and check domain2 and domain12 both return netset2.
			update = api.Update{
				KVPair: model.KVPair{
					Key: netSet1Key,
				},
				UpdateType: api.UpdateTypeKVDeleted,
			}
			ec.OnUpdate(update)
			ed, ok = ec.GetNetworkSetFromEgressDomain(domain1)
			Expect(ok).To(BeFalse())
			ed, ok = ec.GetNetworkSetFromEgressDomain(domain2)
			Expect(ok).To(BeTrue())
			Expect(ed.Key()).To(Equal(netSet2Key))
			ed, ok = ec.GetNetworkSetFromEgressDomain(domain12)
			Expect(ok).To(BeTrue())
			Expect(ed.Key()).To(Equal(netSet2Key))

			// Delete networkset 1.  There should be no domain name mappings now.
			update = api.Update{
				KVPair: model.KVPair{
					Key: netSet2Key,
				},
				UpdateType: api.UpdateTypeKVDeleted,
			}
			ec.OnUpdate(update)
			ed, ok = ec.GetNetworkSetFromEgressDomain(domain1)
			Expect(ok).To(BeFalse())
			ed, ok = ec.GetNetworkSetFromEgressDomain(domain2)
			Expect(ok).To(BeFalse())
			ed, ok = ec.GetNetworkSetFromEgressDomain(domain12)
			Expect(ok).To(BeFalse())
		},
		Entry("tigera+google and projectcalico+google",
			&netSet1WithEgressDomains, &netSet2WithEgressDomains,
			"tigera.io", "projectcalico.org", "google.com",
		),
	)
})
