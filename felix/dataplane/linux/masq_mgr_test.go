// Copyright (c) 2017-2021 Tigera, Inc. All rights reserved.
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
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var _ = Describe("Masquerade manager", func() {
	var (
		masqMgr      *masqManager
		natTable     *mockTable
		ipSets       *dpsets.MockIPSets
		ruleRenderer rules.RuleRenderer
	)

	BeforeEach(func() {
		ipSets = dpsets.NewMockIPSets()
		natTable = newMockTable("nat")
		ruleRenderer = rules.NewRenderer(rules.Config{
			IPSetConfigV4: ipsets.NewIPVersionConfig(
				ipsets.IPFamilyV4,
				"cali",
				nil,
				nil,
			),
			DNSPolicyNfqueueID:       100,
			MarkPass:                 0x1,
			MarkAccept:               0x2,
			MarkScratch0:             0x4,
			MarkScratch1:             0x8,
			MarkDrop:                 0x10,
			MarkIPsec:                0x20,
			MarkEgress:               0x40,
			MarkEndpoint:             0x11110000,
			MarkDNSPolicy:            0x80,
			MarkSkipDNSPolicyNfqueue: 0x400000,
		}, false)
		masqMgr = newMasqManager(ipSets, natTable, ruleRenderer, 1024, 4)
	})

	It("should create its IP sets on startup", func() {
		Expect(ipSets.Members).To(Equal(map[string]set.Set[string]{
			"all-ipam-pools":  set.New[string](),
			"masq-ipam-pools": set.New[string](),
		}))
	})

	Describe("after adding a masq pool", func() {
		BeforeEach(func() {
			masqMgr.OnUpdate(&proto.IPAMPoolUpdate{
				Id: "10.0.0.0-16",
				Pool: &proto.IPAMPool{
					Cidr:       "10.0.0.0/16",
					Masquerade: true,
				},
			})
			// This one should be ignored due to wrong IP version.
			masqMgr.OnUpdate(&proto.IPAMPoolUpdate{
				Id: "feed:beef::-96",
				Pool: &proto.IPAMPool{
					Cidr:       "feed:beef::/96",
					Masquerade: true,
				},
			})
			err := masqMgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should add the pool to the masq IP set", func() {
			Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.From("10.0.0.0/16")))
		})
		It("should add the pool to the all IP set", func() {
			Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.From("10.0.0.0/16")))
		})
		It("should program the chain", func() {
			Expect(natTable.UpdateCalled).To(BeTrue())
			natTable.checkChains([][]*generictables.Chain{{{
				Name: "cali-nat-outgoing",
				Rules: []generictables.Rule{
					{
						Action: iptables.MasqAction{},
						Match: iptables.Match().
							SourceIPSet("cali40masq-ipam-pools").
							NotDestIPSet("cali40all-ipam-pools"),
					},
				},
			}}})
		})
		It("an extra CompleteDeferredWork should be a no-op", func() {
			natTable.UpdateCalled = false
			err := masqMgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			Expect(natTable.UpdateCalled).To(BeFalse())
		})
		It("an unrelated update shouldn't trigger work", func() {
			natTable.UpdateCalled = false
			masqMgr.OnUpdate(&proto.HostMetadataUpdate{
				Hostname: "foo",
				Ipv4Addr: "10.0.0.17",
			})
			err := masqMgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			Expect(natTable.UpdateCalled).To(BeFalse())
		})

		Describe("after adding a non-masq pool", func() {
			BeforeEach(func() {
				masqMgr.OnUpdate(&proto.IPAMPoolUpdate{
					Id: "10.2.0.0-16",
					Pool: &proto.IPAMPool{
						Cidr:       "10.2.0.0/16",
						Masquerade: false,
					},
				})
				err := masqMgr.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())
			})

			It("should not add the pool to the masq IP set", func() {
				Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.From("10.0.0.0/16")))
			})
			It("should add the pool to the all IP set", func() {
				Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.From(
					"10.0.0.0/16", "10.2.0.0/16")))
			})
			It("should program the chain", func() {
				natTable.checkChains([][]*generictables.Chain{{{
					Name: "cali-nat-outgoing",
					Rules: []generictables.Rule{
						{
							Action: iptables.MasqAction{},
							Match: iptables.Match().
								SourceIPSet("cali40masq-ipam-pools").
								NotDestIPSet("cali40all-ipam-pools"),
						},
					},
				}}})
			})

			Describe("after removing masq pool", func() {
				BeforeEach(func() {
					masqMgr.OnUpdate(&proto.IPAMPoolRemove{
						Id: "10.0.0.0-16",
					})
					err := masqMgr.CompleteDeferredWork()
					Expect(err).ToNot(HaveOccurred())
				})
				It("should remove from the masq IP set", func() {
					Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.New[string]()))
				})
				It("should remove from the all IP set", func() {
					Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.From(
						"10.2.0.0/16")))
				})
				It("should program empty chain", func() {
					natTable.checkChains([][]*generictables.Chain{{{
						Name:  "cali-nat-outgoing",
						Rules: nil,
					}}})
				})

				Describe("after removing the non-masq pool", func() {
					BeforeEach(func() {
						masqMgr.OnUpdate(&proto.IPAMPoolRemove{
							Id: "10.2.0.0-16",
						})
						err := masqMgr.CompleteDeferredWork()
						Expect(err).ToNot(HaveOccurred())
					})
					It("masq set should be empty", func() {
						Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.New[string]()))
					})
					It("all set should be empty", func() {
						Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.New[string]()))
					})
					It("should program empty chain", func() {
						natTable.checkChains([][]*generictables.Chain{{{
							Name:  "cali-nat-outgoing",
							Rules: nil,
						}}})
					})
				})
			})
		})
	})

	Describe("after adding a non-masq pool", func() {
		BeforeEach(func() {
			masqMgr.OnUpdate(&proto.IPAMPoolUpdate{
				Id: "10.0.0.0-16",
				Pool: &proto.IPAMPool{
					Cidr:       "10.0.0.0/16",
					Masquerade: false,
				},
			})
			err := masqMgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should not add the pool to the masq IP set", func() {
			Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.New[string]()))
		})
		It("should add the pool to the all IP set", func() {
			Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.From("10.0.0.0/16")))
		})
		It("should program empty chain", func() {
			natTable.checkChains([][]*generictables.Chain{{{
				Name:  "cali-nat-outgoing",
				Rules: nil,
			}}})
		})
	})

	// Begin remote-specific tests.

	// Validate that disjoint remote pools are handled as expected.
	for _, v := range []bool{true, false} {
		masq := v
		// Masquerade enabled and disabled should have the same result, since remote updates should not impact the masq IP set.
		Describe(fmt.Sprintf("after adding a remote pool with masq %v", masq), func() {
			BeforeEach(func() {
				masqMgr.OnUpdate(&proto.RemoteIPAMPoolUpdate{
					Id:      "10.0.0.0-16",
					Cluster: "cluster-a",
					Pool: &proto.IPAMPool{
						Cidr:       "10.0.0.0/16",
						Masquerade: masq,
					},
				})
				err := masqMgr.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())
			})

			It("should only add the pool to the all IP set", func() {
				Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.New[string]()))
				Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.From("10.0.0.0/16")))
				natTable.checkChains([][]*generictables.Chain{{{
					Name:  "cali-nat-outgoing",
					Rules: nil,
				}}})
			})

			Describe("after deleting the remote masq pool", func() {
				BeforeEach(func() {
					masqMgr.OnUpdate(&proto.RemoteIPAMPoolRemove{
						Id:      "10.0.0.0-16",
						Cluster: "cluster-a",
					})
					err := masqMgr.CompleteDeferredWork()
					Expect(err).ToNot(HaveOccurred())
				})

				It("should have no IP set entries", func() {
					Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.New[string]()))
					Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.New[string]()))
					natTable.checkChains([][]*generictables.Chain{{{
						Name:  "cali-nat-outgoing",
						Rules: nil,
					}}})
				})
			})
		})
	}

	// Validate that adding a remote CIDR that matches the local masq pool is handled correctly, and can be undone safely.
	Describe("after adding a local masq pool", func() {
		BeforeEach(func() {
			masqMgr.OnUpdate(&proto.IPAMPoolUpdate{
				Id: "10.0.0.0-16",
				Pool: &proto.IPAMPool{
					Cidr:       "10.0.0.0/16",
					Masquerade: true,
				},
			})
			err := masqMgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		for _, v := range []bool{true, false} {
			masq := v
			// We expect the 'masq' IP set programming to be the same regardless of the remote masq setting since remote updates should not be considered for masq.
			// We also expect the 'all' IP set programming to be the same regardless of the remote pool since it has the same CIDR.
			Describe(fmt.Sprintf("after adding a remote pool with masq %v and the same CIDR", masq), func() {
				BeforeEach(func() {
					masqMgr.OnUpdate(&proto.RemoteIPAMPoolUpdate{
						Id:      "10.0.0.0-16",
						Cluster: "cluster-a",
						Pool: &proto.IPAMPool{
							Cidr:       "10.0.0.0/16",
							Masquerade: masq,
						},
					})
					err := masqMgr.CompleteDeferredWork()
					Expect(err).ToNot(HaveOccurred())
				})

				It("should be programmed for the local masq pool", func() {
					Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.From("10.0.0.0/16")))
					Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.From("10.0.0.0/16")))
					natTable.checkChains([][]*generictables.Chain{{{
						Name: "cali-nat-outgoing",
						Rules: []generictables.Rule{
							{
								Action: iptables.MasqAction{},
								Match: iptables.Match().
									SourceIPSet("cali40masq-ipam-pools").
									NotDestIPSet("cali40all-ipam-pools"),
							},
						},
					}}})
				})

				Describe("after deleting the remote pool", func() {
					BeforeEach(func() {
						masqMgr.OnUpdate(&proto.RemoteIPAMPoolRemove{
							Id:      "10.0.0.0-16",
							Cluster: "cluster-a",
						})
						err := masqMgr.CompleteDeferredWork()
						Expect(err).ToNot(HaveOccurred())
					})

					It("should still be programmed for the local masq pool", func() {
						Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.From("10.0.0.0/16")))
						Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.From("10.0.0.0/16")))
						natTable.checkChains([][]*generictables.Chain{{{
							Name: "cali-nat-outgoing",
							Rules: []generictables.Rule{
								{
									Action: iptables.MasqAction{},
									Match: iptables.Match().
										SourceIPSet("cali40masq-ipam-pools").
										NotDestIPSet("cali40all-ipam-pools"),
								},
							},
						}}})
					})
				})
			})
		}
	})

	// Validate that adding a remote CIDR that matches the local non-masq pool is handled correctly, and can be undone safely.
	Describe("after adding a local non-masq pool", func() {
		BeforeEach(func() {
			masqMgr.OnUpdate(&proto.IPAMPoolUpdate{
				Id: "10.0.0.0-16",
				Pool: &proto.IPAMPool{
					Cidr:       "10.0.0.0/16",
					Masquerade: false,
				},
			})
			err := masqMgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		for _, v := range []bool{true, false} {
			masq := v
			// We expect the 'masq' IP set programming to be the same regardless of the remote masq setting since remote updates should not be considered for masq.
			// We also expect the 'all' IP set programming to be the same regardless of the remote pool since it has the same CIDR.
			Describe(fmt.Sprintf("after adding a remote pool with masq %v and the same CIDR", masq), func() {
				BeforeEach(func() {
					masqMgr.OnUpdate(&proto.RemoteIPAMPoolUpdate{
						Id:      "10.0.0.0-16",
						Cluster: "cluster-a",
						Pool: &proto.IPAMPool{
							Cidr:       "10.0.0.0/16",
							Masquerade: masq,
						},
					})
					err := masqMgr.CompleteDeferredWork()
					Expect(err).ToNot(HaveOccurred())
				})

				It("should be programmed for the local non-masq pool", func() {
					Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.New[string]()))
					Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.From("10.0.0.0/16")))
					natTable.checkChains([][]*generictables.Chain{{{
						Name:  "cali-nat-outgoing",
						Rules: nil,
					}}})
				})

				Describe("after deleting the remote pool", func() {
					BeforeEach(func() {
						masqMgr.OnUpdate(&proto.RemoteIPAMPoolRemove{
							Id:      "10.0.0.0-16",
							Cluster: "cluster-a",
						})
						err := masqMgr.CompleteDeferredWork()
						Expect(err).ToNot(HaveOccurred())
					})

					It("should still be programmed for the local masq pool", func() {
						Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.New[string]()))
						Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.From("10.0.0.0/16")))
						natTable.checkChains([][]*generictables.Chain{{{
							Name:  "cali-nat-outgoing",
							Rules: nil,
						}}})
					})
				})
			})
		}
	})

	// Validate that a remote pool does not have the ability to override the local cluster masquerade settings by containing its CIDRs.
	Describe("after adding a local non-masq pool", func() {
		BeforeEach(func() {
			masqMgr.OnUpdate(&proto.IPAMPoolUpdate{
				Id: "10.0.0.0-16",
				Pool: &proto.IPAMPool{
					Cidr:       "10.0.0.0/16",
					Masquerade: false,
				},
			})
			err := masqMgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		// If the larger remote CIDR was to be programmed into the masq set, then the local clusters IP pool would be masqueraded against its will.
		Describe("after adding multiple remote masq pools that contain the local non-masq pool", func() {
			BeforeEach(func() {
				masqMgr.OnUpdate(&proto.RemoteIPAMPoolUpdate{
					Id:      "10.0.0.0-12",
					Cluster: "cluster-a",
					Pool: &proto.IPAMPool{
						Cidr:       "10.0.0.0/12",
						Masquerade: true,
					},
				})
				masqMgr.OnUpdate(&proto.RemoteIPAMPoolUpdate{
					Id:      "10.0.0.0-8",
					Cluster: "cluster-b",
					Pool: &proto.IPAMPool{
						Cidr:       "10.0.0.0/8",
						Masquerade: true,
					},
				})
				err := masqMgr.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())
			})

			It("should have no masq IPs programmed and have all IPs updated for all pools", func() {
				Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.New[string]()))
				Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.From[string]("10.0.0.0/16", "10.0.0.0/12", "10.0.0.0/8")))
				natTable.checkChains([][]*generictables.Chain{{{
					Name:  "cali-nat-outgoing",
					Rules: nil,
				}}})
			})

			Describe("after deleting the remote masq pools", func() {
				BeforeEach(func() {
					masqMgr.OnUpdate(&proto.RemoteIPAMPoolRemove{
						Id:      "10.0.0.0-12",
						Cluster: "cluster-a",
					})
					masqMgr.OnUpdate(&proto.RemoteIPAMPoolRemove{
						Id:      "10.0.0.0-8",
						Cluster: "cluster-b",
					})
					err := masqMgr.CompleteDeferredWork()
					Expect(err).ToNot(HaveOccurred())
				})

				It("should be programmed for the local non-masq pool", func() {
					Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.New[string]()))
					Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.From[string]("10.0.0.0/16")))
					natTable.checkChains([][]*generictables.Chain{{{
						Name:  "cali-nat-outgoing",
						Rules: nil,
					}}})
				})
			})
		})
	})

	// Validate that remote pools from different clusters with the same CIDR are handled correctly, and can be undone safely.
	Describe("after adding two remote masq pools with the same CIDR", func() {
		BeforeEach(func() {
			masqMgr.OnUpdate(&proto.RemoteIPAMPoolUpdate{
				Id:      "10.0.0.0-16",
				Cluster: "cluster-a",
				Pool: &proto.IPAMPool{
					Cidr:       "10.0.0.0/16",
					Masquerade: true,
				},
			})
			masqMgr.OnUpdate(&proto.RemoteIPAMPoolUpdate{
				Id:      "10.0.0.0-16",
				Cluster: "cluster-b",
				Pool: &proto.IPAMPool{
					Cidr:       "10.0.0.0/16",
					Masquerade: true,
				},
			})
			err := masqMgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should only be programmed to the all IP set", func() {
			Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.New[string]()))
			Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.From[string]("10.0.0.0/16")))
			natTable.checkChains([][]*generictables.Chain{{{
				Name:  "cali-nat-outgoing",
				Rules: nil,
			}}})
		})

		Describe("after deleting one remote pool", func() {
			BeforeEach(func() {
				masqMgr.OnUpdate(&proto.RemoteIPAMPoolRemove{
					Id:      "10.0.0.0-16",
					Cluster: "cluster-a",
				})
				err := masqMgr.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())
			})

			It("should still be programmed to the all IP set", func() {
				Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.New[string]()))
				Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.From[string]("10.0.0.0/16")))
				natTable.checkChains([][]*generictables.Chain{{{
					Name:  "cali-nat-outgoing",
					Rules: nil,
				}}})
			})
		})

		Describe("after deleting both remote pools", func() {
			BeforeEach(func() {
				masqMgr.OnUpdate(&proto.RemoteIPAMPoolRemove{
					Id:      "10.0.0.0-16",
					Cluster: "cluster-a",
				})
				masqMgr.OnUpdate(&proto.RemoteIPAMPoolRemove{
					Id:      "10.0.0.0-16",
					Cluster: "cluster-b",
				})
				err := masqMgr.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())
			})

			It("should have no programming", func() {
				Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.New[string]()))
				Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.New[string]()))
				natTable.checkChains([][]*generictables.Chain{{{
					Name:  "cali-nat-outgoing",
					Rules: nil,
				}}})
			})
		})
	})

	// Validate that if a remote pool exists for the same CIDR as a newly added local pool, the local pool overrides its programming.
	Describe("after adding a remote non-masq pool", func() {
		BeforeEach(func() {
			masqMgr.OnUpdate(&proto.RemoteIPAMPoolUpdate{
				Id:      "10.0.0.0-16",
				Cluster: "cluster-a",
				Pool: &proto.IPAMPool{
					Cidr:       "10.0.0.0/16",
					Masquerade: false,
				},
			})
			err := masqMgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should be programmed only for the all IP set", func() {
			Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.New[string]()))
			Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.From[string]("10.0.0.0/16")))
			natTable.checkChains([][]*generictables.Chain{{{
				Name:  "cali-nat-outgoing",
				Rules: nil,
			}}})
		})

		Describe("after adding a local masq pool with the same CIDR", func() {
			BeforeEach(func() {
				masqMgr.OnUpdate(&proto.IPAMPoolUpdate{
					Id: "10.0.0.0-16",
					Pool: &proto.IPAMPool{
						Cidr:       "10.0.0.0/16",
						Masquerade: true,
					},
				})
				err := masqMgr.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())
			})

			It("should prefer to program for the local pool", func() {
				Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.From[string]("10.0.0.0/16")))
				Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.From[string]("10.0.0.0/16")))
				Expect(natTable.UpdateCalled).To(BeTrue())
				natTable.checkChains([][]*generictables.Chain{{{
					Name: "cali-nat-outgoing",
					Rules: []generictables.Rule{
						{
							Action: iptables.MasqAction{},
							Match: iptables.Match().
								SourceIPSet("cali40masq-ipam-pools").
								NotDestIPSet("cali40all-ipam-pools"),
						},
					},
				}}})
			})
		})
	})
})
