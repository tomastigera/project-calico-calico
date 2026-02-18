// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package intdataplane

import (
	"fmt"
	"net"
	"reflect"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/felix/aws"
	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routerule"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var (
	awsRTIndexes          = []int{10, 11, 12, 13, 250, 251}
	awsTestNetlinkTimeout = 23 * time.Second
)

var _ = Describe("awsIPManager tests mode=Enabled", func() {
	describeAWSIPMgrCommonTests(v3.AWSSecondaryIPEnabled)
})
var _ = Describe("awsIPManager tests mode=ENIPerWorkload", func() {
	describeAWSIPMgrCommonTests(v3.AWSSecondaryIPEnabledENIPerWorkload)
})

func describeAWSIPMgrCommonTests(mode string) {
	var (
		m               *awsIPManager
		fakes           *awsIPMgrFakes
		primaryLink     *fakeLink
		primaryMACStr   = "12:34:56:78:90:12"
		primaryMAC      net.HardwareAddr
		secondaryMACStr = "12:34:56:78:90:22"
		secondaryMAC    net.HardwareAddr
		thirdMACStr     = "12:34:56:78:90:23"
		thirdMAC        net.HardwareAddr
		fourthMACStr    = "12:34:56:78:90:24"
		fourthMAC       net.HardwareAddr

		eth1PrimaryIP       = "100.64.0.5"
		thirdLinkPrimaryIP  = "100.64.0.6"
		fourthLinkPrimaryIP = "100.64.0.7"

		egressGWIP    = "100.64.2.5"
		egressGWCIDR  = "100.64.2.5/32"
		egressGW2IP   = "100.64.2.6"
		egressGW2CIDR = "100.64.2.6/32"

		wep1ID = &proto.WorkloadEndpointID{
			OrchestratorId: "k8s",
			WorkloadId:     "wep1",
			EndpointId:     "eth0",
		}
		wep2ID = &proto.WorkloadEndpointID{
			OrchestratorId: "k8s",
			WorkloadId:     "wep2",
			EndpointId:     "eth0",
		}
	)

	BeforeEach(func() {
		fakes = newAWSMgrFakes()
		primaryLink = newFakeLink()
		var err error
		primaryMAC, err = net.ParseMAC(primaryMACStr)
		Expect(err).NotTo(HaveOccurred())
		secondaryMAC, err = net.ParseMAC(secondaryMACStr)
		Expect(err).NotTo(HaveOccurred())
		thirdMAC, err = net.ParseMAC(thirdMACStr)
		Expect(err).NotTo(HaveOccurred())
		fourthMAC, err = net.ParseMAC(fourthMACStr)
		Expect(err).NotTo(HaveOccurred())
		primaryLink.attrs.HardwareAddr = primaryMAC
		primaryLink.attrs.MTU = 9001
		fakes.Links = []netlink.Link{
			primaryLink,
		}
		opRecorder := logutils.NewSummarizer("aws-ip-mgr-test")

		m = NewAWSIPManager(
			awsRTIndexes,
			Config{
				AWSSecondaryIPRoutingRulePriority: 105,
				NetlinkTimeout:                    awsTestNetlinkTimeout,
				AWSSecondaryIPSupport:             mode,
			},
			opRecorder,
			fakes,
			fakes.FeatureDetector,
			OptNetlinkOverride(fakes),
			OptRouteTableOverride(fakes.NewRouteTable),
			OptRouteRulesOverride(fakes.NewRouteRules),
		)
	})

	It("should send empty snapshot if there are no datastore resources", func() {
		Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())

		Expect(fakes.DatastoreState).To(Equal(&aws.DatastoreState{
			LocalAWSAddrsByDst: map[ip.Addr]aws.AddrInfo{},
			PoolIDsBySubnetID:  map[string]set.Set[string]{},
		}))
	})

	It("should not fail on an interface update before an AWS update", func() {
		m.OnUpdate(&ifaceStateUpdate{
			Name:  "eth1",
			Index: 123,
			State: ifacemonitor.StateDown,
		})

		Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
	})

	It("should do nothing if dataplane is empty and no AWS interfaces are needed", func() {
		Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())

		Expect(fakes.DatastoreState).To(Equal(&aws.DatastoreState{
			LocalAWSAddrsByDst: map[ip.Addr]aws.AddrInfo{},
			PoolIDsBySubnetID:  map[string]set.Set[string]{},
		}))

		m.OnSecondaryIfaceStateUpdate(&aws.LocalAWSNetworkState{})

		Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
	})

	Context("with pools, a local AWS pod and a non-AWS pod", func() {
		var workloadRoute *proto.RouteUpdate

		BeforeEach(func() {
			// Send in non-AWS pools and an AWS pool for hosts and a pool for workloads.
			m.OnUpdate(&proto.IPAMPoolUpdate{
				Id: "non-aws-pool-masq",
				Pool: &proto.IPAMPool{
					Cidr:       "192.168.0.0/16",
					Masquerade: true,
				},
			})
			m.OnUpdate(&proto.IPAMPoolUpdate{
				Id: "non-aws-pool-non-masq",
				Pool: &proto.IPAMPool{
					Cidr: "10.23.0.0/16",
				},
			})
			m.OnUpdate(&proto.RouteUpdate{
				Types:       proto.RouteType_CIDR_INFO,
				IpPoolType:  proto.IPPoolType_IPIP,
				Dst:         "192.168.0.0/16",
				NatOutgoing: true,
			})
			m.OnUpdate(&proto.IPAMPoolUpdate{
				Id: "hosts-pool",
				Pool: &proto.IPAMPool{
					Cidr:        "100.64.1.0/24",
					Masquerade:  false,
					AwsSubnetId: "subnet-123456789012345657",
				},
			})
			m.OnUpdate(&proto.RouteUpdate{
				Types:         proto.RouteType_CIDR_INFO,
				IpPoolType:    proto.IPPoolType_NO_ENCAP,
				Dst:           "100.64.1.0/24",
				NatOutgoing:   false,
				LocalWorkload: false,
				AwsSubnetId:   "subnet-123456789012345657",
			})
			m.OnUpdate(&proto.IPAMPoolUpdate{
				Id: "workloads-pool",
				Pool: &proto.IPAMPool{
					Cidr:        "100.64.2.0/24",
					Masquerade:  false,
					AwsSubnetId: "subnet-123456789012345657",
				},
			})
			m.OnUpdate(&proto.RouteUpdate{
				Types:         proto.RouteType_CIDR_INFO,
				IpPoolType:    proto.IPPoolType_VXLAN,
				Dst:           "100.64.2.0/24",
				NatOutgoing:   false,
				LocalWorkload: false,
				AwsSubnetId:   "subnet-123456789012345657",
			})

			// Local AWS workload.
			workloadRoute = &proto.RouteUpdate{
				Types:         proto.RouteType_LOCAL_WORKLOAD,
				IpPoolType:    proto.IPPoolType_VXLAN,
				Dst:           egressGWCIDR,
				NatOutgoing:   false,
				LocalWorkload: true, // This means "really a workload, not just a local IPAM block"
				AwsSubnetId:   "subnet-123456789012345657",
			}
			m.OnUpdate(workloadRoute)
			// Base case: no elastic IPs, should get ignored.
			wepUpd := &proto.WorkloadEndpointUpdate{
				Id: wep1ID,
				Endpoint: &proto.WorkloadEndpoint{
					Ipv4Nets: []string{egressGWCIDR},
				},
			}
			m.OnUpdate(wepUpd)

			// Local non-AWS workload (should be ignored).
			nonAWSWorkloadRoute := &proto.RouteUpdate{
				Types:         proto.RouteType_LOCAL_WORKLOAD,
				IpPoolType:    proto.IPPoolType_VXLAN,
				Dst:           "192.168.1.2/32",
				NatOutgoing:   true,
				LocalWorkload: true, // This means "really a workload, not just a local IPAM block"
			}
			m.OnUpdate(nonAWSWorkloadRoute)
			// Non-AWS WEP update, should get ignored.
			wepUpd = &proto.WorkloadEndpointUpdate{
				Id: wep2ID,
				Endpoint: &proto.WorkloadEndpoint{
					Ipv4Nets: []string{"192.168.1.2/32"},
				},
			}
			m.OnUpdate(wepUpd)
			// Non-AWS WEP delete, should get ignored.
			wepDel := &proto.WorkloadEndpointRemove{
				Id: wep2ID,
			}
			m.OnUpdate(wepDel)

			Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
		})

		It("should send the right snapshot", func() {
			// Should send the expected snapshot, ignoring non-AWS pools and workloads.
			workloadCIDR := ip.MustParseCIDROrIP(workloadRoute.Dst).Addr()
			Expect(fakes.DatastoreState).To(Equal(&aws.DatastoreState{
				LocalAWSAddrsByDst: map[ip.Addr]aws.AddrInfo{
					workloadCIDR: {
						AWSSubnetId: workloadRoute.AwsSubnetId,
						Dst:         workloadRoute.Dst,
					},
				},
				PoolIDsBySubnetID: map[string]set.Set[string]{
					"subnet-123456789012345657": set.From[string]("hosts-pool", "workloads-pool"),
				},
			}))
		})

		Describe("with elastic IPs", func() {
			const elasticIP1 = "44.0.0.1"
			const elasticIP2 = "44.0.0.2"
			const elasticIP3 = "44.0.0.3"

			BeforeEach(func() {
				wepUpd := &proto.WorkloadEndpointUpdate{
					Id: wep1ID,
					Endpoint: &proto.WorkloadEndpoint{
						Ipv4Nets:      []string{egressGWCIDR},
						AwsElasticIps: []string{elasticIP1},
					},
				}
				m.OnUpdate(wepUpd)
				Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
			})

			It("Should send expected state", func() {
				workloadCIDR := ip.MustParseCIDROrIP(workloadRoute.Dst).Addr()
				Expect(fakes.DatastoreState).To(Equal(&aws.DatastoreState{
					LocalAWSAddrsByDst: map[ip.Addr]aws.AddrInfo{
						workloadCIDR: {
							AWSSubnetId: workloadRoute.AwsSubnetId,
							Dst:         workloadRoute.Dst,
							ElasticIPs:  []ip.Addr{ip.FromString(elasticIP1)},
						},
					},
					PoolIDsBySubnetID: map[string]set.Set[string]{
						"subnet-123456789012345657": set.From[string]("hosts-pool", "workloads-pool"),
					},
				}))
			})

			Describe("with conflicting workloads", func() {
				BeforeEach(func() {
					// Set up two workloads with the same private IP and overlapping elastic IPs.  This is
					// a misconfiguration, but it can happen transiently during resyncs.
					wepUpd := &proto.WorkloadEndpointUpdate{
						Id: wep1ID,
						Endpoint: &proto.WorkloadEndpoint{
							Ipv4Nets:      []string{egressGWCIDR},
							AwsElasticIps: []string{elasticIP1, elasticIP2},
						},
					}
					m.OnUpdate(wepUpd)

					wepUpd = &proto.WorkloadEndpointUpdate{
						Id: wep2ID,
						Endpoint: &proto.WorkloadEndpoint{
							Ipv4Nets:      []string{egressGWCIDR},
							AwsElasticIps: []string{elasticIP2, elasticIP3},
						},
					}
					m.OnUpdate(wepUpd)
					Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
				})

				It("should send expected state", func() {
					workloadCIDR := ip.MustParseCIDROrIP(workloadRoute.Dst).Addr()
					Expect(fakes.DatastoreState).To(Equal(&aws.DatastoreState{
						LocalAWSAddrsByDst: map[ip.Addr]aws.AddrInfo{
							workloadCIDR: {
								AWSSubnetId: workloadRoute.AwsSubnetId,
								Dst:         workloadRoute.Dst,
								// Only the shared elastic IP is passed through.
								ElasticIPs: []ip.Addr{ip.FromString(elasticIP2)},
							},
						},
						PoolIDsBySubnetID: map[string]set.Set[string]{
							"subnet-123456789012345657": set.From[string]("hosts-pool", "workloads-pool"),
						},
					}))
				})

				It("should ignore duplicate updates", func() {
					fakes.DatastoreUpdateCount = 0
					wepUpd := &proto.WorkloadEndpointUpdate{
						Id: wep1ID,
						Endpoint: &proto.WorkloadEndpoint{
							Ipv4Nets:      []string{egressGWCIDR},
							AwsElasticIps: []string{elasticIP1, elasticIP2},
						},
					}
					m.OnUpdate(wepUpd)

					Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
					Expect(fakes.DatastoreUpdateCount).To(BeZero())
				})

				Describe("after cleaning up conflict", func() {
					BeforeEach(func() {
						m.OnUpdate(&proto.WorkloadEndpointRemove{
							Id: wep2ID,
						})
						Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
					})

					It("Should send expected state", func() {
						workloadCIDR := ip.MustParseCIDROrIP(workloadRoute.Dst).Addr()
						Expect(fakes.DatastoreState).To(Equal(&aws.DatastoreState{
							LocalAWSAddrsByDst: map[ip.Addr]aws.AddrInfo{
								workloadCIDR: {
									AWSSubnetId: workloadRoute.AwsSubnetId,
									Dst:         workloadRoute.Dst,
									// Only the shared elastic IP is passed through.
									ElasticIPs: []ip.Addr{ip.FromString(elasticIP1), ip.FromString(elasticIP2)},
								},
							},
							PoolIDsBySubnetID: map[string]set.Set[string]{
								"subnet-123456789012345657": set.From[string]("hosts-pool", "workloads-pool"),
							},
						}))
					})
				})
			})
		})

		It("should handle a change of subnet", func() {
			m.OnUpdate(&proto.IPAMPoolUpdate{
				Id: "workloads-pool",
				Pool: &proto.IPAMPool{
					Cidr:        "100.64.2.0/24",
					Masquerade:  false,
					AwsSubnetId: "subnet-000002",
				},
			})
			m.OnUpdate(&proto.RouteUpdate{
				Types:         proto.RouteType_CIDR_INFO,
				IpPoolType:    proto.IPPoolType_VXLAN,
				Dst:           "100.64.2.0/24",
				NatOutgoing:   false,
				LocalWorkload: false,
				AwsSubnetId:   "subnet-000002",
			})
			workloadRoute = &proto.RouteUpdate{
				Types:         proto.RouteType_LOCAL_WORKLOAD,
				IpPoolType:    proto.IPPoolType_VXLAN,
				Dst:           egressGWCIDR,
				NatOutgoing:   false,
				LocalWorkload: true, // This means "really a workload, not just a local IPAM block"
				AwsSubnetId:   "subnet-000002",
			}
			m.OnUpdate(workloadRoute)

			Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())

			// Should send the expected snapshot with updated subnets.
			workloadCIDR := ip.MustParseCIDROrIP(workloadRoute.Dst).Addr()
			Expect(fakes.DatastoreState).To(Equal(&aws.DatastoreState{
				LocalAWSAddrsByDst: map[ip.Addr]aws.AddrInfo{
					workloadCIDR: {
						AWSSubnetId: workloadRoute.AwsSubnetId,
						Dst:         workloadRoute.Dst,
					},
				},
				PoolIDsBySubnetID: map[string]set.Set[string]{
					"subnet-123456789012345657": set.From[string]("hosts-pool"),
					"subnet-000002":             set.From[string]("workloads-pool"),
				},
			}))
		})

		It("should handle a pool deletion", func() {
			m.OnUpdate(&proto.IPAMPoolRemove{
				Id: "workloads-pool",
			})
			m.OnUpdate(&proto.RouteRemove{
				Dst: "100.64.2.0/24",
			})
			workloadRoute = &proto.RouteUpdate{
				Types:         proto.RouteType_LOCAL_WORKLOAD,
				IpPoolType:    proto.IPPoolType_VXLAN,
				Dst:           egressGWCIDR,
				NatOutgoing:   false,
				LocalWorkload: true, // This means "really a workload, not just a local IPAM block"
			}
			m.OnUpdate(workloadRoute)

			// Should send the expected snapshot
			Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
			Expect(fakes.DatastoreState).To(Equal(&aws.DatastoreState{
				LocalAWSAddrsByDst: map[ip.Addr]aws.AddrInfo{},
				PoolIDsBySubnetID: map[string]set.Set[string]{
					"subnet-123456789012345657": set.From[string]("hosts-pool"),
				},
			}))

			// Delete the other pool, should clean up.
			m.OnUpdate(&proto.IPAMPoolRemove{
				Id: "hosts-pool",
			})

			// Should send the expected snapshot
			Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
			Expect(fakes.DatastoreState).To(Equal(&aws.DatastoreState{
				LocalAWSAddrsByDst: map[ip.Addr]aws.AddrInfo{},
				PoolIDsBySubnetID:  map[string]set.Set[string]{},
			}))
		})

		Context("after responding with expected AWS state", func() {
			var secondaryLink *fakeLink

			checkRouteTable := func(rt *fakeRouteTable, ifaceName string) {
				Expect(rt).ToNot(BeNil())
				Expect(rt.Routes).ToNot(BeNil())
				gwAddrAsCIDR := ip.MustParseCIDROrIP("100.64.0.1/32")
				Expect(rt.Routes[ifaceName]).To(ConsistOf(
					routetable.Target{
						Type: routetable.TargetTypeLinkLocalUnicast,
						CIDR: ip.MustParseCIDROrIP("100.64.0.0/16"),
					},
					routetable.Target{
						Type: routetable.TargetTypeGlobalUnicast,
						CIDR: ip.MustParseCIDROrIP("0.0.0.0/0"),
						GW:   gwAddrAsCIDR.Addr(),
					},
				), "Expected gateway and default routes.")
				Expect(rt.Routes[routetable.InterfaceNone]).To(ConsistOf(
					routetable.Target{
						Type: routetable.TargetTypeThrow,
						CIDR: ip.MustParseCIDROrIP("192.168.0.0/16"),
					},
					routetable.Target{
						Type: routetable.TargetTypeThrow,
						CIDR: ip.MustParseCIDROrIP("10.23.0.0/16"),
					},
				), "Expected 'throw' route for the non-AWS IP pools.")
			}

			var expectSecondaryLinkAddr func()
			var expectSecondaryLinkConfigured func()

			if mode == v3.AWSSecondaryIPEnabledENIPerWorkload {
				BeforeEach(func() {
					// Pretend the background thread attached a new ENI.
					m.OnSecondaryIfaceStateUpdate(&aws.LocalAWSNetworkState{
						PrimaryENIMAC: primaryMACStr,
						SecondaryENIsByMAC: map[string]aws.Iface{
							secondaryMACStr: {
								ID:              "eni-0001",
								MAC:             secondaryMAC,
								PrimaryIPv4Addr: ip.FromString(egressGWIP),
							},
						},
						SubnetCIDR:  ip.MustParseCIDROrIP("100.64.0.0/16"),
						GatewayAddr: ip.FromString("100.64.0.1"),
					})

					// Create a secondary interface ready to go but not actually in the dataplane yet.
					secondaryLink = newFakeLink()
					la := netlink.NewLinkAttrs()
					la.Index = 123
					la.Name = "eth1"
					la.HardwareAddr = secondaryMAC
					secondaryLink.attrs = la
				})

				expectSecondaryLinkAddr = func() {
					// No IPs get added directly.
					Expect(secondaryLink.addrs).To(BeEmpty())
					Expect(secondaryLink.attrs.OperState).To(Equal(netlink.LinkOperState(netlink.OperUp)))
					Expect(fakes.Neighs[NeighKey{Iface: secondaryLink.Attrs().Index, IP: egressGWIP}]).To(Equal(
						&netlink.Neigh{
							LinkIndex: secondaryLink.Attrs().Index,
							Family:    netlink.FAMILY_V4,
							Flags:     netlink.NTF_PROXY,
							IP:        net.ParseIP(egressGWIP),
						}))
					ifaceARPEntries := fakes.ifaceARPEntries(secondaryLink.Attrs().Index)
					ExpectWithOffset(1, ifaceARPEntries).To(HaveLen(1), "Got unexpected extra ARP entries")
				}

				expectSecondaryLinkConfigured = func() {
					expectSecondaryLinkAddr()
					Expect(fakes.RouteTables).To(HaveLen(1))
					rtID, rt := fakes.FindRouteTable("eth1")
					checkRouteTable(rt, "eth1")
					// Rule for each egress gateway workload.
					egRule := routerule.
						NewRule(4, 105).
						MatchSrcAddress(ip.MustParseCIDROrIP(egressGWIP).ToIPNet()).
						GoToTable(rtID)
					Expect(fakes.Rules.Rules).To(ConsistOf(egRule))
				}
			} else {
				BeforeEach(func() {
					// Pretend the background thread attached a new ENI.
					m.OnSecondaryIfaceStateUpdate(&aws.LocalAWSNetworkState{
						PrimaryENIMAC: primaryMACStr,
						SecondaryENIsByMAC: map[string]aws.Iface{
							secondaryMACStr: {
								ID:              "eni-0001",
								MAC:             secondaryMAC,
								PrimaryIPv4Addr: ip.FromString(eth1PrimaryIP),
								SecondaryIPv4Addrs: []ip.Addr{
									ip.FromString(egressGWIP),
								},
							},
						},
						SubnetCIDR:  ip.MustParseCIDROrIP("100.64.0.0/16"),
						GatewayAddr: ip.FromString("100.64.0.1"),
					})

					// Create a secondary interface ready to go but not actually in the dataplane yet.
					secondaryLink = newFakeLink()
					la := netlink.NewLinkAttrs()
					la.Name = "eth1"
					la.HardwareAddr = secondaryMAC
					secondaryLink.attrs = la
				})

				expectSecondaryLinkAddr = func() {
					// Only the primary IP gets added.
					secondaryIfacePriIP, err := netlink.ParseAddr(eth1PrimaryIP + "/32")
					secondaryIfacePriIP.Scope = int(netlink.SCOPE_LINK)
					Expect(err).NotTo(HaveOccurred())
					Expect(secondaryLink.addrs).To(ConsistOf(*secondaryIfacePriIP))
					Expect(secondaryLink.attrs.OperState).To(Equal(netlink.LinkOperState(netlink.OperUp)))
				}

				expectSecondaryLinkConfigured = func() {
					expectSecondaryLinkAddr()
					Expect(fakes.RouteTables).To(HaveLen(1))
					rtID, rt := fakes.FindRouteTable("eth1")
					checkRouteTable(rt, "eth1")
					// Rule for each egress gateway workload.
					primaryIPRule := routerule.
						NewRule(4, 105).
						MatchSrcAddress(ip.MustParseCIDROrIP(eth1PrimaryIP).ToIPNet()).
						GoToTable(rtID)
					egRule := routerule.
						NewRule(4, 105).
						MatchSrcAddress(ip.MustParseCIDROrIP(egressGWIP).ToIPNet()).
						GoToTable(rtID)
					Expect(fakes.Rules.Rules).To(ConsistOf(primaryIPRule, egRule))
				}
			}

			It("with the interface present, it should network the interface", func() {
				fakes.AddFakeLink(secondaryLink)

				// CompleteDeferredWork should configure the interface.
				Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())

				// IP should be added.
				expectSecondaryLinkConfigured()
			})

			It("with the interface missing, it should handle the interface showing up.", func() {
				// Should do nothing to start with.
				Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())

				// Interface shows up.
				fakes.AddFakeLink(secondaryLink)

				// CompleteDeferredWork should not do anything yet.
				Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
				Expect(secondaryLink.addrs).To(BeEmpty())

				// But sending in an interface update should trigger it.
				m.OnUpdate(&ifaceStateUpdate{
					Name:  "eth1",
					Index: 123,
					State: ifacemonitor.StateDown,
				})

				// CompleteDeferredWork should then configure the interface.
				Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())

				// IP should be added.
				expectSecondaryLinkConfigured()
			})

			errEntry := func(name string) TableEntry {
				return Entry(name, name)
			}
			var errEntries []TableEntry
			if mode == v3.AWSSecondaryIPEnabledENIPerWorkload {
				errEntries = []TableEntry{
					errEntry("LinkList"),
					errEntry("LinkSetMTU"),
					errEntry("LinkSetUp"),
					errEntry("AddrList"),
					errEntry("AddrDel"),
					errEntry("NeighSet"),
				}
			} else {
				errEntries = []TableEntry{
					errEntry("LinkList"),
					errEntry("LinkSetMTU"),
					errEntry("LinkSetUp"),
					errEntry("AddrList"),
					errEntry("AddrAdd"),
					errEntry("AddrDel"),
					errEntry("ParseAddr"),
					errEntry("NeighList"),
				}
			}
			DescribeTable("with queued error",
				func(name string) {
					fakes.Errors.QueueError(name)

					// Add a bonus address so that AddrDel will be called.
					extraNLAddr, err := netlink.ParseAddr("1.2.3.4/32")
					Expect(err).NotTo(HaveOccurred())
					secondaryLink.addrs = append(secondaryLink.addrs, *extraNLAddr)
					fakes.AddFakeLink(secondaryLink)

					// Add a bonus proxy ARP entry so that NeighDel will be called.
					fakes.Neighs[NeighKey{
						Iface: secondaryLink.Attrs().Index,
						IP:    "1.2.3.4",
					}] = &netlink.Neigh{
						LinkIndex: secondaryLink.Attrs().Index,
						Family:    netlink.FAMILY_V4,
						Flags:     netlink.NTF_PROXY,
						IP:        net.ParseIP("1.2.3.4"),
					}

					// CompleteDeferredWork should fail once, then succeed.
					Expect(m.CompleteDeferredWork()).To(HaveOccurred())
					Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
					Expect(fakes.DeletedNeighs).To(ConsistOf("1.2.3.4"))

					// IP should be added.
					expectSecondaryLinkConfigured()

					fakes.Errors.ExpectAllErrorsConsumed()
				},
				errEntries,
			)

			It("should handle an interface flap.", func() {
				// Should do nothing to start with.
				Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())

				// Interface shows up.
				fakes.AddFakeLink(secondaryLink)
				m.OnUpdate(&ifaceStateUpdate{
					Name:  "eth1",
					Index: 123,
					State: ifacemonitor.StateDown,
				})

				// CompleteDeferredWork should then configure the interface.
				Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
				expectSecondaryLinkConfigured()

				// Interface re-added with new index
				secondaryLink.addrs = nil
				m.OnUpdate(&ifaceStateUpdate{
					Name:  "eth1",
					Index: 124,
					State: ifacemonitor.StateDown,
				})

				// CompleteDeferredWork should then configure the interface.
				Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
				expectSecondaryLinkConfigured()

				// Resulting signal of the interface going up shouldn't cause a resync.
				m.OnUpdate(&ifaceStateUpdate{
					Name:  "eth1",
					Index: 124,
					State: ifacemonitor.StateUp,
				})
				Expect(m.dataplaneResyncNeeded).To(BeFalse())

				// Resulting signal of the interface going up shouldn't cause a resync but if it goes down
				// then we do care.
				m.OnUpdate(&ifaceStateUpdate{
					Name:  "eth1",
					Index: 124,
					State: ifacemonitor.StateDown,
				})
				Expect(m.dataplaneResyncNeeded).To(BeTrue())
			})

			It("should handle an unexpected IP being added to an interface.", func() {
				// Interface shows up.
				fakes.AddFakeLink(secondaryLink)
				m.OnUpdate(&ifaceStateUpdate{
					Name:  "eth1",
					Index: 123,
					State: ifacemonitor.StateDown,
				})

				// CompleteDeferredWork should then configure the interface.
				Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
				expectSecondaryLinkConfigured()

				// New IP added to interface and signalled.
				extraNLAddr, err := netlink.ParseAddr("1.2.3.4/32")
				Expect(err).NotTo(HaveOccurred())
				secondaryLink.addrs = append(secondaryLink.addrs, *extraNLAddr)
				m.OnUpdate(&ifaceAddrsUpdate{
					Name: "eth1",
					Addrs: set.From[string](
						"daed:beef::",
						"1.2.3.4",
						eth1PrimaryIP,
					),
				})

				// CompleteDeferredWork should clean up the incorrect IP.
				Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
				expectSecondaryLinkConfigured()
			})

			It("should handle an interface delete/re-add.", func() {
				// Should do nothing to start with.
				Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())

				// Interface shows up.
				fakes.AddFakeLink(secondaryLink)
				m.OnUpdate(&ifaceStateUpdate{
					Name:  "eth1",
					Index: 123,
					State: ifacemonitor.StateDown,
				})

				// CompleteDeferredWork should then configure the interface.
				Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
				expectSecondaryLinkConfigured()

				// Interface re-added with new index
				secondaryLink.addrs = nil

				// Delete.
				m.OnUpdate(&ifaceStateUpdate{
					Name:  "eth1",
					Index: 123,
					State: ifacemonitor.StateNotPresent,
				})
				Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())

				// Re-add
				m.OnUpdate(&ifaceStateUpdate{
					Name:  "eth1",
					Index: 124,
					State: ifacemonitor.StateDown,
				})

				// CompleteDeferredWork should then configure the interface.
				Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
				expectSecondaryLinkConfigured()
			})

			It("should provide the route tables.", func() {
				fakes.AddFakeLink(secondaryLink)
				Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())

				Expect(m.GetRouteTableSyncers()).To(HaveLen(1))
				Expect(m.GetRouteRules()).To(ConsistOf(fakes.Rules))
			})

			It("should handle AWS interface going away.", func() {
				fakes.AddFakeLink(secondaryLink)
				Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())

				m.OnSecondaryIfaceStateUpdate(&aws.LocalAWSNetworkState{
					PrimaryENIMAC:      primaryMACStr,
					SecondaryENIsByMAC: map[string]aws.Iface{},
					SubnetCIDR:         ip.MustParseCIDROrIP("100.64.0.0/16"),
					GatewayAddr:        ip.FromString("100.64.0.1"),
				})

				Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())

				// Routing table should be flushed.
				Expect(fakes.RouteTables).To(HaveLen(1))
				for _, rt := range fakes.RouteTables {
					Expect(rt.Routes["eth1"]).To(BeEmpty())
					Expect(rt.Routes[routetable.InterfaceNone]).To(BeEmpty())
				}
				Expect(fakes.Rules.Rules).To(BeEmpty())
			})

			It("should remove an extra IP on the ENI", func() {
				bogusAddr, err := netlink.ParseAddr("1.2.3.4/24")
				secondaryLink.addrs = append(secondaryLink.addrs, *bogusAddr)
				Expect(err).NotTo(HaveOccurred())
				fakes.AddFakeLink(secondaryLink)

				Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
				expectSecondaryLinkConfigured()
			})

			Context("With second egress gateway on second ENI", func() {
				var (
					extraWorkloadRoute *proto.RouteUpdate
					thirdLink          *fakeLink
					fourthLink         *fakeLink
				)

				BeforeEach(func() {
					// Extra route.
					extraWorkloadRoute = &proto.RouteUpdate{
						Types:         proto.RouteType_LOCAL_WORKLOAD,
						IpPoolType:    proto.IPPoolType_VXLAN,
						Dst:           egressGW2CIDR,
						NatOutgoing:   false,
						LocalWorkload: true, // This means "really a workload, not just a local IPAM block"
						AwsSubnetId:   "subnet-123456789012345657",
					}
					m.OnUpdate(extraWorkloadRoute)

					// Pretend the background thread attached a new ENI.
					if mode == v3.AWSSecondaryIPEnabledENIPerWorkload {
						m.OnSecondaryIfaceStateUpdate(&aws.LocalAWSNetworkState{
							PrimaryENIMAC: primaryMACStr,
							SecondaryENIsByMAC: map[string]aws.Iface{
								secondaryMACStr: {
									ID:              "eni-0001",
									MAC:             secondaryMAC,
									PrimaryIPv4Addr: ip.FromString(egressGWIP),
								},
								thirdMACStr: {
									ID:              "eni-0002",
									MAC:             thirdMAC,
									PrimaryIPv4Addr: ip.FromString(egressGW2IP),
								},
							},
							SubnetCIDR:  ip.MustParseCIDROrIP("100.64.0.0/16"),
							GatewayAddr: ip.FromString("100.64.0.1"),
						})
					} else {
						m.OnSecondaryIfaceStateUpdate(&aws.LocalAWSNetworkState{
							PrimaryENIMAC: primaryMACStr,
							SecondaryENIsByMAC: map[string]aws.Iface{
								secondaryMACStr: {
									ID:              "eni-0001",
									MAC:             secondaryMAC,
									PrimaryIPv4Addr: ip.FromString(eth1PrimaryIP),
									SecondaryIPv4Addrs: []ip.Addr{
										ip.FromString(egressGWIP),
									},
								},
								thirdMACStr: {
									ID:              "eni-0002",
									MAC:             thirdMAC,
									PrimaryIPv4Addr: ip.FromString(thirdLinkPrimaryIP),
									SecondaryIPv4Addrs: []ip.Addr{
										ip.FromString(egressGW2IP),
									},
								},
							},
							SubnetCIDR:  ip.MustParseCIDROrIP("100.64.0.0/16"),
							GatewayAddr: ip.FromString("100.64.0.1"),
						})
					}

					// Get a third link ready to go.
					thirdLink = newFakeLink()
					la := netlink.NewLinkAttrs()
					la.Name = "eth2"
					la.HardwareAddr = thirdMAC
					thirdLink.attrs = la
					fourthLink = newFakeLink()
					la.HardwareAddr = fourthMAC
					fourthLink.attrs = la
				})

				var expectLinksConfigured func(eth2PrimaryIP string)
				if mode == v3.AWSSecondaryIPEnabledENIPerWorkload {
					expectLinksConfigured = func(eth2PrimaryIP string) {
						expectSecondaryLinkAddr()
						Expect(fakes.RouteTables).To(HaveLen(2))

						rtID1, rt1 := fakes.FindRouteTable("eth1")
						checkRouteTable(rt1, "eth1")
						rtID2, rt2 := fakes.FindRouteTable("eth2")
						checkRouteTable(rt2, "eth2")

						// Rule for each egress gateway workload.
						Expect(fakes.Rules.Rules).To(ConsistOf(
							routerule.
								NewRule(4, 105).
								MatchSrcAddress(ip.MustParseCIDROrIP(egressGWIP).ToIPNet()).
								GoToTable(rtID1),
							routerule.
								NewRule(4, 105).
								MatchSrcAddress(ip.MustParseCIDROrIP(egressGW2IP).ToIPNet()).
								GoToTable(rtID2),
						))
						Expect(rtID1).NotTo(Equal(rtID2))
						Expect(m.GetRouteTableSyncers()).To(ConsistOf(rt1, rt2))
					}
				} else {
					expectLinksConfigured = func(eth2PrimaryIP string) {
						expectSecondaryLinkAddr()
						Expect(fakes.RouteTables).To(HaveLen(2))

						rtID1, rt1 := fakes.FindRouteTable("eth1")
						checkRouteTable(rt1, "eth1")
						rtID2, rt2 := fakes.FindRouteTable("eth2")
						checkRouteTable(rt2, "eth2")

						// Rule for each egress gateway workload.
						Expect(fakes.Rules.Rules).To(ConsistOf(
							routerule.
								NewRule(4, 105).
								MatchSrcAddress(ip.MustParseCIDROrIP(eth1PrimaryIP).ToIPNet()).
								GoToTable(rtID1),
							routerule.
								NewRule(4, 105).
								MatchSrcAddress(ip.MustParseCIDROrIP(eth2PrimaryIP).ToIPNet()).
								GoToTable(rtID2),
							routerule.
								NewRule(4, 105).
								MatchSrcAddress(ip.MustParseCIDROrIP(egressGWIP).ToIPNet()).
								GoToTable(rtID1),
							routerule.
								NewRule(4, 105).
								MatchSrcAddress(ip.MustParseCIDROrIP(egressGW2IP).ToIPNet()).
								GoToTable(rtID2),
						))
						Expect(rtID1).NotTo(Equal(rtID2))
						Expect(m.GetRouteTableSyncers()).To(ConsistOf(rt1, rt2))
					}
				}

				It("with the interfaces present, it should network the interface", func() {
					// Add the links.
					fakes.AddFakeLink(secondaryLink)
					fakes.AddFakeLink(thirdLink)

					// CompleteDeferredWork should configure the interfaces.
					Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())

					// IP should be added.
					expectLinksConfigured(thirdLinkPrimaryIP /*Ignored in ENI-per-workload mode*/)
				})

				It("flapping second interface should recycle routing table", func() {
					// Pre-flap, should work as normal.
					fakes.AddFakeLink(secondaryLink)
					fakes.AddFakeLink(thirdLink)
					Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
					expectLinksConfigured(thirdLinkPrimaryIP /*Ignored in ENI-per-workload mode*/)

					rtID1, rt1 := fakes.FindRouteTable("eth1")
					rtID2, rt2 := fakes.FindRouteTable("eth2")

					// Take the link away and signal the manager.
					fakes.RemoveFakeLink(thirdLink)
					m.OnUpdate(&ifaceStateUpdate{
						Name:  "eth2",
						Index: 123,
						State: ifacemonitor.StateDown,
					})
					Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())

					// Still expect the route table to be returned (so that it can clean up).
					Expect(m.GetRouteTableSyncers()).To(ConsistOf(rt1, rt2))
					if mode == v3.AWSSecondaryIPEnabledENIPerWorkload {
						// But should only have one rule now.
						Expect(fakes.Rules.Rules).To(ConsistOf(
							routerule.
								NewRule(4, 105).
								MatchSrcAddress(ip.MustParseCIDROrIP(egressGWIP).ToIPNet()).
								GoToTable(rtID1),
						))
					} else {
						// But should only have one pair of rules now.
						Expect(fakes.Rules.Rules).To(ConsistOf(
							routerule.
								NewRule(4, 105).
								MatchSrcAddress(ip.MustParseCIDROrIP(eth1PrimaryIP).ToIPNet()).
								GoToTable(rtID1),
							routerule.
								NewRule(4, 105).
								MatchSrcAddress(ip.MustParseCIDROrIP(egressGWIP).ToIPNet()).
								GoToTable(rtID1),
						))
					}

					// Pretend the background thread attached a new ENI.
					if mode == v3.AWSSecondaryIPEnabledENIPerWorkload {
						m.OnSecondaryIfaceStateUpdate(&aws.LocalAWSNetworkState{
							PrimaryENIMAC: primaryMACStr,
							SecondaryENIsByMAC: map[string]aws.Iface{
								secondaryMACStr: {
									ID:              "eni-0001",
									MAC:             secondaryMAC,
									PrimaryIPv4Addr: ip.FromString(egressGWIP),
								},
								fourthMACStr: {
									ID:              "eni-0003",
									MAC:             fourthMAC,
									PrimaryIPv4Addr: ip.FromString(egressGW2IP),
								},
							},
							SubnetCIDR:  ip.MustParseCIDROrIP("100.64.0.0/16"),
							GatewayAddr: ip.FromString("100.64.0.1"),
						})
					} else {
						m.OnSecondaryIfaceStateUpdate(&aws.LocalAWSNetworkState{
							PrimaryENIMAC: primaryMACStr,
							SecondaryENIsByMAC: map[string]aws.Iface{
								secondaryMACStr: {
									ID:              "eni-0001",
									MAC:             secondaryMAC,
									PrimaryIPv4Addr: ip.FromString(eth1PrimaryIP),
									SecondaryIPv4Addrs: []ip.Addr{
										ip.FromString(egressGWIP),
									},
								},
								fourthMACStr: {
									ID:              "eni-0003",
									MAC:             fourthMAC,
									PrimaryIPv4Addr: ip.FromString(fourthLinkPrimaryIP),
									SecondaryIPv4Addrs: []ip.Addr{
										ip.FromString(egressGW2IP),
									},
								},
							},
							SubnetCIDR:  ip.MustParseCIDROrIP("100.64.0.0/16"),
							GatewayAddr: ip.FromString("100.64.0.1"),
						})
					}
					fakes.AddFakeLink(fourthLink)
					Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())

					rtID2B, rt2B := fakes.FindRouteTable("eth2")
					// New route table should replace the old one.
					Expect(rt2).NotTo(BeIdenticalTo(rt2B))
					Expect(m.GetRouteTableSyncers()).To(ConsistOf(rt1, rt2B))
					// Route table indexes get reused LIFO.
					Expect(rtID2).To(Equal(rtID2B))

					expectLinksConfigured(fourthLinkPrimaryIP /*Ignored in ENI-per-workload mode*/)
				})
			})

			if mode == v3.AWSSecondaryIPEnabled {
				// Some tests only apply to secondary-IP-per-workload mode...

				It("should handle an interface IP removed.", func() {
					// Interface shows up.
					fakes.AddFakeLink(secondaryLink)
					m.OnUpdate(&ifaceStateUpdate{
						Name:  "eth1",
						Index: 123,
						State: ifacemonitor.StateDown,
					})

					// CompleteDeferredWork should then configure the interface.
					Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
					expectSecondaryLinkConfigured()

					// IP deleted.
					secondaryLink.addrs = nil
					m.OnUpdate(&ifaceAddrsUpdate{
						Name: "eth1",
						Addrs: set.From[string](
							"daed:beef::", // IPv6 ignored.
						),
					})

					// CompleteDeferredWork should add the correct IP.
					Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
					expectSecondaryLinkConfigured()

					// Finally signal the correct state.
					m.OnUpdate(&ifaceAddrsUpdate{
						Name: "eth1",
						Addrs: set.From[string](
							"daed:beef::",
							eth1PrimaryIP,
						),
					})

					// Should spot it's correct and not schedule an update.
					Expect(m.dataplaneResyncNeeded).To(BeFalse())

					Expect(m.CompleteDeferredWork()).NotTo(HaveOccurred())
					expectSecondaryLinkConfigured()
				})
			}
		})
	})
}

func newAWSMgrFakes() *awsIPMgrFakes {
	errorProd := testutils.NewErrorProducer()
	return &awsIPMgrFakes{
		RouteTables:     map[int]*fakeRouteTable{},
		Errors:          errorProd,
		Neighs:          map[NeighKey]*netlink.Neigh{},
		FeatureDetector: &environment.FakeFeatureDetector{},
	}
}

type awsIPMgrFakes struct {
	DatastoreState *aws.DatastoreState

	Links  []netlink.Link
	Neighs map[NeighKey]*netlink.Neigh

	RouteTables          map[int]*fakeRouteTable
	Rules                *fakeRouteRules
	Errors               testutils.ErrorProducer
	DatastoreUpdateCount int
	DeletedNeighs        []string
	FeatureDetector      *environment.FakeFeatureDetector
}

type NeighKey struct {
	Iface int
	IP    string
}

func (f *awsIPMgrFakes) ParseAddr(s string) (*netlink.Addr, error) {
	if err := f.Errors.NextErrorByCaller(); err != nil {
		return nil, err
	}
	return netlink.ParseAddr(s)
}

func (f *awsIPMgrFakes) OnDatastoreUpdate(ds aws.DatastoreState) {
	f.DatastoreUpdateCount++
	f.DatastoreState = &ds
}

func (f *awsIPMgrFakes) LinkSetMTU(iface netlink.Link, mtu int) error {
	if err := f.Errors.NextErrorByCaller(); err != nil {
		return err
	}
	iface.(*fakeLink).attrs.MTU = mtu
	return nil
}

func (f *awsIPMgrFakes) LinkSetUp(iface netlink.Link) error {
	if err := f.Errors.NextErrorByCaller(); err != nil {
		return err
	}
	iface.(*fakeLink).attrs.OperState = netlink.OperUp
	return nil
}

func (f *awsIPMgrFakes) AddrList(iface netlink.Link, family int) ([]netlink.Addr, error) {
	if err := f.Errors.NextErrorByCaller(); err != nil {
		return nil, err
	}
	Expect(family).To(Equal(netlink.FAMILY_V4))
	return iface.(*fakeLink).addrs, nil
}

func (f *awsIPMgrFakes) AddrDel(iface netlink.Link, addr *netlink.Addr) error {
	if err := f.Errors.NextErrorByCaller(); err != nil {
		return err
	}
	link := iface.(*fakeLink)
	newAddrs := link.addrs[:0]
	found := false
	for _, a := range link.addrs {
		if a.Equal(*addr) {
			found = true
			continue
		}
		newAddrs = append(newAddrs, a)
	}
	Expect(found).To(BeTrue(), "Asked to delete non-existent IP")
	link.addrs = newAddrs
	return nil
}

func (f *awsIPMgrFakes) AddrAdd(iface netlink.Link, addr *netlink.Addr) error {
	if err := f.Errors.NextErrorByCaller(); err != nil {
		return err
	}
	link := iface.(*fakeLink)
	link.addrs = append(link.addrs, *addr)
	return nil
}

func (f *awsIPMgrFakes) LinkList() ([]netlink.Link, error) {
	if err := f.Errors.NextErrorByCaller(); err != nil {
		return nil, err
	}
	return f.Links, nil
}

func (f *awsIPMgrFakes) NeighSet(neigh *netlink.Neigh) error {
	if err := f.Errors.NextErrorByCaller(); err != nil {
		return err
	}
	f.Neighs[NeighKey{
		Iface: neigh.LinkIndex,
		IP:    neigh.IP.String(),
	}] = neigh
	return nil
}

func (f *awsIPMgrFakes) NeighDel(neigh *netlink.Neigh) error {
	if err := f.Errors.NextErrorByCaller(); err != nil {
		return err
	}
	nk := NeighKey{
		Iface: neigh.LinkIndex,
		IP:    neigh.IP.String(),
	}
	if _, ok := f.Neighs[nk]; !ok {
		return fmt.Errorf("neigh not found")
	}
	delete(f.Neighs, nk)
	f.DeletedNeighs = append(f.DeletedNeighs, neigh.IP.String())
	return nil
}

func (f *awsIPMgrFakes) NeighList(linkIndex, family int) ([]netlink.Neigh, error) {
	if err := f.Errors.NextErrorByCaller(); err != nil {
		return nil, err
	}
	Expect(family).To(Equal(netlink.FAMILY_V4))
	var neighs []netlink.Neigh
	for nk, n := range f.Neighs {
		if nk.Iface == linkIndex {
			neighs = append(neighs, *n)
		}
	}
	return neighs, nil
}

func (f *awsIPMgrFakes) NewRouteTable(
	ifaceNames []string,
	version uint8,
	timeout time.Duration,
	deviceRouteSourceAddress net.IP,
	deviceRouteProtocol netlink.RouteProtocol,
	removeExternalRoutes bool,
	index int,
	reporter logutils.OpRecorder,
	featureDetector environment.FeatureDetectorIface) routetable.Interface {

	Expect(version).To(BeNumerically("==", 4))
	Expect(deviceRouteSourceAddress).To(BeNil())
	Expect(removeExternalRoutes).To(BeTrue())
	Expect(reporter).ToNot(BeNil())

	rt := &fakeRouteTable{
		IfaceNames: ifaceNames,
		Timeout:    timeout,
		Protocol:   deviceRouteProtocol,
		index:      index,
		Routes:     map[string][]routetable.Target{},
		Errors:     f.Errors,
	}
	f.RouteTables[index] = rt
	return rt
}

func (f *awsIPMgrFakes) NewRouteRules(
	ipVersion int,
	priority int,
	tableIndexSet set.Set[int],
	updateFunc routerule.RulesMatchFunc,
	removeFunc routerule.RulesMatchFunc,
	cleanupFunc routerule.RuleFilterFunc,
	netlinkTimeout time.Duration,
	newNetlinkHandle func() (routerule.HandleIface, error),
	opRecorder logutils.OpRecorder) (routeRules, error) {

	if err := f.Errors.NextErrorByCaller(); err != nil {
		return nil, err
	}

	Expect(ipVersion).To(Equal(4))
	Expect(priority).To(Equal(105))
	Expect(tableIndexSet).To(Equal(set.FromArray(awsRTIndexes)))
	Expect(updateFunc).ToNot(BeNil())
	Expect(removeFunc).ToNot(BeNil())
	Expect(opRecorder).ToNot(BeNil())
	Expect(netlinkTimeout).To(Equal(awsTestNetlinkTimeout))
	h, err := newNetlinkHandle()
	Expect(err).NotTo(HaveOccurred())
	Expect(h).ToNot(BeNil())
	Expect(f.Rules).To(BeNil())

	f.Rules = &fakeRouteRules{
		Errors: f.Errors,
	}

	return f.Rules, nil
}

func (f *awsIPMgrFakes) FindRouteTable(ifaceName string) (int, *fakeRouteTable) {
	for rtIdx, rt := range f.RouteTables {
		if rt.IfaceNames[0] == ifaceName {
			return rtIdx, rt
		}
	}
	return 0, nil
}

func (f *awsIPMgrFakes) AddFakeLink(link *fakeLink) {
	f.Links = append(f.Links, link)
}

func (f *awsIPMgrFakes) RemoveFakeLink(link *fakeLink) {
	newLinks := f.Links[:0]
	for _, l := range f.Links {
		if l == link {
			continue
		}
		newLinks = append(newLinks, l)
	}
	f.Links = newLinks
}

func (f *awsIPMgrFakes) ifaceARPEntries(index int) []*netlink.Neigh {
	var neighs []*netlink.Neigh
	for k, v := range f.Neighs {
		if k.Iface == index {
			neighs = append(neighs, v)
		}
	}
	return neighs
}

func newFakeLink() *fakeLink {
	return &fakeLink{}
}

type fakeLink struct {
	attrs netlink.LinkAttrs
	addrs []netlink.Addr
}

func (f *fakeLink) Attrs() *netlink.LinkAttrs {
	return &f.attrs
}

func (f *fakeLink) Type() string {
	return "device"
}

type fakeRouteTable struct {
	IfaceNames []string
	Timeout    time.Duration
	Protocol   netlink.RouteProtocol
	index      int
	Routes     map[string][]routetable.Target
	Errors     testutils.ErrorProducer
}

func (f *fakeRouteTable) OnIfaceStateChanged(s string, idx int, state ifacemonitor.State) {
}

func (f *fakeRouteTable) QueueResync() {
}

func (f *fakeRouteTable) Apply() error {
	return nil
}

func (f *fakeRouteTable) Index() int {
	return f.index
}

func (f *fakeRouteTable) SetRoutes(class routetable.RouteClass, ifaceName string, targets []routetable.Target) {
	if ifaceName != routetable.InterfaceNone {
		Expect(f.IfaceNames[0]).To(Equal(ifaceName))
	}
	f.Routes[ifaceName] = targets
}

func (f *fakeRouteTable) RouteUpdate(class routetable.RouteClass, _ string, _ routetable.Target) {
	panic("implement me")
}

func (f *fakeRouteTable) RouteRemove(class routetable.RouteClass, _ string, _ ip.CIDR) {
	panic("implement me")
}

func (f *fakeRouteTable) QueueResyncIface(_ string) {
	panic("implement me")
}

func (f *fakeRouteTable) ReadRoutesFromKernel(ifaceName string) ([]routetable.Target, error) {
	panic("implement me")
}

func (f *fakeRouteTable) SetRemoveExternalRoutes(_ bool) {
	panic("implement me")
}

type fakeRouteRules struct {
	Rules  []*routerule.Rule
	Errors testutils.ErrorProducer
}

func (f *fakeRouteRules) GetAllActiveRules() []*routerule.Rule {
	panic("implement me")
}

func (f *fakeRouteRules) InitFromKernel() {
	panic("implement me")
}

func (f *fakeRouteRules) SetRule(rule *routerule.Rule) {
	for _, r := range f.Rules {
		// Can't easily inspect the contents of routerule.Rule but comparison is good enough for now.
		if reflect.DeepEqual(r, rule) {
			return
		}
	}
	f.Rules = append(f.Rules, rule)
}

func (f *fakeRouteRules) RemoveRule(rule *routerule.Rule) {
	newRules := f.Rules[:0]
	found := false
	for _, r := range f.Rules {
		if reflect.DeepEqual(r, rule) {
			found = true
			continue
		}
		newRules = append(newRules, r)
	}
	Expect(found).To(BeTrue(), "asked to delete non-existent rule")
	f.Rules = newRules
}

func (f *fakeRouteRules) QueueResync() {

}

func (f *fakeRouteRules) Apply() error {
	return nil
}
