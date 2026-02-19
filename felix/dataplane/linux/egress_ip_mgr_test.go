// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.

package intdataplane

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"regexp"
	"time"

	"github.com/golang-collections/collections/stack"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/types"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routerule"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/rules"
	felixtypes "github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/felix/vxlanfdb"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var _ = Describe("EgressIPManager", func() {
	var manager *egressIPManager
	var dpConfig Config
	var rr *mockRouteRules
	var mainTable *mockRouteTable
	var fdb *mockVXLANFDB
	var rrFactory *mockRouteRulesFactory
	var rtFactory *mockRouteTableFactory
	var podStatusCallback *mockEgressPodStatusCallback
	var healthAgg *health.HealthAggregator
	var procSysWrites chan procSysWrite

	BeforeEach(func() {
		rrFactory = &mockRouteRulesFactory{routeRules: nil}

		mainTable = &mockRouteTable{
			index:         0,
			currentRoutes: map[string][]routetable.Target{},
		}
		fdb = &mockVXLANFDB{}
		rtFactory = &mockRouteTableFactory{count: 0, tables: make(map[int]*mockRouteTable)}

		// Ten free tables to use.
		tableIndexSet := set.New[int]()
		tableIndexStack := stack.New()
		for i := 10; i > 0; i-- {
			tableIndexStack.Push(i)
			tableIndexSet.Add(i)
		}

		var writeProcSys func(string, string) error
		procSysWrites, writeProcSys = createDummyWriteProcSys(100, 10*time.Second)
		matchEth0 := regexp.MustCompile("eth0")
		dpConfig = Config{
			RulesConfig: rules.Config{
				MarkEgress:        0x200,
				EgressIPVXLANVNI:  2,
				EgressIPVXLANPort: 4790,
			},
			EgressIPRoutingRulePriority: 100,
			FelixHostname:               "host0",
			Hostname:                    "host0",
			EgressIPHostIfacePattern:    []*regexp.Regexp{matchEth0},
		}

		podStatusCallback = &mockEgressPodStatusCallback{state: []statusCallbackEntry{}}
		healthAgg = health.NewHealthAggregator()
		healthReportC := make(chan<- EGWHealthReport)
		ipsets := newMockSets()
		bpfIPsets := newMockSets()
		la := netlink.NewLinkAttrs()
		la.Name = "eth0"
		manager = newEgressIPManagerWithShims(
			fdb,
			rrFactory,
			rtFactory,
			tableIndexSet,
			tableIndexStack,
			"egress.calico",
			dpConfig,
			&mockTunnelDataplane{
				links:          []netlink.Link{&mockLink{attrs: la}},
				tunnelLinkName: "egress.calico",
			},
			logutils.NewSummarizer("test loop"),
			func(ifName string) error { return nil },
			podStatusCallback.statusCallback,
			healthAgg,
			rand.NewSource(1), // Seed with 1 to get predictable tests every time.
			healthReportC,
			ipsets,
			bpfIPsets,
			&environment.FakeFeatureDetector{},
			writeProcSys,
		)

		Expect(healthAgg.Summary().Ready).To(BeFalse())

		err := manager.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(healthAgg.Summary().Ready).To(BeTrue())

		// IPSet should be created.
		ipsets.Verify(rules.IPSetIDAllEGWHealthPorts, nil)

		// No routeRules should be created.
		Expect(manager.routeRules).To(BeNil())

		manager.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "host0",
			Ipv4Addr: "172.0.0.2", // mockTunnelDataplane use interface address 172.0.0.2
		})
		manager.lock.Lock()
		nodeIP := manager.nodeIP
		manager.lock.Unlock()
		Expect(nodeIP).To(Equal(net.ParseIP("172.0.0.2")))
		err = manager.configureVXLANDevice(nodeIP, 50)
		Expect(err).NotTo(HaveOccurred())
		Expect(manager.vxlanDeviceLinkIndex).To(Equal(mockedTunnelIndex))
	})

	expectIPSetMembers := func(id string, members []gateway) {
		var matchers []types.GomegaMatcher
		for _, m := range members {
			matchers = append(matchers, ipSetMemberEquals(m))
		}
		Expect(manager.egwTracker.ipSetIDToGateways[id]).To(ContainElements(matchers))
	}

	expectNoRulesAndTable := func(srcIPs []string, table int) {
		var activeRules []netlink.Rule
		for _, r := range rr.GetAllActiveRules() {
			activeRules = append(activeRules, *r.NetLinkRule())
		}
		for _, srcIP := range srcIPs {
			Expect(rr.hasRule(100, srcIP, 0x200, table)).To(BeFalse(), "Expect rule with srcIP: %s, and table: %d, to not exist. Active rules = %v", srcIP, table, activeRules)
		}
		rtFactory.Table(table).checkRoutes(routetable.InterfaceNone, nil)
		rtFactory.Table(table).checkRoutes("egress.calico", nil)
	}

	expectRulesAndTable := func(srcIPs []string, table int, iface string, targets []routetable.Target) {
		var activeRules []netlink.Rule
		for _, r := range rr.GetAllActiveRules() {
			activeRules = append(activeRules, *r.NetLinkRule())
		}
		for _, srcIP := range srcIPs {
			Expect(rr.hasRule(100, srcIP, 0x200, table)).To(BeTrue(), "Expect rule with srcIP: %s, and table: %d, to exist. Active rules = %v", srcIP, table, activeRules)
		}

		rtFactory.Table(table).checkRoutes(iface, targets)
	}

	multiPath := func(ips []string) []routetable.NextHop {
		var multipath []routetable.NextHop
		for _, e := range ips {
			multipath = append(multipath, routetable.NextHop{
				Gw:        ip.FromString(e),
				IfaceName: manager.vxlanDevice,
			})
		}
		return multipath
	}

	Describe("with multiple ipsets and endpoints update", func() {
		var ips0, ips1 []string
		var zeroTime, nowTime, thirtySecsAgo, inThirtySecsTime, inSixtySecsTime time.Time
		var egwRules0, egwRules1 []*proto.EgressGatewayRule
		BeforeEach(func() {
			zeroTime = time.Time{}
			nowTime = time.Now()
			thirtySecsAgo = nowTime.Add(time.Second * -30)
			inThirtySecsTime = nowTime.Add(time.Second * 30)
			inSixtySecsTime = nowTime.Add(time.Second * 60)

			ips0 = []string{
				formatActiveEgressMemberStr("10.0.0.1", "host0"),
				formatActiveEgressMemberStr("10.0.0.2", "host1"),
				formatActiveEgressMemberStr("10.0.0.3", "host2"),
			}
			ips1 = []string{
				formatActiveEgressMemberPortStr("10.0.1.1", 8080, "host0"),
				formatActiveEgressMemberPortStr("10.0.1.2", 8080, "host1"),
				formatActiveEgressMemberPortStr("10.0.1.3", 8082, "host2"),
			}

			manager.OnUpdate(&ifaceStateUpdate{"eth0", ifacemonitor.StateUp, 2})

			manager.OnUpdate(&proto.IPSetUpdate{
				Id:      "set0",
				Members: ips0,
				Type:    proto.IPSetUpdate_EGRESS_IP,
			})
			manager.OnUpdate(&proto.IPSetUpdate{
				Id:      "set1",
				Members: ips1,
				Type:    proto.IPSetUpdate_EGRESS_IP,
			})
			manager.OnUpdate(&proto.IPSetUpdate{
				Id:      "nonEgressIPSet",
				Members: []string{"10.0.100.1", "10.0.100.2"},
				Type:    proto.IPSetUpdate_IP,
			})

			expectIPSetMembers("set0", []gateway{
				{
					addr:                ip.FromString("10.0.0.1"),
					maintenanceStarted:  zeroTime,
					maintenanceFinished: zeroTime,
					hostname:            "host0",
				},
				{
					addr:                ip.FromString("10.0.0.2"),
					maintenanceStarted:  zeroTime,
					maintenanceFinished: zeroTime,
					hostname:            "host1",
				},
				{
					addr:                ip.FromString("10.0.0.3"),
					maintenanceStarted:  zeroTime,
					maintenanceFinished: zeroTime,
					hostname:            "host2",
				},
			})
			expectIPSetMembers("set1", []gateway{
				{
					addr:                ip.FromString("10.0.1.1"),
					maintenanceStarted:  zeroTime,
					maintenanceFinished: zeroTime,
					healthPort:          8080,
					hostname:            "host0",
				},
				{
					addr:                ip.FromString("10.0.1.2"),
					maintenanceStarted:  zeroTime,
					maintenanceFinished: zeroTime,
					healthPort:          8080,
					hostname:            "host1",
				},
				{
					addr:                ip.FromString("10.0.1.3"),
					maintenanceStarted:  zeroTime,
					maintenanceFinished: zeroTime,
					healthPort:          8082,
					hostname:            "host2",
				},
			})
			Expect(manager.egwTracker.ipSetIDToGateways["nonEgressSet"]).To(BeNil())

			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())

			egwRules0 = egwPolicyWithSingleRule("set0", 0)
			egwRules1 = []*proto.EgressGatewayRule{
				{
					Destination: "10.0.0.0/16",
				},
				{
					IpSetId:     "set1",
					Destination: defaultDestv4,
					MaxNextHops: 2,
				},
			}

			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(0, []string{"10.0.240.0/32"}, egwRules0))
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(1, []string{"10.0.241.0/32"}, egwRules0))
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(2, []string{"10.0.242.0/32"}, egwRules0))
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(3, []string{"10.0.243.0/32"}, egwRules1))
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(4, []string{"10.0.244.0/32"}, egwRules1))
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(5, []string{"10.0.245.0/32"}, egwRules1))

			err = manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())

			// routeRules should be created.
			Expect(manager.routeRules).NotTo(BeNil())
			rr = rrFactory.Rules()

			expectRulesAndTable([]string{"10.0.240.0/32"}, 1, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}),
				},
			})

			expectRulesAndTable([]string{"10.0.241.0/32"}, 2, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}),
				},
			})

			expectRulesAndTable([]string{"10.0.242.0/32"}, 3, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}),
				},
			})

			expectRulesAndTable([]string{"10.0.243.0/32"}, 4, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.1.2", "10.0.1.3"}),
				},
				{
					CIDR: ip.MustParseCIDROrIP("10.0.0.0/16"),
					Type: routetable.TargetTypeThrow,
				},
			})

			expectRulesAndTable([]string{"10.0.244.0/32"}, 5, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.1.1", "10.0.1.3"}),
				},
				{
					CIDR: ip.MustParseCIDROrIP("10.0.0.0/16"),
					Type: routetable.TargetTypeThrow,
				},
			})

			expectRulesAndTable([]string{"10.0.245.0/32"}, 6, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.1.1", "10.0.1.2"}),
				},
				{
					CIDR: ip.MustParseCIDROrIP("10.0.0.0/16"),
					Type: routetable.TargetTypeThrow,
				},
			})

			mainTable.checkRoutes(routetable.InterfaceNone, nil)
			mainTable.checkRoutes("egress.calico", nil)

			Expect(fdb.currentVTEPs).To(ConsistOf(
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x01},
					TunnelIP:  ip.FromString("10.0.0.1"),
					HostIP:    ip.FromString("10.0.0.1"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x02},
					TunnelIP:  ip.FromString("10.0.0.2"),
					HostIP:    ip.FromString("10.0.0.2"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x03},
					TunnelIP:  ip.FromString("10.0.0.3"),
					HostIP:    ip.FromString("10.0.0.3"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x01, 0x01},
					TunnelIP:  ip.FromString("10.0.1.1"),
					HostIP:    ip.FromString("10.0.1.1"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x01, 0x02},
					TunnelIP:  ip.FromString("10.0.1.2"),
					HostIP:    ip.FromString("10.0.1.2"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x01, 0x03},
					TunnelIP:  ip.FromString("10.0.1.3"),
					HostIP:    ip.FromString("10.0.1.3"),
				},
			))
		})

		It("should attempt to write procSys for dummy link", func() {
			expectedWrite := procSysWrite{
				path:  "/proc/sys/net/ipv4/conf/eth0/src_valid_mark",
				value: "1",
			}
			Eventually(procSysWrites).Should(Receive(Equal(expectedWrite)))
		})
		It("should not double-write procSys link is updated with same state", func() {
			expectedWrite := procSysWrite{
				path:  "/proc/sys/net/ipv4/conf/eth0/src_valid_mark",
				value: "1",
			}
			Eventually(procSysWrites).Should(Receive(Equal(expectedWrite)))

			manager.OnUpdate(&ifaceStateUpdate{"eth0", ifacemonitor.StateUp, 2})
			Consistently(procSysWrites).ShouldNot(Receive())
		})

		It("should update route rules when workload address changes", func() {
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(0, []string{"10.0.140.0/32"}, egwRules0))
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(1, []string{"10.0.141.0/32"}, egwRules0))
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(2, []string{"10.0.142.0/32"}, egwRules0))
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(3, []string{"10.0.143.0/32"}, egwRules1))
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(4, []string{"10.0.144.0/32"}, egwRules1))
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(5, []string{"10.0.145.0/32"}, egwRules1))

			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())

			// routeRules should be created.
			Expect(manager.routeRules).NotTo(BeNil())
			rr = rrFactory.Rules()

			expectRulesAndTable([]string{"10.0.140.0/32"}, 1, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}),
				},
			})

			expectRulesAndTable([]string{"10.0.141.0/32"}, 2, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}),
				},
			})

			expectRulesAndTable([]string{"10.0.142.0/32"}, 3, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}),
				},
			})

			expectRulesAndTable([]string{"10.0.143.0/32"}, 4, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.1.2", "10.0.1.3"}),
				},
				{
					CIDR: ip.MustParseCIDROrIP("10.0.0.0/16"),
					Type: routetable.TargetTypeThrow,
				},
			})

			expectRulesAndTable([]string{"10.0.144.0/32"}, 5, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.1.1", "10.0.1.3"}),
				},
				{
					CIDR: ip.MustParseCIDROrIP("10.0.0.0/16"),
					Type: routetable.TargetTypeThrow,
				},
			})

			expectRulesAndTable([]string{"10.0.145.0/32"}, 6, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.1.1", "10.0.1.2"}),
				},
				{
					CIDR: ip.MustParseCIDROrIP("10.0.0.0/16"),
					Type: routetable.TargetTypeThrow,
				},
			})

			mainTable.checkRoutes(routetable.InterfaceNone, nil)
			mainTable.checkRoutes("egress.calico", nil)
		})

		It("should have the right routes when PreferLocalEgressGateway is set", func() {
			egwRules := []*proto.EgressGatewayRule{
				&proto.EgressGatewayRule{
					IpSetId:                  "set0",
					Destination:              "10.0.0.0/8",
					PreferLocalEgressGateway: true,
				},
				&proto.EgressGatewayRule{
					IpSetId:     "set1",
					Destination: defaultDestv4,
				},
			}
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(6, []string{"10.0.246.0/32", "10.1.246.0/32"}, egwRules))
			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			expectRulesAndTable([]string{"10.0.246.0/32", "10.1.246.0/32"}, 7, "egress.calico", []routetable.Target{
				{
					CIDR: ip.MustParseCIDROrIP("10.0.0.0/8"),
					Type: routetable.TargetTypeVXLAN,
					GW:   ip.MustParseCIDROrIP("10.0.0.1").Addr(),
				},
			})
			expectRulesAndTable([]string{"10.0.246.0/32", "10.1.246.0/32"}, 7, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.1.1", "10.0.1.2", "10.0.1.3"}),
				},
			})

			// Set the preferLocalEgressGateway to false
			egwRulesUpdated := []*proto.EgressGatewayRule{
				&proto.EgressGatewayRule{
					IpSetId:     "set0",
					Destination: "10.0.0.0/8",
				},
				&proto.EgressGatewayRule{
					IpSetId:     "set1",
					Destination: defaultDestv4,
				},
			}

			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(6, []string{"10.0.246.0/32", "10.1.246.0/32"}, egwRulesUpdated))
			err = manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			expectRulesAndTable([]string{"10.0.246.0/32", "10.1.246.0/32"}, 7, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      ip.MustParseCIDROrIP("10.0.0.0/8"),
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}),
				},
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.1.1", "10.0.1.2", "10.0.1.3"}),
				},
			})

			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(6, []string{"10.0.246.0/32", "10.1.246.0/32"}, egwRules))
			err = manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			expectRulesAndTable([]string{"10.0.246.0/32", "10.1.246.0/32"}, 7, "egress.calico", []routetable.Target{
				{
					CIDR: ip.MustParseCIDROrIP("10.0.0.0/8"),
					Type: routetable.TargetTypeVXLAN,
					GW:   ip.MustParseCIDROrIP("10.0.0.1").Addr(),
				},
			})
			expectRulesAndTable([]string{"10.0.246.0/32", "10.1.246.0/32"}, 7, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.1.1", "10.0.1.2", "10.0.1.3"}),
				},
			})

			// Add another local EGW
			manager.OnUpdate(&proto.IPSetDeltaUpdate{
				Id: "set0",
				AddedMembers: []string{
					formatActiveEgressMemberStr("10.0.0.7", "host0"),
				},
				RemovedMembers: []string{},
			})

			err = manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			expectRulesAndTable([]string{"10.0.246.0/32", "10.1.246.0/32"}, 7, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      ip.MustParseCIDROrIP("10.0.0.0/8"),
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.1", "10.0.0.7"}),
				},
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.1.1", "10.0.1.2", "10.0.1.3"}),
				},
			})

			// Set MaxNextHop to 1
			// Remove both the local EGW
			manager.OnUpdate(&proto.IPSetDeltaUpdate{
				Id:           "set0",
				AddedMembers: []string{},
				RemovedMembers: []string{
					formatActiveEgressMemberStr("10.0.0.7", "host0"),
					formatActiveEgressMemberStr("10.0.0.1", "host0"),
				},
			})
			err = manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			expectRulesAndTable([]string{"10.0.246.0/32", "10.1.246.0/32"}, 7, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      ip.MustParseCIDROrIP("10.0.0.0/8"),
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.2", "10.0.0.3"}),
				},
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.1.1", "10.0.1.2", "10.0.1.3"}),
				},
			})

		})

		It("should be possible to use two egress gateway for different destinations", func() {

			egwRules := []*proto.EgressGatewayRule{
				&proto.EgressGatewayRule{
					IpSetId:     "set0",
					Destination: "10.0.0.0/8",
				},
				&proto.EgressGatewayRule{
					IpSetId:     "set1",
					Destination: defaultDestv4,
				},
			}

			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(6, []string{"10.0.246.0/32", "10.1.246.0/32"}, egwRules))
			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())

			expectRulesAndTable([]string{"10.0.246.0/32", "10.1.246.0/32"}, 7, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      ip.MustParseCIDROrIP("10.0.0.0/8"),
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}),
				},
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.1.1", "10.0.1.2", "10.0.1.3"}),
				},
			})

			Expect(fdb.currentVTEPs).To(ConsistOf(
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x01},
					TunnelIP:  ip.FromString("10.0.0.1"),
					HostIP:    ip.FromString("10.0.0.1"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x02},
					TunnelIP:  ip.FromString("10.0.0.2"),
					HostIP:    ip.FromString("10.0.0.2"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x03},
					TunnelIP:  ip.FromString("10.0.0.3"),
					HostIP:    ip.FromString("10.0.0.3"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x01, 0x01},
					TunnelIP:  ip.FromString("10.0.1.1"),
					HostIP:    ip.FromString("10.0.1.1"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x01, 0x02},
					TunnelIP:  ip.FromString("10.0.1.2"),
					HostIP:    ip.FromString("10.0.1.2"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x01, 0x03},
					TunnelIP:  ip.FromString("10.0.1.3"),
					HostIP:    ip.FromString("10.0.1.3"),
				},
			))
		})

		It("should be possible to skip egress gateway for a destination", func() {

			egwRules := []*proto.EgressGatewayRule{
				&proto.EgressGatewayRule{
					Destination: "11.0.0.0/8",
				},
				&proto.EgressGatewayRule{
					IpSetId: "set1",
				},
			}

			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(6, []string{"10.0.246.0/32", "10.1.246.0/32"}, egwRules))
			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())

			expectRulesAndTable([]string{"10.0.246.0/32", "10.1.246.0/32"}, 7, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR: ip.MustParseCIDROrIP("11.0.0.0/8"),
					Type: routetable.TargetTypeThrow,
				},
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.1.1", "10.0.1.2", "10.0.1.3"}),
				},
			})

			Expect(fdb.currentVTEPs).To(ConsistOf(
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x01},
					TunnelIP:  ip.FromString("10.0.0.1"),
					HostIP:    ip.FromString("10.0.0.1"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x02},
					TunnelIP:  ip.FromString("10.0.0.2"),
					HostIP:    ip.FromString("10.0.0.2"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x03},
					TunnelIP:  ip.FromString("10.0.0.3"),
					HostIP:    ip.FromString("10.0.0.3"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x01, 0x01},
					TunnelIP:  ip.FromString("10.0.1.1"),
					HostIP:    ip.FromString("10.0.1.1"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x01, 0x02},
					TunnelIP:  ip.FromString("10.0.1.2"),
					HostIP:    ip.FromString("10.0.1.2"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x01, 0x03},
					TunnelIP:  ip.FromString("10.0.1.3"),
					HostIP:    ip.FromString("10.0.1.3"),
				},
			))
		})

		It("should support delta update", func() {
			manager.OnUpdate(&proto.IPSetDeltaUpdate{
				Id:             "set1",
				AddedMembers:   []string{formatActiveEgressMemberStr("10.0.1.4", "host0"), formatActiveEgressMemberStr("10.0.1.5", "host1")},
				RemovedMembers: []string{formatActiveEgressMemberStr("10.0.1.1", "host0")},
			})

			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())

			// Changes to an IPSet should have no impact on existing workload tables, only on new workloads.
			expectRulesAndTable([]string{"10.0.243.0/32"}, 4, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.1.2", "10.0.1.3"}),
				},
				{
					CIDR: ip.MustParseCIDROrIP("10.0.0.0/16"),
					Type: routetable.TargetTypeThrow,
				},
			})
			expectRulesAndTable([]string{"10.0.244.0/32"}, 5, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.1.4", "10.0.1.5"}),
				},
				{
					CIDR: ip.MustParseCIDROrIP("10.0.0.0/16"),
					Type: routetable.TargetTypeThrow,
				},
			})
			expectRulesAndTable([]string{"10.0.245.0/32"}, 6, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.1.3", "10.0.1.4"}),
				},
				{
					CIDR: ip.MustParseCIDROrIP("10.0.0.0/16"),
					Type: routetable.TargetTypeThrow,
				},
			})

			Expect(fdb.currentVTEPs).To(ConsistOf(
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x01},
					TunnelIP:  ip.FromString("10.0.0.1"),
					HostIP:    ip.FromString("10.0.0.1"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x02},
					TunnelIP:  ip.FromString("10.0.0.2"),
					HostIP:    ip.FromString("10.0.0.2"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x03},
					TunnelIP:  ip.FromString("10.0.0.3"),
					HostIP:    ip.FromString("10.0.0.3"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x01, 0x02},
					TunnelIP:  ip.FromString("10.0.1.2"),
					HostIP:    ip.FromString("10.0.1.2"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x01, 0x03},
					TunnelIP:  ip.FromString("10.0.1.3"),
					HostIP:    ip.FromString("10.0.1.3"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x01, 0x04},
					TunnelIP:  ip.FromString("10.0.1.4"),
					HostIP:    ip.FromString("10.0.1.4"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x01, 0x05},
					TunnelIP:  ip.FromString("10.0.1.5"),
					HostIP:    ip.FromString("10.0.1.5"),
				},
			))
		})

		It("should release table correctly", func() {
			manager.OnUpdate(&proto.WorkloadEndpointRemove{
				Id: &proto.WorkloadEndpointID{
					OrchestratorId: "k8s",
					WorkloadId:     "default/pod-1",
					EndpointId:     "endpoint-id-1",
				},
			})

			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())

			Expect(manager.tableIndexStack.Peek()).To(Equal(2))
			Expect(manager.tableIndexStack.Len()).To(Equal(5))
			expectNoRulesAndTable([]string{"10.0.241.0/32"}, 2)

			Expect(fdb.currentVTEPs).To(ConsistOf(
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x01},
					TunnelIP:  ip.FromString("10.0.0.1"),
					HostIP:    ip.FromString("10.0.0.1"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x02},
					TunnelIP:  ip.FromString("10.0.0.2"),
					HostIP:    ip.FromString("10.0.0.2"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x03},
					TunnelIP:  ip.FromString("10.0.0.3"),
					HostIP:    ip.FromString("10.0.0.3"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x01, 0x01},
					TunnelIP:  ip.FromString("10.0.1.1"),
					HostIP:    ip.FromString("10.0.1.1"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x01, 0x02},
					TunnelIP:  ip.FromString("10.0.1.2"),
					HostIP:    ip.FromString("10.0.1.2"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x01, 0x03},
					TunnelIP:  ip.FromString("10.0.1.3"),
					HostIP:    ip.FromString("10.0.1.3"),
				},
			))

			// Send same workload endpoint remove
			manager.OnUpdate(&proto.WorkloadEndpointRemove{
				Id: &proto.WorkloadEndpointID{
					OrchestratorId: "k8s",
					WorkloadId:     "default/pod-1",
					EndpointId:     "endpoint-id-1",
				},
			})

			err = manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())

			Expect(manager.tableIndexStack.Peek()).To(Equal(2))
			Expect(manager.tableIndexStack.Len()).To(Equal(5))
			rtFactory.Table(2).checkRoutes("egress.calico", nil)
		})

		It("should report unhealthy if run out of table index", func() {
			for i := 2; i < 10; i++ {
				manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(i, []string{fmt.Sprintf("10.0.24%d.0/32", i)}, egwPolicyWithSingleRule("set0", 0)))
			}

			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			Expect(manager.tableIndexStack.Len()).To(Equal(0))

			breakingWorkloadUpdate := dummyWorkloadEndpointUpdateEgressIP(11, []string{"10.0.250.0/32"}, egwPolicyWithSingleRule("set0", 0))
			manager.OnUpdate(breakingWorkloadUpdate)

			err = manager.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred()) // the manager will not report an error to the dataplane but should report unhealthy
			Expect(healthAgg.Summary().Ready).To(BeFalse())
			key := felixtypes.ProtoToWorkloadEndpointID(breakingWorkloadUpdate.Id)
			Expect(manager.pendingWorkloadUpdates).To(HaveKey(key))

			// resolve the issue
			resolvingUpdate := proto.WorkloadEndpointRemove{
				Id: &proto.WorkloadEndpointID{
					OrchestratorId: "k8s",
					WorkloadId:     "default/pod-9",
					EndpointId:     "endpoint-id-9",
				},
			}
			manager.OnUpdate(&resolvingUpdate)
			err = manager.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())
			Expect(healthAgg.Summary().Ready).To(BeTrue())
			key = felixtypes.ProtoToWorkloadEndpointID(breakingWorkloadUpdate.Id)
			Expect(manager.egwTracker.dirtyEgressIPSet).NotTo(ContainElement(key))
		})

		It("should use same table if endpoint has second ip address", func() {

			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(6, []string{"10.0.246.0/32", "10.1.246.0/32"}, egwPolicyWithSingleRule("set0", 0)))
			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())

			expectRulesAndTable([]string{"10.0.246.0/32", "10.1.246.0/32"}, 7, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}),
				},
			})

			Expect(fdb.currentVTEPs).To(ConsistOf(
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x01},
					TunnelIP:  ip.FromString("10.0.0.1"),
					HostIP:    ip.FromString("10.0.0.1"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x02},
					TunnelIP:  ip.FromString("10.0.0.2"),
					HostIP:    ip.FromString("10.0.0.2"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x03},
					TunnelIP:  ip.FromString("10.0.0.3"),
					HostIP:    ip.FromString("10.0.0.3"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x01, 0x01},
					TunnelIP:  ip.FromString("10.0.1.1"),
					HostIP:    ip.FromString("10.0.1.1"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x01, 0x02},
					TunnelIP:  ip.FromString("10.0.1.2"),
					HostIP:    ip.FromString("10.0.1.2"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x01, 0x03},
					TunnelIP:  ip.FromString("10.0.1.3"),
					HostIP:    ip.FromString("10.0.1.3"),
				},
			))
		})

		It("should set unreachable route if egress ipset has all members removed", func() {
			manager.OnUpdate(&proto.IPSetDeltaUpdate{
				Id:           "set1",
				AddedMembers: []string{},
				RemovedMembers: []string{
					formatActiveEgressMemberStr("10.0.1.1", "host0"),
					formatActiveEgressMemberStr("10.0.1.2", "host1"),
					formatActiveEgressMemberStr("10.0.1.3", "host2"),
				},
			})

			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(2, []string{"10.0.242.0/32"}, egwPolicyWithSingleRule("Set1", 0)))

			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			expectRulesAndTable([]string{"10.0.242.0/32"}, 3, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR: defaultCidr,
					Type: routetable.TargetTypeUnreachable,
				},
			})

			Expect(fdb.currentVTEPs).To(ConsistOf(
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x01},
					TunnelIP:  ip.FromString("10.0.0.1"),
					HostIP:    ip.FromString("10.0.0.1"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x02},
					TunnelIP:  ip.FromString("10.0.0.2"),
					HostIP:    ip.FromString("10.0.0.2"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x03},
					TunnelIP:  ip.FromString("10.0.0.3"),
					HostIP:    ip.FromString("10.0.0.3"),
				},
			))
		})

		It("should remove routes and tables for old workload", func() {
			manager.OnUpdate(&proto.WorkloadEndpointUpdate{
				Id: &proto.WorkloadEndpointID{
					OrchestratorId: "k8s",
					WorkloadId:     "default/pod-0",
					EndpointId:     "endpoint-id-0",
				},
				Endpoint: nil,
			})
			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())

			expectNoRulesAndTable([]string{"10.0.240.0/32"}, 1)
		})

		It("should set recreate rule and table for workload if egress ipset changed", func() {
			// pod-0 use table 1 at start.
			expectRulesAndTable([]string{"10.0.240.0/32"}, 1, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}),
				},
			})
			Expect(rr.hasRule(100, "10.0.240.0/32", 0x200, 1)).To(BeTrue())
			Expect(rr.hasRule(100, "10.0.240.0/32", 0x200, 2)).To(BeFalse())

			// Update pod-0 to use ipset set1.
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(0, []string{"10.0.240.0/32"}, egwPolicyWithSingleRule("set1", 0)))

			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())

			// pod-0 use table 2 as the result.
			expectRulesAndTable([]string{"10.0.240.0/32"}, 1, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.1.1", "10.0.1.2", "10.0.1.3"}),
				},
			})
		})

		It("should wait for ipset update", func() {
			id0 := proto.WorkloadEndpointID{
				OrchestratorId: "k8s",
				WorkloadId:     "default/pod-0",
				EndpointId:     "endpoint-id-0",
			}

			endpoint0 := &proto.WorkloadEndpoint{
				State:      "active",
				Mac:        "01:02:03:04:05:06",
				Name:       "cali12345-0",
				ProfileIds: []string{},
				Tiers:      []*proto.TierInfo{},
				Ipv4Nets:   []string{"10.0.240.0/32"},
				Ipv6Nets:   []string{"2001:db8:2::2/128"},
				EgressGatewayRules: []*proto.EgressGatewayRule{
					&proto.EgressGatewayRule{
						IpSetId: "setx",
					},
				},
			}
			// Update pod-0 to use ipset setx.
			manager.OnUpdate(&proto.WorkloadEndpointUpdate{
				Id:       &id0,
				Endpoint: endpoint0,
			})

			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			expectRulesAndTable([]string{"10.0.240.0/32"}, 1, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR: defaultCidr,
					Type: routetable.TargetTypeUnreachable,
				},
			})

			manager.OnUpdate(&proto.IPSetUpdate{
				Id: "setx",
				Members: []string{
					formatActiveEgressMemberStr("10.0.10.1", "host0"),
					formatActiveEgressMemberStr("10.0.10.2", "host1"),
					formatActiveEgressMemberStr("10.0.10.3", "host2"),
				},
				Type: proto.IPSetUpdate_EGRESS_IP,
			})
			err = manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())

			// pod-0 use table 1 as the result.
			expectRulesAndTable([]string{"10.0.240.0/32"}, 1, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.10.1", "10.0.10.2", "10.0.10.3"}),
				},
			})

			Expect(fdb.currentVTEPs).To(ConsistOf(
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x01},
					TunnelIP:  ip.FromString("10.0.0.1"),
					HostIP:    ip.FromString("10.0.0.1"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x02},
					TunnelIP:  ip.FromString("10.0.0.2"),
					HostIP:    ip.FromString("10.0.0.2"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x03},
					TunnelIP:  ip.FromString("10.0.0.3"),
					HostIP:    ip.FromString("10.0.0.3"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x01, 0x01},
					TunnelIP:  ip.FromString("10.0.1.1"),
					HostIP:    ip.FromString("10.0.1.1"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x01, 0x02},
					TunnelIP:  ip.FromString("10.0.1.2"),
					HostIP:    ip.FromString("10.0.1.2"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x01, 0x03},
					TunnelIP:  ip.FromString("10.0.1.3"),
					HostIP:    ip.FromString("10.0.1.3"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x0a, 0x01},
					TunnelIP:  ip.FromString("10.0.10.1"),
					HostIP:    ip.FromString("10.0.10.1"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x0a, 0x02},
					TunnelIP:  ip.FromString("10.0.10.2"),
					HostIP:    ip.FromString("10.0.10.2"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x0a, 0x03},
					TunnelIP:  ip.FromString("10.0.10.3"),
					HostIP:    ip.FromString("10.0.10.3"),
				},
			))
		})

		It("should leave terminating egw pod in existing tables, but not use it for new tables", func() {
			manager.OnUpdate(&proto.IPSetDeltaUpdate{
				Id:             "set0",
				AddedMembers:   []string{formatTerminatingEgressMemberStr("10.0.0.1", nowTime, inSixtySecsTime, "host0")},
				RemovedMembers: []string{formatActiveEgressMemberStr("10.0.0.1", "host0")},
			})

			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			expectRulesAndTable([]string{"10.0.240.0/32"}, 1, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}),
				},
			})
			expectRulesAndTable([]string{"10.0.241.0/32"}, 2, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}),
				},
			})
			expectRulesAndTable([]string{"10.0.242.0/32"}, 3, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}),
				},
			})

			Expect(fdb.currentVTEPs).To(ConsistOf(
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x01},
					TunnelIP:  ip.FromString("10.0.0.1"),
					HostIP:    ip.FromString("10.0.0.1"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x02},
					TunnelIP:  ip.FromString("10.0.0.2"),
					HostIP:    ip.FromString("10.0.0.2"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x03},
					TunnelIP:  ip.FromString("10.0.0.3"),
					HostIP:    ip.FromString("10.0.0.3"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x01, 0x01},
					TunnelIP:  ip.FromString("10.0.1.1"),
					HostIP:    ip.FromString("10.0.1.1"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x01, 0x02},
					TunnelIP:  ip.FromString("10.0.1.2"),
					HostIP:    ip.FromString("10.0.1.2"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x01, 0x03},
					TunnelIP:  ip.FromString("10.0.1.3"),
					HostIP:    ip.FromString("10.0.1.3"),
				},
			))
			podStatusCallback.checkState([]statusCallbackEntry{
				{
					namespace: "default",

					name:                "host0-k8s-pod--0-endpoint--id--0",
					ip:                  "10.0.0.1",
					maintenanceStarted:  nowTime,
					maintenanceFinished: inSixtySecsTime,
				},
				{
					namespace:           "default",
					name:                "host0-k8s-pod--1-endpoint--id--1",
					ip:                  "10.0.0.1",
					maintenanceStarted:  nowTime,
					maintenanceFinished: inSixtySecsTime,
				},
				{
					namespace:           "default",
					name:                "host0-k8s-pod--2-endpoint--id--2",
					ip:                  "10.0.0.1",
					maintenanceStarted:  nowTime,
					maintenanceFinished: inSixtySecsTime,
				},
			})

			// Create new endpoint6. It has specified 3 next hops, but only 2 are currently available.
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(6, []string{"10.0.246.0/32"}, egwPolicyWithSingleRule("set0", 3)))
			// Create new endpoint7. It has specified 0 next hops, and so will be allocated all available hops.
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(7, []string{"10.0.247.0/32"}, egwPolicyWithSingleRule("set0", 0)))

			err = manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			expectRulesAndTable([]string{"10.0.246.0/32"}, 7, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.2", "10.0.0.3"}),
				},
			})
			expectRulesAndTable([]string{"10.0.247.0/32"}, 8, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.2", "10.0.0.3"}),
				},
			})

			manager.OnUpdate(&proto.IPSetDeltaUpdate{
				Id:             "set0",
				AddedMembers:   []string{formatTerminatingEgressMemberStr("10.0.0.4", zeroTime, zeroTime, "host0")},
				RemovedMembers: []string{formatActiveEgressMemberStr("10.0.0.1", "host0")},
			})

			// Create new endpoint8. It has specified 3 next hops, which are currently available.
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(8, []string{"10.0.248.0/32"}, egwPolicyWithSingleRule("set0", 3)))
			// Create new endpoint9. It has specified 0 next hops, and so will be allocated all available hops.
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(9, []string{"10.0.249.0/32"}, egwPolicyWithSingleRule("set0", 0)))

			err = manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			expectRulesAndTable([]string{"10.0.248.0/32"}, 9, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.2", "10.0.0.3", "10.0.0.4"}),
				},
			})
			expectRulesAndTable([]string{"10.0.249.0/32"}, 10, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.2", "10.0.0.3", "10.0.0.4"}),
				},
			})
		})

		It("should not notify when maintenance window is unchanged", func() {
			manager.OnUpdate(&proto.IPSetDeltaUpdate{
				Id:             "set0",
				AddedMembers:   []string{formatTerminatingEgressMemberStr("10.0.0.1", nowTime, inSixtySecsTime, "host0")},
				RemovedMembers: []string{formatActiveEgressMemberStr("10.0.0.1", "host0")},
			})

			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			podStatusCallback.checkState([]statusCallbackEntry{
				{
					namespace:           "default",
					name:                "host0-k8s-pod--0-endpoint--id--0",
					ip:                  "10.0.0.1",
					maintenanceStarted:  nowTime,
					maintenanceFinished: inSixtySecsTime,
				},
				{
					namespace:           "default",
					name:                "host0-k8s-pod--1-endpoint--id--1",
					ip:                  "10.0.0.1",
					maintenanceStarted:  nowTime,
					maintenanceFinished: inSixtySecsTime,
				},
				{
					namespace:           "default",
					name:                "host0-k8s-pod--2-endpoint--id--2",
					ip:                  "10.0.0.1",
					maintenanceStarted:  nowTime,
					maintenanceFinished: inSixtySecsTime,
				},
			})

			podStatusCallback.clearState()
			err = manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			podStatusCallback.checkState([]statusCallbackEntry{})
		})

		It("should correctly calculate maintenance window for multiple terminating gateway pods", func() {
			manager.OnUpdate(&proto.IPSetDeltaUpdate{
				Id: "set0",
				AddedMembers: []string{
					formatTerminatingEgressMemberStr("10.0.0.1", thirtySecsAgo, inThirtySecsTime, "host0"),
					formatTerminatingEgressMemberStr("10.0.0.2", nowTime, inSixtySecsTime, "host1"),
				},
				RemovedMembers: []string{
					formatActiveEgressMemberStr("10.0.0.1", "host0"),
					formatActiveEgressMemberStr("10.0.0.2", "host1"),
				},
			})

			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			podStatusCallback.checkState([]statusCallbackEntry{
				{
					namespace:           "default",
					name:                "host0-k8s-pod--0-endpoint--id--0",
					ip:                  "10.0.0.2",
					maintenanceStarted:  nowTime,
					maintenanceFinished: inSixtySecsTime,
				},
				{
					namespace:           "default",
					name:                "host0-k8s-pod--1-endpoint--id--1",
					ip:                  "10.0.0.2",
					maintenanceStarted:  nowTime,
					maintenanceFinished: inSixtySecsTime,
				},
				{
					namespace:           "default",
					name:                "host0-k8s-pod--2-endpoint--id--2",
					ip:                  "10.0.0.2",
					maintenanceStarted:  nowTime,
					maintenanceFinished: inSixtySecsTime,
				},
			})

			podStatusCallback.clearState()
			err = manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			podStatusCallback.checkState([]statusCallbackEntry{})
		})

		It("should correctly calculate maintenance window for multiple active and terminating egw pods", func() {
			// egw 10.0.1.1 is terminating
			manager.OnUpdate(&proto.IPSetDeltaUpdate{
				Id:             "set1",
				AddedMembers:   []string{formatTerminatingEgressMemberStr("10.0.1.1", nowTime, inSixtySecsTime, "host1")},
				RemovedMembers: []string{formatActiveEgressMemberStr("10.0.1.1", "host1")},
			})
			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			podStatusCallback.checkState([]statusCallbackEntry{
				{
					namespace:           "default",
					name:                "host0-k8s-pod--4-endpoint--id--4",
					ip:                  "10.0.1.1",
					maintenanceStarted:  nowTime,
					maintenanceFinished: inSixtySecsTime,
				},
				{
					namespace:           "default",
					name:                "host0-k8s-pod--5-endpoint--id--5",
					ip:                  "10.0.1.1",
					maintenanceStarted:  nowTime,
					maintenanceFinished: inSixtySecsTime,
				},
			})

			// egw 10.0.1.4 is created to replace egw 10.0.1.1
			manager.OnUpdate(&proto.IPSetDeltaUpdate{
				Id: "set1",
				AddedMembers: []string{
					formatActiveEgressMemberStr("10.0.1.4", "host0"),
				},
			})
			err = manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())

			// egw 10.0.1.2 is terminating
			manager.OnUpdate(&proto.IPSetDeltaUpdate{
				Id:             "set1",
				AddedMembers:   []string{formatTerminatingEgressMemberStr("10.0.1.2", thirtySecsAgo, inThirtySecsTime, "host1")},
				RemovedMembers: []string{formatActiveEgressMemberStr("10.0.1.2", "host1")},
			})
			err = manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			podStatusCallback.checkState([]statusCallbackEntry{
				{
					namespace:           "default",
					name:                "host0-k8s-pod--3-endpoint--id--3",
					ip:                  "10.0.1.2",
					maintenanceStarted:  thirtySecsAgo,
					maintenanceFinished: inThirtySecsTime,
				},
				{
					namespace:           "default",
					name:                "host0-k8s-pod--4-endpoint--id--4",
					ip:                  "10.0.1.1",
					maintenanceStarted:  nowTime,
					maintenanceFinished: inSixtySecsTime,
				},
				{
					namespace:           "default",
					name:                "host0-k8s-pod--5-endpoint--id--5",
					ip:                  "10.0.1.1",
					maintenanceStarted:  nowTime,
					maintenanceFinished: inSixtySecsTime,
				},
			})

			// egw 10.0.0.5 is created to replace egw 10.0.0.2
			manager.OnUpdate(&proto.IPSetDeltaUpdate{
				Id: "set0",
				AddedMembers: []string{
					formatActiveEgressMemberStr("10.0.0.5", "host1"),
				},
			})
			err = manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())

			// egw 10.0.0.1 has terminated
			manager.OnUpdate(&proto.IPSetDeltaUpdate{
				Id:           "set0",
				AddedMembers: []string{},
				RemovedMembers: []string{
					formatActiveEgressMemberStr("10.0.0.1", "host0"),
				},
			})
			err = manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())

			// egw 10.0.0.2 has terminated
			manager.OnUpdate(&proto.IPSetDeltaUpdate{
				Id:           "set0",
				AddedMembers: []string{},
				RemovedMembers: []string{
					formatActiveEgressMemberStr("10.0.0.2", "host1"),
				},
			})
			err = manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			podStatusCallback.checkState([]statusCallbackEntry{
				{
					namespace:           "default",
					name:                "host0-k8s-pod--3-endpoint--id--3",
					ip:                  "10.0.1.2",
					maintenanceStarted:  thirtySecsAgo,
					maintenanceFinished: inThirtySecsTime,
				},
				{
					namespace:           "default",
					name:                "host0-k8s-pod--4-endpoint--id--4",
					ip:                  "10.0.1.1",
					maintenanceStarted:  nowTime,
					maintenanceFinished: inSixtySecsTime,
				},
				{
					namespace:           "default",
					name:                "host0-k8s-pod--5-endpoint--id--5",
					ip:                  "10.0.1.1",
					maintenanceStarted:  nowTime,
					maintenanceFinished: inSixtySecsTime,
				},
			})
		})

		It("should be tolerant of missing timestamp", func() {
			manager.OnUpdate(&proto.IPSetDeltaUpdate{
				Id:             "set1",
				AddedMembers:   []string{formatTerminatingEgressMemberStr("10.0.3.0", nowTime, inSixtySecsTime, "host2"), "10.0.3.1"},
				RemovedMembers: []string{"10.0.1.1"},
			})
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(2, []string{"10.0.242.0"}, egwPolicyWithSingleRule("set1", 0)))

			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			expectRulesAndTable([]string{"10.0.242.0/32"}, 3, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.1.2", "10.0.1.3", "10.0.3.1"}),
				},
			})

			Expect(fdb.currentVTEPs).To(ConsistOf(
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x01},
					TunnelIP:  ip.FromString("10.0.0.1"),
					HostIP:    ip.FromString("10.0.0.1"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x02},
					TunnelIP:  ip.FromString("10.0.0.2"),
					HostIP:    ip.FromString("10.0.0.2"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x03},
					TunnelIP:  ip.FromString("10.0.0.3"),
					HostIP:    ip.FromString("10.0.0.3"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x01, 0x02},
					TunnelIP:  ip.FromString("10.0.1.2"),
					HostIP:    ip.FromString("10.0.1.2"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x01, 0x03},
					TunnelIP:  ip.FromString("10.0.1.3"),
					HostIP:    ip.FromString("10.0.1.3"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x03, 0x00},
					TunnelIP:  ip.FromString("10.0.3.0"),
					HostIP:    ip.FromString("10.0.3.0"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x03, 0x01},
					TunnelIP:  ip.FromString("10.0.3.1"),
					HostIP:    ip.FromString("10.0.3.1"),
				},
			))
		})
	})

	Describe("with a single ipset and endpoint updates", func() {
		var zeroTime, nowTime, inSixtySecsTime time.Time

		var ips0 []string

		BeforeEach(func() {
			zeroTime = time.Time{}
			nowTime = time.Now()
			inSixtySecsTime = nowTime.Add(time.Second * 60)

			ips0 = []string{
				formatActiveEgressMemberStr("10.0.0.1", "host0"),
				formatActiveEgressMemberStr("10.0.0.2", "host1"),
				formatActiveEgressMemberStr("10.0.0.3", "host2"),
			}

			manager.OnUpdate(&proto.IPSetUpdate{
				Id:      "set0",
				Members: ips0,
				Type:    proto.IPSetUpdate_EGRESS_IP,
			})

			expectIPSetMembers("set0", []gateway{
				{
					addr:                ip.FromString("10.0.0.1"),
					maintenanceStarted:  zeroTime,
					maintenanceFinished: zeroTime,
					hostname:            "host0",
				},
				{
					addr:                ip.FromString("10.0.0.2"),
					maintenanceStarted:  zeroTime,
					maintenanceFinished: zeroTime,
					hostname:            "host1",
				},
				{
					addr:                ip.FromString("10.0.0.3"),
					maintenanceStarted:  zeroTime,
					maintenanceFinished: zeroTime,
					hostname:            "host2",
				},
			})

			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())

			// routeRules should be created.
			Expect(manager.routeRules).NotTo(BeNil())
			rr = rrFactory.Rules()

			mainTable.checkRoutes(routetable.InterfaceNone, nil)
			mainTable.checkRoutes("egress.calico", nil)

			Expect(fdb.currentVTEPs).To(ConsistOf(
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x01},
					TunnelIP:  ip.FromString("10.0.0.1"),
					HostIP:    ip.FromString("10.0.0.1"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x02},
					TunnelIP:  ip.FromString("10.0.0.2"),
					HostIP:    ip.FromString("10.0.0.2"),
				},
				vxlanfdb.VTEP{
					TunnelMAC: []byte{0xa2, 0x2a, 0x0a, 0x00, 0x00, 0x03},
					TunnelIP:  ip.FromString("10.0.0.3"),
					HostIP:    ip.FromString("10.0.0.3"),
				},
			))
		})

		It("should allocate a new rule and table with three hops when maxNextHops is zero", func() {
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(0, []string{"10.0.240.0/32"}, egwPolicyWithSingleRule("set0", 0)))

			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			expectRulesAndTable([]string{"10.0.240.0/32"}, 1, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}),
				},
			})
		})

		It("should allocate a new rule and table with one hop when maxNextHops is one", func() {
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(0, []string{"10.0.240.0/32"}, egwPolicyWithSingleRule("set0", 1)))

			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			expectRulesAndTable([]string{"10.0.240.0/32"}, 1, "egress.calico", []routetable.Target{
				{
					CIDR: defaultCidr,
					Type: routetable.TargetTypeVXLAN,
					GW:   ip.MustParseCIDROrIP("10.0.0.1").Addr(),
				},
			})
		})

		It("should allocate a new rule and table with two hops when maxNextHops is two", func() {
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(0, []string{"10.0.240.0/32"}, egwPolicyWithSingleRule("set0", 2)))

			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			expectRulesAndTable([]string{"10.0.240.0/32"}, 1, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.1", "10.0.0.3"}),
				},
			})
		})

		It("should allocate a new rule and table with three hops when maxNextHops is three", func() {
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(0, []string{"10.0.240.0/32"}, egwPolicyWithSingleRule("set0", 3)))

			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			expectRulesAndTable([]string{"10.0.240.0/32"}, 1, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}),
				},
			})
		})

		It("should allocate rules and tables with an even distribution of one hop starting at random index when maxNextHops is one", func() {
			egwRules := egwPolicyWithSingleRule("set0", 1)
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(0, []string{"10.0.240.0/32"}, egwRules))
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(1, []string{"10.0.240.1/32"}, egwRules))
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(2, []string{"10.0.240.2/32"}, egwRules))
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(3, []string{"10.0.240.3/32"}, egwRules))
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(4, []string{"10.0.240.4/32"}, egwRules))
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(5, []string{"10.0.240.5/32"}, egwRules))

			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			expectRulesAndTable([]string{"10.0.240.0/32"}, 1, "egress.calico", []routetable.Target{
				{
					CIDR: defaultCidr,
					Type: routetable.TargetTypeVXLAN,
					GW:   ip.MustParseCIDROrIP("10.0.0.1").Addr(),
				},
			})
			expectRulesAndTable([]string{"10.0.240.1/32"}, 2, "egress.calico", []routetable.Target{
				{
					CIDR: defaultCidr,
					Type: routetable.TargetTypeVXLAN,
					GW:   ip.MustParseCIDROrIP("10.0.0.2").Addr(),
				},
			})
			expectRulesAndTable([]string{"10.0.240.2/32"}, 3, "egress.calico", []routetable.Target{
				{
					CIDR: defaultCidr,
					Type: routetable.TargetTypeVXLAN,
					GW:   ip.MustParseCIDROrIP("10.0.0.3").Addr(),
				},
			})
			expectRulesAndTable([]string{"10.0.240.3/32"}, 4, "egress.calico", []routetable.Target{
				{
					CIDR: defaultCidr,
					Type: routetable.TargetTypeVXLAN,
					GW:   ip.MustParseCIDROrIP("10.0.0.1").Addr(),
				},
			})
			expectRulesAndTable([]string{"10.0.240.4/32"}, 5, "egress.calico", []routetable.Target{
				{
					CIDR: defaultCidr,
					Type: routetable.TargetTypeVXLAN,
					GW:   ip.MustParseCIDROrIP("10.0.0.3").Addr(),
				},
			})
			expectRulesAndTable([]string{"10.0.240.5/32"}, 6, "egress.calico", []routetable.Target{
				{
					CIDR: defaultCidr,
					Type: routetable.TargetTypeVXLAN,
					GW:   ip.MustParseCIDROrIP("10.0.0.2").Addr(),
				},
			})
		})

		It("should allocate rules and tables with an even distribution of two hops starting at random index when maxNextHops is two", func() {
			egwRules := egwPolicyWithSingleRule("set0", 2)
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(0, []string{"10.0.240.0/32"}, egwRules))
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(1, []string{"10.0.240.1/32"}, egwRules))
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(2, []string{"10.0.240.2/32"}, egwRules))
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(3, []string{"10.0.240.3/32"}, egwRules))
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(4, []string{"10.0.240.4/32"}, egwRules))
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(5, []string{"10.0.240.5/32"}, egwRules))

			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			expectRulesAndTable([]string{"10.0.240.0/32"}, 1, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.1", "10.0.0.3"}),
				},
			})
			expectRulesAndTable([]string{"10.0.240.1/32"}, 2, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.1", "10.0.0.2"}),
				},
			})
			expectRulesAndTable([]string{"10.0.240.2/32"}, 3, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.2", "10.0.0.3"}),
				},
			})
			expectRulesAndTable([]string{"10.0.240.3/32"}, 4, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.1", "10.0.0.3"}),
				},
			})
			expectRulesAndTable([]string{"10.0.240.4/32"}, 5, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.2", "10.0.0.3"}),
				},
			})
			expectRulesAndTable([]string{"10.0.240.5/32"}, 6, routetable.InterfaceNone, []routetable.Target{
				{
					CIDR:      defaultCidr,
					Type:      routetable.TargetTypeVXLAN,
					MultiPath: multiPath([]string{"10.0.0.1", "10.0.0.2"}),
				},
			})
		})

		It("should allocate per-deployment route tables excluding any terminating gateway hops", func() {
			ips0 = []string{
				formatActiveEgressMemberStr("10.0.0.1", "host0"),
				formatTerminatingEgressMemberStr("10.0.0.2", nowTime, inSixtySecsTime, "host1"),
				formatActiveEgressMemberStr("10.0.0.3", "host2"),
			}

			manager.OnUpdate(&proto.IPSetUpdate{
				Id:      "set0",
				Members: ips0,
				Type:    proto.IPSetUpdate_EGRESS_IP,
			})
			egwRules := egwPolicyWithSingleRule("set0", 1)

			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(0, []string{"10.0.240.0/32"}, egwRules))
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(1, []string{"10.0.240.1/32"}, egwRules))
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(2, []string{"10.0.240.2/32"}, egwRules))
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(3, []string{"10.0.240.3/32"}, egwRules))
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(4, []string{"10.0.240.4/32"}, egwRules))
			manager.OnUpdate(dummyWorkloadEndpointUpdateEgressIP(5, []string{"10.0.240.5/32"}, egwRules))

			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			expectRulesAndTable([]string{"10.0.240.0/32"}, 1, "egress.calico", []routetable.Target{
				{
					CIDR: defaultCidr,
					Type: routetable.TargetTypeVXLAN,
					GW:   ip.MustParseCIDROrIP("10.0.0.1").Addr(),
				},
			})
			expectRulesAndTable([]string{"10.0.240.1/32"}, 2, "egress.calico", []routetable.Target{
				{
					CIDR: defaultCidr,
					Type: routetable.TargetTypeVXLAN,
					GW:   ip.MustParseCIDROrIP("10.0.0.3").Addr(),
				},
			})
			expectRulesAndTable([]string{"10.0.240.2/32"}, 3, "egress.calico", []routetable.Target{
				{
					CIDR: defaultCidr,
					Type: routetable.TargetTypeVXLAN,
					GW:   ip.MustParseCIDROrIP("10.0.0.1").Addr(),
				},
			})
			expectRulesAndTable([]string{"10.0.240.3/32"}, 4, "egress.calico", []routetable.Target{
				{
					CIDR: defaultCidr,
					Type: routetable.TargetTypeVXLAN,
					GW:   ip.MustParseCIDROrIP("10.0.0.3").Addr(),
				},
			})
			expectRulesAndTable([]string{"10.0.240.4/32"}, 5, "egress.calico", []routetable.Target{
				{
					CIDR: defaultCidr,
					Type: routetable.TargetTypeVXLAN,
					GW:   ip.MustParseCIDROrIP("10.0.0.1").Addr(),
				},
			})
			expectRulesAndTable([]string{"10.0.240.5/32"}, 6, "egress.calico", []routetable.Target{
				{
					CIDR: defaultCidr,
					Type: routetable.TargetTypeVXLAN,
					GW:   ip.MustParseCIDROrIP("10.0.0.3").Addr(),
				},
			})
		})
	})
})

func dummyWorkloadEndpointID(podNum int) proto.WorkloadEndpointID {
	return proto.WorkloadEndpointID{
		OrchestratorId: "k8s",
		WorkloadId:     fmt.Sprintf("default/pod-%d", podNum),
		EndpointId:     fmt.Sprintf("endpoint-id-%d", podNum),
	}
}

func dummyWorkloadEndpointUpdate(podNum int, cidrs []string, externalNetworkNames []string, egressGatewayRules []*proto.EgressGatewayRule) *proto.WorkloadEndpointUpdate {
	return &proto.WorkloadEndpointUpdate{
		Id: &proto.WorkloadEndpointID{
			OrchestratorId: "k8s",
			WorkloadId:     fmt.Sprintf("default/pod-%d", podNum),
			EndpointId:     fmt.Sprintf("endpoint-id-%d", podNum),
		},
		Endpoint: &proto.WorkloadEndpoint{
			State:                "active",
			Mac:                  "01:02:03:04:05:06",
			Name:                 fmt.Sprintf("cali12345-%d", podNum),
			ProfileIds:           []string{},
			Tiers:                []*proto.TierInfo{},
			Ipv4Nets:             cidrs,
			Ipv6Nets:             []string{"2001:db8:2::2/128"},
			EgressGatewayRules:   egressGatewayRules,
			ExternalNetworkNames: externalNetworkNames,
		},
	}
}

func dummyWorkloadEndpointUpdateEgressIP(podNum int, cidrs []string, egwRules []*proto.EgressGatewayRule) *proto.WorkloadEndpointUpdate {
	return dummyWorkloadEndpointUpdate(podNum, cidrs, []string{}, egwRules)
}

func dummyWorkloadEndpointUpdateExternalNetwork(podNum int, cidrs []string, externalNetworkNames []string) *proto.WorkloadEndpointUpdate {
	return dummyWorkloadEndpointUpdate(podNum, cidrs, externalNetworkNames, nil)
}

type mockRouteRules struct {
	matchForUpdate routerule.RulesMatchFunc
	matchForRemove routerule.RulesMatchFunc
	cleanupFunc    routerule.RuleFilterFunc
	activeRules    set.Set[*routerule.Rule]
}

func (r *mockRouteRules) GetAllActiveRules() []*routerule.Rule {
	var active []*routerule.Rule
	for p := range r.activeRules.All() {
		active = append(active, p)
	}

	return active
}

func (r *mockRouteRules) InitFromKernel() {
}

func (r *mockRouteRules) getActiveRule(rule *routerule.Rule, f routerule.RulesMatchFunc) *routerule.Rule {
	var active *routerule.Rule
	for p := range r.activeRules.All() {
		if f(p, rule) {
			active = p
			break
		}
	}

	return active
}

func (r *mockRouteRules) SetRule(rule *routerule.Rule) {
	if r.getActiveRule(rule, r.matchForUpdate) == nil {
		rule.LogCxt().Debug("adding rule")
		r.activeRules.Add(rule)
	}
}

func (r *mockRouteRules) RemoveRule(rule *routerule.Rule) {
	if p := r.getActiveRule(rule, r.matchForRemove); p != nil {
		rule.LogCxt().Debug("removing rule")
		r.activeRules.Discard(p)
	}
}

func (r *mockRouteRules) QueueResync() {}
func (r *mockRouteRules) Apply() error {
	return nil
}

func (r *mockRouteRules) hasRule(priority int, src string, mark uint32, table int) bool {
	result := false
	for rule := range r.activeRules.All() {
		nlRule := rule.NetLinkRule()
		rule.LogCxt().Debug("checking rule")
		if nlRule.Priority == priority &&
			nlRule.Family == unix.AF_INET &&
			nlRule.Src.String() == src &&
			nlRule.Mark == mark &&
			nlRule.Table == table &&
			nlRule.Invert == false {
			result = true
		}
	}
	return result
}

func (r *mockRouteRules) hasRuleWithSrc(priority int, src string, mark uint32) bool {
	result := false
	for rule := range r.activeRules.All() {
		nlRule := rule.NetLinkRule()
		rule.LogCxt().Debug("checking rule")
		if nlRule.Priority == priority &&
			nlRule.Family == unix.AF_INET &&
			nlRule.Src.String() == src &&
			nlRule.Mark == mark &&
			nlRule.Invert == false {
			result = true
		}
	}
	return result
}

type mockRouteTableFactory struct {
	count  int
	tables map[int]*mockRouteTable
}

func (f *mockRouteTableFactory) NewRouteTable(
	interfacePrefixes []string,
	ipVersion uint8,
	tableIndex int,
	netlinkTimeout time.Duration,
	deviceRouteSourceAddress net.IP,
	deviceRouteProtocol int,
	removeExternalRoutes bool,
	opRecorder logutils.OpRecorder,
	featureDetector environment.FeatureDetectorIface,
) routetable.Interface {

	table := &mockRouteTable{
		index:         tableIndex,
		currentRoutes: map[string][]routetable.Target{},
	}
	f.tables[tableIndex] = table
	f.count += 1

	return table
}

func (f *mockRouteTableFactory) Table(i int) *mockRouteTable {
	Expect(f.tables[i]).NotTo(BeNil())
	return f.tables[i]
}

type mockRouteRulesFactory struct {
	routeRules *mockRouteRules
}

func (f *mockRouteRulesFactory) NewRouteRules(
	ipVersion int,
	tableIndexSet set.Set[int],
	updateFunc, removeFunc routerule.RulesMatchFunc,
	cleanupFunc routerule.RuleFilterFunc,
	netlinkTimeout time.Duration,
	opRecorder logutils.OpRecorder,
) routeRules {
	rr := &mockRouteRules{
		matchForUpdate: updateFunc,
		matchForRemove: removeFunc,
		cleanupFunc:    cleanupFunc,
		activeRules:    set.New[*routerule.Rule](),
	}
	f.routeRules = rr
	return rr
}

func (f *mockRouteRulesFactory) Rules() *mockRouteRules {
	return f.routeRules
}

func formatActiveEgressMemberStr(cidr string, hostname string) string {
	return formatTerminatingEgressMemberStr(cidr, time.Time{}, time.Time{}, hostname)
}

func formatActiveEgressMemberPortStr(cidr string, healthPort int, hostname string) string {
	return formatTerminatingEgressMemberPortStr(cidr, time.Time{}, time.Time{}, healthPort, hostname)
}

func formatTerminatingEgressMemberStr(cidr string, start, finish time.Time, hostname string) string {
	return formatTerminatingEgressMemberPortStr(cidr, start, finish, 0, hostname)
}

func formatTerminatingEgressMemberPortStr(cidr string, start time.Time, finish time.Time, healthPort int, hostname string) string {
	startBytes, err := start.MarshalText()
	Expect(err).NotTo(HaveOccurred())
	finishBytes, err := finish.MarshalText()
	Expect(err).NotTo(HaveOccurred())
	return fmt.Sprintf("%s,%s,%s,%d,%s", cidr, string(startBytes), string(finishBytes), healthPort, hostname)
}

func ipSetMemberEquals(expected gateway) types.GomegaMatcher {
	return &ipSetMemberMatcher{expected: expected}
}

type ipSetMemberMatcher struct {
	expected gateway
}

func (m *ipSetMemberMatcher) Match(actual interface{}) (bool, error) {
	member, ok := actual.(gateway)
	if !ok {
		memberPtr, ok := actual.(*gateway)
		if !ok {
			return false, fmt.Errorf("ipSetMemberMatcher must be passed an gateway. Got\n%s", format.Object(actual, 1))
		}
		member = *memberPtr
	}
	// Need to compare time.Time using Equal(), since having a nil loc and a UTC loc are equivalent.
	match := m.expected.addr == member.addr &&
		m.expected.maintenanceStarted.Equal(member.maintenanceStarted) &&
		m.expected.maintenanceFinished.Equal(member.maintenanceFinished) &&
		m.expected.healthPort == member.healthPort &&
		m.expected.healthStatus == member.healthStatus &&
		m.expected.hostname == member.hostname
	return match, nil

}

func (m *ipSetMemberMatcher) FailureMessage(actual interface{}) string {
	return fmt.Sprintf("Expected %v to match gateway: %v", actual.(gateway), m.expected)
}

func (m *ipSetMemberMatcher) NegatedFailureMessage(actual interface{}) string {
	return fmt.Sprintf("Expected %v to not match gateway: %v", actual.(gateway), m.expected)
}

type statusCallbackEntry struct {
	namespace           string
	name                string
	ip                  string
	maintenanceStarted  time.Time
	maintenanceFinished time.Time
}

type mockEgressPodStatusCallback struct {
	state []statusCallbackEntry
	Fail  bool
}

var (
	errStatusCallbackFail = errors.New("mock egress pod status callback failure")
)

func (t *mockEgressPodStatusCallback) statusCallback(namespace, name string, ip ip.Addr, maintenanceStarted, maintenanceFinished time.Time) error {
	log.WithFields(log.Fields{
		"namespace":           namespace,
		"name":                name,
		"ip":                  ip,
		"maintenanceStarted":  maintenanceStarted,
		"maintenanceFinished": maintenanceFinished,
	}).Info("mockEgressPodStatusCallback")
	if t.Fail {
		return errStatusCallbackFail
	}
	t.state = append(t.state, statusCallbackEntry{
		namespace:           namespace,
		name:                name,
		ip:                  ip.String(),
		maintenanceStarted:  maintenanceStarted,
		maintenanceFinished: maintenanceFinished,
	})
	return nil
}

func (t *mockEgressPodStatusCallback) checkState(expected []statusCallbackEntry) {
	var matchers []types.GomegaMatcher
	for _, e := range expected {
		matchers = append(matchers, statusCallbackEntryEquals(e))
	}
	Expect(t.state).To(ConsistOf(matchers))
}

func (t *mockEgressPodStatusCallback) clearState() {
	t.state = nil
}

func statusCallbackEntryEquals(expected statusCallbackEntry) types.GomegaMatcher {
	return &statusCallbackEntryMatcher{expected: expected}
}

type statusCallbackEntryMatcher struct {
	expected statusCallbackEntry
}

func (m *statusCallbackEntryMatcher) Match(actual interface{}) (bool, error) {
	e, ok := actual.(statusCallbackEntry)
	if !ok {
		return false, fmt.Errorf("statusCallbackEntryMatcher must be passed a statusCallbackEntry. Got\n%s", format.Object(actual, 1))
	}
	// Need to compare time.Time using Equal(), since having a nil loc and a UTC loc are equivalent.
	match := m.expected.namespace == e.namespace &&
		m.expected.name == e.name &&
		m.expected.ip == e.ip &&
		m.expected.maintenanceStarted.Equal(e.maintenanceStarted) &&
		m.expected.maintenanceFinished.Equal(e.maintenanceFinished)
	return match, nil

}

func (m *statusCallbackEntryMatcher) FailureMessage(actual interface{}) string {
	return fmt.Sprintf("Expected %v to match statusCallbackEntry: %v", actual.(statusCallbackEntry), m.expected)
}

func (m *statusCallbackEntryMatcher) NegatedFailureMessage(actual interface{}) string {
	return fmt.Sprintf("Expected %v to not match statusCallbackEntry: %v", actual.(statusCallbackEntry), m.expected)
}

func egressGatewayRule(ipSetId string, maxNextHops int) *proto.EgressGatewayRule {
	return &proto.EgressGatewayRule{
		IpSetId:     ipSetId,
		MaxNextHops: int32(maxNextHops),
	}
}

func egwPolicyWithSingleRule(ipSetId string, maxNextHops int) []*proto.EgressGatewayRule {
	return []*proto.EgressGatewayRule{egressGatewayRule(ipSetId, maxNextHops)}
}

type procSysWrite struct {
	path, value string
}

// Returns a dummy `writeProcSys` func to be given to the module under test.
// Every time the module under test calls the func, the call values will be
// passed across the notif chan to the test harness for consumption.
// Important to note: not draining the chan will result in tests deadlocking.
// For that reason, timeouts should be used diligently.
func createDummyWriteProcSys(notifChannelSize int, writeTimeout time.Duration) (chan procSysWrite, func(string, string) error) {
	notifs := make(chan procSysWrite, notifChannelSize)
	return notifs, func(path, value string) error {
		writeEvent := procSysWrite{
			path:  path,
			value: value,
		}

		select {
		case notifs <- writeEvent:
		case <-time.After(writeTimeout):
			return fmt.Errorf("Test issue: dummy writeProcSys timed out")
		}

		return nil
	}
}
