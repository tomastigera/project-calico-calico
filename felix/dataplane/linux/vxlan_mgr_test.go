// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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
	"context"
	"net"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/dataplane/linux/dataplanedefs"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/vxlanfdb"
)

type mockVXLANFDB struct {
	setVTEPsCalls int
	currentVTEPs  []vxlanfdb.VTEP
}

func (t *mockVXLANFDB) SetVTEPs(targets []vxlanfdb.VTEP) {
	logrus.WithFields(logrus.Fields{
		"targets": targets,
	}).Debug("SetVTEPs")
	t.currentVTEPs = targets
	t.setVTEPsCalls++
}

var _ = DescribeTable("vxlanLinksIncompat",
	func(l1, l2 *netlink.Vxlan, expected string) {
		Expect(vxlanLinksIncompat(l1, l2)).To(Equal(expected))
	},
	Entry("identical legacy devices", &netlink.Vxlan{
		VxlanId: 4096, VtepDevIndex: 2, Port: 4789,
	}, &netlink.Vxlan{
		VxlanId: 4096, VtepDevIndex: 2, Port: 4789,
	}, ""),
	Entry("identical flow-based devices", &netlink.Vxlan{
		FlowBased: true, Port: 4789,
	}, &netlink.Vxlan{
		FlowBased: true, Port: 4789,
	}, ""),
	Entry("legacy to flow-based (iptables to eBPF)", &netlink.Vxlan{
		VxlanId: 4096, VtepDevIndex: 2, Port: 4789,
	}, &netlink.Vxlan{
		FlowBased: true, Port: 4789,
	}, "flow-based mode: false vs true"),
	Entry("flow-based to legacy (eBPF to iptables)", &netlink.Vxlan{
		FlowBased: true, Port: 4789,
	}, &netlink.Vxlan{
		VxlanId: 4096, VtepDevIndex: 2, Port: 4789,
	}, "flow-based mode: true vs false"),
	Entry("VNI mismatch", &netlink.Vxlan{
		VxlanId: 4096, Port: 4789,
	}, &netlink.Vxlan{
		VxlanId: 4097, Port: 4789,
	}, "vni: 4096 vs 4097"),
	Entry("port mismatch", &netlink.Vxlan{
		VxlanId: 4096, Port: 4789,
	}, &netlink.Vxlan{
		VxlanId: 4096, Port: 4790,
	}, "port: 4789 vs 4790"),
	Entry("GBP mismatch", &netlink.Vxlan{
		VxlanId: 4096, Port: 4789, GBP: true,
	}, &netlink.Vxlan{
		VxlanId: 4096, Port: 4789, GBP: false,
	}, "gbp: true vs false"),
	Entry("L2miss mismatch", &netlink.Vxlan{
		VxlanId: 4096, Port: 4789, L2miss: true,
	}, &netlink.Vxlan{
		VxlanId: 4096, Port: 4789, L2miss: false,
	}, "l2miss: true vs false"),
)

var _ = Describe("VXLANManager", func() {
	var (
		vxlanMgr, vxlanMgrV6 *vxlanManager
		rt                   *mockRouteTable
		fdb                  *mockVXLANFDB
		mockProcSys          *testProcSys
	)

	BeforeEach(func() {
		rt = &mockRouteTable{
			currentRoutes: map[string][]routetable.Target{},
		}

		fdb = &mockVXLANFDB{}
		mockProcSys = &testProcSys{state: map[string]string{}}

		la := netlink.NewLinkAttrs()
		la.Name = "eth0"
		opRecorder := logutils.NewSummarizer("test")

		dpConfig := Config{
			MaxIPSetSize:       5,
			Hostname:           "node1",
			ExternalNodesCidrs: []string{"10.0.0.0/24"},
			RulesConfig: rules.Config{
				VXLANVNI:  1,
				VXLANPort: 20,
			},
			EgressIPEnabled: true,
		}
		vxlanMgr = newVXLANManagerWithShims(
			dpsets.NewMockIPSets(),
			rt,
			fdb,
			dataplanedefs.VXLANIfaceNameV4,
			4,
			4444,
			dpConfig,
			opRecorder,
			&mockTunnelDataplane{
				links:          []netlink.Link{&mockLink{attrs: la}},
				tunnelLinkName: dataplanedefs.VXLANIfaceNameV4,
				ipVersion:      4,
			},
			mockProcSys.write,
		)

		dpConfigV6 := Config{
			MaxIPSetSize:       5,
			Hostname:           "node1",
			ExternalNodesCidrs: []string{"fd00:10:244::/112"},
			RulesConfig: rules.Config{
				VXLANVNI:  1,
				VXLANPort: 20,
			},
		}
		vxlanMgrV6 = newVXLANManagerWithShims(
			dpsets.NewMockIPSets(),
			rt,
			fdb,
			dataplanedefs.VXLANIfaceNameV6,
			6,
			6666,
			dpConfigV6,
			opRecorder,
			&mockTunnelDataplane{
				links:          []netlink.Link{&mockLink{attrs: la}},
				tunnelLinkName: dataplanedefs.VXLANIfaceNameV6,
				ipVersion:      6,
			},
			mockProcSys.write,
		)
	})

	It("successfully adds a route to the parent interface", func() {
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		})

		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node2",
			Mac:            "00:0a:95:9d:68:16",
			Ipv4Addr:       "10.0.80.0/32",
			ParentDeviceIp: "172.0.12.1",
		})

		localVTEP := vxlanMgr.getLocalVTEP()
		Expect(localVTEP).NotTo(BeNil())

		vxlanMgr.routeMgr.OnParentDeviceUpdate("eth0")

		Expect(vxlanMgr.myVTEP).NotTo(BeNil())
		Expect(vxlanMgr.routeMgr.parentDevice).NotTo(BeEmpty())

		parent, err := vxlanMgr.routeMgr.detectParentIface()
		Expect(err).NotTo(HaveOccurred())
		Expect(parent).NotTo(BeNil())

		link, addr, err := vxlanMgr.device(parent)
		Expect(err).NotTo(HaveOccurred())
		Expect(link).NotTo(BeNil())
		Expect(addr).NotTo(BeZero())

		err = vxlanMgr.routeMgr.configureTunnelDevice(link, addr, 50, false)
		Expect(err).NotTo(HaveOccurred())

		Expect(parent).NotTo(BeNil())
		Expect(err).NotTo(HaveOccurred())

		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "172.0.0.1/26",
			DstNodeName: "node2",
			DstNodeIp:   "172.8.8.8",
			SameSubnet:  true,
		})

		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "172.0.0.2/26",
			DstNodeName: "node2",
			DstNodeIp:   "172.8.8.8",
		})

		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "172.0.0.0/26",
			DstNodeName: "node1",
			DstNodeIp:   "172.8.8.8",
			SameSubnet:  true,
		})

		// Borrowed /32 should not be programmed as blackhole.
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "172.0.0.1/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.8.8.7",
			SameSubnet:  true,
		})

		Expect(rt.currentRoutes["vxlan.calico"]).To(HaveLen(0))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(0))

		err = vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		Expect(rt.currentRoutes["vxlan.calico"]).To(HaveLen(1))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(1))
		Expect(rt.currentRoutes["eth0"]).NotTo(BeNil())

		mac, err := net.ParseMAC("00:0a:95:9d:68:16")
		Expect(err).NotTo(HaveOccurred())
		Expect(fdb.currentVTEPs).To(ConsistOf(vxlanfdb.VTEP{
			HostIP:    ip.FromString("172.0.12.1"),
			TunnelIP:  ip.FromString("10.0.80.0"),
			TunnelMAC: mac,
		}))
		Expect(fdb.setVTEPsCalls).To(Equal(1))
		err = vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())
		Expect(fdb.setVTEPsCalls).To(Equal(1))
	})

	It("successfully adds a IPv6 route to the parent interface", func() {
		vxlanMgrV6.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:             "node1",
			MacV6:            "00:0a:74:9d:68:16",
			Ipv6Addr:         "fd00:10:244::",
			ParentDeviceIpv6: "fc00:10:96::2",
		})

		vxlanMgrV6.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:             "node2",
			MacV6:            "00:0a:95:9d:68:16",
			Ipv6Addr:         "fd00:10:96::/112",
			ParentDeviceIpv6: "fc00:10:10::1",
		})

		localVTEP := vxlanMgrV6.getLocalVTEP()
		Expect(localVTEP).NotTo(BeNil())

		vxlanMgrV6.routeMgr.OnParentDeviceUpdate("eth0")

		Expect(vxlanMgrV6.myVTEP).NotTo(BeNil())
		Expect(vxlanMgrV6.routeMgr.parentDevice).NotTo(BeEmpty())

		parent, err := vxlanMgrV6.routeMgr.detectParentIface()
		Expect(err).NotTo(HaveOccurred())
		Expect(parent).NotTo(BeNil())

		link, addr, err := vxlanMgrV6.device(parent)
		Expect(err).NotTo(HaveOccurred())
		Expect(link).NotTo(BeNil())
		Expect(addr).NotTo(BeZero())

		err = vxlanMgrV6.routeMgr.configureTunnelDevice(link, addr, 50, false)
		Expect(err).NotTo(HaveOccurred())

		Expect(parent).NotTo(BeNil())
		Expect(err).NotTo(HaveOccurred())

		vxlanMgrV6.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "fc00:10:244::1/112",
			DstNodeName: "node2",
			DstNodeIp:   "fc00:10:10::8",
			SameSubnet:  true,
		})

		vxlanMgrV6.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "fc00:10:244::2/112",
			DstNodeName: "node2",
			DstNodeIp:   "fc00:10:10::8",
		})

		vxlanMgrV6.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "fc00:10:244::/112",
			DstNodeName: "node1",
			DstNodeIp:   "fc00:10:10::8",
			SameSubnet:  true,
		})

		// Borrowed /128 should not be programmed as blackhole.
		vxlanMgrV6.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "fc00:10:244::1/128",
			DstNodeName: "node1",
			DstNodeIp:   "fc00:10:10::7",
			SameSubnet:  true,
		})

		Expect(rt.currentRoutes["vxlan-v6.calico"]).To(HaveLen(0))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(0))

		err = vxlanMgrV6.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		Expect(rt.currentRoutes["vxlan-v6.calico"]).To(HaveLen(1))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(1))
		Expect(rt.currentRoutes["eth0"]).NotTo(BeNil())

		mac, err := net.ParseMAC("00:0a:95:9d:68:16")
		Expect(err).NotTo(HaveOccurred())
		Expect(fdb.currentVTEPs).To(ConsistOf(vxlanfdb.VTEP{
			HostIP:    ip.FromString("fc00:10:10::1"),
			TunnelIP:  ip.FromString("fd00:10:96::"),
			TunnelMAC: mac,
		}))
		Expect(fdb.setVTEPsCalls).To(Equal(1))
		err = vxlanMgrV6.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())
		Expect(fdb.setVTEPsCalls).To(Equal(1))
	})

	It("should fall back to programming tunneled routes if the parent device is not known", func() {
		parentNameC := make(chan string)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go vxlanMgr.keepVXLANDeviceInSync(ctx, 1400, false, 1*time.Second, parentNameC)

		By("Sending another node's VTEP and route.")
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node2",
			Mac:            "00:0a:95:9d:68:16",
			Ipv4Addr:       "10.0.80.0/32",
			ParentDeviceIp: "172.0.12.1",
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "172.0.0.1/26",
			DstNodeName: "node2",
			DstNodeIp:   "172.8.8.8",
			SameSubnet:  true,
		})

		err := vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())
		Expect(vxlanMgr.routeMgr.routesDirty).To(BeFalse())
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV4]).To(HaveLen(1))

		By("Sending another local VTEP.")
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		})
		localVTEP := vxlanMgr.getLocalVTEP()
		Expect(localVTEP).NotTo(BeNil())

		// Note: parent name is sent after configuration so this receive
		// ensures we don't race.
		Eventually(parentNameC, "2s").Should(Receive(Equal("eth0")))
		vxlanMgr.routeMgr.OnParentDeviceUpdate("eth0")

		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		err = vxlanMgr.CompleteDeferredWork()

		Expect(err).NotTo(HaveOccurred())
		Expect(vxlanMgr.routeMgr.routesDirty).To(BeFalse())
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(1))
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV4]).To(HaveLen(0))

		mockProcSys.checkState(map[string]string{
			"/proc/sys/net/ipv4/conf/vxlan.calico/rp_filter": "2",
		})
	})

	It("IPv6: should fall back to programming tunneled routes if the parent device is not known", func() {
		parentNameC := make(chan string)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go vxlanMgrV6.keepVXLANDeviceInSync(ctx, 1400, false, 1*time.Second, parentNameC)

		By("Sending another node's VTEP and route.")
		vxlanMgrV6.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:             "node2",
			MacV6:            "00:0a:95:9d:68:16",
			Ipv6Addr:         "fd00:10:96::/112",
			ParentDeviceIpv6: "fc00:10:10::1",
		})
		vxlanMgrV6.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "fc00:10:244::1/112",
			DstNodeName: "node2",
			DstNodeIp:   "fc00:10:10::8",
			SameSubnet:  true,
		})

		err := vxlanMgrV6.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())
		Expect(vxlanMgrV6.routeMgr.routesDirty).To(BeFalse())
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV6]).To(HaveLen(1))

		By("Sending another local VTEP.")
		vxlanMgrV6.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:             "node1",
			MacV6:            "00:0a:74:9d:68:16",
			Ipv6Addr:         "fd00:10:244::",
			ParentDeviceIpv6: "fc00:10:96::2",
		})
		localVTEP := vxlanMgrV6.getLocalVTEP()
		Expect(localVTEP).NotTo(BeNil())

		// Note: parent name is sent after configuration so this receive
		// ensures we don't race.
		Eventually(parentNameC, "2s").Should(Receive(Equal("eth0")))
		vxlanMgrV6.routeMgr.OnParentDeviceUpdate("eth0")

		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		err = vxlanMgrV6.CompleteDeferredWork()

		Expect(err).NotTo(HaveOccurred())
		Expect(vxlanMgrV6.routeMgr.routesDirty).To(BeFalse())
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(1))
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV6]).To(HaveLen(0))
	})

	It("should program directly connected routes for remote VTEPs with borrowed IP addresses", func() {
		By("Sending a borrowed tunnel IP address")
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.1.1/32",
			DstNodeName: "node2",
			DstNodeIp:   "172.16.0.1",
			Borrowed:    true,
		})

		err := vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect a directly connected route to the borrowed IP.
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV4]).To(HaveLen(1))
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV4][0]).To(Equal(
			routetable.Target{
				RouteKey: routetable.RouteKey{
					CIDR: ip.MustParseCIDROrIP("10.0.1.1/32"),
				},
				MTU: 4444,
			}))

		// Delete the route.
		vxlanMgr.OnUpdate(&proto.RouteRemove{
			Dst: "10.0.1.1/32",
		})

		err = vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect no routes.
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV4]).To(HaveLen(0))
	})

	It("IPv6: should program directly connected routes for remote VTEPs with borrowed IP addresses", func() {
		By("Sending a borrowed tunnel IP address")
		vxlanMgrV6.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "fc00:10:244::1/112",
			DstNodeName: "node2",
			DstNodeIp:   "fc00:10:10::8",
			Borrowed:    true,
		})

		err := vxlanMgrV6.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect a directly connected route to the borrowed IP.
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV6]).To(HaveLen(1))
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV6][0]).To(Equal(
			routetable.Target{
				RouteKey: routetable.RouteKey{
					CIDR: ip.MustParseCIDROrIP("fc00:10:244::1/112"),
				},
				MTU: 6666,
			}))

		// Delete the route.
		vxlanMgrV6.OnUpdate(&proto.RouteRemove{
			Dst: "fc00:10:244::1/112",
		})

		err = vxlanMgrV6.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect no routes.
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV6]).To(HaveLen(0))
	})

	It("should only program black hole routes for local endpoints", func() {
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		})

		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node2",
			Mac:            "00:0a:95:9d:68:16",
			Ipv4Addr:       "10.0.80.0/32",
			ParentDeviceIp: "172.0.12.1",
		})

		localVTEP := vxlanMgr.getLocalVTEP()
		Expect(localVTEP).NotTo(BeNil())

		vxlanMgr.routeMgr.OnParentDeviceUpdate("eth0")

		Expect(vxlanMgr.myVTEP).NotTo(BeNil())
		Expect(vxlanMgr.routeMgr.parentDevice).NotTo(BeEmpty())

		parent, err := vxlanMgr.routeMgr.detectParentIface()
		Expect(err).NotTo(HaveOccurred())
		Expect(parent).NotTo(BeNil())

		link, addr, err := vxlanMgr.device(parent)
		Expect(err).NotTo(HaveOccurred())
		Expect(link).NotTo(BeNil())
		Expect(addr).NotTo(BeZero())

		err = vxlanMgr.routeMgr.configureTunnelDevice(link, addr, 50, false)
		Expect(err).NotTo(HaveOccurred())

		Expect(parent).NotTo(BeNil())
		Expect(err).NotTo(HaveOccurred())

		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "172.0.0.0/26",
			DstNodeName: "node1",
			DstNodeIp:   "172.8.8.8",
			SameSubnet:  true,
		})

		// Borrowed /32 should not be programmed as blackhole.
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "172.0.0.1/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.8.8.7",
			SameSubnet:  true,
		})

		Expect(rt.currentRoutes["vxlan.calico"]).To(HaveLen(0))
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(0))

		err = vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		Expect(rt.currentRoutes["vxlan.calico"]).To(HaveLen(0))
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(1)) // Black hole route
	})

	It("IPv6: should only program black hole routes for local endpoints", func() {
		vxlanMgrV6.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:             "node1",
			MacV6:            "00:0a:74:9d:68:16",
			Ipv6Addr:         "fd00:10:244::",
			ParentDeviceIpv6: "fc00:10:96::2",
		})

		vxlanMgrV6.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:             "node2",
			MacV6:            "00:0a:95:9d:68:16",
			Ipv6Addr:         "fd00:10:96::/112",
			ParentDeviceIpv6: "fc00:10:10::1",
		})

		localVTEP := vxlanMgrV6.getLocalVTEP()
		Expect(localVTEP).NotTo(BeNil())

		vxlanMgrV6.routeMgr.OnParentDeviceUpdate("eth0")

		Expect(vxlanMgrV6.myVTEP).NotTo(BeNil())
		Expect(vxlanMgrV6.routeMgr.parentDevice).NotTo(BeEmpty())

		parent, err := vxlanMgrV6.routeMgr.detectParentIface()
		Expect(err).NotTo(HaveOccurred())
		Expect(parent).NotTo(BeNil())

		link, addr, err := vxlanMgrV6.device(parent)
		Expect(err).NotTo(HaveOccurred())
		Expect(link).NotTo(BeNil())
		Expect(addr).NotTo(BeZero())

		err = vxlanMgrV6.routeMgr.configureTunnelDevice(link, addr, 50, false)
		Expect(err).NotTo(HaveOccurred())

		Expect(parent).NotTo(BeNil())
		Expect(err).NotTo(HaveOccurred())

		vxlanMgrV6.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "fc00:10:244::/112",
			DstNodeName: "node1",
			DstNodeIp:   "fc00:10:10::8",
			SameSubnet:  true,
		})

		// Borrowed /128 should not be programmed as blackhole.
		vxlanMgrV6.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "fc00:10:244::1/128",
			DstNodeName: "node1",
			DstNodeIp:   "fc00:10:10::7",
			SameSubnet:  true,
		})

		Expect(rt.currentRoutes["vxlan-v6.calico"]).To(HaveLen(0))
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(0))

		err = vxlanMgrV6.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		Expect(rt.currentRoutes["vxlan-v6.calico"]).To(HaveLen(0))
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(1)) // Black hole route
	})

	It("should program directly connected routes for remote VTEPs", func() {
		By("Sending a non-borrowed tunnel IP address")
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL | proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.1.1/32",
			DstNodeName: "node2",
			DstNodeIp:   "172.16.0.1",
			Borrowed:    false,
		})

		err := vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect a directly connected route for the remote VTEP.
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV4]).To(HaveLen(1))
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV4][0]).To(Equal(
			routetable.Target{
				RouteKey: routetable.RouteKey{
					CIDR: ip.MustParseCIDROrIP("10.0.1.1/32"),
				},
				MTU: 4444,
			}))

		// Delete the route.
		vxlanMgr.OnUpdate(&proto.RouteRemove{
			Dst: "10.0.1.1/32",
		})

		err = vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect no routes.
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV4]).To(HaveLen(0))
	})

	It("IPv6: should program directly connected routes for remote VTEPs", func() {
		By("Sending a non-borrowed tunnel IP address")
		vxlanMgrV6.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL | proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "fc00:10:244::1/112",
			DstNodeName: "node2",
			DstNodeIp:   "fc00:10:10::8",
			Borrowed:    false,
		})

		err := vxlanMgrV6.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect a directly connected route for the remote VTEP.
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV6]).To(HaveLen(1))
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV6][0]).To(Equal(
			routetable.Target{
				RouteKey: routetable.RouteKey{
					CIDR: ip.MustParseCIDROrIP("fc00:10:244::1/112"),
				},
				MTU: 6666,
			}))

		// Delete the route.
		vxlanMgrV6.OnUpdate(&proto.RouteRemove{
			Dst: "fc00:10:244::1/112",
		})

		err = vxlanMgrV6.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect no routes.
		Expect(rt.currentRoutes[dataplanedefs.VXLANIfaceNameV6]).To(HaveLen(0))
	})

	It("programs remote VTEP L2 route if no conflict present with local cluster VTEP", func() {
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster/node2",
			Mac:            "00:0a:95:9d:68:16",
			Ipv4Addr:       "10.0.80.0",
			ParentDeviceIp: "172.0.12.1",
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.0/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.80.0/32",
			DstNodeName: "remote-cluster/node2",
			DstNodeIp:   "172.0.12.1",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})

		err := vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		mac, err := net.ParseMAC("00:0a:95:9d:68:16")
		Expect(err).NotTo(HaveOccurred())
		// Expect the nodes VTEP to be programmed with the remote cluster VTEP route.
		Expect(fdb.currentVTEPs).To(ConsistOf(vxlanfdb.VTEP{
			TunnelMAC: mac,
			TunnelIP:  ip.FromString("10.0.80.0"),
			HostIP:    ip.FromString("172.0.12.1"),
		}))
	})

	It("does not program remote VTEP L2 route if it conflicts with local cluster VTEP IP of this node", func() {
		// VTEP IPs are equal.
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster/node2",
			Mac:            "00:0a:95:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.12.1",
		})
		// Omit the remote cluster route update, as the Calc Graph will resolve the IP conflict and send the winning L3 route accordingly.
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.0/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})

		err := vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect the nodes VTEP to not be programmed with the remote cluster VTEP route.
		Expect(fdb.currentVTEPs).To(HaveLen(0))
	})

	It("does not program remote VTEP L2 route if it conflicts with local cluster VTEP IP on another node", func() {
		// We should see an L2 route for the local VTEP on another node, even if the L3 route was not sent.
		// This is because we always program local cluster VTEPs.
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node3",
			Mac:            "00:ab:22:32:af:e2",
			Ipv4Addr:       "10.0.0.1",
			ParentDeviceIp: "172.0.0.3",
		})

		err := vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		mac, err := net.ParseMAC("00:ab:22:32:af:e2")
		Expect(err).NotTo(HaveOccurred())
		Expect(fdb.currentVTEPs).To(ConsistOf(vxlanfdb.VTEP{
			TunnelMAC: mac,
			TunnelIP:  ip.FromString("10.0.0.1"),
			HostIP:    ip.FromString("172.0.0.3"),
		}))

		// Add the remote node with conflicting IP, along with the route updates.
		// The remote cluster node does not have a route update, as the Calc Graph picks the local VTEP to win the IP conflict.
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster/node2",
			Mac:            "00:0a:95:9d:68:16",
			Ipv4Addr:       "10.0.0.1",
			ParentDeviceIp: "172.0.12.1",
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.0/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.1/32",
			DstNodeName: "node3",
			DstNodeIp:   "172.0.0.3",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})

		err = vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect the nodes VTEP to still only be programmed with the local route.
		Expect(fdb.currentVTEPs).To(ConsistOf(vxlanfdb.VTEP{
			TunnelMAC: mac,
			TunnelIP:  ip.FromString("10.0.0.1"),
			HostIP:    ip.FromString("172.0.0.3"),
		}))
	})

	It("does not program remote VTEP L2 routes if they conflict with a different remote cluster VTEP IP", func() {
		// Two remote VTEPs have the same IP. The Calc Graph with resolve the IP conflict, sending just one L3 route.
		// Expect that the L2 routes respect the winner of the conflict.
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster-a/node2",
			Mac:            "00:ab:22:32:af:e2",
			Ipv4Addr:       "10.0.0.1",
			ParentDeviceIp: "172.0.0.3",
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster-b/node3",
			Mac:            "00:0a:95:9d:68:16",
			Ipv4Addr:       "10.0.0.1",
			ParentDeviceIp: "172.0.12.1",
		})

		// Assume remote-cluster-a is the winner, so only send a route update for remote-cluster-a.
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.0/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.1/32",
			DstNodeName: "remote-cluster-a/node2",
			DstNodeIp:   "172.0.0.3",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})

		err := vxlanMgr.CompleteDeferredWork()

		Expect(err).NotTo(HaveOccurred())
		mac, err := net.ParseMAC("00:ab:22:32:af:e2")
		Expect(err).NotTo(HaveOccurred())
		// Expect the nodes VTEP to be programmed with the remote cluster A VTEP route.
		Expect(fdb.currentVTEPs).To(ConsistOf(vxlanfdb.VTEP{
			TunnelMAC: mac,
			TunnelIP:  ip.FromString("10.0.0.1"),
			HostIP:    ip.FromString("172.0.0.3"),
		}))
	})

	It("programs VTEP L2 routes correctly during transitions between IP conflict states", func() {
		// Define data for the test - the local and remote node VTEPs have conflicting IPs.
		thisNodeVTEP := &proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		}
		localNodeVTEP := &proto.VXLANTunnelEndpointUpdate{
			Node:           "node3",
			Mac:            "00:ab:22:32:af:e2",
			Ipv4Addr:       "10.0.0.1",
			ParentDeviceIp: "172.0.0.3",
		}
		remoteNodeVTEP := &proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster/node2",
			Mac:            "00:0a:95:9d:68:16",
			Ipv4Addr:       "10.0.0.1",
			ParentDeviceIp: "172.0.12.1",
		}
		thisNodeVTEPRoute := &proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.0/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		}
		localNodeVTEPRoute := &proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.1/32",
			DstNodeName: "node3",
			DstNodeIp:   "172.0.0.3",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		}
		remoteNodeVTEPRoute := &proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.1/32",
			DstNodeName: "remote-cluster/node2",
			DstNodeIp:   "172.0.12.1",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		}
		localMAC, err := net.ParseMAC("00:ab:22:32:af:e2")
		Expect(err).NotTo(HaveOccurred())
		localL2Route := vxlanfdb.VTEP{
			TunnelMAC: localMAC,
			TunnelIP:  ip.FromString("10.0.0.1"),
			HostIP:    ip.FromString("172.0.0.3"),
		}
		remoteMAC, err := net.ParseMAC("00:0a:95:9d:68:16")
		Expect(err).NotTo(HaveOccurred())
		remoteL2Route := vxlanfdb.VTEP{
			TunnelMAC: remoteMAC,
			TunnelIP:  ip.FromString("10.0.0.1"),
			HostIP:    ip.FromString("172.0.12.1"),
		}

		// Establish local VTEPs for this node, and another local node.
		vxlanMgr.OnUpdate(thisNodeVTEP)
		vxlanMgr.OnUpdate(thisNodeVTEPRoute)
		vxlanMgr.OnUpdate(localNodeVTEP)
		vxlanMgr.OnUpdate(localNodeVTEPRoute)
		err = vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect that the local node VTEP has an L2 route.
		Expect(fdb.currentVTEPs).To(ConsistOf(localL2Route))

		// Add the remote node with conflicting IP.
		// We don't add a route update as the Calc Graph should pick the local VTEP as the winner of the IP conflict.
		vxlanMgr.OnUpdate(remoteNodeVTEP)
		err = vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect the nodes VTEP to still only be programmed with the local route.
		Expect(fdb.currentVTEPs).To(ConsistOf(localL2Route))

		// Now remove the local VTEP. The routes should shift to the remote VTEP.
		// We also add the route update for the remote VTEP, as it is no longer conflicted in the calc graph.
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointRemove{Node: localNodeVTEP.Node})
		vxlanMgr.OnUpdate(&proto.RouteRemove{Dst: localNodeVTEPRoute.Dst})
		vxlanMgr.OnUpdate(remoteNodeVTEPRoute)
		err = vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect that the routes shifted to the remote VTEP.
		Expect(fdb.currentVTEPs).To(ConsistOf(remoteL2Route))

		// Now restore the local VTEP.
		vxlanMgr.OnUpdate(localNodeVTEP)
		vxlanMgr.OnUpdate(&proto.RouteRemove{Dst: remoteNodeVTEPRoute.Dst})
		vxlanMgr.OnUpdate(localNodeVTEPRoute)
		err = vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect the routes have shifted back to the local VTEP.
		Expect(fdb.currentVTEPs).To(ConsistOf(localL2Route))
	})

	It("does not program remote VTEP L2 route if it conflicts with local cluster VTEP MAC of this node", func() {
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.0/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster/node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.80.0",
			ParentDeviceIp: "172.0.12.1",
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.80.0/32",
			DstNodeName: "remote-cluster/node1",
			DstNodeIp:   "172.0.12.1",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})
		err := vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect the nodes VTEP to not be programmed with the remote cluster VTEP route.
		Expect(fdb.currentVTEPs).To(HaveLen(0))
	})

	It("does not program remote VTEP L2 route if it conflicts with local cluster VTEP MAC of another node", func() {
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.0/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node3",
			Mac:            "00:ab:22:32:af:e2",
			Ipv4Addr:       "10.0.0.1",
			ParentDeviceIp: "172.0.0.3",
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.1/32",
			DstNodeName: "node3",
			DstNodeIp:   "172.0.0.3",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster/node3",
			Mac:            "00:ab:22:32:af:e2",
			Ipv4Addr:       "10.0.0.3",
			ParentDeviceIp: "172.0.12.1",
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.3/32",
			DstNodeName: "remote-cluster/node3",
			DstNodeIp:   "172.0.12.1",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})

		err := vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		mac, err := net.ParseMAC("00:ab:22:32:af:e2")
		Expect(err).NotTo(HaveOccurred())
		// Expect the nodes VTEP to only be programmed with the local route.
		Expect(fdb.currentVTEPs).To(Equal([]vxlanfdb.VTEP{
			{
				TunnelMAC: mac,
				TunnelIP:  ip.FromString("10.0.0.1"),
				HostIP:    ip.FromString("172.0.0.3"),
			},
		}))
	})

	It("does not program remote VTEP L2 routes if they conflict with a different remote cluster VTEP MAC", func() {
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.0/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster-a/node3",
			Mac:            "00:ab:22:32:af:e2",
			Ipv4Addr:       "10.0.0.1",
			ParentDeviceIp: "172.0.0.3",
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.1/32",
			DstNodeName: "remote-cluster-a/node3",
			DstNodeIp:   "172.0.0.3",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster-b/node3",
			Mac:            "00:ab:22:32:af:e2",
			Ipv4Addr:       "10.0.0.3",
			ParentDeviceIp: "172.0.12.1",
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.3/32",
			DstNodeName: "remote-cluster-b/node3",
			DstNodeIp:   "172.0.12.1",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})

		err := vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect remote A VTEP to be programmed, due to sort on node name to resolve MAC conflict.
		mac, err := net.ParseMAC("00:ab:22:32:af:e2")
		Expect(err).NotTo(HaveOccurred())
		Expect(fdb.currentVTEPs).To(Equal([]vxlanfdb.VTEP{{
			TunnelMAC: mac,
			TunnelIP:  ip.FromString("10.0.0.1"),
			HostIP:    ip.FromString("172.0.0.3"),
		}}))
	})

	It("programs remote VTEP L2 routes correctly during transitions between MAC conflict states", func() {
		// Define the test data. Remote node A and remote node B VTEPs have the same MAC address.
		thisNodeVTEP := &proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		}
		thisNodeVTEPRoute := &proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.0/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		}
		remoteANodeVTEP := &proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster-a/node3",
			Mac:            "00:ab:22:32:af:e2",
			Ipv4Addr:       "10.0.0.1",
			ParentDeviceIp: "172.0.0.3",
		}
		remoteANodeVTEPRoute := &proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.1/32",
			DstNodeName: "remote-cluster-a/node3",
			DstNodeIp:   "172.0.0.3",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		}
		remoteBNodeVTEP := &proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster-b/node3",
			Mac:            "00:ab:22:32:af:e2",
			Ipv4Addr:       "10.0.0.3",
			ParentDeviceIp: "172.0.12.1",
		}
		remoteBNodeVTEPRoute := &proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.3/32",
			DstNodeName: "remote-cluster-b/node3",
			DstNodeIp:   "172.0.12.1",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		}
		remoteAMAC, err := net.ParseMAC("00:ab:22:32:af:e2")
		Expect(err).NotTo(HaveOccurred())
		remoteAL2Route := vxlanfdb.VTEP{
			TunnelMAC: remoteAMAC,
			TunnelIP:  ip.FromString("10.0.0.1"),
			HostIP:    ip.FromString("172.0.0.3"),
		}
		remoteBMAC, err := net.ParseMAC("00:ab:22:32:af:e2")
		Expect(err).NotTo(HaveOccurred())
		remoteBL2Route := vxlanfdb.VTEP{
			TunnelMAC: remoteBMAC,
			TunnelIP:  ip.FromString("10.0.0.3"),
			HostIP:    ip.FromString("172.0.12.1"),
		}

		// Program the remote B VTEP along with this nodes VTEP.
		vxlanMgr.OnUpdate(remoteBNodeVTEP)
		vxlanMgr.OnUpdate(remoteBNodeVTEPRoute)
		vxlanMgr.OnUpdate(thisNodeVTEP)
		vxlanMgr.OnUpdate(thisNodeVTEPRoute)
		err = vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect remote B to be programmed as the L2 route.
		Expect(fdb.currentVTEPs).To(Equal([]vxlanfdb.VTEP{remoteBL2Route}))

		// Program the remote A VTEP.
		vxlanMgr.OnUpdate(remoteANodeVTEP)
		vxlanMgr.OnUpdate(remoteANodeVTEPRoute)
		err = vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect remote A to be programmed as the L2 route, since it wins the MAC conflict resolution by node name order.
		Expect(fdb.currentVTEPs).To(Equal([]vxlanfdb.VTEP{remoteAL2Route}))

		// Remove the remote B VTEP.
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointRemove{Node: remoteBNodeVTEP.Node})
		vxlanMgr.OnUpdate(&proto.RouteRemove{Dst: remoteBNodeVTEPRoute.Dst})
		err = vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect remote A to still be programmed as the L2 route.
		Expect(fdb.currentVTEPs).To(Equal([]vxlanfdb.VTEP{remoteAL2Route}))
	})

	It("utilizes L3 routes to resolve L2 conflicts when two VTEPs have the same IP and MAC", func() {
		// The remote cluster VTEPs have the same IP and MAC.
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster-a/node2",
			Mac:            "00:ab:22:32:af:e2",
			Ipv4Addr:       "10.0.0.1",
			ParentDeviceIp: "172.0.0.3",
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster-b/node2",
			Mac:            "00:ab:22:32:af:e2",
			Ipv4Addr:       "10.0.0.1",
			ParentDeviceIp: "172.0.12.1",
		})

		// We expect only one remote cluster tunnel route to be present, as the Calc Graph should assign a winner.
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.0/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.1/32",
			DstNodeName: "remote-cluster-a/node2",
			DstNodeIp:   "172.0.0.3",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})

		err := vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect the remote A L2 route to be programmed, rather than neither, since the remote B VTEP is conflicted in the Calc Graph.
		mac, err := net.ParseMAC("00:ab:22:32:af:e2")
		Expect(err).NotTo(HaveOccurred())
		Expect(fdb.currentVTEPs).To(Equal([]vxlanfdb.VTEP{
			{
				TunnelMAC: mac,
				TunnelIP:  ip.FromString("10.0.0.1"),
				HostIP:    ip.FromString("172.0.0.3"),
			},
		}))
	})

	It("utilizes L3 routes to resolve L2 conflicts when two VTEPs have the same MAC and one is conflicted at L3", func() {
		// Remote cluster A VTEP has the same MAC as C. Remote cluster B VTEP has the same IP as C.
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster-a/node2",
			Mac:            "00:ab:22:32:af:e2",
			Ipv4Addr:       "10.0.0.1",
			ParentDeviceIp: "172.0.0.3",
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster-b/node3",
			Mac:            "00:bc:22:32:ea:33",
			Ipv4Addr:       "10.0.0.2",
			ParentDeviceIp: "172.0.12.1",
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster-c/node2",
			Mac:            "00:ab:22:32:af:e2",
			Ipv4Addr:       "10.0.0.2",
			ParentDeviceIp: "172.0.22.2",
		})

		// We expect that the Calc Graph will assign B as the winner of the IP conflict.
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.0/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.1/32",
			DstNodeName: "remote-cluster-a/node2",
			DstNodeIp:   "172.0.0.3",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.2/32",
			DstNodeName: "remote-cluster-b/node3",
			DstNodeIp:   "172.0.12.1",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})

		err := vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// As a result, we expect the A and B VTEP to be programmed. Since we ignore the C VTEP due to the L3 conflict, A is
		// not conflicted with it's MAC address.
		aMAC, err := net.ParseMAC("00:ab:22:32:af:e2")
		Expect(err).NotTo(HaveOccurred())
		bMAC, err := net.ParseMAC("00:bc:22:32:ea:33")
		Expect(err).NotTo(HaveOccurred())
		Expect(fdb.currentVTEPs).To(ConsistOf([]vxlanfdb.VTEP{
			{
				TunnelMAC: aMAC,
				TunnelIP:  ip.FromString("10.0.0.1"),
				HostIP:    ip.FromString("172.0.0.3"),
			},
			{
				TunnelMAC: bMAC,
				TunnelIP:  ip.FromString("10.0.0.2"),
				HostIP:    ip.FromString("172.0.12.1"),
			},
		}))
	})

	It("programs remote VTEP L2 route if no conflict present with local cluster VTEP", func() {
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster/node2",
			Mac:            "00:0a:95:9d:68:16",
			Ipv4Addr:       "10.0.80.0",
			ParentDeviceIp: "172.0.12.1",
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.0/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.80.0/32",
			DstNodeName: "remote-cluster/node2",
			DstNodeIp:   "172.0.12.1",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})

		err := vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		mac, err := net.ParseMAC("00:0a:95:9d:68:16")
		Expect(err).NotTo(HaveOccurred())
		// Expect the nodes VTEP to be programmed with the remote cluster VTEP route.
		Expect(fdb.currentVTEPs).To(ConsistOf(vxlanfdb.VTEP{
			TunnelMAC: mac,
			TunnelIP:  ip.FromString("10.0.80.0"),
			HostIP:    ip.FromString("172.0.12.1"),
		}))
	})

	It("does not program remote VTEP L2 route if it conflicts with local cluster VTEP IP of this node", func() {
		// VTEP IPs are equal.
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster/node2",
			Mac:            "00:0a:95:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.12.1",
		})
		// Omit the remote cluster route update, as the Calc Graph will resolve the IP conflict and send the winning L3 route accordingly.
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.0/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})

		err := vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect the nodes VTEP to not be programmed with the remote cluster VTEP route.
		Expect(fdb.currentVTEPs).To(HaveLen(0))
	})

	It("does not program remote VTEP L2 route if it conflicts with local cluster VTEP IP on another node", func() {
		// We should see an L2 route for the local VTEP on another node, even if the L3 route was not sent.
		// This is because we always program local cluster VTEPs.
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node3",
			Mac:            "00:ab:22:32:af:e2",
			Ipv4Addr:       "10.0.0.1",
			ParentDeviceIp: "172.0.0.3",
		})

		err := vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		mac, err := net.ParseMAC("00:ab:22:32:af:e2")
		Expect(err).NotTo(HaveOccurred())
		Expect(fdb.currentVTEPs).To(ConsistOf(vxlanfdb.VTEP{
			TunnelMAC: mac,
			TunnelIP:  ip.FromString("10.0.0.1"),
			HostIP:    ip.FromString("172.0.0.3"),
		}))

		// Add the remote node with conflicting IP, along with the route updates.
		// The remote cluster node does not have a route update, as the Calc Graph picks the local VTEP to win the IP conflict.
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster/node2",
			Mac:            "00:0a:95:9d:68:16",
			Ipv4Addr:       "10.0.0.1",
			ParentDeviceIp: "172.0.12.1",
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.0/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.1/32",
			DstNodeName: "node3",
			DstNodeIp:   "172.0.0.3",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})

		err = vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect the nodes VTEP to still only be programmed with the local route.
		Expect(fdb.currentVTEPs).To(ConsistOf(vxlanfdb.VTEP{
			TunnelMAC: mac,
			TunnelIP:  ip.FromString("10.0.0.1"),
			HostIP:    ip.FromString("172.0.0.3"),
		}))
	})

	It("does not program remote VTEP L2 routes if they conflict with a different remote cluster VTEP IP", func() {
		// Two remote VTEPs have the same IP. The Calc Graph with resolve the IP conflict, sending just one L3 route.
		// Expect that the L2 routes respect the winner of the conflict.
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster-a/node2",
			Mac:            "00:ab:22:32:af:e2",
			Ipv4Addr:       "10.0.0.1",
			ParentDeviceIp: "172.0.0.3",
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster-b/node3",
			Mac:            "00:0a:95:9d:68:16",
			Ipv4Addr:       "10.0.0.1",
			ParentDeviceIp: "172.0.12.1",
		})

		// Assume remote-cluster-a is the winner, so only send a route update for remote-cluster-a.
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.0/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.1/32",
			DstNodeName: "remote-cluster-a/node2",
			DstNodeIp:   "172.0.0.3",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})

		err := vxlanMgr.CompleteDeferredWork()

		Expect(err).NotTo(HaveOccurred())
		mac, err := net.ParseMAC("00:ab:22:32:af:e2")
		Expect(err).NotTo(HaveOccurred())
		// Expect the nodes VTEP to be programmed with the remote cluster A VTEP route.
		Expect(fdb.currentVTEPs).To(ConsistOf(vxlanfdb.VTEP{
			TunnelMAC: mac,
			TunnelIP:  ip.FromString("10.0.0.1"),
			HostIP:    ip.FromString("172.0.0.3"),
		}))
	})

	It("programs VTEP L2 routes correctly during transitions between IP conflict states", func() {
		// Define data for the test - the local and remote node VTEPs have conflicting IPs.
		thisNodeVTEP := &proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		}
		localNodeVTEP := &proto.VXLANTunnelEndpointUpdate{
			Node:           "node3",
			Mac:            "00:ab:22:32:af:e2",
			Ipv4Addr:       "10.0.0.1",
			ParentDeviceIp: "172.0.0.3",
		}
		remoteNodeVTEP := &proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster/node2",
			Mac:            "00:0a:95:9d:68:16",
			Ipv4Addr:       "10.0.0.1",
			ParentDeviceIp: "172.0.12.1",
		}
		thisNodeVTEPRoute := &proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.0/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		}
		localNodeVTEPRoute := &proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.1/32",
			DstNodeName: "node3",
			DstNodeIp:   "172.0.0.3",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		}
		remoteNodeVTEPRoute := &proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.1/32",
			DstNodeName: "remote-cluster/node2",
			DstNodeIp:   "172.0.12.1",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		}
		localMAC, err := net.ParseMAC("00:ab:22:32:af:e2")
		Expect(err).NotTo(HaveOccurred())
		localL2Route := vxlanfdb.VTEP{
			TunnelMAC: localMAC,
			TunnelIP:  ip.FromString("10.0.0.1"),
			HostIP:    ip.FromString("172.0.0.3"),
		}
		remoteMAC, err := net.ParseMAC("00:0a:95:9d:68:16")
		Expect(err).NotTo(HaveOccurred())
		remoteL2Route := vxlanfdb.VTEP{
			TunnelMAC: remoteMAC,
			TunnelIP:  ip.FromString("10.0.0.1"),
			HostIP:    ip.FromString("172.0.12.1"),
		}

		// Establish local VTEPs for this node, and another local node.
		vxlanMgr.OnUpdate(thisNodeVTEP)
		vxlanMgr.OnUpdate(thisNodeVTEPRoute)
		vxlanMgr.OnUpdate(localNodeVTEP)
		vxlanMgr.OnUpdate(localNodeVTEPRoute)
		err = vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect that the local node VTEP has an L2 route.
		Expect(fdb.currentVTEPs).To(ConsistOf(localL2Route))

		// Add the remote node with conflicting IP.
		// We don't add a route update as the Calc Graph should pick the local VTEP as the winner of the IP conflict.
		vxlanMgr.OnUpdate(remoteNodeVTEP)
		err = vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect the nodes VTEP to still only be programmed with the local route.
		Expect(fdb.currentVTEPs).To(ConsistOf(localL2Route))

		// Now remove the local VTEP. The routes should shift to the remote VTEP.
		// We also add the route update for the remote VTEP, as it is no longer conflicted in the calc graph.
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointRemove{Node: localNodeVTEP.Node})
		vxlanMgr.OnUpdate(&proto.RouteRemove{Dst: localNodeVTEPRoute.Dst})
		vxlanMgr.OnUpdate(remoteNodeVTEPRoute)
		err = vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect that the routes shifted to the remote VTEP.
		Expect(fdb.currentVTEPs).To(ConsistOf(remoteL2Route))

		// Now restore the local VTEP.
		vxlanMgr.OnUpdate(localNodeVTEP)
		vxlanMgr.OnUpdate(&proto.RouteRemove{Dst: remoteNodeVTEPRoute.Dst})
		vxlanMgr.OnUpdate(localNodeVTEPRoute)
		err = vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect the routes have shifted back to the local VTEP.
		Expect(fdb.currentVTEPs).To(ConsistOf(localL2Route))
	})

	It("does not program remote VTEP L2 route if it conflicts with local cluster VTEP MAC of this node", func() {
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.0/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster/node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.80.0",
			ParentDeviceIp: "172.0.12.1",
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.80.0/32",
			DstNodeName: "remote-cluster/node1",
			DstNodeIp:   "172.0.12.1",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})
		err := vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect the nodes VTEP to not be programmed with the remote cluster VTEP route.
		Expect(fdb.currentVTEPs).To(HaveLen(0))
	})

	It("does not program remote VTEP L2 route if it conflicts with local cluster VTEP MAC of another node", func() {
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.0/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node3",
			Mac:            "00:ab:22:32:af:e2",
			Ipv4Addr:       "10.0.0.1",
			ParentDeviceIp: "172.0.0.3",
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.1/32",
			DstNodeName: "node3",
			DstNodeIp:   "172.0.0.3",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster/node3",
			Mac:            "00:ab:22:32:af:e2",
			Ipv4Addr:       "10.0.0.3",
			ParentDeviceIp: "172.0.12.1",
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.3/32",
			DstNodeName: "remote-cluster/node3",
			DstNodeIp:   "172.0.12.1",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})

		err := vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		mac, err := net.ParseMAC("00:ab:22:32:af:e2")
		Expect(err).NotTo(HaveOccurred())
		// Expect the nodes VTEP to only be programmed with the local route.
		Expect(fdb.currentVTEPs).To(Equal([]vxlanfdb.VTEP{
			{
				TunnelMAC: mac,
				TunnelIP:  ip.FromString("10.0.0.1"),
				HostIP:    ip.FromString("172.0.0.3"),
			},
		}))
	})

	It("does not program remote VTEP L2 routes if they conflict with a different remote cluster VTEP MAC", func() {
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.0/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster-a/node3",
			Mac:            "00:ab:22:32:af:e2",
			Ipv4Addr:       "10.0.0.1",
			ParentDeviceIp: "172.0.0.3",
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.1/32",
			DstNodeName: "remote-cluster-a/node3",
			DstNodeIp:   "172.0.0.3",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster-b/node3",
			Mac:            "00:ab:22:32:af:e2",
			Ipv4Addr:       "10.0.0.3",
			ParentDeviceIp: "172.0.12.1",
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.3/32",
			DstNodeName: "remote-cluster-b/node3",
			DstNodeIp:   "172.0.12.1",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})

		err := vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect remote A VTEP to be programmed, due to sort on node name to resolve MAC conflict.
		mac, err := net.ParseMAC("00:ab:22:32:af:e2")
		Expect(err).NotTo(HaveOccurred())
		Expect(fdb.currentVTEPs).To(Equal([]vxlanfdb.VTEP{{
			TunnelMAC: mac,
			TunnelIP:  ip.FromString("10.0.0.1"),
			HostIP:    ip.FromString("172.0.0.3"),
		}}))
	})

	It("programs remote VTEP L2 routes correctly during transitions between MAC conflict states", func() {
		// Define the test data. Remote node A and remote node B VTEPs have the same MAC address.
		thisNodeVTEP := &proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		}
		thisNodeVTEPRoute := &proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.0/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		}
		remoteANodeVTEP := &proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster-a/node3",
			Mac:            "00:ab:22:32:af:e2",
			Ipv4Addr:       "10.0.0.1",
			ParentDeviceIp: "172.0.0.3",
		}
		remoteANodeVTEPRoute := &proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.1/32",
			DstNodeName: "remote-cluster-a/node3",
			DstNodeIp:   "172.0.0.3",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		}
		remoteBNodeVTEP := &proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster-b/node3",
			Mac:            "00:ab:22:32:af:e2",
			Ipv4Addr:       "10.0.0.3",
			ParentDeviceIp: "172.0.12.1",
		}
		remoteBNodeVTEPRoute := &proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.3/32",
			DstNodeName: "remote-cluster-b/node3",
			DstNodeIp:   "172.0.12.1",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		}
		remoteAMAC, err := net.ParseMAC("00:ab:22:32:af:e2")
		Expect(err).NotTo(HaveOccurred())
		remoteAL2Route := vxlanfdb.VTEP{
			TunnelMAC: remoteAMAC,
			TunnelIP:  ip.FromString("10.0.0.1"),
			HostIP:    ip.FromString("172.0.0.3"),
		}
		remoteBMAC, err := net.ParseMAC("00:ab:22:32:af:e2")
		Expect(err).NotTo(HaveOccurred())
		remoteBL2Route := vxlanfdb.VTEP{
			TunnelMAC: remoteBMAC,
			TunnelIP:  ip.FromString("10.0.0.3"),
			HostIP:    ip.FromString("172.0.12.1"),
		}

		// Program the remote B VTEP along with this nodes VTEP.
		vxlanMgr.OnUpdate(remoteBNodeVTEP)
		vxlanMgr.OnUpdate(remoteBNodeVTEPRoute)
		vxlanMgr.OnUpdate(thisNodeVTEP)
		vxlanMgr.OnUpdate(thisNodeVTEPRoute)
		err = vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect remote B to be programmed as the L2 route.
		Expect(fdb.currentVTEPs).To(Equal([]vxlanfdb.VTEP{remoteBL2Route}))

		// Program the remote A VTEP.
		vxlanMgr.OnUpdate(remoteANodeVTEP)
		vxlanMgr.OnUpdate(remoteANodeVTEPRoute)
		err = vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect remote A to be programmed as the L2 route, since it wins the MAC conflict resolution by node name order.
		Expect(fdb.currentVTEPs).To(Equal([]vxlanfdb.VTEP{remoteAL2Route}))

		// Remove the remote B VTEP.
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointRemove{Node: remoteBNodeVTEP.Node})
		vxlanMgr.OnUpdate(&proto.RouteRemove{Dst: remoteBNodeVTEPRoute.Dst})
		err = vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect remote A to still be programmed as the L2 route.
		Expect(fdb.currentVTEPs).To(Equal([]vxlanfdb.VTEP{remoteAL2Route}))
	})

	It("utilizes L3 routes to resolve L2 conflicts when two VTEPs have the same IP and MAC", func() {
		// The remote cluster VTEPs have the same IP and MAC.
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster-a/node2",
			Mac:            "00:ab:22:32:af:e2",
			Ipv4Addr:       "10.0.0.1",
			ParentDeviceIp: "172.0.0.3",
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster-b/node2",
			Mac:            "00:ab:22:32:af:e2",
			Ipv4Addr:       "10.0.0.1",
			ParentDeviceIp: "172.0.12.1",
		})

		// We expect only one remote cluster tunnel route to be present, as the Calc Graph should assign a winner.
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.0/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.1/32",
			DstNodeName: "remote-cluster-a/node2",
			DstNodeIp:   "172.0.0.3",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})

		err := vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect the remote A L2 route to be programmed, rather than neither, since the remote B VTEP is conflicted in the Calc Graph.
		mac, err := net.ParseMAC("00:ab:22:32:af:e2")
		Expect(err).NotTo(HaveOccurred())
		Expect(fdb.currentVTEPs).To(Equal([]vxlanfdb.VTEP{
			{
				TunnelMAC: mac,
				TunnelIP:  ip.FromString("10.0.0.1"),
				HostIP:    ip.FromString("172.0.0.3"),
			},
		}))
	})

	It("utilizes L3 routes to resolve L2 conflicts when two VTEPs have the same MAC and one is conflicted at L3", func() {
		// Remote cluster A VTEP has the same MAC as C. Remote cluster B VTEP has the same IP as C.
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "node1",
			Mac:            "00:0a:74:9d:68:16",
			Ipv4Addr:       "10.0.0.0",
			ParentDeviceIp: "172.0.0.2",
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster-a/node2",
			Mac:            "00:ab:22:32:af:e2",
			Ipv4Addr:       "10.0.0.1",
			ParentDeviceIp: "172.0.0.3",
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster-b/node3",
			Mac:            "00:bc:22:32:ea:33",
			Ipv4Addr:       "10.0.0.2",
			ParentDeviceIp: "172.0.12.1",
		})
		vxlanMgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
			Node:           "remote-cluster-c/node2",
			Mac:            "00:ab:22:32:af:e2",
			Ipv4Addr:       "10.0.0.2",
			ParentDeviceIp: "172.0.22.2",
		})

		// We expect that the Calc Graph will assign B as the winner of the IP conflict.
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.0/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.1/32",
			DstNodeName: "remote-cluster-a/node2",
			DstNodeIp:   "172.0.0.3",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})
		vxlanMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.0.2/32",
			DstNodeName: "remote-cluster-b/node3",
			DstNodeIp:   "172.0.12.1",
			TunnelType:  &proto.TunnelType{Vxlan: true},
		})

		err := vxlanMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// As a result, we expect the A and B VTEP to be programmed. Since we ignore the C VTEP due to the L3 conflict, A is
		// not conflicted with it's MAC address.
		aMAC, err := net.ParseMAC("00:ab:22:32:af:e2")
		Expect(err).NotTo(HaveOccurred())
		bMAC, err := net.ParseMAC("00:bc:22:32:ea:33")
		Expect(err).NotTo(HaveOccurred())
		Expect(fdb.currentVTEPs).To(ConsistOf([]vxlanfdb.VTEP{
			{
				TunnelMAC: aMAC,
				TunnelIP:  ip.FromString("10.0.0.1"),
				HostIP:    ip.FromString("172.0.0.3"),
			},
			{
				TunnelMAC: bMAC,
				TunnelIP:  ip.FromString("10.0.0.2"),
				HostIP:    ip.FromString("172.0.12.1"),
			},
		}))
	})
})
