// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package intdataplane

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
)

var _ = Describe("ExternalNetworkManager", func() {
	Describe("Handling updates", func() {
		var manager *externalNetworkManager
		var dpConfig Config
		var rr *mockRouteRules
		var rrFactory *mockRouteRulesFactory

		BeforeEach(func() {
			rrFactory = &mockRouteRulesFactory{routeRules: nil}
			dpConfig = Config{
				RulesConfig: rules.Config{
					MarkEgress: 0x200,
				},
				ExternalNetworkEnabled:             true,
				ExternalNetworkRoutingRulePriority: 100,
			}

			manager = newExternalNetworkManagerWithShims(
				dpConfig,
				rrFactory,
				logutils.NewSummarizer("test loop"),
			)

			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())

			// No routeRules should be created.
			Expect(manager.routeRules).To(BeNil())
		})

		expectNoRules := func(srcIPs []string, table int) {
			var activeRules []netlink.Rule
			for _, r := range rr.GetAllActiveRules() {
				activeRules = append(activeRules, *r.NetLinkRule())
			}
			for _, srcIP := range srcIPs {
				Expect(rr.hasRule(100, srcIP, 0x200, table)).To(BeFalse(), "Expect rule with srcIP: %s, and table: %d, to not exist. Active rules = %v", srcIP, table, activeRules)
			}
		}

		expectNoRulesWithSrc := func(srcIPs []string) {
			var activeRules []netlink.Rule
			for _, r := range rr.GetAllActiveRules() {
				activeRules = append(activeRules, *r.NetLinkRule())
			}
			for _, srcIP := range srcIPs {
				Expect(rr.hasRuleWithSrc(100, srcIP, 0x200)).To(BeFalse(), "Expect rule with srcIP: %s to not exist. Active rules = %v", srcIP, activeRules)
			}
		}

		expectRules := func(srcIPs []string, table int) {
			var activeRules []netlink.Rule
			for _, r := range rr.GetAllActiveRules() {
				activeRules = append(activeRules, *r.NetLinkRule())
			}
			for _, srcIP := range srcIPs {
				Expect(rr.hasRule(100, srcIP, 0x200, table)).To(BeTrue(), "Expect rule with srcIP: %s, and table: %d, to exist. Active rules = %v", srcIP, table, activeRules)
			}
		}

		Describe("with multiple networks and endpoints update", func() {
			BeforeEach(func() {
				manager.OnUpdate(dummyExternalNetworkUpdate("net0", 100))
				manager.OnUpdate(dummyExternalNetworkUpdate("net1", 101))
				// No update for net2.

				manager.OnUpdate(dummyWorkloadEndpointUpdateExternalNetwork(0, []string{"10.0.240.0/32"}, []string{"net0"}))
				manager.OnUpdate(dummyWorkloadEndpointUpdateExternalNetwork(1, []string{"10.0.241.0/32"}, []string{"net2"}))
				manager.OnUpdate(dummyWorkloadEndpointUpdateExternalNetwork(2, []string{"10.0.242.0/32", "10.0.242.1/32"}, []string{"net0", "net1"}))
				manager.OnUpdate(dummyWorkloadEndpointUpdateExternalNetwork(3, []string{"10.0.243.0/32"}, []string{"net0", "net2"}))

				err := manager.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())

				// routeRules should be created.
				Expect(manager.routeRules).NotTo(BeNil())
				rr = rrFactory.Rules()

				expectRules([]string{"10.0.240.0/32"}, 100)
				expectNoRulesWithSrc([]string{"10.0.241.0/32"}) // no update for net2
				expectRules([]string{"10.0.242.0/32", "10.0.242.1/32"}, 100)
				expectRules([]string{"10.0.242.0/32", "10.0.242.1/32"}, 101)
				expectRules([]string{"10.0.243.0/32"}, 100)
			})

			It("should support external network update", func() {
				manager.OnUpdate(dummyExternalNetworkUpdate("net0", 99))  // Update net0
				manager.OnUpdate(dummyExternalNetworkUpdate("net2", 102)) // Add net2

				err := manager.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())

				expectRules([]string{"10.0.240.0/32"}, 99)
				expectRules([]string{"10.0.241.0/32"}, 102)
				expectRules([]string{"10.0.242.0/32", "10.0.242.1/32"}, 99)
				expectRules([]string{"10.0.242.0/32", "10.0.242.1/32"}, 101)
				expectRules([]string{"10.0.243.0/32"}, 99)
				expectRules([]string{"10.0.243.0/32"}, 102)
			})

			It("should support external network remove", func() {
				manager.OnUpdate(dummyExternalNetworkRemove("net0"))      // Remove net0
				manager.OnUpdate(dummyExternalNetworkUpdate("net2", 102)) // Add net2

				err := manager.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())

				expectNoRulesWithSrc([]string{"10.0.240.0/32"})
				expectRules([]string{"10.0.241.0/32"}, 102)
				expectNoRules([]string{"10.0.242.0/32"}, 100)
				expectNoRules([]string{"10.0.242.1/32"}, 100)
				expectRules([]string{"10.0.242.0/32", "10.0.242.1/32"}, 101)
				expectNoRules([]string{"10.0.243.0/32"}, 100)
				expectRules([]string{"10.0.243.0/32"}, 102)
			})

			It("should support workload endpoint update", func() {
				// Update from net0 to net1.
				manager.OnUpdate(dummyWorkloadEndpointUpdateExternalNetwork(1, []string{"10.0.241.0/32"}, []string{"net1"}))
				// Update first ip, set network to net1.
				manager.OnUpdate(dummyWorkloadEndpointUpdateExternalNetwork(2, []string{"10.0.245.0/32", "10.0.242.1/32"}, []string{"net1"}))

				err := manager.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())

				expectRules([]string{"10.0.240.0/32"}, 100)
				expectRules([]string{"10.0.241.0/32"}, 101)
				expectNoRules([]string{"10.0.242.0/32", "10.0.242.1/32"}, 100)
				expectRules([]string{"10.0.245.0/32", "10.0.242.1/32"}, 101)
				expectRules([]string{"10.0.243.0/32"}, 100)
			})

			It("should support workload endpoint remove", func() {
				// Remove pod 2.
				manager.OnUpdate(&proto.WorkloadEndpointRemove{
					Id: &proto.WorkloadEndpointID{
						OrchestratorId: "k8s",
						WorkloadId:     "default/pod-2",
						EndpointId:     "endpoint-id-2",
					},
				})

				err := manager.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())

				expectNoRulesWithSrc([]string{"10.0.242.0/32", "10.0.242.1/32"})
			})
		})
	})

})

func dummyExternalNetworkUpdate(name string, routeTableIndex int) *proto.ExternalNetworkUpdate {
	return &proto.ExternalNetworkUpdate{
		Id:      &proto.ExternalNetworkID{Name: name},
		Network: &proto.ExternalNetwork{Name: name, RouteTableIndex: uint32(routeTableIndex)},
	}
}

func dummyExternalNetworkRemove(name string) *proto.ExternalNetworkRemove {
	return &proto.ExternalNetworkRemove{
		Id: &proto.ExternalNetworkID{Name: name},
	}
}
