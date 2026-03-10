// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package fv_test

import (
	"context"
	"fmt"
	"regexp"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// This test verifies that egress gateway traffic is correctly routed via ExternalNetwork
// routing tables in both iptables and BPF dataplane modes.
//
// The customer scenario (CI-1953): EgressGateway pods with ExternalNetwork routing fail
// in BPF mode because the fwmark (0x10000000) is not set on outbound packets, so ip-rule
// entries never match and traffic falls back to the default route.
var _ = infrastructure.DatastoreDescribe(
	"_BPF-SAFE_ Egress IP with ExternalNetwork routing",
	[]apiconfig.DatastoreType{apiconfig.Kubernetes},
	func(getInfra infrastructure.InfraFactory) {
		var (
			infra        infrastructure.DatastoreInfra
			tc           infrastructure.TopologyContainers
			calicoClient client.Interface
			overlay      bool

			// The egress gateway workload — registered in the datastore.
			egw *workload.Workload

			// A client workload that uses the egress gateway.
			clientW *workload.Workload

			// Fake external interface — NOT registered in the datastore.
			// This simulates the ExternalNetwork exit interface.
			extIface *workload.Workload

			// ExternalNetwork routing table index.
			extNetTableIndex uint32 = 920
		)

		// JustBeforeEach so that the overlay/sameNode variables are set by Context BeforeEach.
		JustBeforeEach(func() {
			infra = getInfra()
			opts := infrastructure.DefaultTopologyOptions()
			opts.FelixLogSeverity = "Debug"
			opts.ExtraEnvVars["FELIX_EGRESSIPSUPPORT"] = "EnabledPerNamespaceOrPerPod"
			opts.ExtraEnvVars["FELIX_EGRESSIPVXLANPORT"] = "4790"
			opts.ExtraEnvVars["FELIX_EGRESSIPHOSTIFACEPATTERN"] = "eth0"
			opts.ExtraEnvVars["FELIX_ExternalNetworkSupport"] = "Enabled"
			opts.ExtraEnvVars["FELIX_PolicySyncPathPrefix"] = "/var/run/calico/policysync"
			opts.EnableIPv6 = false
			if overlay {
				opts.VXLANMode = api.VXLANModeAlways
				opts.VXLANStrategy = infrastructure.NewDefaultTunnelStrategy(opts.IPPoolCIDR, opts.IPv6PoolCIDR)
			}
			opts.IPIPMode = api.IPIPModeNever
			if BPFMode() {
				opts.ExtraEnvVars["FELIX_BPFLogLevel"] = "Debug"
			}
			tc, calicoClient = infrastructure.StartNNodeTopology(2, opts, infra)

			infra.AddDefaultAllow()

			By("Creating egress IP pool")
			egressPool := api.NewIPPool()
			egressPool.Name = "egress-pool"
			egressPool.Spec.CIDR = "172.25.154.0/24"
			egressPool.Spec.NATOutgoing = false
			egressPool.Spec.BlockSize = 26
			egressPool.Spec.NodeSelector = "!all()"
			if overlay {
				egressPool.Spec.VXLANMode = api.VXLANModeAlways
			}
			_, err := calicoClient.IPPools().Create(context.Background(), egressPool, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Creating ExternalNetwork resource")
			_, err = calicoClient.ExternalNetworks().Create(context.Background(), &api.ExternalNetwork{
				ObjectMeta: metav1.ObjectMeta{Name: "ext-net-920"},
				Spec: api.ExternalNetworkSpec{
					RouteTableIndex: &extNetTableIndex,
				},
			}, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			if clientW != nil {
				clientW.Stop()
				clientW = nil
			}
			if egw != nil {
				egw.Stop()
				egw = nil
			}
			if extIface != nil {
				extIface.Stop()
				extIface = nil
			}
			if calicoClient != nil {
				calicoClient.ExternalNetworks().Delete(context.Background(), "ext-net-920", options.DeleteOptions{})
				calicoClient.IPPools().Delete(context.Background(), "egress-pool", options.DeleteOptions{})
			}
			tc.Stop()
			infra.Stop()
		})

		// setupEgwNode configures the egress gateway, external interface, and routing
		// on the given Felix node. Returns the Felix hosting the egw.
		setupEgwNode := func(egwFelix *infrastructure.Felix) {
			By("Creating egress gateway workload on " + egwFelix.Name)
			infrastructure.AssignIP("egw-0", "172.25.154.1", egwFelix.Hostname, calicoClient)
			egw = workload.RunEgressGateway(egwFelix, "egw-0", "default", "172.25.154.1")
			egw.WorkloadEndpoint.Spec.ExternalNetworkNames = []string{"ext-net-920"}
			egw.ConfigureInInfra(infra)

			By("Setting up fake external interface on " + egwFelix.Name)
			extIface = &workload.Workload{
				Name:          "eth20",
				C:             egwFelix.Container,
				IP:            "192.168.20.1",
				Ports:         "57005",
				Protocol:      "tcp",
				InterfaceName: "eth20",
				MTU:           1500,
			}
			err := extIface.Start(infra)
			Expect(err).NotTo(HaveOccurred())

			By("Configuring RPF to allow asymmetric routing on " + egwFelix.Name)
			egwFelix.Exec("sysctl", "-w", "net.ipv4.conf.eth0.rp_filter=2")
			Eventually(func() error {
				return egwFelix.ExecMayFail("sysctl", "-w", "net.ipv4.conf.eth20.rp_filter=2")
			}, "5s", "300ms").Should(Succeed())

			By("Setting up ExternalNetwork routing table on " + egwFelix.Name)
			egwFelix.Exec("ip", "addr", "add", "192.168.20.20/24", "dev", "eth20")
			egwFelix.Exec("bash", "-c", fmt.Sprintf("echo %d ext_net_table >> /etc/iproute2/rt_tables", extNetTableIndex))
			egwFelix.Exec("ip", "neigh", "add", "192.168.20.100", "lladdr", "ee:ee:ee:ee:ee:ee", "dev", "eth20")
			egwFelix.Exec("ip", "route", "add", "default", "dev", "eth20",
				"table", fmt.Sprintf("%d", extNetTableIndex))
			// Add a fake neighbor for the health probe ping target so the kernel
			// can resolve the next-hop and actually send the packet on eth20.
			egwFelix.Exec("ip", "neigh", "add", "10.99.99.99", "lladdr", "ee:ee:ee:ee:ee:ee", "dev", "eth20")
			egwFelix.Exec("ip", "route", "flush", "cache")
		}

		setupClient := func(clientFelix *infrastructure.Felix) {
			By("Creating client workload on " + clientFelix.Name)
			infrastructure.AssignIP("client-0", "10.65.0.2", clientFelix.Hostname, calicoClient)
			clientW = workload.Run(clientFelix, "client-0", "default", "10.65.0.2", "8055", "tcp")
			clientW.WorkloadEndpoint.Spec.EgressGateway = &api.EgressGatewaySpec{
				Gateway: &api.EgressSpec{
					Selector: fmt.Sprintf("name == '%s'", egw.Name),
				},
			}
			clientW.ConfigureInInfra(infra)
		}

		waitForIPRule := func(egwFelix *infrastructure.Felix) {
			fwmark := "0x80000/0x80000"
			if BPFMode() {
				fwmark = "0x10000000/0x10000000"
			}
			Eventually(func() string {
				out, _ := egwFelix.ExecOutput("ip", "rule")
				return out
			}, "15s", "500ms").Should(And(
				ContainSubstring("172.25.154.1"),
				MatchRegexp(`lookup (920|ext_net_table)`),
				ContainSubstring(fwmark),
			))
		}

		checkConnectivity := func(egwFelix *infrastructure.Felix) {
			By("Attaching tcpdump on eth20 to verify traffic exits via external interface")
			dump := egwFelix.AttachTCPDump("eth20")
			dump.SetLogEnabled(true)
			dump.AddMatcher("egw-traffic", regexp.MustCompile(`172\.25\.154\.1`))
			dump.Start(infra, "-v", "src", "host", "172.25.154.1")

			By("Verifying end-to-end connectivity: client -> egw -> ExternalNetwork -> extIface")
			cc := &connectivity.Checker{
				Protocol: "tcp",
			}
			if BPFMode() {
				cc.MinTimeout = 30 * time.Second
			}
			cc.CheckSNAT = true
			cc.ExpectSNAT(clientW, "172.25.154.1", extIface, 57005)
			cc.CheckConnectivity()

			By("Verifying traffic appeared on eth20 with egress gateway source IP")
			Eventually(dump.MatchCountFn("egw-traffic"), "10s", "330ms").Should(
				BeNumerically(">=", 1),
				"Expected egress gateway traffic to exit via eth20 (ExternalNetwork interface)")
		}

		for _, useOverlay := range []bool{false, true} {
			for _, sameNode := range []bool{true, false} {
				desc := ""
				if useOverlay {
					desc += "VXLAN overlay"
				} else {
					desc += "no overlay"
				}
				desc += ", client and gateway on "
				if sameNode {
					desc += "same node"
				} else {
					desc += "different nodes"
				}

				Context(desc, func() {
					// Capture loop variables.
					sameNode := sameNode
					useOverlay := useOverlay

					BeforeEach(func() {
						overlay = useOverlay
					})

					JustBeforeEach(func() {
						// EGW always on node 1 (tc.Felixes[1]).
						egwFelix := tc.Felixes[1]
						setupEgwNode(egwFelix)

						// Client on same or different node.
						clientFelix := tc.Felixes[0]
						if sameNode {
							clientFelix = tc.Felixes[1]
						}
						setupClient(clientFelix)

						if !sameNode && !useOverlay {
							// Without overlay, cross-node needs a manual route
							// for the egress IP to reach the EGW node.
							tc.Felixes[0].Exec("ip", "route", "add", "172.25.154.1/32", "via", egwFelix.IP)
						}

						if BPFMode() {
							ensureAllNodesBPFProgramsAttached(tc.Felixes, "egress.calico")
						}
					})

					It("should create ip-rule entries with fwmark for egress gateway IPs", func() {
						waitForIPRule(tc.Felixes[1])
					})

					It("should route client traffic via egress gateway and ExternalNetwork interface", func() {
						waitForIPRule(tc.Felixes[1])
						checkConnectivity(tc.Felixes[1])
					})

					It("should route egress gateway pod's own traffic via ExternalNetwork interface (health probes)", func() {
						egwFelix := tc.Felixes[1]
						waitForIPRule(egwFelix)

						By("Starting tcpdump on eth20 to capture ICMP from egress gateway pod")
						dump := egwFelix.AttachTCPDump("eth20")
						dump.SetLogEnabled(true)
						dump.AddMatcher("icmp-from-egw", regexp.MustCompile(`172\.25\.154\.1`))
						dump.Start(infra, "-v", "icmp")

						By("Pinging external IP from egress gateway pod's network namespace")
						// Ping a non-routable IP. We only need to verify the packet exits
						// via eth20 (ExternalNetwork table), not that it gets a reply.
						// Table 920 routes via gateway 192.168.20.100 on eth20.
						egw.RunCmd("ping", "-c", "3", "-W", "1", "10.99.99.99")

						By("Verifying ICMP packets appeared on eth20 with egress gateway source IP")
						Eventually(dump.MatchCountFn("icmp-from-egw"), "10s", "330ms").Should(
							BeNumerically(">=", 1),
							"Expected egw pod's own ICMP traffic to exit via eth20 (ExternalNetwork interface)")
					})
				})
			}
		}
	},
)
