// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.
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
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libcalicoapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

type Overlay int

const (
	OV_NONE  Overlay = 1
	OV_VXLAN Overlay = 2
	OV_IPIP  Overlay = 3
)

func (ov Overlay) String() string {
	switch ov {
	case OV_NONE:
		return "no overlay"
	case OV_VXLAN:
		return "VXLAN overlay"
	case OV_IPIP:
		return "IP-IP overlay"
	}
	return "invalid value"
}

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ Egress IP", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra        infrastructure.DatastoreInfra
		tc           infrastructure.TopologyContainers
		client       client.Interface
		err          error
		supportLevel string
	)

	overlay := OV_NONE

	makeGatewayWithLabel := func(felix *infrastructure.Felix, wIP, wName, egwLable string) *workload.Workload {
		infrastructure.AssignIP(wName, wIP, felix.Hostname, client)
		gw := workload.RunEgressGateway(felix, wName, "default", wIP)
		gw.WorkloadEndpoint.Labels["egress-code"] = egwLable
		gw.ConfigureInInfra(infra)
		return gw
	}

	makeGateway := func(felix *infrastructure.Felix, wIP, wName string) *workload.Workload {
		return makeGatewayWithLabel(felix, wIP, wName, "red")
	}

	rulesProgrammed := func(felix *infrastructure.Felix, polNames []string) bool {
		out, err := getRuleset(felix)
		if err != nil {
			return false
		}
		for _, polName := range polNames {
			if strings.Count(out, polName) == 0 {
				return false
			}
		}
		return true
	}

	createHostEndPointPolicy := func(felix *infrastructure.Felix) {
		protoTCP := numorstring.ProtocolFromString(numorstring.ProtocolTCP)
		protoUDP := numorstring.ProtocolFromString(numorstring.ProtocolUDP)

		hep := api.NewHostEndpoint()
		hep.Name = "hep-" + felix.Name
		hep.Labels = map[string]string{
			"name":          hep.Name,
			"hostname":      felix.Hostname,
			"host-endpoint": "true",
		}
		hep.Spec.Node = felix.Hostname
		hep.Spec.ExpectedIPs = []string{felix.IP}
		hep.Spec.InterfaceName = "eth0"
		_, err := client.HostEndpoints().Create(utils.Ctx, hep, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// create an allow-all policy
		order := 100.0
		allowAllPolicy := api.NewGlobalNetworkPolicy()
		allowAllPolicy.Name = "default.allow-all"
		allowAllPolicy.Spec.Ingress = []api.Rule{{Action: api.Allow}}
		allowAllPolicy.Spec.Egress = []api.Rule{{Action: api.Allow}}
		allowAllPolicy.Spec.Selector = fmt.Sprintf("hostname == '%s'", felix.Hostname)
		allowAllPolicy.Spec.Order = &order
		allowAllPolicy, err = client.GlobalNetworkPolicies().Create(utils.Ctx, allowAllPolicy, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// create a policy to drop traffic to port 4790
		order = 0.0
		denyEGWPolicy := api.NewGlobalNetworkPolicy()
		denyEGWPolicy.Name = "default.deny-egw"
		denyEGWPolicy.Spec.Egress = []api.Rule{{Action: api.Deny, Protocol: &protoUDP}}
		denyEGWPolicy.Spec.Egress[0].Destination = api.EntityRule{Ports: []numorstring.Port{numorstring.SinglePort(4790)}}
		denyEGWPolicy.Spec.Selector = fmt.Sprintf("hostname == '%s'", felix.Hostname)
		denyEGWPolicy.Spec.Order = &order
		denyEGWPolicy, err = client.GlobalNetworkPolicies().Create(utils.Ctx, denyEGWPolicy, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// create a policy to drop EGW health probes
		order = 1.0
		denyEGWHealthPolicy := api.NewGlobalNetworkPolicy()
		denyEGWHealthPolicy.Name = "default.deny-egw-health"
		denyEGWHealthPolicy.Spec.Egress = []api.Rule{{Action: api.Deny, Protocol: &protoTCP}}
		denyEGWHealthPolicy.Spec.Egress[0].Destination = api.EntityRule{Ports: []numorstring.Port{numorstring.SinglePort(8080)}}
		denyEGWHealthPolicy.Spec.Selector = fmt.Sprintf("hostname == '%s'", felix.Hostname)
		denyEGWHealthPolicy.Spec.Order = &order
		denyEGWHealthPolicy, err = client.GlobalNetworkPolicies().Create(utils.Ctx, denyEGWHealthPolicy, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		if BPFMode() {
			hostEndpointProgrammed := func() bool {
				return felix.NumTCBPFProgsEth0() == 2
			}
			Eventually(hostEndpointProgrammed, "30s", "1s").Should(BeTrue(),
				"Expected host endpoint to be programmed")

			Eventually(func() bool {
				return bpfCheckIfGlobalNetworkPolicyProgrammed(felix, "eth0", "egress", "default.allow-all", "allow", false)
			}, "5s", "200ms").Should(BeTrue())

			Eventually(func() bool {
				return bpfCheckIfGlobalNetworkPolicyProgrammed(felix, "eth0", "ingress", "default.allow-all", "allow", false)
			}, "5s", "200ms").Should(BeTrue())

			Eventually(func() bool {
				return bpfCheckIfGlobalNetworkPolicyProgrammed(felix, "eth0", "egress", "default.deny-egw", "deny", false)
			}, "5s", "200ms").Should(BeTrue())

			Eventually(func() bool {
				return bpfCheckIfGlobalNetworkPolicyProgrammed(felix, "eth0", "egress", "default.deny-egw-health", "deny", false)
			}, "5s", "200ms").Should(BeTrue())
		} else {
			hostEndpointProgrammed := func() bool {
				out, err := getRuleset(felix)
				Expect(err).NotTo(HaveOccurred())
				return (strings.Count(out, "cali-thfw-eth0") > 0)
			}
			Eventually(hostEndpointProgrammed, "10s", "1s").Should(BeTrue(),
				"Expected HostEndpoint rules to appear")
			polNames := []string{"default.allow-all", "default.deny-egw", "default.deny-egw-health"}
			Eventually(func() bool {
				return rulesProgrammed(felix, polNames)
			}, "10s", "1s").Should(BeTrue(), "Expected rules to appear on the felix instances")
		}
	}

	makeClient := func(felix *infrastructure.Felix, wIP, wName string) *workload.Workload {
		infrastructure.AssignIP(wName, wIP, felix.Hostname, client)
		app := workload.Run(felix, wName, "default", wIP, "8055", "tcp")
		app.WorkloadEndpoint.Spec.EgressGateway = &api.EgressGatewaySpec{
			Gateway: &api.EgressSpec{
				Selector: "egress-code == 'red'",
			},
		}
		app.ConfigureInInfra(infra)
		return app
	}

	makeClientWithEGWPolicy := func(felix *infrastructure.Felix, wIP, wName, policy string) *workload.Workload {
		infrastructure.AssignIP(wName, wIP, felix.Hostname, client)
		app := workload.Run(felix, wName, "default", wIP, "8055", "tcp")
		app.WorkloadEndpoint.Spec.EgressGateway = &api.EgressGatewaySpec{
			Policy: policy,
			Gateway: &api.EgressSpec{
				Selector: "egress-code == 'red'",
			},
		}
		app.ConfigureInInfra(infra)
		return app
	}

	getIPRules := func() map[string]string {
		rules, err := tc.Felixes[0].ExecOutput("ip", "rule")
		log.WithError(err).Infof("ip rule said:\n%v", rules)
		Expect(err).NotTo(HaveOccurred())
		mappings := map[string]string{}
		fwmarkRE := regexp.MustCompile(`from ([0-9.]+) fwmark [^ ]+ lookup ([0-9]+)`)
		for line := range strings.SplitSeq(rules, "\n") {
			match := fwmarkRE.FindStringSubmatch(line)
			if len(match) < 3 {
				continue
			}
			mappings[match[1]] = match[2]
		}
		log.Infof("Found mappings: %v", mappings)
		return mappings
	}

	getIPRoute := func(table string) string {
		route, err := tc.Felixes[0].ExecOutput("ip", "r", "l", "table", table)
		log.WithError(err).Infof("ip r l said:\n%v", route)
		Expect(err).NotTo(HaveOccurred())
		return strings.TrimSpace(route)
	}

	checkIPRoute := func(table, expectedRoute string) {
		Eventually(func() string {
			return getIPRoute(table)
		}, "10s", "1s").Should(Equal(expectedRoute))
		Consistently(func() string {
			return getIPRoute(table)
		}).Should(Equal(expectedRoute))
	}

	getIPNeigh := func() map[string]string {
		neigh, err := tc.Felixes[0].ExecOutput("ip", "neigh", "show", "dev", "egress.calico")
		log.WithError(err).Infof("ip neigh said:\n%v", neigh)
		Expect(err).NotTo(HaveOccurred())
		mappings := map[string]string{}
		lladdrRE := regexp.MustCompile(`([0-9.]+) lladdr ([0-9a-f:]+)`)
		for line := range strings.SplitSeq(neigh, "\n") {
			match := lladdrRE.FindStringSubmatch(line)
			if len(match) < 3 {
				continue
			}
			mappings[match[1]] = match[2]
		}
		log.Infof("Found mappings: %v", mappings)
		return mappings
	}

	getBridgeFDB := func() map[string]string {
		fdb, err := tc.Felixes[0].ExecOutput("bridge", "fdb", "show", "dev", "egress.calico")
		log.WithError(err).Infof("bridge fdb said:\n%v", fdb)
		Expect(err).NotTo(HaveOccurred())
		mappings := map[string]string{}
		fdbRE := regexp.MustCompile(`([0-9a-f:]+) dst ([0-9.]+)`)
		for line := range strings.SplitSeq(fdb, "\n") {
			match := fdbRE.FindStringSubmatch(line)
			if len(match) < 3 {
				continue
			}
			mappings[match[1]] = match[2]
		}
		log.Infof("Found mappings: %v", mappings)
		return mappings
	}

	createEgwIngPol := func(gw *workload.Workload) {
		protoUDP := numorstring.ProtocolFromString(numorstring.ProtocolUDP)
		pol := api.NewGlobalNetworkPolicy()
		pol.Name = "default.egw-deny-ingress"
		pol.Spec.Tier = "default"
		pol.Spec.Types = []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress}
		pol.Spec.Ingress = []api.Rule{{Action: api.Deny, Protocol: &protoUDP}}
		pol.Spec.Ingress[0].Destination = api.EntityRule{Ports: []numorstring.Port{numorstring.SinglePort(4790)}}
		pol.Spec.Egress = []api.Rule{{Action: api.Allow}}
		pol.Spec.Selector = gw.NameSelector()
		pol, err := client.GlobalNetworkPolicies().Create(utils.Ctx, pol, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())
	}

	JustBeforeEach(func() {
		infra = getInfra()
		topologyOptions := infrastructure.DefaultTopologyOptions()
		topologyOptions.FelixDebugFilenameRegex = `route_table\.go|egress_ip_mgr\.go`
		topologyOptions.ExtraEnvVars["FELIX_EGRESSIPSUPPORT"] = supportLevel
		topologyOptions.ExtraEnvVars["FELIX_PolicySyncPathPrefix"] = "/var/run/calico/policysync"
		topologyOptions.ExtraEnvVars["FELIX_EGRESSIPVXLANPORT"] = "4790"
		topologyOptions.ExtraEnvVars["FELIX_EGRESSIPVXLANPORT"] = "4790"
		topologyOptions.ExtraEnvVars["FELIX_EGRESSIPHOSTIFACEPATTERN"] = "eth0"
		// IPv6 is not supported in egress gateways
		topologyOptions.EnableIPv6 = false
		if overlay == OV_VXLAN {
			topologyOptions.VXLANMode = api.VXLANModeAlways
			topologyOptions.VXLANStrategy = infrastructure.NewDefaultTunnelStrategy(topologyOptions.IPPoolCIDR, topologyOptions.IPv6PoolCIDR)
		}
		if overlay != OV_IPIP {
			topologyOptions.IPIPMode = api.IPIPModeNever
		}
		tc, client = infrastructure.StartNNodeTopology(2, topologyOptions, infra)

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		// Create an egress IP pool.
		ippool := api.NewIPPool()
		ippool.Name = "egress-pool"
		ippool.Spec.CIDR = "10.10.10.0/29"
		ippool.Spec.NATOutgoing = false
		ippool.Spec.BlockSize = 29
		ippool.Spec.NodeSelector = "!all()"
		switch overlay {
		case OV_VXLAN:
			ippool.Spec.VXLANMode = api.VXLANModeAlways
		case OV_IPIP:
			ippool.Spec.IPIPMode = api.IPIPModeAlways
		}
		_, err = client.IPPools().Create(context.Background(), ippool, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	expectedRoute := func(ips ...string) string {
		if len(ips) == 0 {
			return "unreachable default scope link"
		} else if len(ips) == 1 {
			return "default via " + ips[0] + " dev egress.calico onlink"
		} else {
			var r strings.Builder
			r.WriteString("default onlink \n")
			for _, ip := range ips {
				r.WriteString("\tnexthop via " + ip + " dev egress.calico weight 1 onlink \n")
			}
			return strings.TrimSpace(r.String())
		}
	}

	Context("EnabledPerNamespaceOrPerPod", func() {
		BeforeEach(func() {
			supportLevel = "EnabledPerNamespaceOrPerPod"
		})

		Context("with external server", func() {
			var (
				extHost     *containers.Container
				extWorkload *workload.Workload
				cc          *connectivity.Checker
				protocol    string
			)

			JustBeforeEach(func() {
				extHostOpts := infrastructure.ExtClientOpts{
					Image: utils.Config.FelixImage,
				}
				extHost = infrastructure.RunExtClientWithOpts(infra, "external-server", extHostOpts)

				extWorkload = &workload.Workload{
					C:        extHost,
					Name:     "ext-server",
					Ports:    "4321",
					Protocol: protocol,
					IP:       extHost.IP,
				}

				err = extWorkload.Start(infra)
				Expect(err).NotTo(HaveOccurred())

				cc = &connectivity.Checker{
					Protocol: protocol,
				}
				if BPFMode() {
					cc.MinTimeout = 30 * time.Second
				}
			})

			AfterEach(func() {
				extWorkload.Stop()
				extHost.Stop()
			})

			for _, sameNode := range []bool{true, false} {
				for _, ov := range []Overlay{OV_NONE, OV_VXLAN, OV_IPIP} {
					for _, proto := range []string{"tcp", "udp"} {
						description := "with " + ov.String() + ", client and gateway on "
						if sameNode {
							description += "same node"
						} else {
							description += "different nodes"
						}
						description += " (" + proto + ")"

						Context("egress selector "+description, func() {
							var egwClient, gw *workload.Workload

							BeforeEach(func() {
								overlay = ov
								protocol = proto
							})

							JustBeforeEach(func() {
								rulesProgrammed := func() bool {
									felix := tc.Felixes[1]
									if sameNode {
										felix = tc.Felixes[0]
									}
									if BPFMode() {
										return bpfCheckIfGlobalNetworkPolicyProgrammed(felix, gw.InterfaceName, "ingress", "default.egw-deny-ingress", "deny", true)
									}
									out, err := getRuleset(felix)
									Expect(err).NotTo(HaveOccurred())
									return (strings.Contains(out, "default.egw-deny-ingress"))
								}
								egwClient = makeClient(tc.Felixes[0], "10.65.0.2", "client")
								if sameNode {
									gw = makeGateway(tc.Felixes[0], "10.10.10.1", "gw")
								} else {
									gw = makeGateway(tc.Felixes[1], "10.10.10.1", "gw")
									switch ov {
									case OV_NONE:
										tc.Felixes[0].Exec("ip", "route", "add", "10.10.10.1/32", "via", gw.C.IP)
									case OV_VXLAN:
										// Felix programs the routes in this case.
									case OV_IPIP:
										tc.Felixes[0].Exec("ip", "route", "add", "10.10.10.1/32", "via", gw.C.IP, "dev", "tunl0", "onlink")
									}
								}
								if BPFMode() {
									ensureAllNodesBPFProgramsAttached(tc.Felixes, "egress.calico")
								}
								if !sameNode && ov == OV_NONE {
									createHostEndPointPolicy(tc.Felixes[0])
								}
								createEgwIngPol(gw)
								Eventually(rulesProgrammed, "10s", "1s").Should(BeTrue(),
									"Expected rules to appear on the correct felix instances")
								extWorkload.C.Exec("ip", "route", "add", "10.10.10.1/32", "via", gw.C.IP)
							})

							AfterEach(func() {
								egwClient.Stop()
								gw.Stop()
							})

							It("should preserve DSCP with traffic SNATed by egress gateways", func() {
								extWorkload.C.Exec("ip", "route", "add", egwClient.IP, "via", tc.Felixes[0].IP)
								extWorkload.C.Exec("iptables", "-A", "INPUT", "-m", "dscp", "!", "--dscp", "0x20", "-j", "DROP")

								cc.ExpectNone(egwClient, extWorkload)
								cc.CheckConnectivity()

								dscp32 := numorstring.DSCPFromInt(32) // 0x20
								egwClient.WorkloadEndpoint.Spec.QoSControls = &libcalicoapi.QoSControls{
									DSCP: &dscp32,
								}
								egwClient.UpdateInInfra(infra)

								cc.ResetExpectations()
								cc.ExpectSNAT(egwClient, gw.IP, extWorkload, 4321)
								cc.CheckConnectivity()
							})

							It("should use Host IP when ippool natOutgoing is true", func() {
								// Check that originally traffic is SNATed to the gateway pod's IP
								cc.ResetExpectations()
								cc.ExpectSNAT(egwClient, gw.IP, extWorkload, 4321)
								cc.CheckConnectivity()

								// Enable natOutgoing on the egress IP pool.
								ippool, err := client.IPPools().Get(context.Background(), "egress-pool", options.GetOptions{})
								Expect(err).NotTo(HaveOccurred())
								ippool.Spec.NATOutgoing = true
								_, err = client.IPPools().Update(context.Background(), ippool, options.SetOptions{})
								Expect(err).NotTo(HaveOccurred())

								// The traffic should be SNATed to the IP of the node hosting the gateway pod.
								gwNodeIP := tc.Felixes[0].IP
								if !sameNode {
									gwNodeIP = tc.Felixes[1].IP
								}

								// Check connectivity which should be SNATed to the Host IP.
								cc.ResetExpectations()
								cc.ExpectSNAT(egwClient, gwNodeIP, extWorkload, 4321)
								cc.CheckConnectivity()

								// Revert natOutgoing back to false.
								ippool, err = client.IPPools().Get(context.Background(), "egress-pool", options.GetOptions{})
								Expect(err).NotTo(HaveOccurred())
								ippool.Spec.NATOutgoing = false
								_, err = client.IPPools().Update(context.Background(), ippool, options.SetOptions{})
								Expect(err).NotTo(HaveOccurred())

								// Traffic should now be SNATed to the gateway pod's IP again.
								cc.ResetExpectations()
								cc.ExpectSNAT(egwClient, gw.IP, extWorkload, 4321)
								cc.CheckConnectivity()
							})
						})
					}
				}
			}
		})

		Context("with 3 external servers", func() {
			var (
				extHosts     []*containers.Container
				extWorkloads []*workload.Workload
				cc           *connectivity.Checker
				protocol     string
				ctx          context.Context
				cancel       context.CancelFunc
			)

			JustBeforeEach(func() {
				for i := range 4 {
					extHost := infrastructure.RunExtClient(infra, "external-server")
					extWorkload := &workload.Workload{
						C:        extHost,
						Name:     fmt.Sprintf("ext-server%v", i),
						Ports:    "4321",
						Protocol: protocol,
						IP:       extHost.IP,
					}
					err = extWorkload.Start(infra)
					Expect(err).NotTo(HaveOccurred())
					extHosts = append(extHosts, extHost)
					extWorkloads = append(extWorkloads, extWorkload)
				}

				cc = &connectivity.Checker{
					Protocol: protocol,
				}
				if BPFMode() {
					cc.MinTimeout = 30 * time.Second
				}

				// Create an egress IP pool.
				ippool := api.NewIPPool()
				ippool.Name = "egress-pool-blue"
				ippool.Spec.CIDR = "10.10.11.0/29"
				ippool.Spec.NATOutgoing = false
				ippool.Spec.BlockSize = 29
				ippool.Spec.NodeSelector = "!all()"
				switch overlay {
				case OV_VXLAN:
					ippool.Spec.VXLANMode = api.VXLANModeAlways
				case OV_IPIP:
					ippool.Spec.IPIPMode = api.IPIPModeAlways
				}
				_, err = client.IPPools().Create(context.Background(), ippool, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())

				egwPolicy1 := api.NewEgressGatewayPolicy()
				egwPolicy1.Name = "egw-policy1"
				egwPolicy1.Spec.Rules = []api.EgressGatewayRule{
					{
						Description: "to reach to workload 0 directly, skipping egw",
						Destination: &api.EgressGatewayPolicyDestinationSpec{
							CIDR: extWorkloads[0].IP,
						},
					},
					{
						Description: "to reach to workload 1 via egw blue",
						Destination: &api.EgressGatewayPolicyDestinationSpec{
							CIDR: extWorkloads[1].IP,
						},
						Gateway: &api.EgressSpec{
							Selector:          "egress-code == 'blue'",
							NamespaceSelector: "projectcalico.org/name == 'default'",
						},
					},
					{
						Description: "to reach to other Workloads, like workload 2, via the default egw",
						Gateway: &api.EgressSpec{
							Selector:          "egress-code == 'red'",
							NamespaceSelector: "projectcalico.org/name == 'default'",
						},
					},
					{
						Description: "to reach to workload 3 directly, skipping egw",
						Destination: &api.EgressGatewayPolicyDestinationSpec{
							CIDR: extWorkloads[3].IP,
						},
					},
				}

				ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
				_, err := client.EgressGatewayPolicy().Create(ctx, egwPolicy1, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
			})

			AfterEach(func() {
				ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
				_, err := client.EgressGatewayPolicy().Delete(ctx, "egw-policy1", options.DeleteOptions{})
				Expect(err).NotTo(HaveOccurred())
				for i := range 4 {
					extWorkloads[i].Stop()
					extHosts[i].Stop()
				}
				extWorkloads = nil
				extHosts = nil
				cancel()
			})

			Context("egress gateway policy with localPreference", func() {
				var egwClient *workload.Workload
				var redGWs []*workload.Workload
				var blueGWs []*workload.Workload
				var gw *workload.Workload

				BeforeEach(func() {
					overlay = OV_NONE
					protocol = "tcp"
				})

				JustBeforeEach(func() {
					for _, l := range []string{"blue", "red"} {
						j := 0
						if l == "red" {
							j = 2
						}
						for i := range 2 {
							gwName := fmt.Sprintf("gw%v-%v", l, i)
							gwAddr := fmt.Sprintf("10.10.11.%v", i+j)
							gwRoute := fmt.Sprintf("10.10.11.%v/32", i+j)

							if i == 0 {
								gw = makeGatewayWithLabel(tc.Felixes[0], gwAddr, gwName, l)
							} else {
								gw = makeGatewayWithLabel(tc.Felixes[1], gwAddr, gwName, l)
							}
							if l == "blue" {
								blueGWs = append(blueGWs, gw)
							} else {
								redGWs = append(redGWs, gw)
							}
							for i := range 4 {
								extWorkloads[i].C.Exec("ip", "route", "add", gwRoute, "via", gw.C.IP)
							}
						}
					}
					for i := range 4 {
						extWorkloads[i].C.Exec("ip", "route", "add", "10.65.0.2", "via", tc.Felixes[0].IP)
					}
					if BPFMode() {
						ensureAllNodesBPFProgramsAttached(tc.Felixes, "egress.calico")
					}
				})
				AfterEach(func() {
					for i := range 2 {
						redGWs[i].Stop()
						blueGWs[i].Stop()
					}
					redGWs = nil
					blueGWs = nil
				})

				It("Should use the local gateway when GatewayPreference is set to PreferNodeLocal", func() {
					egwClient = makeClientWithEGWPolicy(tc.Felixes[0], "10.65.0.2", "client", "egw-policy1")
					defer egwClient.Stop()

					Eventually(getIPRules, "10s", "1s").Should(HaveLen(1))
					Eventually(getIPRules, "10s", "1s").Should(HaveKey("10.65.0.2"))
					table := getIPRules()["10.65.0.2"]
					Expect(table).To(Equal("250"))

					By("should use the local gateway to connect to external server")
					// update the EGW policy to set LocalPrefence
					ctx, cancel = context.WithTimeout(context.Background(), 60*time.Second)
					egwPolicy1, err := client.EgressGatewayPolicy().Get(ctx, "egw-policy1", options.GetOptions{})
					Expect(err).NotTo(HaveOccurred())
					localNodePreference := api.GatewayPreferenceNodeLocal
					egwPolicy1.Spec.Rules[0].GatewayPreference = &localNodePreference
					egwPolicy1.Spec.Rules[1].GatewayPreference = &localNodePreference
					egwPolicy1.Spec.Rules[2].GatewayPreference = &localNodePreference
					egwPolicy1.Spec.Rules[3].GatewayPreference = &localNodePreference
					_, err = client.EgressGatewayPolicy().Update(ctx, egwPolicy1, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())

					cc.ExpectSNAT(egwClient, egwClient.IP, extWorkloads[0], 4321)
					cc.ExpectSNAT(egwClient, blueGWs[0].IP, extWorkloads[1], 4321)
					cc.ExpectSNAT(egwClient, redGWs[0].IP, extWorkloads[2], 4321)
					cc.ExpectSNAT(egwClient, egwClient.IP, extWorkloads[3], 4321)
					cc.CheckConnectivity()

					By("Deleting the local gateway, client should connect via the non-local gateway")
					blueGWs[0].Stop()
					redGWs[0].Stop()
					blueGWs[0].RemoveFromInfra(infra)
					redGWs[0].RemoveFromInfra(infra)
					cc.ResetExpectations()
					cc.ExpectSNAT(egwClient, blueGWs[1].IP, extWorkloads[1], 4321)
					cc.ExpectSNAT(egwClient, redGWs[1].IP, extWorkloads[2], 4321)
					cc.CheckConnectivity()
					cc.ResetExpectations()

					By("Adding the local pods back")
					Expect(blueGWs[0].Start(infra)).To(Succeed())
					Expect(redGWs[0].Start(infra)).To(Succeed())
					blueGWs[0].ConfigureInInfra(infra)
					redGWs[0].ConfigureInInfra(infra)
					cc.ExpectSNAT(egwClient, blueGWs[0].IP, extWorkloads[1], 4321)
					cc.ExpectSNAT(egwClient, redGWs[0].IP, extWorkloads[2], 4321)
					cc.CheckConnectivity()
				})
			})

			for _, sameNode := range []bool{true, false} {
				for _, ov := range []Overlay{OV_NONE, OV_VXLAN, OV_IPIP} {
					for _, proto := range []string{"tcp", "udp"} {
						description := "with " + ov.String() + ", client and gateway on "
						if sameNode {
							description += "same node"
						} else {
							description += "different nodes"
						}
						description += " (" + proto + ")"

						Context("egress gateway policy "+description, func() {
							var egwClient *workload.Workload
							var gws []*workload.Workload
							var gw *workload.Workload

							BeforeEach(func() {
								overlay = ov
								protocol = proto
							})

							JustBeforeEach(func() {
								rulesProgrammed := func() bool {
									felix := tc.Felixes[1]
									if sameNode {
										felix = tc.Felixes[0]
									}
									if BPFMode() {
										return bpfCheckIfGlobalNetworkPolicyProgrammed(felix, gw.InterfaceName, "ingress", "default.egw-deny-ingress", "deny", true)
									}
									out, err := getRuleset(felix)
									Expect(err).NotTo(HaveOccurred())
									return (strings.Contains(out, "default.egw-deny-ingress"))
								}

								for i, l := range []string{"blue", "red"} {
									gwName := fmt.Sprintf("gw-%v", l)
									gwAddr := fmt.Sprintf("10.10.1%v.1", i)
									gwRoute := fmt.Sprintf("10.10.1%v.1/32", i)
									if sameNode {
										gw = makeGatewayWithLabel(tc.Felixes[0], gwAddr, gwName, l)
									} else {
										gw = makeGatewayWithLabel(tc.Felixes[1], gwAddr, gwName, l)
										switch ov {
										case OV_NONE:
											tc.Felixes[0].Exec("ip", "route", "add", gwRoute, "via", gw.C.IP)
										case OV_VXLAN:
											// Felix programs the routes in this case.
										case OV_IPIP:
											tc.Felixes[0].Exec("ip", "route", "add", gwRoute, "via", gw.C.IP, "dev", "tunl0", "onlink")
										}
									}
									gws = append(gws, gw)
								}
								if BPFMode() {
									ensureAllNodesBPFProgramsAttached(tc.Felixes, "egress.calico")
								}
								if !sameNode && ov == OV_NONE {
									createHostEndPointPolicy(tc.Felixes[0])
								}
								createEgwIngPol(gw)
								Eventually(rulesProgrammed, "10s", "1s").Should(BeTrue(),
									"Expected rules to appear on the correct felix instances")
								for i := range 4 {
									for j := range 2 {
										gwRoute := fmt.Sprintf("10.10.1%v.1/32", j)
										extWorkloads[i].C.Exec("ip", "route", "add", gwRoute, "via", gws[j].C.IP)
									}
									extWorkloads[i].C.Exec("ip", "route", "add", "10.65.0.2", "via", tc.Felixes[0].IP)
								}
							})

							AfterEach(func() {
								for i := range 2 {
									gws[i].Stop()
								}
								gws = nil
							})

							It("server should see correct IPs when client connects to it", func() {
								egwClient = makeClientWithEGWPolicy(tc.Felixes[0], "10.65.0.2", "client", "egw-policy1")
								defer egwClient.Stop()

								cc.ExpectSNAT(egwClient, egwClient.IP, extWorkloads[0], 4321)
								cc.ExpectSNAT(egwClient, gws[0].IP, extWorkloads[1], 4321)
								cc.ExpectSNAT(egwClient, gws[1].IP, extWorkloads[2], 4321)
								cc.ExpectSNAT(egwClient, egwClient.IP, extWorkloads[3], 4321)
								cc.CheckConnectivity()

								// Check route rules and tables
								Eventually(getIPRules, "10s", "1s").Should(HaveLen(1))
								Eventually(getIPRules, "10s", "1s").Should(HaveKey("10.65.0.2"))
								table := getIPRules()["10.65.0.2"]
								Expect(table).To(Equal("250"))
							})

							It("should reuse existing route rule and table", func() {
								triggerStartup := tc.Felixes[0].RestartWithDelayedStartup()

								// Add route rule and table for client, to check if egress ip manager picks table 220 for this client
								fwmark := "0x80000/0x80000"
								if BPFMode() {
									fwmark = "0x10000000/0x10000000"
								}
								tc.Felixes[0].Exec("ip", "rule", "add", "from", "10.65.0.2", "fwmark", fwmark, "priority", "100", "lookup", "220")
								tc.Felixes[0].Exec("ip", "route", "add", "throw", extWorkloads[0].IP, "table", "220")
								tc.Felixes[0].Exec("ip", "route", "add", extWorkloads[1].IP, "via", "10.10.10.1", "dev", "egress.calico", "onlink", "table", "220")
								tc.Felixes[0].Exec("ip", "route", "add", "default", "via", "10.10.11.1", "dev", "egress.calico", "onlink", "table", "220")
								tc.Felixes[0].Exec("ip", "route", "add", "throw", extWorkloads[3].IP, "table", "220")

								// Add route rules and tables to check if egress ip manager cleans it
								tc.Felixes[0].Exec("ip", "rule", "add", "from", "10.65.0.3", "fwmark", "0x21000000/0x21000000", "priority", "100", "lookup", "230")
								tc.Felixes[0].Exec("ip", "route", "add", "throw", extWorkloads[0].IP, "table", "230")
								tc.Felixes[0].Exec("ip", "route", "add", extWorkloads[1].IP, "via", "10.10.10.1", "dev", "egress.calico", "onlink", "table", "230")
								tc.Felixes[0].Exec("ip", "route", "add", "default", "via", "10.10.11.1", "dev", "egress.calico", "onlink", "table", "230")
								tc.Felixes[0].Exec("ip", "route", "add", "throw", extWorkloads[3].IP, "table", "230")

								tc.Felixes[0].Exec("ip", "rule", "add", "from", "10.65.0.4", "fwmark", "0x80000/0x80000", "priority", "100", "lookup", "231")
								tc.Felixes[0].Exec("ip", "route", "add", "default", "via", "10.10.11.1", "dev", "egress.calico", "onlink", "table", "231")

								tc.Felixes[0].Exec("ip", "rule", "add", "from", "10.65.0.4", "fwmark", "0x10000000/0x10000000", "priority", "100", "lookup", "232")

								// Need to create client PODs after EGW deployment to make sure IPSets are not empty.
								// This is just to test re-using existing route rule and table works fine.
								egwClient = makeClientWithEGWPolicy(tc.Felixes[0], "10.65.0.2", "client", "egw-policy1")
								defer egwClient.Stop()

								// Confirm the route rules we added are present.
								Eventually(getIPRules, "10s", "1s").Should(HaveLen(3))

								triggerStartup()
								tc.Felixes[0].WaitForReady()
								if BPFMode() {
									ensureAllNodesBPFProgramsAttached(tc.Felixes, "egress.calico")
								}

								// Expect the extra rules and tables to be cleaned up before attempting the connectivity check to
								// mitigate race conditions.
								Eventually(getIPRules, "60s", "1s").Should(HaveLen(1))

								// Expect correct connectivity.
								cc.ExpectSNAT(egwClient, egwClient.IP, extWorkloads[0], 4321)
								cc.ExpectSNAT(egwClient, gws[0].IP, extWorkloads[1], 4321)
								cc.ExpectSNAT(egwClient, gws[1].IP, extWorkloads[2], 4321)
								cc.ExpectSNAT(egwClient, egwClient.IP, extWorkloads[3], 4321)
								cc.CheckConnectivity()

								// Check route rules and tables
								Eventually(getIPRules, "10s", "1s").Should(HaveLen(1))
								Eventually(getIPRules, "10s", "1s").Should(HaveKey("10.65.0.2"))
								table := getIPRules()["10.65.0.2"]
								Expect(table).To(Equal("220"))
							})
						})
					}
				}
			}
		})

		It("keeps gateway device route when client goes away", func() {
			By("Create a gateway and client")
			gw := makeGateway(tc.Felixes[0], "10.10.10.1", "gw1")
			defer gw.Stop()
			app := makeClient(tc.Felixes[0], "10.65.0.2", "app")
			appExists := true
			defer func() {
				if appExists {
					app.Stop()
				}
			}()

			By("Check gateway route exists")
			gwRouteRe := regexp.MustCompile(`^10.10.10.1 dev cali`)
			checkGatewayRoute := func() (err error) {
				routes, err := tc.Felixes[0].ExecOutput("ip", "r")
				if err != nil {
					return
				}
				for route := range strings.SplitSeq(routes, "\n") {
					if matched := gwRouteRe.MatchString(route); matched {
						return
					}
				}
				return fmt.Errorf("10.10.10.1 device route is not present in:\n%v", routes)
			}
			Eventually(checkGatewayRoute, "10s", "1s").Should(Succeed())

			By("Remove the client again")
			app.RemoveFromInfra(infra)
			app.Stop()
			appExists = false

			By("Check gateway route still present")
			Expect(checkGatewayRoute()).To(Succeed())
			Consistently(checkGatewayRoute, "5s", "1s").Should(Succeed())
		})

		It("programs src_valid_mark according to FELIX_EGRESSIPHOSTIFACEPATTERN", func() {
			Eventually(tc.Felixes[0].ProcSysValueForIfaceFn("eth0"), "10s").Should(BeEquivalentTo("1"))
		})

		It("updates rules and routing as gateways are added and removed", func() {
			By("Create a gateway.")
			gw := makeGateway(tc.Felixes[0], "10.10.10.1", "gw1")
			defer gw.Stop()

			By("No egress ip rules expected yet.")
			Consistently(getIPRules).Should(BeEmpty())

			By("Create a client.")
			app := makeClient(tc.Felixes[0], "10.65.0.2", "app")
			defer app.Stop()

			By("Check ip rules.")
			Eventually(getIPRules, "10s", "1s").Should(HaveLen(1))
			Eventually(getIPRules, "10s", "1s").Should(HaveKey("10.65.0.2"))
			table1 := getIPRules()["10.65.0.2"]

			By("Check ip routes.")
			checkIPRoute(table1, expectedRoute("10.10.10.1"))

			By("Check L2.")
			Expect(getIPNeigh()).To(Equal(map[string]string{
				"10.10.10.1": "a2:2a:0a:0a:0a:01",
			}))
			Expect(getBridgeFDB()).To(Equal(map[string]string{
				"a2:2a:0a:0a:0a:01": "10.10.10.1",
			}))

			By("Create another client.")
			app2 := makeClient(tc.Felixes[0], "10.65.0.3", "app2")
			defer app2.Stop()

			By("Check ip rules.")
			Eventually(getIPRules, "10s", "1s").Should(HaveLen(2))
			Eventually(getIPRules, "10s", "1s").Should(HaveKey("10.65.0.2"))
			table2 := getIPRules()["10.65.0.3"]
			Eventually(getIPRules, "10s", "1s").Should(Equal(map[string]string{"10.65.0.2": table1, "10.65.0.3": table2}))

			By("Check ip routes.")
			checkIPRoute(table1, expectedRoute("10.10.10.1"))
			checkIPRoute(table2, expectedRoute("10.10.10.1"))

			By("Check L2.")
			Expect(getIPNeigh()).To(Equal(map[string]string{
				"10.10.10.1": "a2:2a:0a:0a:0a:01",
			}))
			Expect(getBridgeFDB()).To(Equal(map[string]string{
				"a2:2a:0a:0a:0a:01": "10.10.10.1",
			}))

			By("Create another gateway.")
			gw2 := makeGateway(tc.Felixes[0], "10.10.10.2", "gw2")
			defer gw2.Stop()

			By("Check ip rules and routes.")
			Eventually(getIPRules, "10s", "1s").Should(Equal(map[string]string{"10.65.0.2": table1, "10.65.0.3": table2}))
			checkIPRoute(table1, expectedRoute("10.10.10.1", "10.10.10.2"))
			checkIPRoute(table2, expectedRoute("10.10.10.1", "10.10.10.2"))

			By("Check L2.")
			Expect(getIPNeigh()).To(Equal(map[string]string{
				"10.10.10.1": "a2:2a:0a:0a:0a:01",
				"10.10.10.2": "a2:2a:0a:0a:0a:02",
			}))
			Expect(getBridgeFDB()).To(Equal(map[string]string{
				"a2:2a:0a:0a:0a:01": "10.10.10.1",
				"a2:2a:0a:0a:0a:02": "10.10.10.2",
			}))

			By("Create 3rd gateway.")
			gw3 := makeGateway(tc.Felixes[0], "10.10.10.3", "gw3")
			defer gw3.Stop()

			By("Check ip rules and routes.")
			Eventually(getIPRules, "10s", "1s").Should(Equal(map[string]string{"10.65.0.2": table1, "10.65.0.3": table2}))
			checkIPRoute(table1, expectedRoute("10.10.10.1", "10.10.10.2", "10.10.10.3"))
			checkIPRoute(table2, expectedRoute("10.10.10.1", "10.10.10.2", "10.10.10.3"))

			By("Check L2.")
			Expect(getIPNeigh()).To(Equal(map[string]string{
				"10.10.10.1": "a2:2a:0a:0a:0a:01",
				"10.10.10.2": "a2:2a:0a:0a:0a:02",
				"10.10.10.3": "a2:2a:0a:0a:0a:03",
			}))
			Expect(getBridgeFDB()).To(Equal(map[string]string{
				"a2:2a:0a:0a:0a:01": "10.10.10.1",
				"a2:2a:0a:0a:0a:02": "10.10.10.2",
				"a2:2a:0a:0a:0a:03": "10.10.10.3",
			}))

			By("Create another client.")
			app3 := makeClient(tc.Felixes[0], "10.65.0.4", "app3")
			defer app3.Stop()

			By("Check ip rules.")
			Eventually(getIPRules, "10s", "1s").Should(HaveLen(3))
			Eventually(getIPRules, "10s", "1s").Should(HaveKey("10.65.0.4"))
			table3 := getIPRules()["10.65.0.4"]
			Eventually(getIPRules, "10s", "1s").Should(Equal(map[string]string{"10.65.0.2": table1, "10.65.0.3": table2, "10.65.0.4": table3}))

			By("Check ip routes.")
			checkIPRoute(table1, expectedRoute("10.10.10.1", "10.10.10.2", "10.10.10.3"))
			checkIPRoute(table2, expectedRoute("10.10.10.1", "10.10.10.2", "10.10.10.3"))
			checkIPRoute(table3, expectedRoute("10.10.10.1", "10.10.10.2", "10.10.10.3"))

			By("Remove 3rd gateway again.")
			gw3.RemoveFromInfra(infra)

			By("Check ip rules and routes.")
			Eventually(getIPRules, "10s", "1s").Should(Equal(map[string]string{"10.65.0.2": table1, "10.65.0.3": table2, "10.65.0.4": table3}))
			checkIPRoute(table1, expectedRoute("10.10.10.1", "10.10.10.2"))
			checkIPRoute(table2, expectedRoute("10.10.10.1", "10.10.10.2"))
			checkIPRoute(table3, expectedRoute("10.10.10.1", "10.10.10.2"))

			By("Check L2.")
			Expect(getIPNeigh()).To(Equal(map[string]string{
				"10.10.10.1": "a2:2a:0a:0a:0a:01",
				"10.10.10.2": "a2:2a:0a:0a:0a:02",
			}))
			Expect(getBridgeFDB()).To(Equal(map[string]string{
				"a2:2a:0a:0a:0a:01": "10.10.10.1",
				"a2:2a:0a:0a:0a:02": "10.10.10.2",
			}))

			By("Remove the second gateway.")
			gw2.RemoveFromInfra(infra)

			By("Check ip rules and routes.")
			Eventually(getIPRules, "10s", "1s").Should(Equal(map[string]string{"10.65.0.2": table1, "10.65.0.3": table2, "10.65.0.4": table3}))
			checkIPRoute(table1, expectedRoute("10.10.10.1"))
			checkIPRoute(table2, expectedRoute("10.10.10.1"))
			checkIPRoute(table3, expectedRoute("10.10.10.1"))

			By("Check L2.")
			Expect(getIPNeigh()).To(Equal(map[string]string{
				"10.10.10.1": "a2:2a:0a:0a:0a:01",
			}))
			Expect(getBridgeFDB()).To(Equal(map[string]string{
				"a2:2a:0a:0a:0a:01": "10.10.10.1",
			}))

			By("Remove the first gateway.")
			gw.RemoveFromInfra(infra)

			By("Check ip rules and routes.")
			Consistently(getIPRules, "5s", "1s").Should(Equal(map[string]string{"10.65.0.2": table1, "10.65.0.3": table2, "10.65.0.4": table3}))
			checkIPRoute(table1, expectedRoute())
			checkIPRoute(table2, expectedRoute())
			checkIPRoute(table3, expectedRoute())

			By("Check L2.")
			Expect(getIPNeigh()).To(Equal(map[string]string{}))
			Expect(getBridgeFDB()).To(Equal(map[string]string{}))
		})
	})

	Context("Disabled", func() {
		BeforeEach(func() {
			supportLevel = "Disabled"
		})

		It("does nothing when egress IP is disabled", func() {
			By("Create a gateway.")
			gw := makeGateway(tc.Felixes[0], "10.10.10.1", "gw1")
			defer gw.Stop()

			By("Create a client.")
			app := makeClient(tc.Felixes[0], "10.65.0.2", "app")
			defer app.Stop()

			By("Should be no ip rules.")
			Consistently(getIPRules, "5s", "1s").Should(BeEmpty())
		})
	})

	Context("EnabledPerNamespace", func() {
		BeforeEach(func() {
			supportLevel = "EnabledPerNamespace"
		})

		It("honours namespace annotations but not per-pod", func() {
			By("Create a gateway.")
			gw := makeGateway(tc.Felixes[0], "10.10.10.1", "gw1")
			defer gw.Stop()

			By("Create a client.")
			app := makeClient(tc.Felixes[0], "10.65.0.2", "app")
			defer app.Stop()

			By("Should be no ip rules.")
			Consistently(getIPRules, "5s", "1s").Should(BeEmpty())

			By("Add egress annotations to the default namespace.")
			coreV1 := infra.(*infrastructure.K8sDatastoreInfra).K8sClient.CoreV1()
			ns, err := coreV1.Namespaces().Get(context.Background(), app.WorkloadEndpoint.Namespace, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			if ns.Annotations == nil {
				ns.Annotations = map[string]string{}
			}
			ns.Annotations["egress.projectcalico.org/selector"] = "egress-code == 'red'"
			_, err = coreV1.Namespaces().Update(context.Background(), ns, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Check ip rules.")
			// (In this example the gateway is also in the default namespace, but is
			// prevented from looping around to itself (or to any other gateway) because
			// it is an egress gateway itself.)
			Eventually(getIPRules, "10s", "1s").Should(HaveLen(1))
			rules := getIPRules()
			Expect(rules).To(HaveKey("10.65.0.2"))
			table1 := rules["10.65.0.2"]

			By("Check ip routes.")
			checkIPRoute(table1, expectedRoute("10.10.10.1"))
		})
	})
})

func getRuleset(felix *infrastructure.Felix) (string, error) {
	if NFTMode() {
		return felix.ExecOutput("nft", "list", "ruleset")
	}
	return felix.ExecOutput("iptables-save", "-t", "filter")
}
