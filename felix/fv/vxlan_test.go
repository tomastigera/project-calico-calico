// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.
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

//go:build fvtests

package fv_test

import (
	"context"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/metrics"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribeWithRemote("_BPF-SAFE_ VXLAN topology before adding host IPs to IP sets", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(infraFactories infrastructure.LocalRemoteInfraFactories) {
	type testConf struct {
		VXLANMode   api.VXLANMode
		RouteSource string
		BrokenXSum  bool
		EnableIPv6  bool
		Overlap     OverlapTestType
	}
	for _, testConfig := range []testConf{
		{api.VXLANModeCrossSubnet, "CalicoIPAM", true, true, OverlapTestType_None},
		{api.VXLANModeCrossSubnet, "CalicoIPAM", false, true, OverlapTestType_None},
		{api.VXLANModeCrossSubnet, "WorkloadIPs", false, true, OverlapTestType_None},
		{api.VXLANModeCrossSubnet, "CalicoIPAM", true, false, OverlapTestType_None},
		{api.VXLANModeCrossSubnet, "WorkloadIPs", false, false, OverlapTestType_None},

		{api.VXLANModeAlways, "CalicoIPAM", true, true, OverlapTestType_None},
		{api.VXLANModeAlways, "WorkloadIPs", false, true, OverlapTestType_None},
		{api.VXLANModeAlways, "CalicoIPAM", true, false, OverlapTestType_None},
		{api.VXLANModeAlways, "WorkloadIPs", false, false, OverlapTestType_None},

		// Validate that the local cluster connectivity does not break when connecting an overlapping IP pool.
		{api.VXLANModeAlways, "CalicoIPAM", true, true, OverlapTestType_Connect},
		{api.VXLANModeAlways, "CalicoIPAM", true, false, OverlapTestType_Connect},
		{api.VXLANModeAlways, "CalicoIPAM", true, true, OverlapTestType_ConnectDisconnect},
		{api.VXLANModeAlways, "CalicoIPAM", true, false, OverlapTestType_ConnectDisconnect},
	} {
		vxlanMode := testConfig.VXLANMode
		routeSource := testConfig.RouteSource
		brokenXSum := testConfig.BrokenXSum
		enableIPv6 := testConfig.EnableIPv6
		overlap := testConfig.Overlap

		Describe(fmt.Sprintf("VXLAN mode set to %s, routeSource %s, brokenXSum: %v, enableIPv6: %v, overlap: %v, isRemote: %v", vxlanMode, routeSource, brokenXSum, enableIPv6, overlap, infraFactories.IsRemoteSetup()), func() {
			var (
				cs *VXLANClusters
				cc *connectivity.Checker
			)

			BeforeEach(func() {
				if !infraFactories.IsRemoteSetup() && overlap != OverlapTestType_None {
					Skip("Skipping overlapping pools tests for non-remote setup")
				}
				cs = &VXLANClusters{
					overlap: overlap,
				}

				for i, infraFactory := range infraFactories.AllFactories() {
					creatingRemote := i == 1
					infra := infraFactory()

					if getDataStoreType(infra) == "etcdv3" && BPFMode() {
						Skip("Skipping BPF tests for etcdv3 backend.")
					}
					if (NFTMode() || BPFMode()) && getDataStoreType(infra) == "etcdv3" {
						Skip("Skipping NFT / BPF tests for etcdv3 backend.")
					}

					topologyOptions := createVXLANBaseTopologyOptions(vxlanMode, enableIPv6, routeSource, brokenXSum)
					topologyOptions.FelixLogSeverity = "Debug"
					if infraFactories.IsRemoteSetup() {
						topologyOptions.WithTypha = true
						if creatingRemote && overlap == OverlapTestType_None {
							logrus.Info("OverlapTestType_None: local and remote clusters use unique CIDRs.")
							// Change CIDR for the second datastore to prevent overlap.
							topologyOptions.IPPoolCIDR = "10.75.0.0/16"
							topologyOptions.IPv6PoolCIDR = "dead:cafe::/64"
							topologyOptions.VXLANStrategy = infrastructure.NewDefaultTunnelStrategy(topologyOptions.IPPoolCIDR, topologyOptions.IPv6PoolCIDR)
						} else if overlap == OverlapTestType_Connect {
							logrus.Info("OverlapTestType_Connect: local and remote clusters share IP pool CIDRs.")
						} else if overlap == OverlapTestType_ConnectDisconnect {
							logrus.Info("OverlapTestType_ConnectDisconnect: local and remote clusters share IP pool CIDRs.")
						}
					}

					// Deploy the topology.
					tc, client := infrastructure.StartNNodeTopology(3, topologyOptions, infra)

					w, w6, hostW, hostW6 := setupWorkloads(infra, tc, topologyOptions, client, enableIPv6)

					clusterState := &VXLANClusterState{
						infra:   infra,
						client:  client,
						tc:      tc,
						felixes: [3]*infrastructure.Felix{tc.Felixes[0], tc.Felixes[1], tc.Felixes[2]},
						w:       w,
						w6:      w6,
						hostW:   hostW,
						hostW6:  hostW6,
					}

					if creatingRemote {
						cs.remote = clusterState
					} else {
						cs.local = clusterState
					}

					// TODO: This call currently fails in the remote setup case. It's been disabled for now to
					// unblock the OSS merges. The below call fails when invoked for the remote cluster.
					// Tracked here: https://tigera.atlassian.net/browse/CORE-11147
					// Assign tunnel addresees in IPAM based on the topology.
					// assignTunnelAddresses(infra, tc, client)
				}

				if cs.IsRemoteSetup() {
					// Setup local with an RCC for remote.
					remoteRCC := cs.remote.infra.GetRemoteClusterConfig()
					_, err := cs.local.infra.GetCalicoClient().RemoteClusterConfigurations().Create(context.Background(), remoteRCC, options.SetOptions{})
					Expect(err).To(BeNil())

					// Setup remote with an RCC for local.
					localRCC := cs.local.infra.GetRemoteClusterConfig()
					_, err = cs.remote.infra.GetCalicoClient().RemoteClusterConfigurations().Create(context.Background(), localRCC, options.SetOptions{})
					Expect(err).To(BeNil())

					// Wait for the remotes to sync to reduce flakes. We expect routes and IP sets to only reflect
					// the local cluster as part of overlap handling, so we check the number of nodes seen by Felix
					// to determine the status.
					expectedNumHosts := len(cs.local.felixes) + len(cs.remote.felixes)
					for _, localFelix := range cs.local.felixes {
						Eventually(metrics.GetFelixMetricIntFn(localFelix.IP, "felix_cluster_num_hosts"), "60s", "200ms").Should(Equal(expectedNumHosts))
					}
					for _, remoteFelix := range cs.remote.felixes {
						Eventually(metrics.GetFelixMetricIntFn(remoteFelix.IP, "felix_cluster_num_hosts"), "60s", "200ms").Should(Equal(expectedNumHosts))
					}

					if overlap == OverlapTestType_ConnectDisconnect {
						// Wait for the remotes to sync before we disconnect. We expect routes and IP sets to only reflect the local cluster as
						// part of overlap handling, so we check the number of nodes seen by Felix to determine the status.
						_, err = cs.local.infra.GetCalicoClient().RemoteClusterConfigurations().Delete(context.Background(), remoteRCC.Name, options.DeleteOptions{})
						_, err = cs.remote.infra.GetCalicoClient().RemoteClusterConfigurations().Delete(context.Background(), localRCC.Name, options.DeleteOptions{})
					}
				}

				cc = &connectivity.Checker{}
			})

			JustAfterEach(func() {
				for _, c := range cs.GetProvisionedClusters() {
					if CurrentGinkgoTestDescription().Failed {
						for _, felix := range c.felixes {

							if NFTMode() {
								logNFTDiags(felix)
							} else {

								felix.Exec("iptables-save", "-c")
								felix.Exec("ipset", "list")
							}
							felix.Exec("ip", "r")
							felix.Exec("ip", "a")
							if enableIPv6 {
								felix.Exec("ip", "-6", "route")
							}
							felix.Exec("ip", "-d", "link")
						}
						c.infra.DumpErrorData()
					}
				}
			})

			AfterEach(func() {
				for _, c := range cs.GetProvisionedClusters() {
					for _, wl := range c.w {
						wl.Stop()
					}
					for _, wl := range c.w6 {
						wl.Stop()
					}
					for _, wl := range c.hostW {
						wl.Stop()
					}
					for _, wl := range c.hostW6 {
						wl.Stop()
					}

					c.tc.Stop()
					c.infra.Stop()
				}
			})

			if brokenXSum {
				It("should disable checksum offload", func() {
					if cs.IsRemoteSetup() {
						Skip("Skipping host configuration tests for remote cluster scenarios")
					}
					Eventually(func() string {
						out, err := cs.local.felixes[0].ExecOutput("ethtool", "-k", "vxlan.calico")
						if err != nil {
							return fmt.Sprintf("ERROR: %v", err)
						}
						return out
					}, "10s", "100ms").Should(ContainSubstring("tx-checksumming: off"))
				})
			} else {
				It("should not disable checksum offload", func() {
					if cs.IsRemoteSetup() {
						Skip("Skipping host configuration tests for remote cluster scenarios")
					}
					Eventually(func() string {
						out, err := cs.local.felixes[0].ExecOutput("ethtool", "-k", "vxlan.calico")
						if err != nil {
							return fmt.Sprintf("ERROR: %v", err)
						}
						return out
					}, "10s", "100ms").Should(ContainSubstring("tx-checksumming: on"))
				})
			}
			It("should fully randomize MASQUERADE rules", func() {
				if cs.IsRemoteSetup() {
					Skip("Skipping host configuration tests for remote cluster scenarios")
				}
				for _, c := range cs.GetActiveClusters() {
					for _, felix := range c.felixes {
						if NFTMode() {
							Eventually(func() string {
								out, _ := felix.ExecOutput("nft", "list", "table", "calico")
								return out
							}, "10s", "100ms").Should(ContainSubstring("fully-random"))
						} else {
							Eventually(func() string {
								out, _ := felix.ExecOutput("iptables-save", "-c")
								return out
							}, "10s", "100ms").Should(ContainSubstring("--random-fully"))
						}
					}
				}
			})

			It("should have workload to workload connectivity", func() {
				cc.ExpectSome(cs.local.w[0], cs.local.w[1])
				cc.ExpectSome(cs.local.w[1], cs.local.w[0])
				if cs.ExpectRemoteConnectivity() {
					cc.ExpectSome(cs.local.w[0], cs.remote.w[1])
					cc.ExpectSome(cs.remote.w[1], cs.local.w[0])
				}

				if enableIPv6 {
					cc.ExpectSome(cs.local.w6[0], cs.local.w6[1])
					cc.ExpectSome(cs.local.w6[1], cs.local.w6[0])
					if cs.ExpectRemoteConnectivity() {
						cc.ExpectSome(cs.local.w6[0], cs.remote.w6[1])
						cc.ExpectSome(cs.remote.w6[1], cs.local.w6[0])
					}
				}

				cc.CheckConnectivity()
			})

			It("should have some blackhole routes installed", func() {
				if routeSource == "WorkloadIPs" {
					Skip("not applicable for workload ips")
					return
				}
				if cs.IsRemoteSetup() {
					Skip("Skipping host configuration tests for remote cluster scenarios")
				}
				nodes := [2][3]string{
					{
						"blackhole 10.65.0.0/26 proto 80",
						"blackhole 10.65.1.0/26 proto 80",
						"blackhole 10.65.2.0/26 proto 80",
					},
					{
						"blackhole 10.75.0.0/26 proto 80",
						"blackhole 10.75.1.0/26 proto 80",
						"blackhole 10.75.2.0/26 proto 80",
					},
				}

				for i, c := range cs.GetActiveClusters() {
					for n, result := range nodes[i] {
						Eventually(func() string {
							o, _ := c.felixes[n].ExecOutput("ip", "r", "s", "type", "blackhole")
							return o
						}, "10s", "100ms").Should(ContainSubstring(result))
						wName := fmt.Sprintf("w%d", n)

						err := c.client.IPAM().ReleaseByHandle(context.TODO(), wName)
						Expect(err).NotTo(HaveOccurred())

						if enableIPv6 {
							w6Name := fmt.Sprintf("w6-%d", n)
							err := c.client.IPAM().ReleaseByHandle(context.TODO(), w6Name)
							Expect(err).NotTo(HaveOccurred())
						}

						affinityCfg := ipam.AffinityConfig{
							AffinityType: ipam.AffinityTypeHost,
							Host:         c.felixes[n].Hostname,
						}
						err = c.client.IPAM().ReleaseHostAffinities(context.TODO(), affinityCfg, true)
						Expect(err).NotTo(HaveOccurred())

						Eventually(func() string {
							o, _ := c.felixes[n].ExecOutput("ip", "r", "s", "type", "blackhole")
							return o
						}, "10s", "100ms").Should(BeEmpty())
					}
				}
			})

			if vxlanMode == api.VXLANModeCrossSubnet && !enableIPv6 && routeSource == "CalicoIPAM" {
				It("should move same-subnet routes when the node IP moves to a new interface", func() {
					// Routes should look like this:
					//
					//   default via 172.17.0.1 dev eth0
					//   blackhole 10.65.0.0/26 proto 80
					//   10.65.0.2 dev cali29f56ea1abf scope link
					//   10.65.1.0/26 via 172.17.0.6 dev eth0 proto 80 onlink
					//   10.65.2.0/26 via 172.17.0.5 dev eth0 proto 80 onlink
					//   172.17.0.0/16 dev eth0 proto kernel scope link src 172.17.0.7
					tc := cs.local.tc
					felix := tc.Felixes[0]
					Eventually(felix.ExecOutputFn("ip", "route", "show"), "10s").Should(ContainSubstring(
						fmt.Sprintf("10.65.1.0/26 via %s dev eth0 proto 80 onlink", tc.Felixes[1].IP)))

					// Find the default and subnet routes, we'll need to
					// recreate those after moving the IP.
					defaultRoute, err := felix.ExecOutput("ip", "route", "show", "default")
					Expect(err).NotTo(HaveOccurred())
					lines := strings.Split(strings.Trim(defaultRoute, "\n "), "\n")
					Expect(lines).To(HaveLen(1))
					defaultRouteArgs := strings.Split(strings.Replace(lines[0], "eth0", "bond0", -1), " ")

					// Assuming the subnet route will be "proto kernel" and that will be the only such route.
					subnetRoute, err := felix.ExecOutput("ip", "route", "show", "proto", "kernel")
					Expect(err).NotTo(HaveOccurred())
					lines = strings.Split(strings.Trim(subnetRoute, "\n "), "\n")
					Expect(lines).To(HaveLen(1), "expected only one proto kernel route, has docker's routing set-up changed?")
					subnetArgs := strings.Split(strings.Replace(lines[0], "eth0", "bond0", -1), " ")

					// Add the bond, replacing eth0.
					felix.Exec("ip", "addr", "del", felix.IP, "dev", "eth0")
					felix.Exec("ip", "link", "add", "dev", "bond0", "type", "bond")
					felix.Exec("ip", "link", "set", "dev", "eth0", "down")
					felix.Exec("ip", "link", "set", "dev", "eth0", "master", "bond0")
					felix.Exec("ip", "link", "set", "dev", "eth0", "up")
					felix.Exec("ip", "link", "set", "dev", "bond0", "up")

					// Move IP to bond0.  We don't actually set up more than one
					// bonded interface in this test, we just want to know that
					// felix spots the IP move.
					ipWithSubnet := felix.IP + "/" + felix.GetIPPrefix()
					felix.Exec("ip", "addr", "add", ipWithSubnet, "dev", "bond0")

					// Re-add the default routes, via bond0 (one gets removed when
					// eth0 goes down, the other gets stuck on eth0).
					felix.Exec(append([]string{"ip", "r", "add"}, defaultRouteArgs...)...)
					felix.Exec(append([]string{"ip", "r", "replace"}, subnetArgs...)...)

					expCrossSubRoute := fmt.Sprintf("10.65.1.0/26 via %s dev bond0 proto 80 onlink", tc.Felixes[1].IP)
					Eventually(felix.ExecOutputFn("ip", "route", "show"), "10s").Should(
						ContainSubstring(expCrossSubRoute),
						"Cross-subnet route should move from eth0 to bond0.",
					)
				})
			}

			It("should have host to workload connectivity", func() {
				if vxlanMode == api.VXLANModeAlways && routeSource == "WorkloadIPs" {
					Skip("Skipping due to known issue with tunnel IPs not being programmed in WEP mode")
				}
				cc.ExpectSome(cs.local.felixes[0], cs.local.w[1])
				cc.ExpectSome(cs.local.felixes[0], cs.local.w[0])
				if cs.ExpectRemoteConnectivity() {
					cc.ExpectSome(cs.local.felixes[0], cs.remote.w[1])
					cc.ExpectSome(cs.remote.felixes[0], cs.local.w[0])
				}
				if enableIPv6 {
					cc.ExpectSome(cs.local.felixes[0], cs.local.w6[1])
					cc.ExpectSome(cs.local.felixes[0], cs.local.w6[0])
					if cs.ExpectRemoteConnectivity() {
						cc.ExpectSome(cs.local.felixes[0], cs.remote.w6[1])
						cc.ExpectSome(cs.remote.felixes[0], cs.local.w6[0])
					}
				}
				cc.CheckConnectivity()
			})

			It("should have host to host connectivity", func() {
				cc.ExpectSome(cs.local.felixes[0], cs.local.hostW[1])
				cc.ExpectSome(cs.local.felixes[1], cs.local.hostW[0])
				if cs.ExpectRemoteConnectivity() {
					cc.ExpectSome(cs.local.felixes[0], cs.remote.hostW[1])
					cc.ExpectSome(cs.remote.felixes[1], cs.local.hostW[0])
				}
				if enableIPv6 {
					cc.ExpectSome(cs.local.felixes[0], cs.local.hostW6[1])
					cc.ExpectSome(cs.local.felixes[1], cs.local.hostW6[0])
					if cs.ExpectRemoteConnectivity() {
						cc.ExpectSome(cs.local.felixes[0], cs.remote.hostW6[1])
						cc.ExpectSome(cs.remote.felixes[1], cs.local.hostW6[0])
					}
				}
				cc.CheckConnectivity()
			})

			Context("with host protection policy in place", func() {
				BeforeEach(func() {
					if enableIPv6 {
						Skip("Skipping due to known issue with ICMPv6 NDP being dropped with host endpoints")
					}
					for _, c := range cs.GetActiveClusters() {
						// Make sure our new host endpoints don't cut felix off from the datastore.
						err := c.infra.AddAllowToDatastore("host-endpoint=='true'")
						Expect(err).NotTo(HaveOccurred())

						ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
						defer cancel()

						for _, f := range c.felixes {
							hep := api.NewHostEndpoint()
							hep.Name = "eth0-" + f.Name
							hep.Labels = map[string]string{
								"host-endpoint": "true",
							}
							hep.Spec.Node = f.Hostname
							hep.Spec.ExpectedIPs = []string{f.IP}
							_, err := c.client.HostEndpoints().Create(ctx, hep, options.SetOptions{})
							Expect(err).NotTo(HaveOccurred())
						}
					}
				})

				It("should have workload connectivity but not host connectivity", func() {
					// Host endpoints (with no policies) block host-host traffic due to default drop.
					cc.ExpectNone(cs.local.felixes[0], cs.local.hostW[1])
					cc.ExpectNone(cs.local.felixes[1], cs.local.hostW[0])
					if cs.ExpectRemoteConnectivity() {
						cc.ExpectNone(cs.local.felixes[0], cs.remote.hostW[1])
						cc.ExpectNone(cs.remote.felixes[1], cs.local.hostW[0])
					}
					if enableIPv6 {
						cc.ExpectNone(cs.local.felixes[0], cs.local.hostW6[1])
						cc.ExpectNone(cs.local.felixes[1], cs.local.hostW6[0])
						if cs.ExpectRemoteConnectivity() {
							cc.ExpectNone(cs.local.felixes[0], cs.remote.hostW6[1])
							cc.ExpectNone(cs.remote.felixes[1], cs.local.hostW6[0])
						}
					}

					// But the rules to allow VXLAN between our hosts let the workload traffic through.
					cc.ExpectSome(cs.local.w[0], cs.local.w[1])
					cc.ExpectSome(cs.local.w[1], cs.local.w[0])
					if cs.ExpectRemoteConnectivity() {
						cc.ExpectSome(cs.local.w[0], cs.remote.w[1])
						cc.ExpectSome(cs.remote.w[1], cs.local.w[0])
					}
					if enableIPv6 {
						cc.ExpectSome(cs.local.w6[0], cs.local.w6[1])
						cc.ExpectSome(cs.local.w6[1], cs.local.w6[0])
						if cs.ExpectRemoteConnectivity() {
							cc.ExpectSome(cs.local.w6[0], cs.remote.w6[1])
							cc.ExpectSome(cs.remote.w6[1], cs.local.w6[0])
						}
					}
					cc.CheckConnectivity()
				})
			})

			Context("with all-interfaces host protection policy in place", func() {
				BeforeEach(func() {
					if enableIPv6 {
						Skip("Skipping due to known issue with ICMPv6 NDP being dropped with host endpoints")
					}
					for _, c := range cs.GetActiveClusters() {
						// Make sure our new host endpoints don't cut felix off from the datastore.
						err := c.infra.AddAllowToDatastore("host-endpoint=='true'")
						Expect(err).NotTo(HaveOccurred())

						ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
						defer cancel()

						for _, f := range c.felixes {
							hep := api.NewHostEndpoint()
							hep.Name = "all-interfaces-" + f.Name
							hep.Labels = map[string]string{
								"host-endpoint": "true",
								"hostname":      f.Hostname,
							}
							hep.Spec.Node = f.Hostname
							hep.Spec.ExpectedIPs = []string{f.IP}
							hep.Spec.InterfaceName = "*"
							_, err := c.client.HostEndpoints().Create(ctx, hep, options.SetOptions{})
							Expect(err).NotTo(HaveOccurred())
						}
					}
				})

				It("should have workload connectivity but not host connectivity", func() {
					// Host endpoints (with no policies) block host-host traffic due to default drop.
					cc.ExpectNone(cs.local.felixes[0], cs.local.hostW[1])
					cc.ExpectNone(cs.local.felixes[1], cs.local.hostW[0])
					if cs.ExpectRemoteConnectivity() {
						cc.ExpectNone(cs.local.felixes[0], cs.remote.hostW[1])
						cc.ExpectNone(cs.remote.felixes[1], cs.local.hostW[0])
					}
					if enableIPv6 {
						cc.ExpectNone(cs.local.felixes[0], cs.local.hostW6[1])
						cc.ExpectNone(cs.local.felixes[1], cs.local.hostW6[0])
						if cs.ExpectRemoteConnectivity() {
							cc.ExpectNone(cs.local.felixes[0], cs.remote.hostW6[1])
							cc.ExpectNone(cs.remote.felixes[1], cs.local.hostW6[0])
						}
					}

					// Host => workload is not allowed
					cc.ExpectNone(cs.local.felixes[0], cs.local.w[1])
					cc.ExpectNone(cs.local.felixes[1], cs.local.w[0])
					if cs.ExpectRemoteConnectivity() {
						cc.ExpectNone(cs.local.felixes[0], cs.remote.w[1])
						cc.ExpectNone(cs.remote.felixes[1], cs.local.w[0])
					}
					if enableIPv6 {
						cc.ExpectNone(cs.local.felixes[0], cs.local.w6[1])
						cc.ExpectNone(cs.local.felixes[1], cs.local.w6[0])
						if cs.ExpectRemoteConnectivity() {
							cc.ExpectNone(cs.local.felixes[0], cs.remote.w6[1])
							cc.ExpectNone(cs.remote.felixes[1], cs.local.w6[0])
						}
					}

					// But host => own-workload is allowed
					cc.ExpectSome(cs.local.felixes[0], cs.local.w[0])
					cc.ExpectSome(cs.local.felixes[1], cs.local.w[1])
					if cs.ExpectRemoteConnectivity() {
						cc.ExpectSome(cs.remote.felixes[0], cs.remote.w[0])
						cc.ExpectSome(cs.remote.felixes[1], cs.remote.w[1])
					}
					if enableIPv6 {
						cc.ExpectSome(cs.local.felixes[0], cs.local.w6[0])
						cc.ExpectSome(cs.local.felixes[1], cs.local.w6[1])
						if cs.ExpectRemoteConnectivity() {
							cc.ExpectSome(cs.remote.felixes[0], cs.remote.w6[0])
							cc.ExpectSome(cs.remote.felixes[1], cs.remote.w6[1])
						}
					}

					// But the rules to allow VXLAN between our hosts let the workload traffic through.
					cc.ExpectSome(cs.local.w[0], cs.local.w[1])
					cc.ExpectSome(cs.local.w[1], cs.local.w[0])
					if cs.ExpectRemoteConnectivity() {
						cc.ExpectSome(cs.local.w[0], cs.remote.w[1])
						cc.ExpectSome(cs.remote.w[1], cs.local.w[0])
					}
					if enableIPv6 {
						cc.ExpectSome(cs.local.w6[0], cs.local.w6[1])
						cc.ExpectSome(cs.local.w6[1], cs.local.w6[0])
						if cs.ExpectRemoteConnectivity() {
							cc.ExpectSome(cs.local.w6[0], cs.remote.w6[1])
							cc.ExpectSome(cs.remote.w6[1], cs.local.w6[0])
						}
					}
					cc.CheckConnectivity()
				})

				It("should allow felixes[0] to reach felixes[1] if ingress and egress policies are in place", func() {
					// Create a policy selecting felix[0] that allows egress.
					for _, c := range cs.GetActiveClusters() {
						policy := api.NewGlobalNetworkPolicy()
						policy.Name = "f0-egress"
						policy.Spec.Egress = []api.Rule{{Action: api.Allow}}
						policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", c.felixes[0].Hostname)
						_, err := c.client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
						Expect(err).NotTo(HaveOccurred())
					}

					// But there is no policy allowing ingress into felix[1].
					cc.ExpectNone(cs.local.felixes[0], cs.local.hostW[1])
					if cs.ExpectRemoteConnectivity() {
						cc.ExpectNone(cs.local.felixes[0], cs.remote.hostW[1])
					}
					if enableIPv6 {
						cc.ExpectNone(cs.local.felixes[0], cs.local.hostW6[1])
						if cs.ExpectRemoteConnectivity() {
							cc.ExpectNone(cs.local.felixes[0], cs.remote.hostW6[1])
						}
					}

					// felixes[1] can't reach felixes[0].
					cc.ExpectNone(cs.local.felixes[1], cs.local.hostW[0])
					if cs.ExpectRemoteConnectivity() {
						cc.ExpectNone(cs.remote.felixes[1], cs.local.hostW[0])
					}
					if enableIPv6 {
						cc.ExpectNone(cs.local.felixes[1], cs.local.hostW6[0])
						if cs.ExpectRemoteConnectivity() {
							cc.ExpectNone(cs.remote.felixes[1], cs.local.hostW6[0])
						}
					}

					// Workload connectivity is unchanged.
					cc.ExpectSome(cs.local.w[0], cs.local.w[1])
					cc.ExpectSome(cs.local.w[1], cs.local.w[0])
					if cs.ExpectRemoteConnectivity() {
						cc.ExpectSome(cs.local.w[0], cs.remote.w[1])
						cc.ExpectSome(cs.remote.w[1], cs.local.w[0])
					}
					if enableIPv6 {
						cc.ExpectSome(cs.local.w6[0], cs.local.w6[1])
						cc.ExpectSome(cs.local.w6[1], cs.local.w6[0])
						if cs.ExpectRemoteConnectivity() {
							cc.ExpectSome(cs.local.w6[0], cs.remote.w6[1])
							cc.ExpectSome(cs.remote.w6[1], cs.local.w6[0])
						}
					}

					cc.CheckConnectivity()

					cc.ResetExpectations()

					// Now add a policy selecting felix[1] that allows ingress.
					for _, c := range cs.GetActiveClusters() {
						policy := api.NewGlobalNetworkPolicy()
						policy.Name = "f1-ingress"
						policy.Spec.Ingress = []api.Rule{{Action: api.Allow}}
						policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", c.felixes[1].Hostname)
						_, err := c.client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
						Expect(err).NotTo(HaveOccurred())
					}

					// Now felixes[0] can reach felixes[1].
					cc.ExpectSome(cs.local.felixes[0], cs.local.hostW[1])
					if cs.ExpectRemoteConnectivity() {
						cc.ExpectSome(cs.local.felixes[0], cs.remote.hostW[1])
					}
					if enableIPv6 {
						cc.ExpectSome(cs.local.felixes[0], cs.local.hostW6[1])
						if cs.ExpectRemoteConnectivity() {
							cc.ExpectSome(cs.local.felixes[0], cs.remote.hostW6[1])
						}
					}

					// felixes[1] still can't reach felixes[0].
					cc.ExpectNone(cs.local.felixes[1], cs.local.hostW[0])
					if cs.ExpectRemoteConnectivity() {
						cc.ExpectNone(cs.remote.felixes[1], cs.local.hostW[0])
					}
					if enableIPv6 {
						cc.ExpectNone(cs.local.felixes[1], cs.local.hostW6[0])
						if cs.ExpectRemoteConnectivity() {
							cc.ExpectNone(cs.remote.felixes[1], cs.local.hostW6[0])
						}
					}

					// Workload connectivity is unchanged.
					cc.ExpectSome(cs.local.w[0], cs.local.w[1])
					cc.ExpectSome(cs.local.w[1], cs.local.w[0])
					if cs.ExpectRemoteConnectivity() {
						cc.ExpectSome(cs.local.w[0], cs.remote.w[1])
						cc.ExpectSome(cs.remote.w[1], cs.local.w[0])
					}
					if enableIPv6 {
						cc.ExpectSome(cs.local.w6[0], cs.local.w6[1])
						cc.ExpectSome(cs.local.w6[1], cs.local.w6[0])
						if cs.ExpectRemoteConnectivity() {
							cc.ExpectSome(cs.local.w6[0], cs.remote.w6[1])
							cc.ExpectSome(cs.remote.w6[1], cs.local.w6[0])
						}
					}
					cc.CheckConnectivity()
				})

				Context("with policy allowing port 8055", func() {
					BeforeEach(func() {
						tcp := numorstring.ProtocolFromString("tcp")
						udp := numorstring.ProtocolFromString("udp")
						p8055 := numorstring.SinglePort(8055)
						policy := api.NewGlobalNetworkPolicy()
						policy.Name = "allow-8055"
						policy.Spec.Ingress = []api.Rule{
							{
								Protocol: &udp,
								Destination: api.EntityRule{
									Ports: []numorstring.Port{p8055},
								},
								Action: api.Allow,
							},
							{
								Protocol: &tcp,
								Destination: api.EntityRule{
									Ports: []numorstring.Port{p8055},
								},
								Action: api.Allow,
							},
						}
						policy.Spec.Egress = []api.Rule{
							{
								Protocol: &udp,
								Destination: api.EntityRule{
									Ports: []numorstring.Port{p8055},
								},
								Action: api.Allow,
							},
							{
								Protocol: &tcp,
								Destination: api.EntityRule{
									Ports: []numorstring.Port{p8055},
								},
								Action: api.Allow,
							},
						}
						policy.Spec.Selector = fmt.Sprintf("has(host-endpoint)")

						for _, c := range cs.GetActiveClusters() {
							_, err := c.client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
							Expect(err).NotTo(HaveOccurred())
						}
					})

					// Please take care if adding other connectivity checks into this case, to
					// avoid those other checks setting up conntrack state that allows the
					// existing case to pass for a different reason.
					It("allows host0 to remote Calico-networked workload via service IP", func() {
						if vxlanMode == api.VXLANModeAlways && routeSource == "WorkloadIPs" {
							Skip("Skipping due to known issue with tunnel IPs not being programmed in WEP mode")
						}
						// Allocate a service IP.
						serviceIP := "10.101.0.11"
						remoteServiceIP := "10.101.0.22"
						serviceV6IP := "deca:fbad:0000:0000:0000:0000:0000:0001"
						remoteServiceV6IP := "deca:fbad:0000:0000:0000:0000:0000:0002"
						port := 8055
						tgtPort := 8055
						createK8sServiceWithoutKubeProxy(createK8sServiceWithoutKubeProxyArgs{
							infra:                  cs.local.infra,
							felix:                  cs.local.felixes[0],
							w:                      cs.local.w[1],
							svcName:                "test-svc",
							serviceIP:              serviceIP,
							targetIP:               cs.local.w[1].IP,
							port:                   port,
							tgtPort:                tgtPort,
							chain:                  "OUTPUT",
							ipv6:                   false,
							serviceInRemoteCluster: false,
						})
						if cs.ExpectRemoteConnectivity() {
							createK8sServiceWithoutKubeProxy(createK8sServiceWithoutKubeProxyArgs{
								infra:                  cs.local.infra,
								felix:                  cs.local.felixes[0],
								w:                      cs.remote.w[1],
								svcName:                "test-remote-svc",
								serviceIP:              remoteServiceIP,
								targetIP:               cs.remote.w[1].IP,
								port:                   port,
								tgtPort:                tgtPort,
								chain:                  "OUTPUT",
								ipv6:                   false,
								serviceInRemoteCluster: true,
							})
						}
						if enableIPv6 {
							createK8sServiceWithoutKubeProxy(createK8sServiceWithoutKubeProxyArgs{
								infra:                  cs.local.infra,
								felix:                  cs.local.felixes[0],
								w:                      cs.local.w6[1],
								svcName:                "test-v6-svc",
								serviceIP:              serviceV6IP,
								targetIP:               cs.local.w6[1].IP,
								port:                   port,
								tgtPort:                tgtPort,
								chain:                  "OUTPUT",
								ipv6:                   true,
								serviceInRemoteCluster: false,
							})
							if cs.ExpectRemoteConnectivity() {
								createK8sServiceWithoutKubeProxy(createK8sServiceWithoutKubeProxyArgs{
									infra:                  cs.local.infra,
									felix:                  cs.local.felixes[0],
									w:                      cs.remote.w6[1],
									svcName:                "test-remote-v6-svc",
									serviceIP:              remoteServiceV6IP,
									targetIP:               cs.remote.w6[1].IP,
									port:                   port,
									tgtPort:                tgtPort,
									chain:                  "OUTPUT",
									ipv6:                   true,
									serviceInRemoteCluster: true,
								})
							}
						}

						// Expect to connect to the service IP.
						cc.ExpectSome(cs.local.felixes[0], connectivity.TargetIP(serviceIP), uint16(port))
						if cs.ExpectRemoteConnectivity() {
							// Expect to connect to the remote service IP.
							cc.ExpectSome(cs.local.felixes[0], connectivity.TargetIP(remoteServiceIP), uint16(port))
						}
						if enableIPv6 {
							cc.ExpectSome(cs.local.felixes[0], connectivity.TargetIP(serviceV6IP), uint16(port))
							if cs.ExpectRemoteConnectivity() {
								// Expect to connect to the remote service IP.
								cc.ExpectSome(cs.local.felixes[0], connectivity.TargetIP(remoteServiceV6IP), uint16(port))
							}
						}
						cc.CheckConnectivity()
					})
				})
			})

			calculateBaseIPSetMemberCount := func() int {
				var numFelixes int

				// In BPF mode, we examine the routes map, which contains
				// all known hosts.  In iptables mode, we examine the
				// VXLAN IP set, which only contains hosts with a valid VTEP
				// so the expected count differs.
				if (BPFMode() && cs.ExpectRemoteClusterConnection()) || (!BPFMode() && cs.ExpectRemoteConnectivity()) {
					numFelixes = len(cs.local.felixes) + len(cs.remote.felixes)
				} else {
					numFelixes = len(cs.local.felixes)
				}
				baseIPSetMemberCount := numFelixes - 1
				return baseIPSetMemberCount
			}

			Context("after removing BGP address from third node", func() {
				// Simulate having a host send VXLAN traffic from an unknown source, should get blocked.
				var baseIPSetMemberCount int
				var numIPsRemoved int

				BeforeEach(func() {
					waitPeriod := "10s"
					if cs.IsRemoteSetup() {
						waitPeriod = "60s"
					}
					baseIPSetMemberCount = calculateBaseIPSetMemberCount()

					for _, c := range cs.GetActiveClusters() {
						for _, f := range c.felixes {
							if BPFMode() {
								Eventually(f.BPFNumRemoteHostRoutes, waitPeriod, "200ms").Should(Equal(baseIPSetMemberCount),
									fmt.Sprintf("Expected felix %s to have %d host routes, got: %s", f.IP, baseIPSetMemberCount, f.BPFRoutes()))
							} else if NFTMode() {
								Eventually(f.NFTSetSizeFn("cali40all-vxlan-net"), "10s", "200ms").Should(Equal(baseIPSetMemberCount))
							} else {
								Eventually(f.IPSetSizeFn("cali40all-vxlan-net"), waitPeriod, "200ms").Should(Equal(baseIPSetMemberCount))
							}
						}
					}

					numIPsRemoved = 0
					for _, c := range cs.GetActiveClusters() {
						ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
						defer cancel()
						c.infra.RemoveNodeAddresses(c.felixes[2])
						node, err := c.client.Nodes().Get(ctx, c.felixes[2].Hostname, options.GetOptions{})
						Expect(err).NotTo(HaveOccurred())

						// Pause felix so it can't touch the dataplane!
						pid := c.felixes[2].GetFelixPID()
						c.felixes[2].Exec("kill", "-STOP", fmt.Sprint(pid))

						node.Spec.BGP = nil
						_, err = c.client.Nodes().Update(ctx, node, options.SetOptions{})
						Expect(err).NotTo(HaveOccurred())
						numIPsRemoved++
					}
				})

				It("should have no connectivity from third felix and expected number of IPs in allow list", func() {
					adjustedIPSetMemberCount := baseIPSetMemberCount - numIPsRemoved
					if BPFMode() {
						Eventually(cs.local.felixes[0].BPFNumRemoteHostRoutes, "10s", "200ms").Should(Equal(adjustedIPSetMemberCount),
							fmt.Sprintf("Expected %d host routes, got:\n%s", adjustedIPSetMemberCount, cs.local.felixes[0].BPFRoutes()))
					} else if NFTMode() {
						Eventually(cs.local.felixes[0].NFTSetSizeFn("cali40all-vxlan-net"), "5s", "200ms").Should(Equal(adjustedIPSetMemberCount))
					} else {
						Eventually(cs.local.felixes[0].IPSetSizeFn("cali40all-vxlan-net"), "5s", "200ms").Should(
							Equal(adjustedIPSetMemberCount))
					}

					cc.ExpectSome(cs.local.w[0], cs.local.w[1])
					cc.ExpectSome(cs.local.w[1], cs.local.w[0])
					cc.ExpectNone(cs.local.w[0], cs.local.w[2])
					cc.ExpectNone(cs.local.w[2], cs.local.w[0])
					cc.ExpectNone(cs.local.w[1], cs.local.w[2])
					cc.ExpectNone(cs.local.w[2], cs.local.w[1])
					if cs.ExpectRemoteConnectivity() {
						cc.ExpectSome(cs.local.w[0], cs.remote.w[1])
						cc.ExpectSome(cs.remote.w[1], cs.local.w[0])
						cc.ExpectNone(cs.local.w[0], cs.remote.w[2])
						cc.ExpectNone(cs.remote.w[2], cs.local.w[0])
						cc.ExpectNone(cs.local.w[2], cs.remote.w[1])
						cc.ExpectNone(cs.remote.w[1], cs.local.w[2])
					}

					if enableIPv6 {
						cc.ExpectSome(cs.local.w6[0], cs.local.w6[1])
						cc.ExpectSome(cs.local.w6[1], cs.local.w6[0])
						cc.ExpectNone(cs.local.w6[0], cs.local.w6[2])
						cc.ExpectNone(cs.local.w6[2], cs.local.w6[0])
						cc.ExpectNone(cs.local.w6[1], cs.local.w6[2])
						cc.ExpectNone(cs.local.w6[2], cs.local.w6[1])
						if cs.ExpectRemoteConnectivity() {
							cc.ExpectSome(cs.local.w6[0], cs.remote.w6[1])
							cc.ExpectSome(cs.remote.w6[1], cs.local.w6[0])
							cc.ExpectNone(cs.local.w6[0], cs.remote.w6[2])
							cc.ExpectNone(cs.remote.w6[2], cs.local.w6[0])
							cc.ExpectNone(cs.local.w6[2], cs.remote.w6[1])
							cc.ExpectNone(cs.remote.w6[1], cs.local.w6[2])
						}
					}
					cc.CheckConnectivity()
				})
			})

			// Explicitly verify that the VXLAN allow-list IP set is doing its job (since Felix makes multiple dataplane
			// changes when the BGP IP disappears, and we want to make sure that it's the rule that's causing the
			// connectivity to drop).
			Context("after removing BGP address from third node, all felixes paused", func() {
				// Simulate having a host send VXLAN traffic from an unknown source, should get blocked.
				var baseIPSetMemberCount int

				BeforeEach(func() {
					if BPFMode() {
						Skip("Skipping due to manual removal of host from ipset not breaking connectivity in BPF mode")
						return
					}

					waitPeriod := "10s"
					if cs.IsRemoteSetup() {
						waitPeriod = "60s"
					}
					baseIPSetMemberCount = calculateBaseIPSetMemberCount()

					// Check we initially have the expected number of entries.
					for _, c := range cs.GetActiveClusters() {
						for _, f := range c.felixes {
							// Wait for Felix to set up the allow list.
							if NFTMode() {
								Eventually(f.NFTSetSizeFn("cali40all-vxlan-net"), waitPeriod, "200ms").Should(Equal(baseIPSetMemberCount))
							} else {
								Eventually(f.IPSetSizeFn("cali40all-vxlan-net"), waitPeriod, "200ms").Should(Equal(baseIPSetMemberCount))
							}
						}
						// Wait until dataplane has settled.
						cc.ExpectSome(c.w[0], c.w[1])
						cc.ExpectSome(c.w[0], c.w[2])
						cc.ExpectSome(c.w[1], c.w[2])
						cc.CheckConnectivity()
						cc.ResetExpectations()
					}

					for _, c := range cs.GetActiveClusters() {
						// Then pause all the felixes.
						for _, f := range c.felixes {
							pid := f.GetFelixPID()
							f.Exec("kill", "-STOP", fmt.Sprint(pid))
						}
					}
				})

				// BPF mode doesn't use the IP set.
				if vxlanMode == api.VXLANModeAlways && !BPFMode() {
					It("after manually removing third node from allow list should have expected connectivity", func() {
						if NFTMode() {
							cs.local.felixes[0].Exec("nft", "delete", "element", "ip", "calico", "cali40all-vxlan-net", fmt.Sprintf("{ %s }", cs.local.felixes[2].IP))
							if cs.ExpectRemoteConnectivity() {
								cs.local.felixes[0].Exec("nft", "delete", "element", "ip", "calico", "cali40all-vxlan-net", fmt.Sprintf("{ %s }", cs.remote.felixes[2].IP))
							}
							if enableIPv6 {
								cs.local.felixes[0].Exec("nft", "delete", "element", "ip6", "calico", "cali60all-vxlan-net", fmt.Sprintf("{ %s }", cs.local.felixes[2].IPv6))
								if cs.ExpectRemoteConnectivity() {
									cs.local.felixes[0].Exec("nft", "delete", "element", "ip6", "calico", "cali60all-vxlan-net", fmt.Sprintf("{ %s }", cs.remote.felixes[2].IPv6))
								}
							}
						} else {
							cs.local.felixes[0].Exec("ipset", "del", "cali40all-vxlan-net", cs.local.felixes[2].IP)
							if cs.ExpectRemoteConnectivity() {
								cs.local.felixes[0].Exec("ipset", "del", "cali40all-vxlan-net", cs.remote.felixes[2].IP)
							}
							if enableIPv6 {
								cs.local.felixes[0].Exec("ipset", "del", "cali60all-vxlan-net", cs.local.felixes[2].IPv6)
								if cs.ExpectRemoteConnectivity() {
									cs.local.felixes[0].Exec("ipset", "del", "cali60all-vxlan-net", cs.remote.felixes[2].IPv6)
								}
							}
						}

						cc.ExpectSome(cs.local.w[0], cs.local.w[1])
						cc.ExpectSome(cs.local.w[1], cs.local.w[0])
						cc.ExpectSome(cs.local.w[1], cs.local.w[2])
						cc.ExpectNone(cs.local.w[2], cs.local.w[0])
						if cs.ExpectRemoteConnectivity() {
							cc.ExpectSome(cs.local.w[0], cs.remote.w[1])
							cc.ExpectSome(cs.remote.w[1], cs.local.w[0])
							cc.ExpectSome(cs.local.w[1], cs.remote.w[2])
							cc.ExpectNone(cs.remote.w[2], cs.local.w[0])
						}

						if enableIPv6 {
							cc.ExpectSome(cs.local.w6[0], cs.local.w6[1])
							cc.ExpectSome(cs.local.w6[1], cs.local.w6[0])
							cc.ExpectSome(cs.local.w6[1], cs.local.w6[2])
							cc.ExpectNone(cs.local.w6[2], cs.local.w6[0])
							if cs.ExpectRemoteConnectivity() {
								cc.ExpectSome(cs.local.w6[0], cs.remote.w6[1])
								cc.ExpectSome(cs.remote.w6[1], cs.local.w6[0])
								cc.ExpectSome(cs.local.w6[1], cs.remote.w6[2])
								cc.ExpectNone(cs.remote.w6[2], cs.local.w6[0])
							}
						}

						cc.CheckConnectivity()
					})
				}
			})

			_ = !BPFMode() && It("should configure the vxlan device correctly", func() {
				if cs.IsRemoteSetup() {
					Skip("Skipping host configuration tests for remote cluster scenarios")
				}
				for _, c := range cs.GetActiveClusters() {
					// The VXLAN device should appear with default MTU, etc. FV environment uses MTU 1500,
					// which means that we should expect 1450 after subtracting VXLAN overhead for IPv4 or 1430 for IPv6.
					mtuStr := "mtu 1450"
					mtuStrV6 := "mtu 1430"
					for _, felix := range c.felixes {
						Eventually(func() string {
							out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan.calico")
							return out
						}, "60s", "500ms").Should(ContainSubstring(mtuStr))
						Eventually(func() string {
							out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan.calico")
							return out
						}, "10s", "100ms").Should(ContainSubstring("vxlan id 4096"))
						Eventually(func() string {
							out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan.calico")
							return out
						}, "10s", "100ms").Should(ContainSubstring("dstport 4789"))
						if enableIPv6 {
							Eventually(func() string {
								out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan-v6.calico")
								return out
							}, "60s", "500ms").Should(ContainSubstring(mtuStrV6))
							Eventually(func() string {
								out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan-v6.calico")
								return out
							}, "10s", "100ms").Should(ContainSubstring("vxlan id 4096"))
							Eventually(func() string {
								out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan-v6.calico")
								return out
							}, "10s", "100ms").Should(ContainSubstring("dstport 4789"))
						}
					}

					// Change the host device's MTU, and expect the VXLAN device to be updated.
					for _, felix := range c.felixes {
						Eventually(func() error {
							_, err := felix.ExecOutput("ip", "link", "set", "eth0", "mtu", "1400")
							return err
						}, "10s", "100ms").Should(BeNil())
					}

					// MTU should be auto-detected, and updated to the host MTU minus 50 bytes overhead for IPv4 or 70 bytes for IPv6.
					mtuStr = "mtu 1350"
					mtuStrV6 = "mtu 1330"
					mtuValue := "1350"
					if enableIPv6 {
						mtuValue = "1330"
					}
					for _, felix := range c.felixes {
						// Felix checks host MTU every 30s
						Eventually(func() string {
							out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan.calico")
							return out
						}, "60s", "500ms").Should(ContainSubstring(mtuStr))

						if enableIPv6 {
							// Felix checks host MTU every 30s
							Eventually(func() string {
								out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan-v6.calico")
								return out
							}, "60s", "500ms").Should(ContainSubstring(mtuStrV6))
						}

						// And expect the MTU file on disk to be updated.
						Eventually(func() string {
							out, _ := felix.ExecOutput("cat", "/var/lib/calico/mtu")
							return out
						}, "30s", "100ms").Should(ContainSubstring(mtuValue))
					}

					// Explicitly configure the MTU.
					felixConfig := api.NewFelixConfiguration() // Create a default FelixConfiguration
					felixConfig.Name = "default"
					mtu := 1300
					vni := 4097
					port := 4790
					felixConfig.Spec.VXLANMTU = &mtu
					felixConfig.Spec.VXLANMTUV6 = &mtu
					felixConfig.Spec.VXLANPort = &port
					felixConfig.Spec.VXLANVNI = &vni
					_, err := c.client.FelixConfigurations().Create(context.Background(), felixConfig, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())

					// Expect the settings to be changed on the device.
					for _, felix := range c.felixes {
						// Felix checks host MTU every 30s
						Eventually(func() string {
							out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan.calico")
							return out
						}, "60s", "500ms").Should(ContainSubstring("mtu 1300"))
						Eventually(func() string {
							out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan.calico")
							return out
						}, "10s", "100ms").Should(ContainSubstring("vxlan id 4097"))
						Eventually(func() string {
							out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan.calico")
							return out
						}, "10s", "100ms").Should(ContainSubstring("dstport 4790"))

						if enableIPv6 {
							// Felix checks host MTU every 30s
							Eventually(func() string {
								out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan-v6.calico")
								return out
							}, "60s", "500ms").Should(ContainSubstring("mtu 1300"))
							Eventually(func() string {
								out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan-v6.calico")
								return out
							}, "10s", "100ms").Should(ContainSubstring("vxlan id 4097"))
							Eventually(func() string {
								out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan-v6.calico")
								return out
							}, "10s", "100ms").Should(ContainSubstring("dstport 4790"))

						}
					}
				}
			})

			It("should delete the vxlan device when vxlan is disabled", func() {
				if cs.IsRemoteSetup() {
					Skip("Skipping host configuration tests for remote cluster scenarios")
				}
				for _, c := range cs.GetActiveClusters() {
					// Wait for the VXLAN device to be created.
					mtuStr := "mtu 1450"
					mtuStrV6 := "mtu 1430"
					if BPFMode() {
						mtuStr = "mtu 1500"
						mtuStrV6 = "mtu 1500"
					}
					for _, felix := range c.felixes {
						Eventually(func() string {
							out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan.calico")
							return out
						}, "60s", "500ms").Should(ContainSubstring(mtuStr))
						if !BPFMode() && enableIPv6 {
							Eventually(func() string {
								out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan-v6.calico")
								return out
							}, "60s", "500ms").Should(ContainSubstring(mtuStrV6))
						}
					}

					// Disable VXLAN in Felix.
					felixConfig := api.NewFelixConfiguration()
					felixConfig.Name = "default"
					enabled := false
					felixConfig.Spec.VXLANEnabled = &enabled
					_, err := c.client.FelixConfigurations().Create(context.Background(), felixConfig, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())

					// Expect the ipv4 VXLAN device to be deleted.
					if !BPFMode() || !enableIPv6 {
						// Expect the ipv4 VXLAN device to be deleted. In BPFMode
						// the same device is used for V6 as well
						for _, felix := range c.felixes {
							Eventually(func() string {
								out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan.calico")
								return out
							}, "60s", "500ms").ShouldNot(ContainSubstring(mtuStr))
							// IPv6 ignores the VXLAN enabled flag and must be disabled at the pool level. As such the ipv6
							// interfaces should still exist at this point
							if enableIPv6 {
								Eventually(func() string {
									if BPFMode() {
										out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan.calico")
										return out
									}
									out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan-v6.calico")
									return out
								}, "60s", "500ms").Should(ContainSubstring(mtuStrV6))
							}
						}
					}

					if enableIPv6 {
						ip6pool, err := c.client.IPPools().Get(context.Background(), infrastructure.DefaultIPv6PoolName, options.GetOptions{})
						Expect(err).NotTo(HaveOccurred())
						ip6pool.Spec.VXLANMode = "Never"
						_, err = c.client.IPPools().Update(context.Background(), ip6pool, options.SetOptions{})
						Expect(err).NotTo(HaveOccurred())

						// Expect the ipv6 VXLAN device to be deleted.
						for _, felix := range c.felixes {
							Eventually(func() string {
								out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan-v6.calico")
								return out
							}, "60s", "500ms").ShouldNot(ContainSubstring(mtuStrV6))
						}
					}
				}
			})
		})

		Describe("with a borrowed tunnel IP on one host", func() {
			var (
				infra           infrastructure.DatastoreInfra
				tc              infrastructure.TopologyContainers
				felixes         []*infrastructure.Felix
				client          client.Interface
				w               [3]*workload.Workload
				w6              [3]*workload.Workload
				hostW           [3]*workload.Workload
				hostW6          [3]*workload.Workload
				cc              *connectivity.Checker
				topologyOptions infrastructure.TopologyOptions
			)

			BeforeEach(func() {
				if infraFactories.IsRemoteSetup() || overlap != OverlapTestType_None {
					Skip("Test only requires single-cluster coverage")
				}

				// We should always have access to the local InfraFactory instance
				iFactories := infraFactories.AllFactories()
				localFactory := iFactories[0]
				infra = localFactory()

				if (NFTMode() || BPFMode()) && getDataStoreType(infra) == "etcdv3" {
					Skip("Skipping NFT / BPF tests for etcdv3 backend.")
				}

				topologyOptions = createVXLANBaseTopologyOptions(vxlanMode, enableIPv6, routeSource, brokenXSum)
				topologyOptions.FelixLogSeverity = "Debug"
				topologyOptions.VXLANStrategy = infrastructure.NewBorrowedIPTunnelStrategy(topologyOptions.IPPoolCIDR, topologyOptions.IPv6PoolCIDR, 3)

				cc = &connectivity.Checker{}

				// Deploy the topology.
				tc, client = infrastructure.StartNNodeTopology(3, topologyOptions, infra)

				w, w6, hostW, hostW6 = setupWorkloads(infra, tc, topologyOptions, client, enableIPv6)
				felixes = tc.Felixes

				// Assign tunnel addresees in IPAM based on the topology.
				assignTunnelAddresses(infra, tc, client)
			})

			AfterEach(func() {
				if CurrentGinkgoTestDescription().Failed {
					for _, felix := range felixes {
						if NFTMode() {
							logNFTDiags(felix)
						} else {
							felix.Exec("iptables-save", "-c")
							felix.Exec("ipset", "list")
						}
						felix.Exec("ipset", "list")
						felix.Exec("ip", "r")
						felix.Exec("ip", "a")
						felix.Exec("calico-bpf", "routes", "dump")
						if enableIPv6 {
							felix.Exec("ip", "-6", "route")
							felix.Exec("calico-bpf", "-6", "routes", "dump")
						}
					}
				}

				for _, wl := range w {
					wl.Stop()
				}
				for _, wl := range w6 {
					wl.Stop()
				}
				for _, wl := range hostW {
					wl.Stop()
				}
				for _, wl := range hostW6 {
					wl.Stop()
				}
				tc.Stop()

				if CurrentGinkgoTestDescription().Failed {
					infra.DumpErrorData()
				}
				infra.Stop()
			})

			It("should have host to workload connectivity", func() {
				if vxlanMode == api.VXLANModeAlways && routeSource == "WorkloadIPs" {
					Skip("Skipping due to known issue with tunnel IPs not being programmed in WEP mode")
				}

				for i := 0; i < 3; i++ {
					f := felixes[i]
					cc.ExpectSome(f, w[0])
					cc.ExpectSome(f, w[1])
					cc.ExpectSome(f, w[2])

					if enableIPv6 {
						cc.ExpectSome(f, w6[0])
						cc.ExpectSome(f, w6[1])
						cc.ExpectSome(f, w6[2])
					}
				}

				cc.CheckConnectivity()
			})
		})

		Describe("with a separate tunnel address pool that uses /32 blocks", func() {
			var (
				infra           infrastructure.DatastoreInfra
				tc              infrastructure.TopologyContainers
				felixes         []*infrastructure.Felix
				client          client.Interface
				w               [3]*workload.Workload
				w6              [3]*workload.Workload
				hostW           [3]*workload.Workload
				hostW6          [3]*workload.Workload
				cc              *connectivity.Checker
				topologyOptions infrastructure.TopologyOptions
			)

			BeforeEach(func() {
				if infraFactories.IsRemoteSetup() || overlap != OverlapTestType_None {
					Skip("Test only requires single-cluster coverage")
				}

				// We should always have access to the local InfraFactory instance
				iFactories := infraFactories.AllFactories()
				localFactory := iFactories[0]
				infra = localFactory()

				if (NFTMode() || BPFMode()) && getDataStoreType(infra) == "etcdv3" {
					Skip("Skipping NFT / BPF tests for etcdv3 backend.")
				}

				topologyOptions = createVXLANBaseTopologyOptions(vxlanMode, enableIPv6, routeSource, brokenXSum)
				topologyOptions.FelixLogSeverity = "Debug"

				// Configure the default IP pool to be used for workloads only.
				topologyOptions.IPPoolUsages = []api.IPPoolAllowedUse{api.IPPoolAllowedUseWorkload}
				topologyOptions.IPv6PoolUsages = []api.IPPoolAllowedUse{api.IPPoolAllowedUseWorkload}

				// Create a separate IP pool for tunnel addresses that uses /32 addresses.
				tunnelPool := api.NewIPPool()
				tunnelPool.Name = "tunnel-addr-pool"
				tunnelPool.Spec.CIDR = "10.66.0.0/16"
				tunnelPool.Spec.BlockSize = 32
				tunnelPool.Spec.VXLANMode = vxlanMode
				tunnelPool.Spec.AllowedUses = []api.IPPoolAllowedUse{api.IPPoolAllowedUseTunnel}
				cli := infra.GetCalicoClient()
				_, err := cli.IPPools().Create(context.Background(), tunnelPool, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())

				// And one for v6.
				tunnelPoolV6 := api.NewIPPool()
				tunnelPoolV6.Name = "tunnel-addr-pool-v6"
				tunnelPoolV6.Spec.CIDR = "dead:feed::/64"
				tunnelPoolV6.Spec.BlockSize = 128
				tunnelPoolV6.Spec.VXLANMode = vxlanMode
				tunnelPoolV6.Spec.AllowedUses = []api.IPPoolAllowedUse{api.IPPoolAllowedUseTunnel}
				_, err = cli.IPPools().Create(context.Background(), tunnelPoolV6, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())

				// Configure the VXLAN strategy to use this IP pool for tunnel addresses allocation.
				topologyOptions.VXLANStrategy = infrastructure.NewDefaultTunnelStrategy(tunnelPool.Spec.CIDR, tunnelPoolV6.Spec.CIDR)

				cc = &connectivity.Checker{}

				// Deploy the topology.
				tc, client = infrastructure.StartNNodeTopology(3, topologyOptions, infra)

				w, w6, hostW, hostW6 = setupWorkloads(infra, tc, topologyOptions, client, enableIPv6)
				felixes = tc.Felixes

				// Assign tunnel addresees in IPAM based on the topology.
				assignTunnelAddresses(infra, tc, client)
			})

			AfterEach(func() {
				if CurrentGinkgoTestDescription().Failed {
					for _, felix := range felixes {
						if NFTMode() {
							logNFTDiags(felix)
						} else {
							felix.Exec("iptables-save", "-c")
							felix.Exec("ipset", "list")
						}
						felix.Exec("ipset", "list")
						felix.Exec("ip", "r")
						felix.Exec("ip", "a")
						if enableIPv6 {
							felix.Exec("ip", "-6", "route")
						}
						felix.Exec("calico-bpf", "routes", "dump")
					}
				}

				for _, wl := range w {
					wl.Stop()
				}
				for _, wl := range w6 {
					wl.Stop()
				}
				for _, wl := range hostW {
					wl.Stop()
				}
				for _, wl := range hostW6 {
					wl.Stop()
				}
				tc.Stop()

				if CurrentGinkgoTestDescription().Failed {
					infra.DumpErrorData()
				}
				infra.Stop()
			})

			It("should have host to workload connectivity", func() {
				if vxlanMode == api.VXLANModeAlways && routeSource == "WorkloadIPs" {
					Skip("Skipping due to known issue with tunnel IPs not being programmed in WEP mode")
				}

				for i := 0; i < 3; i++ {
					f := felixes[i]
					cc.ExpectSome(f, w[0])
					cc.ExpectSome(f, w[1])
					cc.ExpectSome(f, w[2])

					if enableIPv6 {
						cc.ExpectSome(f, w6[0])
						cc.ExpectSome(f, w6[1])
						cc.ExpectSome(f, w6[2])
					}
				}
				cc.CheckConnectivity()
			})

			It("should have workload to workload connectivity", func() {
				cc.ExpectSome(w[0], w[1])
				cc.ExpectSome(w[1], w[0])

				if enableIPv6 {
					cc.ExpectSome(w6[0], w6[1])
					cc.ExpectSome(w6[1], w6[0])
				}
				cc.CheckConnectivity()
			})
		})
	}
})

func createVXLANBaseTopologyOptions(vxlanMode api.VXLANMode, enableIPv6 bool, routeSource string, brokenXSum bool) infrastructure.TopologyOptions {
	topologyOptions := infrastructure.DefaultTopologyOptions()
	topologyOptions.VXLANMode = vxlanMode
	topologyOptions.VXLANStrategy = infrastructure.NewDefaultTunnelStrategy(topologyOptions.IPPoolCIDR, topologyOptions.IPv6PoolCIDR)
	topologyOptions.IPIPMode = api.IPIPModeNever
	topologyOptions.EnableIPv6 = enableIPv6
	topologyOptions.ExtraEnvVars["FELIX_ROUTESOURCE"] = routeSource
	// We force the broken checksum handling on or off so that we're not dependent on kernel version
	// for these tests.  Since we're testing in containers anyway, checksum offload can't really be
	// tested but we can verify the state with ethtool.
	topologyOptions.ExtraEnvVars["FELIX_FeatureDetectOverride"] = fmt.Sprintf("ChecksumOffloadBroken=%t", brokenXSum)
	topologyOptions.FelixDebugFilenameRegex = "vxlan|route_table|l3_route_resolver|int_dataplane"
	topologyOptions.ExtraEnvVars["FELIX_BPFLogLevel"] = "off"
	return topologyOptions
}

// assignTunnelAddresses assigns tunnel addresses in IPAM based on the tunnel addresses specified in the topology to make sure
// our IPAM state is consistent with the topology.
func assignTunnelAddresses(infra infrastructure.DatastoreInfra, tc infrastructure.TopologyContainers, client client.Interface) {
	for _, f := range tc.Felixes {
		// Assign the tunnel address.
		if f.ExpectedVXLANTunnelAddr != "" {
			handle := fmt.Sprintf("vxlan-tunnel-addr-%s", f.Hostname)
			err := client.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP:       net.MustParseIP(f.ExpectedVXLANTunnelAddr),
				HandleID: &handle,
				Attrs: map[string]string{
					ipam.AttributeNode: f.Hostname,
					ipam.AttributeType: ipam.AttributeTypeVXLAN,
				},
				Hostname: f.Hostname,
			})
			Expect(err).NotTo(HaveOccurred(), "failed to assign VXLAN tunnel address")
		}
		if f.ExpectedVXLANV6TunnelAddr != "" {
			handle := fmt.Sprintf("vxlan-tunnel-addr-%s", f.Hostname)
			err := client.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP:       net.MustParseIP(f.ExpectedVXLANV6TunnelAddr),
				HandleID: &handle,
				Attrs: map[string]string{
					ipam.AttributeNode: f.Hostname,
					ipam.AttributeType: ipam.AttributeTypeVXLANV6,
				},
				Hostname: f.Hostname,
			})
			Expect(err).NotTo(HaveOccurred(), "failed to assign VXLAN v6 tunnel address")
		}
		if f.ExpectedIPIPTunnelAddr != "" {
			handle := fmt.Sprintf("ipip-tunnel-addr-%s", f.Hostname)
			err := client.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP:       net.MustParseIP(f.ExpectedIPIPTunnelAddr),
				HandleID: &handle,
				Attrs: map[string]string{
					ipam.AttributeNode: f.Hostname,
					ipam.AttributeType: ipam.AttributeTypeIPIP,
				},
				Hostname: f.Hostname,
			})
			Expect(err).NotTo(HaveOccurred(), "failed to assign IPIP tunnel address")
		}
	}
}

func setupWorkloads(infra infrastructure.DatastoreInfra, tc infrastructure.TopologyContainers, to infrastructure.TopologyOptions, client client.Interface, enableIPv6 bool) (w, w6, hostW, hostW6 [3]*workload.Workload) {
	// Install a default profile that allows all ingress and egress, in the absence of any Policy.
	infra.AddDefaultAllow()

	// Wait until the vxlan device appears.
	Eventually(func() error {
		for i, f := range tc.Felixes {
			out, err := f.ExecOutput("ip", "link")
			if err != nil {
				return err
			}
			if strings.Contains(out, "vxlan.calico") {
				continue
			}
			return fmt.Errorf("felix %d has no vxlan device", i)
		}
		return nil
	}, "10s", "100ms").ShouldNot(HaveOccurred())

	if enableIPv6 && !BPFMode() {
		Eventually(func() error {
			for i, f := range tc.Felixes {
				out, err := f.ExecOutput("ip", "link")
				if err != nil {
					return err
				}
				if strings.Contains(out, "vxlan-v6.calico") {
					continue
				}
				return fmt.Errorf("felix %d has no IPv6 vxlan device", i)
			}
			return nil
		}, "10s", "100ms").ShouldNot(HaveOccurred())
	}

	// Create workloads, using that profile.  One on each "host".
	_, IPv4CIDR, err := net.ParseCIDR(to.IPPoolCIDR)
	Expect(err).To(BeNil())
	_, IPv6CIDR, err := net.ParseCIDR(to.IPv6PoolCIDR)
	Expect(err).To(BeNil())
	for ii := range w {
		wIP := fmt.Sprintf("%d.%d.%d.2", IPv4CIDR.IP[0], IPv4CIDR.IP[1], ii)
		wName := fmt.Sprintf("w%d", ii)
		err := client.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
			IP:       net.MustParseIP(wIP),
			HandleID: &wName,
			Attrs: map[string]string{
				ipam.AttributeNode: tc.Felixes[ii].Hostname,
			},
			Hostname: tc.Felixes[ii].Hostname,
		})
		Expect(err).NotTo(HaveOccurred())

		w[ii] = workload.Run(tc.Felixes[ii], wName, "default", wIP, "8055", "tcp")
		w[ii].ConfigureInInfra(infra)

		if enableIPv6 {
			w6IP := fmt.Sprintf("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%d:3", IPv6CIDR.IP[0], IPv6CIDR.IP[1], IPv6CIDR.IP[2], IPv6CIDR.IP[3], IPv6CIDR.IP[4], IPv6CIDR.IP[5], IPv6CIDR.IP[6], IPv6CIDR.IP[7], IPv6CIDR.IP[8], IPv6CIDR.IP[9], IPv6CIDR.IP[10], IPv6CIDR.IP[11], ii)
			w6Name := fmt.Sprintf("w6-%d", ii)
			err := client.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP:       net.MustParseIP(w6IP),
				HandleID: &w6Name,
				Attrs: map[string]string{
					ipam.AttributeNode: tc.Felixes[ii].Hostname,
				},
				Hostname: tc.Felixes[ii].Hostname,
			})
			Expect(err).NotTo(HaveOccurred())

			w6[ii] = workload.Run(tc.Felixes[ii], w6Name, "default", w6IP, "8055", "tcp")
			w6[ii].ConfigureInInfra(infra)
		}

		hostW[ii] = workload.Run(tc.Felixes[ii], fmt.Sprintf("host%d", ii), "", tc.Felixes[ii].IP, "8055", "tcp")
		if enableIPv6 {
			hostW6[ii] = workload.Run(tc.Felixes[ii], fmt.Sprintf("host%d-v6", ii), "", tc.Felixes[ii].IPv6, "8055", "tcp")
		}
	}

	if BPFMode() {
		ensureAllNodesBPFProgramsAttached(tc.Felixes)
	}

	return
}

type VXLANClusterState struct {
	infra   infrastructure.DatastoreInfra
	tc      infrastructure.TopologyContainers
	client  client.Interface
	felixes [3]*infrastructure.Felix
	w       [3]*workload.Workload
	w6      [3]*workload.Workload
	hostW   [3]*workload.Workload
	hostW6  [3]*workload.Workload
}

type VXLANClusters struct {
	local   *VXLANClusterState
	remote  *VXLANClusterState
	overlap OverlapTestType
}

type OverlapTestType string

const (
	OverlapTestType_None              OverlapTestType = ""
	OverlapTestType_Connect           OverlapTestType = "Connect"
	OverlapTestType_ConnectDisconnect OverlapTestType = "ConnectDisconnect"
)

func (c *VXLANClusters) GetActiveClusters() []*VXLANClusterState {
	return c.GetClusters(false)
}

func (c *VXLANClusters) GetProvisionedClusters() []*VXLANClusterState {
	return c.GetClusters(true)
}

func (c *VXLANClusters) GetClusters(forceIncludeOverlappingRemote bool) []*VXLANClusterState {
	clusters := []*VXLANClusterState{c.local}
	if c.IsRemoteSetup() && (forceIncludeOverlappingRemote || c.overlap == OverlapTestType_None) {
		clusters = append(clusters, c.remote)
	}
	return clusters
}

func (c *VXLANClusters) IsRemoteSetup() bool {
	return c.remote != nil
}

// ExpectRemoteClusterConnection returns true if there should be a federation
// connection (even one with overlapping IPPools).
func (c *VXLANClusters) ExpectRemoteClusterConnection() bool {
	return c.IsRemoteSetup() && c.overlap != OverlapTestType_ConnectDisconnect
}

// ExpectRemoteConnectivity returns true if there should be connectivity to
// remote pods.
func (c *VXLANClusters) ExpectRemoteConnectivity() bool {
	return c.IsRemoteSetup() && c.overlap == OverlapTestType_None
}
