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

package fv_test

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/metrics"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribeRemoteOnly("_BPF-SAFE_ Cluster mesh VXLAN topology before adding host IPs to IP sets", func(infraFactories infrastructure.LocalRemoteInfraFactories) {
	type testConf struct {
		VXLANMode   api.VXLANMode
		RouteSource string
		BrokenXSum  bool
		EnableIPv6  bool
		Overlap     OverlapTestType
	}
	for _, testConfig := range []testConf{
		{api.VXLANModeCrossSubnet, "CalicoIPAM", true, true, OverlapTestType_None},
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

		Describe(fmt.Sprintf("VXLAN mode set to %s, routeSource %s, brokenXSum: %v, enableIPv6: %v, overlap: %v", vxlanMode, routeSource, brokenXSum, enableIPv6, overlap), func() {
			var (
				cs *VXLANClusters
				cc *connectivity.Checker
			)

			BeforeEach(func() {
				cc = &connectivity.Checker{}
				cs = &VXLANClusters{
					overlap: overlap,
				}

				Expect(infraFactories.IsRemoteSetup()).To(BeTrue(), "This test requires a remote cluster")

				for i, infraFactory := range infraFactories.AllFactories() {
					creatingRemote := i == 1
					infra := infraFactory()

					if (NFTMode() || BPFMode()) && getDataStoreType(infra) == "etcdv3" {
						Skip("Skipping NFT / BPF tests for etcdv3 backend.")
					}

					topologyOptions := createVXLANBaseTopologyOptions(vxlanMode, enableIPv6, routeSource, brokenXSum)
					topologyOptions.FelixLogSeverity = "Debug"

					topologyOptions.WithTypha = true
					if creatingRemote && overlap == OverlapTestType_None {
						logrus.Info("OverlapTestType_None: local and remote clusters use unique CIDRs.")
						// Change CIDR for the second datastore to prevent overlap.
						topologyOptions.IPPoolCIDR = "10.75.0.0/16"
						topologyOptions.IPv6PoolCIDR = "dead:cafe::/64"
					} else if overlap == OverlapTestType_Connect {
						logrus.Info("OverlapTestType_Connect: local and remote clusters share IP pool CIDRs.")
					} else if overlap == OverlapTestType_ConnectDisconnect {
						logrus.Info("OverlapTestType_ConnectDisconnect: local and remote clusters share IP pool CIDRs.")
					}
					topologyOptions.VXLANStrategy = infrastructure.NewDefaultTunnelStrategyWithOffset(topologyOptions.IPPoolCIDR, topologyOptions.IPv6PoolCIDR, i*3)

					// Deploy the topology.
					tc, client := infrastructure.StartNNodeTopology(3, topologyOptions, infra)

					w, w6, hostW, hostW6 := setupWorkloadsWithOffset(infra, tc, topologyOptions, client, enableIPv6, i*3)

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
				}

				// From here, we establish the remote cluster connections in both directions.
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
					Expect(err).NotTo(HaveOccurred())
					_, err = cs.remote.infra.GetCalicoClient().RemoteClusterConfigurations().Delete(context.Background(), localRCC.Name, options.DeleteOptions{})
					Expect(err).NotTo(HaveOccurred())
				}
			})

			JustAfterEach(func() {
				for _, c := range cs.GetClusters() {
					if CurrentSpecReport().Failed() {
						for _, felix := range c.felixes {
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
							felix.Exec("ip", "-d", "link")
						}

						c.infra.DumpErrorData()
					}
				}
			})

			It("should have workload to workload connectivity", func() {
				cc.ExpectSome(cs.local.w[0], cs.local.w[1])
				cc.ExpectSome(cs.local.w[1], cs.local.w[0])
				cs.MaybeExpectWorkloadCrossCluster(cs.local.w[0], cs.remote.w[1], cc)
				cs.MaybeExpectWorkloadCrossCluster(cs.remote.w[1], cs.local.w[0], cc)

				if enableIPv6 {
					cc.ExpectSome(cs.local.w6[0], cs.local.w6[1])
					cc.ExpectSome(cs.local.w6[1], cs.local.w6[0])
					cs.MaybeExpectWorkloadCrossCluster(cs.local.w6[0], cs.remote.w6[1], cc)
					cs.MaybeExpectWorkloadCrossCluster(cs.remote.w6[1], cs.local.w6[0], cc)
				}

				cc.CheckConnectivity()
			})

			It("should have host to workload connectivity", func() {
				if vxlanMode == api.VXLANModeAlways && routeSource == "WorkloadIPs" {
					Skip("Skipping due to known issue with tunnel IPs not being programmed in WEP mode")
				}

				for i := 0; i < 3; i++ {
					f := cs.local.felixes[i]
					cc.ExpectSome(f, cs.local.w[0])
					cc.ExpectSome(f, cs.local.w[1])
					cc.ExpectSome(f, cs.local.w[2])
					cs.MaybeExpectWorkloadCrossCluster(f, cs.remote.w[0], cc)
					cs.MaybeExpectWorkloadCrossCluster(f, cs.remote.w[1], cc)
					cs.MaybeExpectWorkloadCrossCluster(f, cs.remote.w[2], cc)

					if enableIPv6 {
						cc.ExpectSome(f, cs.local.w6[0])
						cc.ExpectSome(f, cs.local.w6[1])
						cc.ExpectSome(f, cs.local.w6[2])
						cs.MaybeExpectWorkloadCrossCluster(f, cs.remote.w6[0], cc)
						cs.MaybeExpectWorkloadCrossCluster(f, cs.remote.w6[1], cc)
						cs.MaybeExpectWorkloadCrossCluster(f, cs.remote.w6[2], cc)
					}

					// Repeat the same tests, now with the remote felix originating the connection.
					f = cs.remote.felixes[i]
					cs.MaybeExpectWorkloadCrossCluster(f, cs.local.w[0], cc)
					cs.MaybeExpectWorkloadCrossCluster(f, cs.local.w[1], cc)
					cs.MaybeExpectWorkloadCrossCluster(f, cs.local.w[2], cc)
					cc.ExpectSome(f, cs.remote.w[0])
					cc.ExpectSome(f, cs.remote.w[1])
					cc.ExpectSome(f, cs.remote.w[2])

					if enableIPv6 {
						cs.MaybeExpectWorkloadCrossCluster(f, cs.local.w6[0], cc)
						cs.MaybeExpectWorkloadCrossCluster(f, cs.local.w6[1], cc)
						cs.MaybeExpectWorkloadCrossCluster(f, cs.local.w6[2], cc)
						cc.ExpectSome(f, cs.remote.w6[0])
						cc.ExpectSome(f, cs.remote.w6[1])
						cc.ExpectSome(f, cs.remote.w6[2])
					}
				}

				cc.CheckConnectivity()
			})

			It("should have host to host connectivity", func() {
				cc.ExpectSome(cs.local.felixes[0], cs.local.hostW[1])
				cc.ExpectSome(cs.local.felixes[1], cs.local.hostW[0])
				cc.ExpectSome(cs.local.felixes[0], cs.remote.hostW[1])
				cc.ExpectSome(cs.remote.felixes[1], cs.local.hostW[0])

				if enableIPv6 {
					cc.ExpectSome(cs.local.felixes[0], cs.local.hostW6[1])
					cc.ExpectSome(cs.local.felixes[1], cs.local.hostW6[0])
					cc.ExpectSome(cs.local.felixes[0], cs.remote.hostW6[1])
					cc.ExpectSome(cs.remote.felixes[1], cs.local.hostW6[0])
				}

				cc.CheckConnectivity()
			})

			Context("with host protection policy in place", func() {
				BeforeEach(func() {
					if enableIPv6 {
						Skip("Skipping due to known issue with ICMPv6 NDP being dropped with host endpoints")
					}

					for _, c := range cs.GetClusters() {
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
					cc.ExpectNone(cs.local.felixes[0], cs.remote.hostW[1])
					cc.ExpectNone(cs.remote.felixes[1], cs.local.hostW[0])
					if enableIPv6 {
						cc.ExpectNone(cs.local.felixes[0], cs.local.hostW6[1])
						cc.ExpectNone(cs.local.felixes[1], cs.local.hostW6[0])
						cc.ExpectNone(cs.local.felixes[0], cs.remote.hostW6[1])
						cc.ExpectNone(cs.remote.felixes[1], cs.local.hostW6[0])
					}

					// But the rules to allow VXLAN between our hosts let the workload traffic through.
					cc.ExpectSome(cs.local.w[0], cs.local.w[1])
					cc.ExpectSome(cs.local.w[1], cs.local.w[0])
					cs.MaybeExpectWorkloadCrossCluster(cs.local.w[0], cs.remote.w[1], cc)
					cs.MaybeExpectWorkloadCrossCluster(cs.remote.w[1], cs.local.w[0], cc)
					if enableIPv6 {
						cc.ExpectSome(cs.local.w6[0], cs.local.w6[1])
						cc.ExpectSome(cs.local.w6[1], cs.local.w6[0])
						cs.MaybeExpectWorkloadCrossCluster(cs.local.w6[0], cs.remote.w6[1], cc)
						cs.MaybeExpectWorkloadCrossCluster(cs.remote.w6[1], cs.local.w6[0], cc)
					}
					cc.CheckConnectivity()
				})
			})

			Context("with all-interfaces host protection policy in place", func() {
				BeforeEach(func() {
					if enableIPv6 {
						Skip("Skipping due to known issue with ICMPv6 NDP being dropped with host endpoints")
					}

					for _, c := range cs.GetClusters() {
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
					cc.ExpectNone(cs.local.felixes[0], cs.remote.hostW[1])
					cc.ExpectNone(cs.remote.felixes[1], cs.local.hostW[0])
					if enableIPv6 {
						cc.ExpectNone(cs.local.felixes[0], cs.local.hostW6[1])
						cc.ExpectNone(cs.local.felixes[1], cs.local.hostW6[0])
						cc.ExpectNone(cs.local.felixes[0], cs.remote.hostW6[1])
						cc.ExpectNone(cs.remote.felixes[1], cs.local.hostW6[0])
					}

					// Host => workload is not allowed
					cc.ExpectNone(cs.local.felixes[0], cs.local.w[1])
					cc.ExpectNone(cs.local.felixes[1], cs.local.w[0])
					cc.ExpectNone(cs.local.felixes[0], cs.remote.w[1])
					cc.ExpectNone(cs.remote.felixes[1], cs.local.w[0])
					if enableIPv6 {
						cc.ExpectNone(cs.local.felixes[0], cs.local.w6[1])
						cc.ExpectNone(cs.local.felixes[1], cs.local.w6[0])
						cc.ExpectNone(cs.local.felixes[0], cs.remote.w6[1])
						cc.ExpectNone(cs.remote.felixes[1], cs.local.w6[0])
					}

					// But host => own-workload is allowed
					cc.ExpectSome(cs.local.felixes[0], cs.local.w[0])
					cc.ExpectSome(cs.local.felixes[1], cs.local.w[1])
					cc.ExpectSome(cs.remote.felixes[0], cs.remote.w[0])
					cc.ExpectSome(cs.remote.felixes[1], cs.remote.w[1])
					if enableIPv6 {
						cc.ExpectSome(cs.local.felixes[0], cs.local.w6[0])
						cc.ExpectSome(cs.local.felixes[1], cs.local.w6[1])
						cc.ExpectSome(cs.remote.felixes[0], cs.remote.w6[0])
						cc.ExpectSome(cs.remote.felixes[1], cs.remote.w6[1])
					}

					// But the rules to allow VXLAN between our hosts let the workload traffic through.
					cc.ExpectSome(cs.local.w[0], cs.local.w[1])
					cc.ExpectSome(cs.local.w[1], cs.local.w[0])
					cs.MaybeExpectWorkloadCrossCluster(cs.local.w[0], cs.remote.w[1], cc)
					cs.MaybeExpectWorkloadCrossCluster(cs.remote.w[1], cs.local.w[0], cc)

					if enableIPv6 {
						cc.ExpectSome(cs.local.w6[0], cs.local.w6[1])
						cc.ExpectSome(cs.local.w6[1], cs.local.w6[0])
						cs.MaybeExpectWorkloadCrossCluster(cs.local.w6[0], cs.remote.w6[1], cc)
						cs.MaybeExpectWorkloadCrossCluster(cs.remote.w6[1], cs.local.w6[0], cc)
					}

					cc.CheckConnectivity()
				})

				It("should allow felixes[0] to reach felixes[1] if ingress and egress policies are in place", func() {
					// Create a policy selecting felix[0] that allows egress.
					for _, c := range cs.GetClusters() {
						policy := api.NewGlobalNetworkPolicy()
						policy.Name = "f0-egress"
						policy.Spec.Egress = []api.Rule{{Action: api.Allow}}
						policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", c.felixes[0].Hostname)
						_, err := c.client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
						Expect(err).NotTo(HaveOccurred())
					}

					// But there is no policy allowing ingress into felix[1].
					cc.ExpectNone(cs.local.felixes[0], cs.local.hostW[1])
					cc.ExpectNone(cs.local.felixes[0], cs.remote.hostW[1])
					if enableIPv6 {
						cc.ExpectNone(cs.local.felixes[0], cs.local.hostW6[1])
						cc.ExpectNone(cs.local.felixes[0], cs.remote.hostW6[1])
					}

					// felixes[1] can't reach felixes[0].
					cc.ExpectNone(cs.local.felixes[1], cs.local.hostW[0])
					cc.ExpectNone(cs.remote.felixes[1], cs.local.hostW[0])
					if enableIPv6 {
						cc.ExpectNone(cs.local.felixes[1], cs.local.hostW6[0])
						cc.ExpectNone(cs.remote.felixes[1], cs.local.hostW6[0])
					}

					// Workload connectivity is unchanged.
					cc.ExpectSome(cs.local.w[0], cs.local.w[1])
					cc.ExpectSome(cs.local.w[1], cs.local.w[0])
					cs.MaybeExpectWorkloadCrossCluster(cs.local.w[0], cs.remote.w[1], cc)
					cs.MaybeExpectWorkloadCrossCluster(cs.remote.w[1], cs.local.w[0], cc)
					if enableIPv6 {
						cc.ExpectSome(cs.local.w6[0], cs.local.w6[1])
						cc.ExpectSome(cs.local.w6[1], cs.local.w6[0])
						cs.MaybeExpectWorkloadCrossCluster(cs.local.w6[0], cs.remote.w6[1], cc)
						cs.MaybeExpectWorkloadCrossCluster(cs.remote.w6[1], cs.local.w6[0], cc)
					}
					cc.CheckConnectivity()

					cc.ResetExpectations()

					// Now add a policy selecting felix[1] that allows ingress.
					for _, c := range cs.GetClusters() {
						policy := api.NewGlobalNetworkPolicy()
						policy.Name = "f1-ingress"
						policy.Spec.Ingress = []api.Rule{{Action: api.Allow}}
						policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", c.felixes[1].Hostname)
						_, err := c.client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
						Expect(err).NotTo(HaveOccurred())
					}

					// Now felixes[0] can reach felixes[1].
					cc.ExpectSome(cs.local.felixes[0], cs.local.hostW[1])
					cc.ExpectSome(cs.local.felixes[0], cs.remote.hostW[1])
					if enableIPv6 {
						cc.ExpectSome(cs.local.felixes[0], cs.local.hostW6[1])
						cc.ExpectSome(cs.local.felixes[0], cs.remote.hostW6[1])
					}

					// felixes[1] still can't reach felixes[0].
					cc.ExpectNone(cs.local.felixes[1], cs.local.hostW[0])
					cc.ExpectNone(cs.remote.felixes[1], cs.local.hostW[0])
					if enableIPv6 {
						cc.ExpectNone(cs.local.felixes[1], cs.local.hostW6[0])
						cc.ExpectNone(cs.remote.felixes[1], cs.local.hostW6[0])
					}

					// Workload connectivity is unchanged.
					cc.ExpectSome(cs.local.w[0], cs.local.w[1])
					cc.ExpectSome(cs.local.w[1], cs.local.w[0])
					cs.MaybeExpectWorkloadCrossCluster(cs.local.w[0], cs.remote.w[1], cc)
					cs.MaybeExpectWorkloadCrossCluster(cs.remote.w[1], cs.local.w[0], cc)
					if enableIPv6 {
						cc.ExpectSome(cs.local.w6[0], cs.local.w6[1])
						cc.ExpectSome(cs.local.w6[1], cs.local.w6[0])
						cs.MaybeExpectWorkloadCrossCluster(cs.local.w6[0], cs.remote.w6[1], cc)
						cs.MaybeExpectWorkloadCrossCluster(cs.remote.w6[1], cs.local.w6[0], cc)
					}
					cc.CheckConnectivity()
				})
			})
		})
	}
})

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

func (c *VXLANClusters) GetClusters() []*VXLANClusterState {
	return []*VXLANClusterState{c.local, c.remote}
}

func (c *VXLANClusters) MaybeExpectWorkloadCrossCluster(from connectivity.ConnectionSource, to connectivity.ConnectionTarget, cc *connectivity.Checker) {
	if c.overlap == OverlapTestType_None {
		cc.ExpectSome(from, to)
	} else {
		cc.ExpectNone(from, to)
	}
}
