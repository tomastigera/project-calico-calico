// Copyright (c) 2019,2021 Tigera, Inc. All rights reserved.
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
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("NATOutgoing rule rendering test", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra  infrastructure.DatastoreInfra
		tc     infrastructure.TopologyContainers
		client client.Interface
	)

	BeforeEach(func() {
		var err error
		infra = getInfra()

		opts := infrastructure.DefaultTopologyOptions()
		opts.IPIPMode = api.IPIPModeNever
		opts.EnableIPv6 = true

		if NFTMode() {
			Skip("NFT mode not supported in this test")
		}

		opts.ExtraEnvVars = map[string]string{
			"FELIX_IptablesNATOutgoingInterfaceFilter": "eth+",
			"FELIX_NATOutgoingExclusions":              "IPPoolsAndHostIPs",
		}
		tc, client = infrastructure.StartSingleNodeTopology(opts, infra)

		ctx := context.Background()
		ippool := api.NewIPPool()
		ippool.Name = "nat-pool"
		ippool.Spec.CIDR = "10.244.255.0/24"
		ippool.Spec.NATOutgoing = true
		ippool, err = client.IPPools().Create(ctx, ippool, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should have expected restriction on the nat outgoing rule", func() {
		if NFTMode() {
			Eventually(func() string {
				output, _ := tc.Felixes[0].ExecOutput("nft", "list", "chain", "ip", "calico", "nat-cali-nat-outgoing")
				return output
			}, 5*time.Second, 100*time.Millisecond).Should(MatchRegexp(".* oifname eth\\+"))
		} else {
			Eventually(func() string {
				output, _ := tc.Felixes[0].ExecOutput("iptables-save", "-t", "nat")
				return output
			}, 5*time.Second, 100*time.Millisecond).Should(MatchRegexp("-A cali-nat-outgoing .*-o eth\\+ "))
		}
	})
})

var _ = infrastructure.DatastoreDescribe("NATPortRange rendering test", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra  infrastructure.DatastoreInfra
		tc     infrastructure.TopologyContainers
		client client.Interface
	)

	BeforeEach(func() {
		var err error
		infra = getInfra()

		opts := infrastructure.DefaultTopologyOptions()
		opts.IPIPMode = api.IPIPModeNever
		opts.EnableIPv6 = true

		opts.ExtraEnvVars = map[string]string{
			"FELIX_NATPortRange": "32768:65535",
		}
		tc, client = infrastructure.StartSingleNodeTopology(opts, infra)

		ctx := context.Background()
		ippool := api.NewIPPool()
		ippool.Name = "nat-pool"
		ippool.Spec.CIDR = "10.244.255.0/24"
		ippool.Spec.NATOutgoing = true
		ippool, err = client.IPPools().Create(ctx, ippool, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should have expected rendering", func() {
		if NFTMode() {
			Eventually(func() string {
				output, _ := tc.Felixes[0].ExecOutput("nft", "list", "chain", "ip", "calico", "nat-cali-nat-outgoing")
				return output
			}, 5*time.Second, 100*time.Millisecond).Should(ContainSubstring("32768-65535"))
		} else {
			Eventually(func() string {
				output, _ := tc.Felixes[0].ExecOutput("iptables-save", "-t", "nat")
				return output
			}, 5*time.Second, 100*time.Millisecond).Should(ContainSubstring("32768-65535"))
		}
	})
})

var _ = infrastructure.DatastoreDescribeRemoteOnly("NATOutgoing remote cluster rendering test", func(factories infrastructure.LocalRemoteInfraFactories) {
	var infra [2]infrastructure.DatastoreInfra
	var tc [2]infrastructure.TopologyContainers
	var natPool [2]*api.IPPool

	BeforeEach(func() {
		for i, infraFactory := range factories.AllFactories() {
			topologyOptions := infrastructure.DefaultTopologyOptions()
			topologyOptions.VXLANMode = api.VXLANModeAlways
			topologyOptions.VXLANStrategy = infrastructure.NewDefaultTunnelStrategy(topologyOptions.IPPoolCIDR, topologyOptions.IPv6PoolCIDR)
			topologyOptions.WithTypha = true
			topologyOptions.IPIPMode = api.IPIPModeNever
			if i == 1 {
				// Change CIDR of the default pool for the second datastore to prevent overlap.
				topologyOptions.IPPoolCIDR = "10.75.0.0/16"
			}

			infra[i] = infraFactory()
			tc[i], _ = infrastructure.StartNNodeTopology(1, topologyOptions, infra[i])

			// Create a NAT outgoing pool for each cluster. Set VXLAN mode and create before the RCC to default OverlayRoutingMode correctly.
			var err error
			natPool[i] = api.NewIPPool()
			natPool[i].Name = "nat-pool"
			if i == 1 {
				// Change CIDR of the NAT pool for the second datastore to prevent overlap.
				natPool[i].Spec.CIDR = "10.255.255.0/24"
			} else {
				natPool[i].Spec.CIDR = "10.244.255.0/24"
			}
			natPool[i].Spec.VXLANMode = api.VXLANModeAlways
			natPool[i].Spec.NATOutgoing = true
			natPool[i], err = infra[i].GetCalicoClient().IPPools().Create(context.Background(), natPool[i], options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
		}

		var err error

		// Setup local with an RCC for remote.
		remoteRCC := infra[1].GetRemoteClusterConfig()
		_, err = infra[0].GetCalicoClient().RemoteClusterConfigurations().Create(context.Background(), remoteRCC, options.SetOptions{})
		Expect(err).To(BeNil())

		// Setup remote with an RCC for local.
		localRCC := infra[0].GetRemoteClusterConfig()
		_, err = infra[1].GetCalicoClient().RemoteClusterConfigurations().Create(context.Background(), localRCC, options.SetOptions{})
		Expect(err).To(BeNil())
	})

	It("should have expected all pools ipset", func() {
		if NFTMode() {
			listingAllIPAMPoolsIPSet := func() string {
				output, _ := tc[0].Felixes[0].ExecOutput("nft", "list", "set", "ip", "calico", "cali40all-ipam-pools")
				return output
			}
			Eventually(listingAllIPAMPoolsIPSet, 5*time.Second, 100*time.Millisecond).Should(ContainSubstring(natPool[0].Spec.CIDR))
			Eventually(listingAllIPAMPoolsIPSet, 5*time.Second, 100*time.Millisecond).Should(ContainSubstring(natPool[1].Spec.CIDR))
		} else {
			listingAllIPAMPoolsIPSet := func() string {
				output, _ := tc[0].Felixes[0].ExecOutput("ipset", "-L", "cali40all-ipam-pools")
				return output
			}

			// The remote pool should be included in the all pools ipset, as traffic to it should not be masqueraded.
			Eventually(listingAllIPAMPoolsIPSet, 5*time.Second, 100*time.Millisecond).Should(ContainSubstring("Number of entries: 2"))
			Eventually(listingAllIPAMPoolsIPSet, 5*time.Second, 100*time.Millisecond).Should(ContainSubstring(natPool[0].Spec.CIDR))
			Eventually(listingAllIPAMPoolsIPSet, 5*time.Second, 100*time.Millisecond).Should(ContainSubstring(natPool[1].Spec.CIDR))
		}
	})

	It("should have expected masq pools ipset", func() {
		if NFTMode() {
			listingMasqIPAMPoolsIPSet := func() string {
				output, _ := tc[0].Felixes[0].ExecOutput("nft", "list", "set", "ip", "calico", "cali40masq-ipam-pools")
				return output
			}
			Eventually(listingMasqIPAMPoolsIPSet, 5*time.Second, 100*time.Millisecond).Should(ContainSubstring(natPool[0].Spec.CIDR))
		} else {
			listingMasqIPAMPoolsIPSet := func() string {
				output, _ := tc[0].Felixes[0].ExecOutput("ipset", "-L", "cali40masq-ipam-pools")
				return output
			}

			// The remote pool should not be programmed as a masq pool for the local cluster.
			Eventually(listingMasqIPAMPoolsIPSet, 5*time.Second, 100*time.Millisecond).Should(ContainSubstring("Number of entries: 1"))
			Eventually(listingMasqIPAMPoolsIPSet, 5*time.Second, 100*time.Millisecond).Should(ContainSubstring(natPool[0].Spec.CIDR))
		}
	})
})
