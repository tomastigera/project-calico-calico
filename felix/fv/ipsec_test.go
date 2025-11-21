// Copyright (c) 2018-2021 Tigera, Inc. All rights reserved.

package fv_test

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/felix/ipsec"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

const numPoliciesPerWep = 3

var _ = infrastructure.DatastoreDescribe("IPsec tests", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra    infrastructure.DatastoreInfra
		tc       infrastructure.TopologyContainers
		tcpdumps []*containers.TCPDump
		client   clientv3.Interface
		// w[n] is a simulated workload for host n.  It has its own network namespace (as if it was a container).
		w [2]*workload.Workload
		// hostW[n] is a simulated host networked workload for host n.  It runs in felix's network namespace.
		hostW [2]*workload.Workload
		cc    *connectivity.Checker
	)

	BeforeEach(func() {
		Skip("Skip ipsec tests")
		infra = getInfra()

		topologyOptions := ipSecTopologyOptions()
		tc, client = infrastructure.StartNNodeTopology(2, topologyOptions, infra)

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		// Start tcpdump inside each host container.  Dumping inside the container means that we'll see a lot less
		// noise from the rest of the system.
		tcpdumps = nil
		for _, f := range tc.Felixes {
			tcpdump := containers.AttachTCPDump(f.Container, "eth0", "esp", "or", "udp", "or", "net", "10.65.0.0/16")
			tcpdump.AddMatcher("numIKEPackets", regexp.MustCompile(`.*isakmp:.*`))
			tcpdump.AddMatcher("numInboundESPPackets", regexp.MustCompile(`.*`+regexp.QuoteMeta("> "+f.IP)+`.*ESP.*`))
			tcpdump.AddMatcher("numOutboundESPPackets", regexp.MustCompile(`.*`+regexp.QuoteMeta(f.IP+" >")+`.*ESP.*`))
			tcpdump.AddMatcher("numInboundWorkloadPackets",
				regexp.MustCompile(`.*`+regexp.QuoteMeta(">")+` 10\.65\.\d+\.2.*`))
			tcpdump.AddMatcher("numInboundWorkloadToHostPackets",
				regexp.MustCompile(`.*10\.65\.\d+\.2.\d+ `+regexp.QuoteMeta("> "+f.IP)))
			tcpdump.Start(infra)
			tcpdumps = append(tcpdumps, tcpdump)

			f.TriggerDelayedStart()
		}

		startWorkloadsandWaitForPolicy(infra, tc.Felixes, w[:], hostW[:], "tcp", client)

		cc = &connectivity.Checker{}
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			for _, felix := range tc.Felixes {
				felix.Exec("ip", "xfrm", "state")
				felix.Exec("ip", "xfrm", "policy")
			}
		}
	})

	tcpdumpMatches := func(felix int, name string) func() int {
		return func() int {
			return tcpdumps[felix].MatchCount(name)
		}
	}

	expectIKE := func() {
		for i := range tc.Felixes {
			By(fmt.Sprintf("Doing IKE (felix %v)", i))
			Eventually(tcpdumpMatches(i, "numIKEPackets")).Should(BeNumerically(">", 0),
				"tcpdump didn't record any IKE packets")
		}
	}

	expectNoESP := func() {
		for i := range tc.Felixes {
			By(fmt.Sprintf("Doing no ESP (felix %v)", i))
			Eventually(tcpdumpMatches(i, "numInboundESPPackets")).Should(BeNumerically("==", 0),
				"tcpdump saw unexpected inbound ESP packets")
			Eventually(tcpdumpMatches(i, "numOutboundESPPackets")).Should(BeNumerically("==", 0),
				"tcpdump saw unexpected outbound ESP packets")
		}
	}

	expectIKEAndESP := func() {
		expectIKE()

		for i := range tc.Felixes {
			By(fmt.Sprintf("Doing ESP (felix %v)", i))
			Eventually(tcpdumpMatches(i, "numInboundESPPackets")).Should(BeNumerically(">", 0),
				"tcpdump didn't record any inbound ESP packets")
			Eventually(tcpdumpMatches(i, "numOutboundESPPackets")).Should(BeNumerically(">", 0),
				"tcpdump didn't record any inbound ESP packets")
		}
	}

	It("workload-to-workload should be allowed and encrypted", func() {
		cc.ExpectSome(w[0], w[1])
		cc.ExpectSome(w[1], w[0])
		cc.CheckConnectivity()

		expectIKEAndESP()

		for i := range tc.Felixes {
			By(fmt.Sprintf("Doing IKE and ESP (felix %v)", i))

			// When snooping, tcpdump sees both inbound post-decryption packets as well as both inbound and outbound
			// encrypted packets.  That means we expect the number of unencrypted packets that we see in the capture
			// to be equal to the number of inbound encrypted packets.
			Eventually(func() int {
				return tcpdumpMatches(i, "numInboundWorkloadPackets")() -
					tcpdumpMatches(i, "numInboundESPPackets")()
			}).Should(BeZero(), "Number of inbound unencrypted packets didn't match number of inbound ESP packets")
		}
	})

	felixTunnelAddr := func() string {
		output, _ := tc.Felixes[0].ExecOutput("ip", "addr", "show", "tunl0")
		return output
	}

	It("should not enable the IPIP tunnel", func() {
		Consistently(felixTunnelAddr, "5s").ShouldNot(ContainSubstring(tc.Felixes[0].ExpectedIPIPTunnelAddr))
	})

	It("host-to-workload connections should be encrypted", func() {
		cc.ExpectSome(tc.Felixes[0], w[1])
		cc.ExpectSome(tc.Felixes[1], w[0])
		cc.ExpectSome(w[0], hostW[1])
		cc.ExpectSome(w[1], hostW[0])
		cc.CheckConnectivity()

		expectIKEAndESP()

		for i := range tc.Felixes {
			By(fmt.Sprintf("Having expected mix of encrypted/unencrypted packets (felix %v)", i))

			// When snooping, tcpdump sees both inbound post-decryption packets as well as both inbound and outbound
			// encrypted packets.  That means we expect the number of unencrypted packets that we see in the capture
			// to be equal to the number of inbound encrypted packets.
			Eventually(func() int {
				return tcpdumpMatches(i, "numInboundWorkloadPackets")() +
					tcpdumpMatches(i, "numInboundWorkloadToHostPackets")() -
					tcpdumpMatches(i, "numInboundESPPackets")()
			}).Should(BeZero(), "Number of inbound unencrypted packets didn't match number of inbound ESP packets")
		}
	})

	Describe("with a DNAT rule in place", func() {
		// This mimics the NAT rule used by kube-proxy to expose teh kube API server, i.e. a NAT rule from a service IP
		// to a remote host port.
		BeforeEach(func() {
			for i, f := range tc.Felixes {
				for j := range tc.Felixes {
					if i == j {
						continue
					}
					f.Exec("iptables", "-t", "nat", "-A", "PREROUTING",
						"-w",
						"-p", "tcp",
						"-d", fmt.Sprintf("10.66.%d.1", j),
						"-m", "tcp", "--dport", "8080",
						"-j", "DNAT", "--to-destination",
						tc.Felixes[j].IP+":8055")
					f.Exec("iptables", "-t", "nat", "-A", "PREROUTING",
						"-w",
						"-p", "tcp",
						"-d", fmt.Sprintf("10.66.%d.2", j),
						"-m", "tcp", "--dport", "8080",
						"-j", "DNAT", "--to-destination",
						w[j].IP+":8055")
				}
			}
		})

		It("should have connectivity via NAT entries", func() {
			// NAT to remote host
			cc.ExpectSome(w[0], connectivity.TargetIP("10.66.1.1"), 8080)
			cc.ExpectSome(w[1], connectivity.TargetIP("10.66.0.1"), 8080)
			// NAT to remote workload
			cc.ExpectSome(w[0], connectivity.TargetIP("10.66.1.2"), 8080)
			cc.ExpectSome(w[1], connectivity.TargetIP("10.66.0.2"), 8080)
			cc.CheckConnectivity()
		})
	})

	It("should have unencrypted host to host connectivity", func() {
		cc.ExpectSome(tc.Felixes[0], hostW[1])
		cc.ExpectSome(tc.Felixes[1], hostW[0])
		cc.CheckConnectivity()

		expectIKE()
		expectNoESP()
	})

	It("should have host to local workload connectivity", func() {
		cc.ExpectSome(tc.Felixes[0], w[0])
		cc.ExpectSome(tc.Felixes[1], w[1])
		cc.ExpectSome(tc.Felixes[0], hostW[0])
		cc.ExpectSome(tc.Felixes[1], hostW[1])
		cc.CheckConnectivity()
	})

	Context("with host protection policy in place", func() {
		BeforeEach(func() {
			// Make sure host endpoints don't block IPSec traffic (since they deny all traffic by default)
			err := infra.AddAllowToDatastore("host-endpoint=='true'")
			Expect(err).NotTo(HaveOccurred())

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			for _, f := range tc.Felixes {
				hep := api.NewHostEndpoint()
				hep.Name = "eth0-" + f.Name
				hep.Labels = map[string]string{
					"host-endpoint": "true",
				}
				hep.Spec.Node = f.Hostname
				hep.Spec.ExpectedIPs = []string{f.IP}
				_, err := client.HostEndpoints().Create(ctx, hep, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
			}
		})

		It("should have workload connectivity but not host connectivity", func() {
			// Host endpoints (with no policies) block host-host traffic due to default drop.
			cc.ExpectNone(tc.Felixes[0], hostW[1])
			cc.ExpectNone(tc.Felixes[1], hostW[0])
			// But the rules to allow IPSec between our hosts let the workload traffic through.
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[1], w[0])
			cc.CheckConnectivity()
		})
	})

	var savedBGPSpec libapi.NodeBGPSpec
	var node *libapi.Node

	restoreBGPSpec := func() {
		felixPID := tc.Felixes[0].GetFelixPID()
		node.Spec.BGP = &savedBGPSpec
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		var err error
		node, err = client.Nodes().Update(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
		// Wait for felix to restart.
		Eventually(tc.Felixes[0].GetFelixPID, "5s", "100ms").ShouldNot(Equal(felixPID))
	}

	Context("after removing host address from nodes", func() {
		// In this scenario, we remove the host IP from one of the nodes, this should trigger Felix to
		// blacklist the workload IPs on the remote host.

		BeforeEach(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			felixPID := tc.Felixes[0].GetFelixPID()

			l, err := client.Nodes().List(ctx, options.ListOptions{Name: tc.Felixes[0].Hostname})
			Expect(err).NotTo(HaveOccurred())
			Expect(l.Items).To(HaveLen(1))
			n := l.Items[0]
			log.WithField("node", n).Info("Removing BGP state from node")
			savedBGPSpec = *n.Spec.BGP
			n.Spec.BGP = nil
			node, err = client.Nodes().Update(ctx, &n, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Wait for felix to restart.
			Eventually(tc.Felixes[0].GetFelixPID, "5s", "100ms").ShouldNot(Equal(felixPID))
		})

		It("should have no workload to workload connectivity until we restore the host IP", func() {
			By("Having no connectivity initially")
			cc.ExpectNone(w[0], w[1])
			cc.ExpectNone(w[1], w[0])
			cc.CheckConnectivity()

			By("Having connectivity after we restore the host IP")
			restoreBGPSpec()

			cc.ResetExpectations()
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[1], w[0])
			cc.CheckConnectivity()
		})
	})

	Context("after changing the host address on a node to a bad value", func() {
		// In this scenario, we remove the host IP from one of the nodes, this should trigger Felix to
		// blacklist the workload IPs on the remote host.

		var felixPID int

		BeforeEach(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			felixPID = tc.Felixes[0].GetFelixPID()

			l, err := client.Nodes().List(ctx, options.ListOptions{Name: tc.Felixes[0].Hostname})
			Expect(err).NotTo(HaveOccurred())
			Expect(l.Items).To(HaveLen(1))
			n := l.Items[0]
			log.WithField("node", n).Info("Replacing BGP IP with garbage")
			savedBGPSpec = *n.Spec.BGP

			s := strings.Split(n.Spec.BGP.IPv4Address, "/") // split x.x.x.x/x
			Expect(len(s)).To(Equal(2))
			Expect(s[0]).To(Equal(tc.Felixes[0].IP))
			n.Spec.BGP.IPv4Address = "10.65.0.100" + "/" + s[1] // Unused workload IP.
			node, err = client.Nodes().Update(ctx, &n, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		It("felix should program bad policies and then restore the policies once we restore the IP", func() {
			Eventually(tc.Felixes[0].GetFelixPID, "5s", "100ms").ShouldNot(Equal(felixPID))

			Eventually(func() int { return policyCount(tc.Felixes[0], tc.Felixes[0].IP) }, "5s", "100ms").Should(BeZero())
			Eventually(func() int { return policyCount(tc.Felixes[0], "10.65.0.100") }, "5s", "100ms").ShouldNot(BeZero())

			// Should have no connectivity with broken config.
			cc.ExpectNone(w[0], w[1])
			cc.ExpectNone(w[1], w[0])
			cc.CheckConnectivity()

			restoreBGPSpec()

			Eventually(func() int { return policyCount(tc.Felixes[0], tc.Felixes[0].IP) }, "5s", "100ms").ShouldNot(BeZero())
			Eventually(func() int { return policyCount(tc.Felixes[0], "10.65.0.100") }, "5s", "100ms").Should(BeZero())

			cc.ResetExpectations()
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[1], w[0])
			cc.CheckConnectivity()
		})
	})

	Context("after disabling IPsec", func() {
		totalPolCount := func() (count int) {
			for _, f := range tc.Felixes {
				count += policyCount(f, fmt.Sprint(ipsec.ReqID))
			}
			return
		}

		BeforeEach(func() {
			// Check that our policy counting function does pick up our policies before we use it in anger below.
			Eventually(totalPolCount, "5s", "100ms").Should(BeNumerically(">", 0))
			disableIPSec(client)
		})

		It("should enable the IPIP tunnel", func() {
			Eventually(felixTunnelAddr, "5s").Should(ContainSubstring(tc.Felixes[0].ExpectedIPIPTunnelAddr))
		})

		It("should remove the IPsec policy and have connectivity", func() {
			// The policy is disabled gracefully so it can take a while for all the policy to be gone.
			Eventually(totalPolCount, "180s", "100ms").Should(BeZero())

			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[1], w[0])
			cc.ExpectSome(tc.Felixes[0], w[1])
			cc.ExpectSome(tc.Felixes[1], w[0])
			cc.ExpectSome(tc.Felixes[0], w[0])
			cc.ExpectSome(tc.Felixes[1], w[1])
			cc.CheckConnectivity()
		})
	})

	Context("after switching to allow-unsecured mode IPsec", func() {
		BeforeEach(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			felixConfig, err := client.FelixConfigurations().Get(ctx, "default", options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			t := true
			felixConfig.Spec.IPSecAllowUnsecuredTraffic = &t
			felixConfig, err = client.FelixConfigurations().Update(ctx, felixConfig, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			for _, f := range tc.Felixes {
				Eventually(func() int { return policyCount(f, "level use") }, "5s").Should(BeNumerically(">", numPoliciesPerWep))
			}
		})

		It("should have connectivity", func() {
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[1], w[0])
			cc.ExpectSome(tc.Felixes[0], w[1])
			cc.ExpectSome(tc.Felixes[1], w[0])
			cc.ExpectSome(tc.Felixes[0], w[0])
			cc.ExpectSome(tc.Felixes[1], w[1])
			cc.ExpectSome(w[0], hostW[1])
			cc.ExpectSome(w[1], hostW[0])
			cc.CheckConnectivity()
		})
	})

	Context("after applying a grace-period license", func() {
		BeforeEach(func() {
			infrastructure.ApplyGracePeriodLicense(client)
		})

		It("should switch to optional policies and have connectivity", func() {
			for _, f := range tc.Felixes {
				Eventually(func() int { return policyCount(f, "level use") }, "5s").Should(BeNumerically(">", numPoliciesPerWep))
			}

			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[1], w[0])
			cc.ExpectSome(tc.Felixes[0], w[1])
			cc.ExpectSome(tc.Felixes[1], w[0])
			cc.ExpectSome(tc.Felixes[0], w[0])
			cc.ExpectSome(tc.Felixes[1], w[1])
			cc.ExpectSome(w[0], hostW[1])
			cc.ExpectSome(w[1], hostW[0])
			cc.CheckConnectivity()
		})
	})

	Context("after flushing IPsec policy on one host", func() {
		BeforeEach(func() {
			// Felix will spot this eventually, but its default refresh time is several minutes...
			tc.Felixes[0].Exec("ip", "xfrm", "policy", "flush")
		})

		It("should have no workload connectivity", func() {
			cc.ExpectNone(w[0], w[1])
			cc.ExpectNone(w[1], w[0])
			cc.ExpectNone(w[0], hostW[1])
			cc.ExpectNone(w[1], hostW[0])
			cc.ExpectNone(tc.Felixes[0], w[1])
			cc.ExpectNone(tc.Felixes[1], w[0])
			cc.CheckConnectivity()
		})
	})
})

var _ = infrastructure.DatastoreDescribe("IPsec initially disabled tests", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra  infrastructure.DatastoreInfra
		tc     infrastructure.TopologyContainers
		client clientv3.Interface
		// w[n] is a simulated workload for host n.  It has its own network namespace (as if it was a container).
		w [2]*workload.Workload
		// hostW[n] is a simulated host networked workload for host n.  It runs in felix's network namespace.
		hostW [2]*workload.Workload
		cc    *connectivity.Checker
	)

	BeforeEach(func() {
		Skip("Skip ipsec tests")
		var err error

		infra = getInfra()

		topologyOptions := ipSecTopologyOptions()

		fc := api.NewFelixConfiguration()
		fc.SetName("default")
		t := true
		fc.Spec.IPSecAllowUnsecuredTraffic = &t

		topologyOptions.InitialFelixConfiguration = fc
		tc, client = infrastructure.StartNNodeTopology(2, topologyOptions, infra)

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		for _, f := range tc.Felixes {
			f.TriggerDelayedStart()
		}

		createWorkloads(infra, tc.Felixes, w[:], hostW[:], "tcp", client)

		cc = &connectivity.Checker{}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Enable IPsec at node scope on one host.
		fc = api.NewFelixConfiguration()
		fc.Name = "node." + tc.Felixes[1].Hostname
		fc.Spec.IPSecMode = "PSK"
		_, err = client.FelixConfigurations().Create(ctx, fc, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Turning on the option should make felix switch to "use"-level policy.
		Eventually(func() int { return policyCount(tc.Felixes[1], "level use") }, "5s").ShouldNot(BeZero())
		Eventually(func() int { return policyCount(tc.Felixes[1], w[0].IP) }, "5s", "100ms").Should(
			Equal(numPoliciesPerWep),
			fmt.Sprintf("Expected to see %d IPsec policies for workload IP %s in felix container %s",
				numPoliciesPerWep, w[0].IP, tc.Felixes[1].Name))
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			for _, felix := range tc.Felixes {
				felix.Exec("ip", "xfrm", "state")
				felix.Exec("ip", "xfrm", "policy")
			}
		}
	})

	It("should still have workload connectivity", func() {
		cc.ExpectSome(w[0], w[1])
		cc.ExpectSome(w[1], w[0])
		cc.ExpectSome(w[0], hostW[1])
		cc.ExpectSome(w[1], hostW[0])
		cc.ExpectSome(tc.Felixes[0], w[1])
		cc.ExpectSome(tc.Felixes[1], w[0])
		cc.CheckConnectivity()
	})
})

var _ = infrastructure.DatastoreDescribe("IPsec 3-node tests", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra    infrastructure.DatastoreInfra
		tc       infrastructure.TopologyContainers
		tcpdumps []*containers.TCPDump
		client   clientv3.Interface
		// w[n] is a simulated workload for host n.  It has its own network namespace (as if it was a container).
		w [2]*workload.Workload
		// hostW[n] is a simulated host networked workload for host n.  It runs in felix's network namespace.
		hostW [3]*workload.Workload
		cc    *connectivity.Checker
	)

	BeforeEach(func() {
		Skip("Skip ipsec tests")
		infra = getInfra()

		tc, client = infrastructure.StartNNodeTopology(3, ipSecTopologyOptions(), infra)

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		// Start tcpdump inside each host container.  Dumping inside the container means that we'll see a lot less
		// noise from the rest of the system.
		tcpdumps = nil
		for _, f := range tc.Felixes {
			tcpdump := containers.AttachTCPDump(f.Container, "eth0", "esp", "or", "udp")
			tcpdump.AddMatcher("numInboundESPPackets", regexp.MustCompile(`.*`+regexp.QuoteMeta("> "+f.IP)+`.*ESP.*`))
			tcpdump.AddMatcher("numPlaintextOutboundWorkloadPackets", regexp.MustCompile(`.*10\.65\.\d+\.2.*`+regexp.QuoteMeta(" >")+`.*`))
			tcpdump.AddMatcher("numInboundWorkloadToHostPackets",
				regexp.MustCompile(`.*10\.65\.\d+\.2.\d+ `+regexp.QuoteMeta("> "+f.IP)))
			tcpdump.Start(infra)
			tcpdumps = append(tcpdumps, tcpdump)

			f.TriggerDelayedStart()
		}

		startWorkloadsandWaitForPolicy(infra, tc.Felixes, w[:], hostW[:], "udp", client) /* UDP for packet loss test */

		cc = &connectivity.Checker{}
		cc.Protocol = "udp"
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			for _, felix := range tc.Felixes {
				felix.Exec("ip", "xfrm", "state")
				felix.Exec("ip", "xfrm", "policy")
			}
		}
	})

	It("should have encrypted connectivity from host with no workloads to/from workloads", func() {
		cc.ExpectSome(tc.Felixes[2], w[0])
		cc.ExpectSome(tc.Felixes[2], w[1])
		cc.ExpectSome(w[0], hostW[2])
		cc.ExpectSome(w[1], hostW[2])
		cc.CheckConnectivity()

		Eventually(func() int {
			return tcpdumps[2].MatchCount("numInboundESPPackets")
		}).Should(BeNumerically(">", 0))

		// Wait for tcpdump to finish its output.
		lastSeenESP := 0
		Eventually(func() int {
			espSeen := tcpdumps[2].MatchCount("numInboundESPPackets")
			newESPs := espSeen - lastSeenESP
			lastSeenESP = espSeen
			return newESPs
		}, "2s", "200ms").Should(BeNumerically("==", 0))

		Consistently(func() int {
			return tcpdumps[0].MatchCount("numPlaintextOutboundWorkloadPackets")
		}).Should(BeZero(), "expected no plaintext outbound workload packets")
		Eventually(func() int {
			return tcpdumps[2].MatchCount("numInboundESPPackets") -
				tcpdumps[2].MatchCount("numInboundWorkloadToHostPackets")
		}).Should(BeZero(), "saw a difference between the number of encrypted and plaintext packets")
	})

	describeGracefulShutdownTest := func(disableFunc func(clientv3.Interface)) {
		totalPolCount := func() (count int) {
			for _, f := range tc.Felixes {
				count += policyCount(f, fmt.Sprint(ipsec.ReqID))
			}
			return
		}

		BeforeEach(func() {
			// Wait for IPsec policy to converge before starting the test.
			const expNumXFRMPols = 24
			Eventually(totalPolCount, "10s", "100ms").Should(Equal(expNumXFRMPols))
		})

		It("should remove the IPsec policy gracefully, maintaining connectivity", func() {
			// Sanity check before we start the main packet loss measurement.
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(hostW[0], w[1])
			cc.ExpectSome(w[0], hostW[1])
			cc.CheckConnectivity()

			var wg sync.WaitGroup
			wg.Add(1)
			defer wg.Wait() // Make sure we wait for background work to finish even if test fails.
			go func() {
				defer wg.Done()
				time.Sleep(5 * time.Second)
				disableFunc(client)
			}()

			// Since we're about to send a lot of traffic, disable tcpdump logging.
			for _, t := range tcpdumps {
				t.SetLogEnabled(false)
			}

			cc.ResetExpectations()
			// Unfortunately, there is a long-standing bug in our IPsec implementation that means that
			// disabling IPsec _is_ disruptive.  While we carefully tear down the XFRM policies in a non-destructive
			// way, Felix restarts when IPsec is disabled, which in turn causes the Charon to exit.  As part of its
			// shut-down processing, it tears down the IPsec peerings, causing unexpected disruption.
			const expectedLossPct = 10
			cc.ExpectLoss(w[0], w[1], 20*time.Second, expectedLossPct, -1)
			cc.ExpectLoss(hostW[0], w[1], 20*time.Second, expectedLossPct, -1)
			cc.ExpectLoss(w[0], hostW[1], 20*time.Second, expectedLossPct, -1)
			cc.CheckConnectivity()

			wg.Wait()
			Eventually(totalPolCount, "60s", "100ms").Should(BeZero())

			// As a cross check on our regex, check that we do see the plaintext packets
			Eventually(func() int {
				return tcpdumps[0].MatchCount("numPlaintextOutboundWorkloadPackets")
			}).Should(BeNumerically(">", 0),
				"expected plaintext outbound workload packets")
		})
	}
	Context("after disabling IPsec", func() {
		describeGracefulShutdownTest(disableIPSec)
	})
	Context("after license expires IPsec", func() {
		describeGracefulShutdownTest(infrastructure.ApplyExpiredLicense)
	})
})

func ipSecTopologyOptions() infrastructure.TopologyOptions {
	topologyOptions := infrastructure.DefaultTopologyOptions()
	// Delay Felix startup until we trigger it so that we can attach tcpdump first.
	topologyOptions.DelayFelixStart = true
	// Set up IPsec.
	topologyOptions.ExtraEnvVars["FELIX_IPSECPSKFILE"] = "/proc/1/cmdline"
	topologyOptions.ExtraEnvVars["FELIX_DebugUseShortPollIntervals"] = "true"

	felixConfig := api.NewFelixConfiguration()
	felixConfig.SetName("default")
	felixConfig.Spec.IPSecMode = "PSK"
	topologyOptions.InitialFelixConfiguration = felixConfig

	// Set up IPIP configuration but routes as if IPIP was disabled.  This allows us to check that Felix correctly
	// ignores IPIP configuration when IPsec is enabled.
	topologyOptions.IPIPMode = api.IPIPModeAlways
	// Turn on NAT outgoing because it interacts with IPsec; when a workload connects to a remote host with IPsec
	// then we _do not_ SNAT the traffic because it is tunneled.  Otherwise, we _do_ NAT such traffic because
	// we can't guarantee that the traffic won't get dropped by the fabric due to RPF.
	topologyOptions.NATOutgoingEnabled = true
	return topologyOptions
}

func disableIPSec(client clientv3.Interface) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	felixConfig, err := client.FelixConfigurations().Get(ctx, "default", options.GetOptions{})
	Expect(err).NotTo(HaveOccurred())
	felixConfig.Spec.IPSecMode = ""
	felixConfig, err = client.FelixConfigurations().Update(ctx, felixConfig, options.SetOptions{})
	Expect(err).NotTo(HaveOccurred())
}

func startWorkloadsandWaitForPolicy(
	infra infrastructure.DatastoreInfra,
	felixes []*infrastructure.Felix,
	w, hostW []*workload.Workload,
	protocol string,
	client clientv3.Interface,
) {
	createWorkloads(infra, felixes, w, hostW, protocol, client)
	waitForPolicy(felixes, w)
}

func createWorkloads(
	infra infrastructure.DatastoreInfra,
	felixes []*infrastructure.Felix,
	w, hostW []*workload.Workload,
	protocol string,
	client clientv3.Interface,
) {
	// Create workloads, using the default profile.  One on each "host".
	for ii := range w {
		wIP := fmt.Sprintf("10.65.%d.2", ii)
		wName := fmt.Sprintf("w%d", ii)
		infrastructure.AssignIP(wName, wIP, felixes[ii].Hostname, client)
		w[ii] = workload.Run(felixes[ii], wName, "default", wIP, "8055", protocol)
		w[ii].ConfigureInInfra(infra)
	}
	for ii := range hostW {
		hostW[ii] = workload.Run(felixes[ii], fmt.Sprintf("host%d", ii), "", felixes[ii].IP, "8055", protocol)
	}
}

func waitForPolicy(felixes []*infrastructure.Felix, w []*workload.Workload) {
	// Wait for Felix to program the IPsec policy.  Otherwise, we might see some unencrypted traffic at
	// start-of-day.  There's not much we can do about that in general since we don't know the workload's IP
	// to blacklist it until we hear about the workload.
	for i, f := range felixes {
		for j := range w {
			if i == j {
				continue
			}

			// Felix might restart during set up, causing a 2s delay here.
			Eventually(func() int { return policyCount(f, w[j].IP) }, "5s", "100ms").Should(
				Equal(numPoliciesPerWep),
				fmt.Sprintf("Expected to see %d IPsec policies for workload IP %s in felix container %s",
					numPoliciesPerWep, w[j].IP, f.Name))
		}
	}
}

func policyCount(felix *infrastructure.Felix, needle string) int {
	out, err := felix.ExecOutput("ip", "xfrm", "policy")
	Expect(err).NotTo(HaveOccurred())
	return strings.Count(out, needle)
}
