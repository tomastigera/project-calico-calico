// Copyright (c) 2018-2021 Tigera, Inc. All rights reserved.

package fv_test

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/metrics"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

// Pause time before felix will generate Calico Enterprise metrics
var pollingInterval = time.Duration(10) * time.Second

var _ = infrastructure.DatastoreDescribe("Calico Enterprise Metrics, etcd datastore, 4 workloads", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra          infrastructure.DatastoreInfra
		tc             infrastructure.TopologyContainers
		defaultProfile *api.Profile
		felix          *infrastructure.Felix
		client         client.Interface
		w              [4]*workload.Workload
		err            error
	)

	BeforeEach(func() {
		infra = getInfra()

		tc, client = infrastructure.StartNNodeTopology(1, infrastructure.DefaultTopologyOptions(), infra)
		felix = tc.Felixes[0]

		// Default profile that ensures connectivity.
		defaultProfile = api.NewProfile()
		defaultProfile.Name = "default"
		defaultProfile.Spec.LabelsToApply = map[string]string{"default": ""}
		defaultProfile.Spec.Egress = []api.Rule{{Action: api.Allow}}
		defaultProfile.Spec.Ingress = []api.Rule{{
			Action: api.Allow,
			Source: api.EntityRule{Selector: "default == ''"},
		}}
		defaultProfile, err = client.Profiles().Create(utils.Ctx, defaultProfile, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// Create two workloads, using the profile created above.
		for ii := range w {
			iiStr := strconv.Itoa(ii)
			w[ii] = workload.Run(felix, "w"+iiStr, "default", "10.65.0.1"+iiStr, "8055", "tcp")
			w[ii].Configure(client)
		}
	})

	AfterEach(func() {
		if CurrentSpecReport().Failed() {
			felix.Exec("iptables-save", "-c")
			felix.Exec("ip", "r")
			cprc, _ := metrics.GetCNXMetrics(felix.IP, "cnx_policy_rule_connections")
			cprp, _ := metrics.GetCNXMetrics(felix.IP, "cnx_policy_rule_packets")
			cprb, _ := metrics.GetCNXMetrics(felix.IP, "cnx_policy_rule_bytes")
			cdp, _ := metrics.GetCNXMetrics(felix.IP, "calico_denied_packets")
			cdb, _ := metrics.GetCNXMetrics(felix.IP, "calico_denied_bytes")
			log.Info("Collected Calico Enterprise Metrics\n\n" +
				"cnx_policy_rule_connections\n" +
				"===========================\n" +
				strings.Join(cprc, "\n") + "\n\n" +
				"cnx_policy_rule_packets\n" +
				"=======================\n" +
				strings.Join(cprp, "\n") + "\n\n" +
				"cnx_policy_rule_bytes\n" +
				"=====================\n" +
				strings.Join(cprb, "\n") + "\n\n" +
				"calico_denied_packets\n" +
				"=====================\n" +
				strings.Join(cdp, "\n") + "\n\n" +
				"calico_denied_bytes\n" +
				"===================\n" +
				strings.Join(cdb, "\n") + "\n\n",
			)
		}
	})

	It("should generate connection metrics for rule matches on a profile", func() {
		var conns, bytes, packets int
		incCounts := func(deltaConn, numPackets, packetSize int) {
			conns += deltaConn
			packets += numPackets
			bytes += calculateBytesForPacket("ICMP", numPackets, packetSize)
		}
		expectCounts := func() {
			// Pause to allow felix to export metrics.
			time.Sleep(pollingInterval)
			// Local-to-Local traffic causes accounting from both workload perspectives.
			Expect(func() (int, error) {
				return metrics.GetCNXConnectionMetricsIntForPolicy(felix.IP, "", "__PROFILE__", "default", "outbound")
			}()).Should(BeNumerically("==", conns))
			// ICMP request and responses are the same size.
			Expect(func() (int, error) {
				return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, "", "allow", "__PROFILE__", "default", "outbound", "ingress")
			}()).Should(BeNumerically("==", packets))
			Expect(func() (int, error) {
				return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, "", "allow", "__PROFILE__", "default", "inbound", "ingress")
			}()).Should(BeNumerically("==", packets))
			Expect(func() (int, error) {
				return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, "", "allow", "__PROFILE__", "default", "outbound", "ingress")
			}()).Should(BeNumerically("==", bytes))
			Expect(func() (int, error) {
				return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, "", "allow", "__PROFILE__", "default", "inbound", "ingress")
			}()).Should(BeNumerically("==", bytes))
		}

		By("Sending pings from w0->w1 and w1->w0 and checking received counts")
		// Wait a bit for policy to be programmed.
		time.Sleep(pollingInterval)
		stderr, err := w[0].SendPacketsTo(w[1].IP, 1, 2)
		Expect(err).NotTo(HaveOccurred(), stderr)
		incCounts(1, 1, 2)
		stderr, err = w[1].SendPacketsTo(w[0].IP, 1, 2)
		Expect(err).NotTo(HaveOccurred(), stderr)
		incCounts(1, 1, 2)
		expectCounts()

		By("Sending pings more pings from w0->w1 and sending pings from w1->w2 and w2->w3 and checking received counts")
		stderr, err = w[0].SendPacketsTo(w[1].IP, 1, 1)
		Expect(err).NotTo(HaveOccurred(), stderr)
		incCounts(1, 1, 1)
		stderr, err = w[1].SendPacketsTo(w[2].IP, 2, 5)
		Expect(err).NotTo(HaveOccurred(), stderr)
		incCounts(1, 2, 5)
		stderr, err = w[2].SendPacketsTo(w[3].IP, 3, 7)
		Expect(err).NotTo(HaveOccurred(), stderr)
		incCounts(1, 3, 7)
		expectCounts()
	})

	Context("should generate connection metrics for rule matches on a policy", func() {
		It("should generate connection metrics when there is full connectivity between workloads, testing ingress rule index", func() {
			By("Creating a policy with multiple ingress rules matching on different workloads")
			policy := api.NewNetworkPolicy()
			policy.Namespace = "fv"
			policy.Name = "default.policy-test-ingress-idx"
			policy.Spec.Tier = "default"
			policy.Spec.Types = []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress}
			policy.Spec.Ingress = []api.Rule{
				{
					Action:      api.Allow,
					Destination: api.EntityRule{Selector: w[0].NameSelector()},
				},
				{
					Action:      api.Allow,
					Destination: api.EntityRule{Selector: w[1].NameSelector()},
				},
				{
					Action:      api.Allow,
					Destination: api.EntityRule{Selector: w[2].NameSelector()},
				},
				{
					Action:      api.Allow,
					Destination: api.EntityRule{Selector: w[3].NameSelector()},
				},
			}
			policy.Spec.Egress = []api.Rule{{Action: api.Allow}}
			policy.Spec.Selector = "default == ''"
			_, err := client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			// There are 4 ingress rules, only one egress. All match on the single egress rule.
			var igrConns, igrBytes, igrPackets [4]int
			var egrConns, egrBytes, egrPackets int
			incCounts := func(deltaConn, numPackets, packetSize, igrRuleIdx int) {
				egrConns += deltaConn
				egrPackets += numPackets
				egrBytes += calculateBytesForPacket("ICMP", numPackets, packetSize)
				igrConns[igrRuleIdx] += deltaConn
				igrPackets[igrRuleIdx] += numPackets
				igrBytes[igrRuleIdx] += calculateBytesForPacket("ICMP", numPackets, packetSize)
			}
			expectCounts := func() {
				// Pause to allow felix to export metrics.
				time.Sleep(pollingInterval)
				kind := policy.GetObjectKind().GroupVersionKind().Kind
				// Local-to-Local traffic causes accounting from both workload perspectives.
				Expect(func() (int, error) {
					return metrics.GetCNXConnectionMetricsIntForPolicy(felix.IP, kind, policy.Spec.Tier, policy.Name, "outbound")
				}()).Should(BeNumerically("==", egrConns))
				Expect(func() (int, error) {
					return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, kind, "allow", policy.Spec.Tier, policy.Name, "outbound", "egress")
				}()).Should(BeNumerically("==", egrPackets))
				Expect(func() (int, error) {
					return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, kind, "allow", policy.Spec.Tier, policy.Name, "inbound", "egress")
				}()).Should(BeNumerically("==", egrPackets))
				Expect(func() (int, error) {
					return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, kind, "allow", policy.Spec.Tier, policy.Name, "outbound", "egress")
				}()).Should(BeNumerically("==", egrBytes))
				Expect(func() (int, error) {
					return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, kind, "allow", policy.Spec.Tier, policy.Name, "inbound", "egress")
				}()).Should(BeNumerically("==", egrBytes))
				for i := range igrConns {
					// Include the ruleIdx in the expect description to assist in debugging.
					ruleIdxString := fmt.Sprintf("RuleIndex=%d", i)
					Expect(func() (int, error) {
						return metrics.GetCNXConnectionMetricsIntForPolicy(felix.IP, kind, policy.Spec.Tier, policy.Name, "inbound", i)
					}()).Should(BeNumerically("==", igrConns[i]), ruleIdxString)
					Expect(func() (int, error) {
						return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, kind, "allow", policy.Spec.Tier, policy.Name, "outbound", "ingress", i)
					}()).Should(BeNumerically("==", igrPackets[i]), ruleIdxString)
					Expect(func() (int, error) {
						return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, kind, "allow", policy.Spec.Tier, policy.Name, "inbound", "ingress", i)
					}()).Should(BeNumerically("==", igrPackets[i]), ruleIdxString)
					Expect(func() (int, error) {
						return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, kind, "allow", policy.Spec.Tier, policy.Name, "outbound", "ingress", i)
					}()).Should(BeNumerically("==", igrBytes[i]), ruleIdxString)
					Expect(func() (int, error) {
						return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, kind, "allow", policy.Spec.Tier, policy.Name, "inbound", "ingress", i)
					}()).Should(BeNumerically("==", igrBytes[i]), ruleIdxString)
				}
			}

			By("Sending pings from w0->w1 and w1->w0 and checking received counts")
			// Wait a bit for policy to be programmed.
			time.Sleep(pollingInterval)
			stderr, err := w[0].SendPacketsTo(w[1].IP, 1, 2)
			Expect(err).NotTo(HaveOccurred(), stderr)
			incCounts(1, 1, 2, 1) // Ingress to w1, so matches on rule index 1
			stderr, err = w[1].SendPacketsTo(w[0].IP, 1, 2)
			Expect(err).NotTo(HaveOccurred(), stderr)
			incCounts(1, 1, 2, 0) // Ingress to w0, so matches on rule index 0
			expectCounts()

			By("Sending pings more pings from w0->w1 and sending pings from w1->w2 and w2->w3 and checking received counts")
			stderr, err = w[0].SendPacketsTo(w[1].IP, 1, 1)
			Expect(err).NotTo(HaveOccurred(), stderr)
			incCounts(1, 1, 1, 1) // Ingress to w1, so matches on rule index 1
			stderr, err = w[1].SendPacketsTo(w[2].IP, 2, 5)
			Expect(err).NotTo(HaveOccurred(), stderr)
			incCounts(1, 2, 5, 2) // Ingress to w2, so matches on rule index 2
			stderr, err = w[2].SendPacketsTo(w[3].IP, 3, 7)
			Expect(err).NotTo(HaveOccurred(), stderr)
			incCounts(1, 3, 7, 3) // Ingress to w3, so matches on rule index 3
			expectCounts()
		})

		It("should generate connection metrics when there is full connectivity between workloads, testing egress rule index", func() {
			By("Creating a policy with multiple egress rules matching on different workloads")
			policy := api.NewNetworkPolicy()
			policy.Namespace = "fv"
			policy.Name = "default.policy-test-egress-idx"
			policy.Spec.Tier = "default"
			policy.Spec.Types = []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress}
			policy.Spec.Egress = []api.Rule{
				{
					Action:      api.Allow,
					Destination: api.EntityRule{Selector: w[0].NameSelector()},
				},
				{
					Action:      api.Allow,
					Destination: api.EntityRule{Selector: w[1].NameSelector()},
				},
				{
					Action:      api.Allow,
					Destination: api.EntityRule{Selector: w[2].NameSelector()},
				},
				{
					Action:      api.Allow,
					Destination: api.EntityRule{Selector: w[3].NameSelector()},
				},
			}
			policy.Spec.Ingress = []api.Rule{{Action: api.Allow}}
			policy.Spec.Selector = "default == ''"
			_, err := client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			kind := policy.GetObjectKind().GroupVersionKind().Kind

			// There are 4 egress rules, only one ingress. All match on the single ingress rule.
			var egrConns, egrBytes, egrPackets [4]int
			var igrConns, igrBytes, igrPackets int
			incCounts := func(deltaConn, numPackets, packetSize, egrRuleIdx int) {
				igrConns += deltaConn
				igrPackets += numPackets
				igrBytes += calculateBytesForPacket("ICMP", numPackets, packetSize)
				egrConns[egrRuleIdx] += deltaConn
				egrPackets[egrRuleIdx] += numPackets
				egrBytes[egrRuleIdx] += calculateBytesForPacket("ICMP", numPackets, packetSize)
			}
			expectCounts := func() {
				// Pause to allow felix to export metrics.
				time.Sleep(pollingInterval)
				// Local-to-Local traffic causes accounting from both workload perspectives.
				Expect(func() (int, error) {
					return metrics.GetCNXConnectionMetricsIntForPolicy(felix.IP, kind, policy.Spec.Tier, policy.Name, "outbound")
				}()).Should(BeNumerically("==", igrConns))
				Expect(func() (int, error) {
					return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, kind, "allow", policy.Spec.Tier, policy.Name, "outbound", "ingress")
				}()).Should(BeNumerically("==", igrPackets))
				Expect(func() (int, error) {
					return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, kind, "allow", policy.Spec.Tier, policy.Name, "inbound", "ingress")
				}()).Should(BeNumerically("==", igrPackets))
				Expect(func() (int, error) {
					return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, kind, "allow", policy.Spec.Tier, policy.Name, "outbound", "ingress")
				}()).Should(BeNumerically("==", igrBytes))
				Expect(func() (int, error) {
					return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, kind, "allow", policy.Spec.Tier, policy.Name, "inbound", "ingress")
				}()).Should(BeNumerically("==", igrBytes))
				for i := range egrConns {
					// Include the ruleIdx in the expect description to assist in debugging.
					ruleIdxString := fmt.Sprintf("RuleIndex=%d", i)
					Expect(func() (int, error) {
						return metrics.GetCNXConnectionMetricsIntForPolicy(felix.IP, kind, policy.Spec.Tier, policy.Name, "outbound", i)
					}()).Should(BeNumerically("==", egrConns[i]), ruleIdxString)
					Expect(func() (int, error) {
						return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, kind, "allow", policy.Spec.Tier, policy.Name, "outbound", "egress", i)
					}()).Should(BeNumerically("==", egrPackets[i]), ruleIdxString)
					Expect(func() (int, error) {
						return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, kind, "allow", policy.Spec.Tier, policy.Name, "inbound", "egress", i)
					}()).Should(BeNumerically("==", egrPackets[i]), ruleIdxString)
					Expect(func() (int, error) {
						return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, kind, "allow", policy.Spec.Tier, policy.Name, "outbound", "egress", i)
					}()).Should(BeNumerically("==", egrBytes[i]), ruleIdxString)
					Expect(func() (int, error) {
						return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, kind, "allow", policy.Spec.Tier, policy.Name, "inbound", "egress", i)
					}()).Should(BeNumerically("==", egrBytes[i]), ruleIdxString)
				}
			}

			By("Sending pings from w0->w1 and w1->w0 and checking received counts")
			// Wait a bit for policy to be programmed.
			time.Sleep(pollingInterval)
			stderr, err := w[0].SendPacketsTo(w[1].IP, 1, 2)
			Expect(err).NotTo(HaveOccurred(), stderr)
			incCounts(1, 1, 2, 1) // Egress to w1, so matches on rule index 1
			stderr, err = w[1].SendPacketsTo(w[0].IP, 1, 2)
			Expect(err).NotTo(HaveOccurred(), stderr)
			incCounts(1, 1, 2, 0) // Egress to w0, so matches on rule index 0
			expectCounts()

			By("Sending pings more pings from w0->w1 and sending pings from w1->w2 and w2->w3 and checking received counts")
			stderr, err = w[0].SendPacketsTo(w[1].IP, 1, 1)
			Expect(err).NotTo(HaveOccurred(), stderr)
			incCounts(1, 1, 1, 1) // Egress to w1, so matches on rule index 1
			stderr, err = w[1].SendPacketsTo(w[2].IP, 2, 5)
			Expect(err).NotTo(HaveOccurred(), stderr)
			incCounts(1, 2, 5, 2) // Egress to w2, so matches on rule index 2
			stderr, err = w[2].SendPacketsTo(w[3].IP, 3, 7)
			Expect(err).NotTo(HaveOccurred(), stderr)
			incCounts(1, 3, 7, 3) // Egress to w3, so matches on rule index 3
			expectCounts()
		})
	})

	Context("should generate denied packet metrics with ingress deny rule to w1", func() {
		var policy *api.NetworkPolicy
		var kind string
		BeforeEach(func() {
			policy = api.NewNetworkPolicy()
			policy.Namespace = "fv"
			policy.Name = "default.policy-1"
			policy.Spec.Tier = "default"
			policy.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
			policy.Spec.Ingress = []api.Rule{{Action: api.Deny}}
			policy.Spec.Egress = []api.Rule{{Action: api.Allow}}
			policy.Spec.Selector = w[1].NameSelector()
			_, err := client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			kind = policy.GetObjectKind().GroupVersionKind().Kind
		})

		It("w0 cannot connect to w1 and denied packet metrics are generated", func() {
			var bytes, packets int
			incCounts := func(numPackets, packetSize int) {
				packets += numPackets
				bytes += calculateBytesForPacket("ICMP", numPackets, packetSize)
			}
			expectCounts := func() {
				// Pause to allow felix to export metrics.
				time.Sleep(pollingInterval)
				Expect(func() (int, error) {
					return metrics.GetCNXConnectionMetricsIntForPolicy(felix.IP, kind, policy.Spec.Tier, policy.Name, "inbound", 0)
				}()).Should(BeNumerically("==", 0))
				Expect(func() (int, error) {
					return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, kind, "deny", policy.Spec.Tier, policy.Name, "inbound", "ingress", 0)
				}()).Should(BeNumerically("==", packets))
				Expect(func() (int, error) {
					return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, kind, "deny", policy.Spec.Tier, policy.Name, "inbound", "ingress", 0)
				}()).Should(BeNumerically("==", bytes))
				Expect(func() (int, error) {
					return metrics.GetCalicoDeniedPacketMetrics(felix.IP, policy.Spec.Tier, policy.Name)
				}()).Should(BeNumerically("==", packets))
			}

			By("Sending pings from w0->w1 and checking denied counts")
			// Wait a bit for policy to be programmed.
			time.Sleep(pollingInterval)
			stderr, err := w[0].SendPacketsTo(w[1].IP, 1, 2)
			Expect(err).To(HaveOccurred(), stderr)
			incCounts(1, 2)
			expectCounts()

			By("Sending pings more pings from w0->w1 and sending pings from w2->w1 and w3->w1 and checking denied counts")
			stderr, err = w[0].SendPacketsTo(w[1].IP, 1, 2)
			Expect(err).To(HaveOccurred(), stderr)
			incCounts(1, 2)
			expectCounts()
			stderr, err = w[2].SendPacketsTo(w[1].IP, 3, 5)
			Expect(err).To(HaveOccurred(), stderr)
			incCounts(3, 5)
			expectCounts()
			stderr, err = w[3].SendPacketsTo(w[1].IP, 2, 3)
			Expect(err).To(HaveOccurred(), stderr)
			incCounts(2, 3)
			expectCounts()
		})
	})

	Context("should generate metrics with egress deny rule from w0", func() {
		var kind string
		BeforeEach(func() {
			proto := numorstring.ProtocolFromString("ICMP")
			policy := api.NewNetworkPolicy()
			policy.Namespace = "fv"
			policy.Name = "default.policy-icmp"
			policy.Spec.Tier = "default"
			policy.Spec.Types = []api.PolicyType{api.PolicyTypeEgress}
			policy.Spec.Ingress = []api.Rule{{Action: api.Deny}}
			policy.Spec.Egress = []api.Rule{{Protocol: &proto, Action: api.Deny}}
			policy.Spec.Selector = w[0].NameSelector()
			_, err := client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			kind = policy.GetObjectKind().GroupVersionKind().Kind
		})

		It("w0 cannot connect to w1 and denied packet metrics are generated", func() {
			var bytes, packets int
			incCounts := func(numPackets, packetSize int) {
				packets += numPackets
				bytes += calculateBytesForPacket("ICMP", numPackets, packetSize)
			}
			expectCounts := func() {
				// Pause to allow felix to export metrics.
				time.Sleep(pollingInterval)
				Expect(func() (int, error) {
					return metrics.GetCNXConnectionMetricsIntForPolicy(felix.IP, kind, "default", "default.policy-icmp", "outbound")
				}()).Should(BeNumerically("==", 0))
				Expect(func() (int, error) {
					return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, kind, "deny", "default", "default.policy-icmp", "outbound", "egress")
				}()).Should(BeNumerically("==", packets))
				Expect(func() (int, error) {
					return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, kind, "deny", "default", "default.policy-icmp", "outbound", "egress")
				}()).Should(BeNumerically("==", bytes))
				Expect(func() (int, error) {
					return metrics.GetCalicoDeniedPacketMetrics(felix.IP, "default", "default.policy-icmp")
				}()).Should(BeNumerically("==", packets))
			}

			By("Sending pings from w0->w1 and checking denied counts")
			// Wait a bit for policy to be programmed.
			time.Sleep(pollingInterval)
			stderr, err := w[0].SendPacketsTo(w[1].IP, 1, 2)
			Expect(err).To(HaveOccurred(), stderr)
			incCounts(1, 2)
			expectCounts()

			By("Sending pings from w0->w1,w2&w3 and checking denied counts")
			// Wait a bit for policy to be programmed.
			time.Sleep(pollingInterval)
			stderr, err = w[0].SendPacketsTo(w[1].IP, 1, 0)
			Expect(err).To(HaveOccurred(), stderr)
			incCounts(1, 0)
			time.Sleep(pollingInterval)
			stderr, err = w[0].SendPacketsTo(w[2].IP, 3, 4)
			Expect(err).To(HaveOccurred(), stderr)
			incCounts(3, 4)
			time.Sleep(pollingInterval)
			stderr, err = w[0].SendPacketsTo(w[3].IP, 5, 6)
			Expect(err).To(HaveOccurred(), stderr)
			incCounts(5, 6)
			expectCounts()
		})
	})

	Context("should generate denied packet metrics with deny rule in a different tier", func() {
		var kind string
		BeforeEach(func() {
			tier := api.NewTier()
			tier.Name = "tier1"
			o := 10.00
			tier.Spec.Order = &o
			_, err := client.Tiers().Create(utils.Ctx, tier, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			policy := api.NewNetworkPolicy()
			policy.Namespace = "fv"
			policy.Name = "tier1.policy-1"
			policy.Spec.Tier = "tier1"
			policy.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
			policy.Spec.Ingress = []api.Rule{{Action: api.Deny}}
			policy.Spec.Egress = []api.Rule{{Action: api.Allow}}
			policy.Spec.Selector = w[1].NameSelector()
			_, err = client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			kind = policy.GetObjectKind().GroupVersionKind().Kind
		})

		It("w0 cannot connect to w1 and denied packet metrics are generated for tier1", func() {
			var bytes, packets int
			incCounts := func(numPackets, packetSize int) {
				packets += numPackets
				bytes += calculateBytesForPacket("ICMP", numPackets, packetSize)
			}
			expectCounts := func() {
				// Pause to allow felix to export metrics.
				time.Sleep(pollingInterval)
				Expect(func() (int, error) {
					return metrics.GetCNXConnectionMetricsIntForPolicy(felix.IP, kind, "tier1", "tier1.policy-1", "inbound")
				}()).Should(BeNumerically("==", 0))
				Expect(func() (int, error) {
					return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, kind, "deny", "tier1", "tier1.policy-1", "inbound", "ingress")
				}()).Should(BeNumerically("==", packets))
				Expect(func() (int, error) {
					return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, kind, "deny", "tier1", "tier1.policy-1", "inbound", "ingress")
				}()).Should(BeNumerically("==", bytes))
				Expect(func() (int, error) {
					return metrics.GetCalicoDeniedPacketMetrics(felix.IP, "tier1", "tier1.policy-1")
				}()).Should(BeNumerically("==", packets))
			}

			By("Verifying that w0 cannot reach w1")
			// Wait a bit for policy to be programmed.
			time.Sleep(pollingInterval)
			stderr, err := w[0].SendPacketsTo(w[1].IP, 1, 2)
			Expect(err).To(HaveOccurred(), stderr)
			incCounts(1, 2)
			expectCounts()

			By("Pinging again and verifying that w0 cannot reach w1")
			stderr, err = w[0].SendPacketsTo(w[1].IP, 1, 2)
			Expect(err).To(HaveOccurred(), stderr)
			incCounts(1, 2)
			expectCounts()
		})
	})

	Context("Tests with very long tier and policy names", func() {
		longTierName := "this-in-a-very-long-tier-name-012345678900123456789001234567890"
		longPolicyName := "this-is-a-very-long-policy-name-012345678900123456789001234567890"

		var policy *api.NetworkPolicy
		var kind string
		BeforeEach(func() {
			tier := api.NewTier()
			tier.Name = longTierName
			o := 10.00
			tier.Spec.Order = &o
			_, err := client.Tiers().Create(utils.Ctx, tier, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			policy = api.NewNetworkPolicy()
			policy.Namespace = "fv"
			policy.Name = longTierName + "." + longPolicyName
			policy.Spec.Tier = longTierName
			policy.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
			policy.Spec.Ingress = []api.Rule{{Action: api.Deny}}
			policy.Spec.Egress = []api.Rule{{Action: api.Allow}}
			policy.Spec.Selector = w[1].NameSelector()
			_, err = client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
			kind = policy.GetObjectKind().GroupVersionKind().Kind
		})

		It("Deny metrics for long named tier and policy", func() {
			// Indicates we need to create the tier.
			By("Verifying that w0 cannot reach w1")
			time.Sleep(pollingInterval)
			stderr, err := w[0].SendPacketsTo(w[1].IP, 3, 5)
			Expect(err).To(HaveOccurred(), stderr)

			By("Ensuring the stats are accurate")
			// Pause to allow felix to export metrics.
			time.Sleep(pollingInterval)
			Expect(func() (int, error) {
				return metrics.GetCNXConnectionMetricsIntForPolicy(felix.IP, kind, longTierName, policy.Name, "inbound")
			}()).Should(BeNumerically("==", 0))
			Expect(func() (int, error) {
				return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, kind, "deny", longTierName, policy.Name, "inbound", "ingress")
			}()).Should(BeNumerically("==", 3))
			Expect(func() (int, error) {
				return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, kind, "deny", longTierName, policy.Name, "inbound", "ingress")
			}()).Should(BeNumerically("==", calculateBytesForPacket("ICMP", 3, 5)))
			Expect(func() (int, error) {
				return metrics.GetCalicoDeniedPacketMetrics(felix.IP, longTierName, policy.Name)
			}()).Should(BeNumerically("==", 3))
		})
	})

	Context("should generate tier ingress-drop matches", func() {
		var policy *api.NetworkPolicy
		var kind string

		BeforeEach(func() {
			policy = api.NewNetworkPolicy()
			policy.Namespace = "fv"
			policy.Name = "default.ingress-drop"
			policy.Spec.Tier = "default"
			policy.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
			policy.Spec.Ingress = []api.Rule{}
			policy.Spec.Selector = w[1].NameSelector()
			_, err := client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
			kind = policy.GetObjectKind().GroupVersionKind().Kind
		})

		It("w0 cannot connect to w1 and tier drop metrics are generated", func() {
			By("Sending pings from w0->w1")
			packets := 1
			packetSize := 2
			bytes := calculateBytesForPacket("ICMP", packets, packetSize)
			// Wait a bit for policy to be programmed.
			time.Sleep(pollingInterval)
			stderr, err := w[0].SendPacketsTo(w[1].IP, packets, packetSize)
			Expect(err).To(HaveOccurred(), stderr)

			By("Checking tier ingress-drop counts")
			time.Sleep(pollingInterval)
			Expect(func() (int, error) {
				return metrics.GetCNXConnectionMetricsIntForPolicy(felix.IP, kind, policy.Spec.Tier, policy.Name, "inbound")
			}()).Should(BeNumerically("==", 0))
			Expect(func() (int, error) {
				return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, kind, "deny", policy.Spec.Tier, policy.Name, "inbound", "ingress")
			}()).Should(BeNumerically("==", packets))
			Expect(func() (int, error) {
				return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, kind, "deny", policy.Spec.Tier, policy.Name, "inbound", "ingress")
			}()).Should(BeNumerically("==", bytes))
		})
	})

	Context("should generate tier egress-drop matches", func() {
		var policy *api.NetworkPolicy
		var kind string

		BeforeEach(func() {
			policy = api.NewNetworkPolicy()
			policy.Namespace = "fv"
			policy.Name = "default.egress-drop"
			policy.Spec.Tier = "default"
			policy.Spec.Types = []api.PolicyType{api.PolicyTypeEgress}
			policy.Spec.Egress = []api.Rule{}
			policy.Spec.Selector = w[1].NameSelector()
			_, err := client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
			kind = policy.GetObjectKind().GroupVersionKind().Kind
		})

		It("w0 cannot connect to w1 and tier drop metrics are generated", func() {
			By("Sending pings from w1->w0")
			packets := 1
			packetSize := 2
			bytes := calculateBytesForPacket("ICMP", packets, packetSize)
			// Wait a bit for policy to be programmed.
			time.Sleep(pollingInterval)
			stderr, err := w[1].SendPacketsTo(w[0].IP, packets, packetSize)
			Expect(err).To(HaveOccurred(), stderr)

			By("Checking tier egress-drop counts")
			time.Sleep(pollingInterval)
			Expect(func() (int, error) {
				return metrics.GetCNXConnectionMetricsIntForPolicy(felix.IP, kind, policy.Spec.Tier, policy.Name, "outbound")
			}()).Should(BeNumerically("==", 0))
			Expect(func() (int, error) {
				return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, kind, "deny", policy.Spec.Tier, policy.Name, "outbound", "egress", -1)
			}()).Should(BeNumerically("==", packets))
			Expect(func() (int, error) {
				return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, kind, "deny", policy.Spec.Tier, policy.Name, "outbound", "egress", -1)
			}()).Should(BeNumerically("==", bytes))
		})
	})

	Context("should generate profile ingress-drop matches", func() {
		It("w0 cannot connect to w1 and profile drop metrics are generated", func() {
			By("Updating the default profile to not match on ingress")
			defaultProfile.Spec.Ingress = []api.Rule{}
			defaultProfile, err = client.Profiles().Update(utils.Ctx, defaultProfile, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			By("Sending pings from w0->w1")
			packets := 1
			packetSize := 2
			bytes := calculateBytesForPacket("ICMP", packets, packetSize)
			// Wait a bit for policy to be programmed.
			time.Sleep(pollingInterval)
			stderr, err := w[0].SendPacketsTo(w[1].IP, packets, packetSize)
			Expect(err).To(HaveOccurred(), stderr)

			By("Checking profile ingress-drop counts")
			time.Sleep(pollingInterval)
			Expect(func() (int, error) {
				return metrics.GetCNXConnectionMetricsIntForPolicy(felix.IP, "", "__PROFILE__", "default", "inbound")
			}()).Should(BeNumerically("==", 0))
			Expect(func() (int, error) {
				return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, "", "deny", "__PROFILE__", "__NO_MATCH__", "inbound", "ingress")
			}()).Should(BeNumerically("==", packets))
			Expect(func() (int, error) {
				return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, "", "deny", "__PROFILE__", "__NO_MATCH__", "inbound", "ingress")
			}()).Should(BeNumerically("==", bytes))
		})
	})

	Context("should generate profile egress-drop matches", func() {
		It("w0 cannot connect to w1 and profile drop metrics are generated", func() {
			By("Updating the default profile to not match on egress")
			defaultProfile.Spec.Egress = []api.Rule{}
			defaultProfile, err = client.Profiles().Update(utils.Ctx, defaultProfile, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			By("Sending pings from w0->w1")
			packets := 1
			packetSize := 2
			bytes := calculateBytesForPacket("ICMP", packets, packetSize)
			// Wait a bit for policy to be programmed.
			time.Sleep(pollingInterval)
			stderr, err := w[0].SendPacketsTo(w[1].IP, packets, packetSize)
			Expect(err).To(HaveOccurred(), stderr)

			By("Checking profile egress-drop counts")
			time.Sleep(pollingInterval)
			Expect(func() (int, error) {
				return metrics.GetCNXConnectionMetricsIntForPolicy(felix.IP, "", "__PROFILE__", "default", "outbound")
			}()).Should(BeNumerically("==", 0))
			Expect(func() (int, error) {
				return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, "", "deny", "__PROFILE__", "__NO_MATCH__", "outbound", "egress")
			}()).Should(BeNumerically("==", packets))
			Expect(func() (int, error) {
				return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, "", "deny", "__PROFILE__", "__NO_MATCH__", "outbound", "egress")
			}()).Should(BeNumerically("==", bytes))
		})
	})

	Context("should generate pass action metrics with rule in multiple tiers", func() {
		var policy *api.NetworkPolicy
		var kind string

		BeforeEach(func() {
			tier := api.NewTier()
			tier.Name = "tier1"
			o := 10.00
			tier.Spec.Order = &o
			_, err := client.Tiers().Create(utils.Ctx, tier, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			policy = api.NewNetworkPolicy()
			policy.Namespace = "fv"
			policy.Name = "tier1.policy-1"
			policy.Spec.Tier = "tier1"
			policy.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
			policy.Spec.Ingress = []api.Rule{{Action: api.Pass}}
			policy.Spec.Egress = []api.Rule{{Action: api.Allow}}
			policy.Spec.Selector = w[1].NameSelector()
			_, err = client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
			kind = policy.GetObjectKind().GroupVersionKind().Kind
		})

		// TODO: This test may not be relevant any more now that policy names are unique across tiers.
		It("w0 cannot connect to w1 and pass and denied action packet metrics are generated at appropriate tier", func() {
			var bytes, packets int
			incCounts := func(numPackets, packetSize int) {
				packets += numPackets
				bytes += calculateBytesForPacket("ICMP", numPackets, packetSize)
			}
			expectCounts := func() {
				// Pause to allow felix to export metrics.
				time.Sleep(pollingInterval)
				Expect(func() (int, error) {
					return metrics.GetCNXConnectionMetricsIntForPolicy(felix.IP, kind, "tier2", "tier1.policy-1", "inbound")
				}()).Should(BeNumerically("==", 0))
				Expect(func() (int, error) {
					return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, kind, "deny", "tier2", "tier2.policy-1", "inbound", "ingress")
				}()).Should(BeNumerically("==", packets))
				Expect(func() (int, error) {
					return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, kind, "deny", "tier2", "tier2.policy-1", "inbound", "ingress")
				}()).Should(BeNumerically("==", bytes))
				Expect(func() (int, error) {
					return metrics.GetCalicoDeniedPacketMetrics(felix.IP, "tier2", "tier2.policy-1")
				}()).Should(BeNumerically("==", packets))

				// And check that the pass action metrics are incremented equally
				Expect(func() (int, error) {
					return metrics.GetCNXConnectionMetricsIntForPolicy(felix.IP, kind, "tier1", "tier1.policy-1", "inbound")
				}()).Should(BeNumerically("==", 0))
				Expect(func() (int, error) {
					return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, kind, "pass", "tier1", "tier1.policy-1", "inbound", "ingress")
				}()).Should(BeNumerically("==", packets))
				Expect(func() (int, error) {
					return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, kind, "pass", "tier1", "tier1.policy-1", "inbound", "ingress")
				}()).Should(BeNumerically("==", bytes))
			}

			By("Creating a deny policy at next tier")
			tier2 := api.NewTier()
			tier2.Name = "tier2"
			o2 := 20.00
			tier2.Spec.Order = &o2
			_, err2 := client.Tiers().Create(utils.Ctx, tier2, utils.NoOptions)
			Expect(err2).NotTo(HaveOccurred())

			policy2 := api.NewNetworkPolicy()
			policy2.Namespace = "fv"
			policy2.Name = "tier2.policy-1"
			policy2.Spec.Tier = "tier2"
			policy2.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
			policy2.Spec.Ingress = []api.Rule{{Action: api.Deny}}
			policy2.Spec.Egress = []api.Rule{{Action: api.Allow}}
			policy2.Spec.Selector = w[1].NameSelector()
			_, err = client.NetworkPolicies().Create(utils.Ctx, policy2, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying that w0 cannot reach w1")
			// Wait a bit for policy to be programmed.
			time.Sleep(pollingInterval)
			stderr, err := w[0].SendPacketsTo(w[1].IP, 1, 2)
			Expect(err).To(HaveOccurred(), stderr)
			incCounts(1, 2)
			expectCounts()
		})

		// TODO: This test may not be relevant any more now that policy names are unique across tiers.
		It("w0 can connect to w1 and pass and allow action packet metrics are generated at appropriate tier", func() {
			var bytes, packets int
			incCounts := func(numPackets, packetSize int) {
				packets += numPackets
				bytes += calculateBytesForPacket("ICMP", numPackets, packetSize)
			}
			expectCounts := func() {
				// Pause to allow felix to export metrics.
				time.Sleep(pollingInterval)
				Expect(func() (int, error) {
					return metrics.GetCNXConnectionMetricsIntForPolicy(felix.IP, kind, "tier2", "tier2.policy-1", "inbound")
				}()).Should(BeNumerically("==", 1))
				Expect(func() (int, error) {
					return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, kind, "allow", "tier2", "tier2.policy-1", "inbound", "ingress")
				}()).Should(BeNumerically("==", packets))
				Expect(func() (int, error) {
					return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, kind, "allow", "tier2", "tier2.policy-1", "inbound", "ingress")
				}()).Should(BeNumerically("==", bytes))

				// And check that the pass action metrics are incremented equally
				Expect(func() (int, error) {
					return metrics.GetCNXConnectionMetricsIntForPolicy(felix.IP, kind, "tier1", "tier1.policy-1", "inbound")
				}()).Should(BeNumerically("==", 0))
				Expect(func() (int, error) {
					return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, kind, "pass", "tier1", "tier1.policy-1", "inbound", "ingress")
				}()).Should(BeNumerically("==", packets))
				Expect(func() (int, error) {
					return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, kind, "pass", "tier1", "tier1.policy-1", "inbound", "ingress")
				}()).Should(BeNumerically("==", bytes))
			}

			By("Creating a allow policy at next tier")
			tier2 := api.NewTier()
			tier2.Name = "tier2"
			o2 := 20.00
			tier2.Spec.Order = &o2
			_, err2 := client.Tiers().Create(utils.Ctx, tier2, utils.NoOptions)
			Expect(err2).NotTo(HaveOccurred())

			policy2 := api.NewNetworkPolicy()
			policy2.Namespace = "fv"
			policy2.Name = "tier2.policy-1"
			policy2.Spec.Tier = "tier2"
			policy2.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
			policy2.Spec.Ingress = []api.Rule{{Action: api.Allow}}
			policy2.Spec.Egress = []api.Rule{{Action: api.Allow}}
			policy2.Spec.Selector = w[1].NameSelector()
			_, err = client.NetworkPolicies().Create(utils.Ctx, policy2, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying that w0 can reach w1")
			// Wait a bit for policy to be programmed.
			time.Sleep(pollingInterval)
			_, err := w[0].SendPacketsTo(w[1].IP, 1, 2)
			Expect(err).ToNot(HaveOccurred())
			incCounts(1, 2)
			expectCounts()
		})
	})
})

// These tests include tests of Kubernetes policies as well as other policy types. To ensure we have the correct
// behavior, run using the Kubernetes infrastructure only.
var _ = infrastructure.DatastoreDescribe("Calico Enterprise stats with staged policy tests", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra    infrastructure.DatastoreInfra
		tc       infrastructure.TopologyContainers
		felix    *infrastructure.Felix
		client   client.Interface
		ep1, ep2 *workload.Workload
	)

	BeforeEach(func() {
		infra = getInfra()
		opts := infrastructure.DefaultTopologyOptions()

		// Start felix instances.
		tc, client = infrastructure.StartNNodeTopology(1, opts, infra)
		felix = tc.Felixes[0]

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		ep1 = workload.Run(felix, "ep1", "default", "10.65.0.0", "8055", "tcp")
		ep1.ConfigureInInfra(infra)

		ep2 = workload.Run(felix, "ep2", "default", "10.65.1.0", "8055", "tcp")
		ep2.ConfigureInInfra(infra)
	})

	AfterEach(func() {
		if CurrentSpecReport().Failed() {
			felix.Exec("iptables-save", "-c")
			felix.Exec("ip", "r")
			cprc, _ := metrics.GetCNXMetrics(felix.IP, "cnx_policy_rule_connections")
			cprp, _ := metrics.GetCNXMetrics(felix.IP, "cnx_policy_rule_packets")
			cprb, _ := metrics.GetCNXMetrics(felix.IP, "cnx_policy_rule_bytes")
			cdp, _ := metrics.GetCNXMetrics(felix.IP, "calico_denied_packets")
			cdb, _ := metrics.GetCNXMetrics(felix.IP, "calico_denied_bytes")
			log.Info("Collected Calico Enterprise Metrics\n\n" +
				"cnx_policy_rule_connections\n" +
				"===========================\n" +
				strings.Join(cprc, "\n") + "\n\n" +
				"cnx_policy_rule_packets\n" +
				"=======================\n" +
				strings.Join(cprp, "\n") + "\n\n" +
				"cnx_policy_rule_bytes\n" +
				"=====================\n" +
				strings.Join(cprb, "\n") + "\n\n" +
				"calico_denied_packets\n" +
				"=====================\n" +
				strings.Join(cdp, "\n") + "\n\n" +
				"calico_denied_bytes\n" +
				"===================\n" +
				strings.Join(cdb, "\n") + "\n\n",
			)
		}
	})

	Context("should generate metrics for staged policies", func() {
		BeforeEach(func() {
			// Staged policies in tier 1 with allow, pass
			tier := api.NewTier()
			tier.Name = "tier1"
			o1 := 10.00
			tier.Spec.Order = &o1
			_, err := client.Tiers().Create(utils.Ctx, tier, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			snp := api.NewStagedNetworkPolicy()
			snp.Name = "tier1.np1-1"
			snp.Namespace = "default"
			snp.Spec.Order = &float1_0
			snp.Spec.Tier = "tier1"
			snp.Spec.Selector = ep2.NameSelector()
			snp.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
			snp.Spec.Ingress = []api.Rule{{Action: api.Allow}}
			_, err = client.StagedNetworkPolicies().Create(utils.Ctx, snp, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			sgnp := api.NewStagedGlobalNetworkPolicy()
			sgnp.Name = "tier1.gnp1-2"
			sgnp.Spec.Order = &float2_0
			sgnp.Spec.Tier = "tier1"
			sgnp.Spec.Selector = ep2.NameSelector()
			sgnp.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
			sgnp.Spec.Ingress = []api.Rule{{Action: api.Pass}}
			_, err = client.StagedGlobalNetworkPolicies().Create(utils.Ctx, sgnp, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			// Staged k8s policy no-match (translated to deny)
			sknp := api.NewStagedKubernetesNetworkPolicy()
			sknp.Name = "knp2-1"
			sknp.Namespace = "default"
			sknp.Spec.PodSelector = metav1.LabelSelector{
				MatchLabels: map[string]string{
					"name": ep2.Name,
				},
			}
			sknp.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
			_, err = client.StagedKubernetesNetworkPolicies().Create(utils.Ctx, sknp, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		})

		It("w0 can connect to w1 and pass and allow action packet metrics are generated at appropriate tier", func() {
			var bytes, packets int
			incCounts := func(numPackets, packetSize int) {
				packets += numPackets
				bytes += calculateBytesForPacket("ICMP", numPackets, packetSize)
			}
			expectCounts := func() {
				// Pause to allow felix to export metrics.
				time.Sleep(pollingInterval)

				// Ingress np1-1 (staged)
				Expect(func() (int, error) {
					return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, "StagedNetworkPolicy", "allow", "tier1", "tier1.np1-1", "inbound", "ingress", 0)
				}()).Should(BeNumerically("==", packets))
				Expect(func() (int, error) {
					return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, "StagedNetworkPolicy", "allow", "tier1", "tier1.np1-1", "inbound", "ingress", 0)
				}()).Should(BeNumerically("==", bytes))
				Expect(func() (int, error) {
					return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, "StagedNetworkPolicy", "allow", "tier1", "tier1.np1-1", "outbound", "ingress", 0)
				}()).Should(BeNumerically("==", packets))
				Expect(func() (int, error) {
					return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, "StagedNetworkPolicy", "allow", "tier1", "tier1.np1-1", "outbound", "ingress", 0)
				}()).Should(BeNumerically("==", bytes))

				// Ingress gnp1-2 (staged) - a verdict was reached in the np1-1 policy, so this policy should not be hit.
				Expect(func() (int, error) {
					return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, "StagedGlobalNetworkPolicy", "pass", "tier1", "tier1.gnp1-2", "inbound", "ingress", 0)
				}()).Should(BeNumerically("==", 0))
				Expect(func() (int, error) {
					return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, "StagedGlobalNetworkPolicy", "pass", "tier1", "tier1.gnp1-2", "inbound", "ingress", 0)
				}()).Should(BeNumerically("==", 0))
				Expect(func() (int, error) {
					return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, "StagedGlobalNetworkPolicy", "pass", "tier1", "tier1.gnp1-2", "outbound", "ingress", 0)
				}()).Should(BeNumerically("==", 0))
				Expect(func() (int, error) {
					return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, "StagedGlobalNetworkPolicy", "pass", "tier1", "tier1.gnp1-2", "outbound", "ingress", 0)
				}()).Should(BeNumerically("==", 0))

				// Ingress knp (staged) - a verdict was reached in the np1-1 policy, so this policy should not be hit.
				Expect(func() (int, error) {
					return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, "StagedKubernetesNetworkPolicy", "deny", "default", "knp.default.knp2-1", "inbound", "ingress", 0)
				}()).Should(BeNumerically("==", 0))
				Expect(func() (int, error) {
					return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, "StagedKubernetesNetworkPolicy", "deny", "default", "knp.default.knp2-1", "inbound", "ingress", 0)
				}()).Should(BeNumerically("==", 0))

				// Profile matches
				Expect(func() (int, error) {
					return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, "", "allow", "__PROFILE__", "kns.default", "inbound", "ingress", 0)
				}()).Should(BeNumerically("==", packets))
				Expect(func() (int, error) {
					return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, "", "allow", "__PROFILE__", "kns.default", "outbound", "ingress", 0)
				}()).Should(BeNumerically("==", bytes))
				Expect(func() (int, error) {
					return metrics.GetCNXPacketMetricsIntForPolicy(felix.IP, "", "allow", "__PROFILE__", "kns.default", "inbound", "egress", 0)
				}()).Should(BeNumerically("==", packets))
				Expect(func() (int, error) {
					return metrics.GetCNXByteMetricsIntForPolicy(felix.IP, "", "allow", "__PROFILE__", "kns.default", "outbound", "egress", 0)
				}()).Should(BeNumerically("==", bytes))
			}

			By("Verifying that w0 can reach w1")
			// Wait a bit for policy to be programmed.
			time.Sleep(pollingInterval)
			_, err := ep1.SendPacketsTo(ep2.IP, 1, 2)
			Expect(err).ToNot(HaveOccurred())
			incCounts(1, 2)
			expectCounts()
		})
	})
})

func calculateBytesForPacket(proto string, pktCount, packetSize int) int {
	switch proto {
	case "ICMP":
		// 8 byte ICMP header + 20 byte IP header
		return (packetSize + 8 + 20) * pktCount
	default:
		// Not implemented for now.
		return -1
	}
}
