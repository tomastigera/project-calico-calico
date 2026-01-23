// Copyright (c) 2022-2023 Tigera, Inc. All rights reserved.

package fv_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/felix/collector/flowlog"
	"github.com/projectcalico/calico/felix/collector/types/endpoint"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/dns"
	"github.com/projectcalico/calico/felix/fv/flowlogs"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

// This is an extension of the flow_logs_tests.go file to test flow logs for flows enforced with DNS based policies.
//
// Felix1
//  EP1-1 ----> www.fake-google.test
//  EP1-1 ----> fake-microsoft.test
//
// NetworkSet "netset1" with *.fake-google.test
// NetworkSet "netset2" with fake-microsoft.test
//
// Egress Policies
//   Tier1                          |  Tier2
//   snp1-1 (A-netset1 and netset2) |  np2-1 (A-netset2)
//
// A=allow

// These tests use a small subset of the policy types - the main purpose of the tests is to check handling of DNS
// based policy and reverse DNS lookup.
// TODO(rlb): add in BPF checks when DNS policy is fully fixed for BPF.
var _ = infrastructure.DatastoreDescribe("flow log with DNS tests", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra             infrastructure.DatastoreInfra
		opts              infrastructure.TopologyOptions
		tc                infrastructure.TopologyContainers
		dnsServer         *containers.Container
		externalWorkloads []*containers.Container
		flowLogsReaders   []flowlogs.FlowLogReader
		client            client.Interface
		ep1_1             *workload.Workload
		dnsServerIP       string
	)

	bpfEnabled := os.Getenv("FELIX_FV_ENABLE_BPF") == "true"

	logAndReport := func(out string, err error) error {
		log.WithError(err).Infof("test-dns said:\n%v", out)
		return err
	}

	wgetDomainErrFn := func(domain string) func() error {
		return func() error {
			out, err := ep1_1.ExecCombinedOutput("test-dns", "-", domain, fmt.Sprintf("--dns-server=%s:%d", dnsServerIP, 53))
			return logAndReport(out, err)
		}
	}

	canWgetDomain := func(domain string) {
		ExpectWithOffset(1, wgetDomainErrFn(domain)()).NotTo(HaveOccurred())
		ConsistentlyWithOffset(1, wgetDomainErrFn(domain), "4s", "1s").ShouldNot(HaveOccurred())
	}

	cannotWgetDomain := func(domain string) {
		ExpectWithOffset(1, wgetDomainErrFn(domain)()).To(HaveOccurred())
		ConsistentlyWithOffset(1, wgetDomainErrFn(domain), "4s", "1s").Should(HaveOccurred())
	}

	BeforeEach(func() {
		infra = getInfra()
		opts = infrastructure.DefaultTopologyOptions()
		opts.FlowLogSource = infrastructure.FlowLogSourceFile

		// Instead of relying on external websites for DNS tests, we use an internally hosted HTTP service,
		// and internal dns server, making functional validation tests more self-contained and reliable.
		externalWorkloads = infrastructure.StartExternalWorkloads(infra, "dns-external-workload", 2)
		dnsRecords := map[string][]dns.RecordIP{
			"www.fake-google.test": {{TTL: 20, IP: externalWorkloads[0].IP}},
			"fake-microsoft.test":  {{TTL: 20, IP: externalWorkloads[1].IP}},
		}
		dnsServer = dns.StartServer(infra, dnsRecords)
		dnsServerIP = dnsServer.IP

		opts.IPIPMode = api.IPIPModeNever
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEENABLED"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "5"
		opts.ExtraEnvVars["FELIX_FLOWLOGSENABLEHOSTENDPOINT"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSENABLENETWORKSETS"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEINCLUDELABELS"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEINCLUDEPOLICIES"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEAGGREGATIONKINDFORALLOWED"] = strconv.Itoa(int(AggrNone))
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEAGGREGATIONKINDFORDENIED"] = strconv.Itoa(int(AggrNone))
		opts.ExtraEnvVars["FELIX_FLOWLOGSCOLLECTORDEBUGTRACE"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSDESTDOMAINSBYCLIENT"] = "false"
		opts.ExtraEnvVars["FELIX_DNSTRUSTEDSERVERS"] = dnsServerIP
		opts.ExtraEnvVars["FELIX_DNSLOGSFILEENABLED"] = "false"
		opts.ExtraEnvVars["FELIX_DNSLOGSLATENCY"] = "false"

		// Start felix instances.
		tc, client = infrastructure.StartNNodeTopology(1, opts, infra)

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		// Create workload on host 1.
		ep1_1 = workload.Run(tc.Felixes[0], "ep1-1", "default", "10.65.0.0", "8055", "tcp")
		ep1_1.ConfigureInInfra(infra)

		// Create tiers tier1 and tier2
		tier := api.NewTier()
		tier.Name = "tier1"
		tier.Spec.Order = &float1_0
		_, err := client.Tiers().Create(utils.Ctx, tier, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		tier = api.NewTier()
		tier.Name = "tier2"
		tier.Spec.Order = &float2_0
		_, err = client.Tiers().Create(utils.Ctx, tier, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// Add two global network sets one for the two different domains.
		gns := api.NewGlobalNetworkSet()
		gns.Name = "netset1"
		gns.Labels = map[string]string{"netset1": ""}
		gns.Spec.AllowedEgressDomains = []string{"*.fake-google.test"}
		_, err = client.GlobalNetworkSets().Create(utils.Ctx, gns, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		gns = api.NewGlobalNetworkSet()
		gns.Name = "netset2"
		gns.Labels = map[string]string{"netset2": ""}
		gns.Spec.AllowedEgressDomains = []string{"fake-microsoft.test"}
		_, err = client.GlobalNetworkSets().Create(utils.Ctx, gns, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// Allow traffic to both networksets in staged policy
		udp := numorstring.ProtocolFromString(numorstring.ProtocolUDP)
		sgnp := api.NewStagedGlobalNetworkPolicy()
		sgnp.Name = "tier1.ep1-1-allow-netset1-netset2"
		sgnp.Spec.Order = &float1_0
		sgnp.Spec.Tier = "tier1"
		sgnp.Spec.Selector = ep1_1.NameSelector()
		sgnp.Spec.Types = []api.PolicyType{api.PolicyTypeEgress}
		sgnp.Spec.Egress = []api.Rule{
			{
				Action:   api.Allow,
				Protocol: &udp,
				Destination: api.EntityRule{
					Ports: []numorstring.Port{numorstring.SinglePort(53)},
				},
			},
			{
				Destination: api.EntityRule{
					Selector: "has(netset1)",
				},
				Action: api.Allow,
			},
			{
				Destination: api.EntityRule{
					Selector: "has(netset2)",
				},
				Action: api.Allow,
			},
		}
		_, err = client.StagedGlobalNetworkPolicies().Create(utils.Ctx, sgnp, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// Allow traffic to networkset2.
		gnp := api.NewGlobalNetworkPolicy()
		gnp.Name = "tier2.ep1-1-allow-netset2"
		gnp.Spec.Order = &float1_0
		gnp.Spec.Tier = "tier2"
		gnp.Spec.Selector = ep1_1.NameSelector()
		gnp.Spec.Types = []api.PolicyType{api.PolicyTypeEgress}
		gnp.Spec.Egress = []api.Rule{
			{
				Action:   api.Allow,
				Protocol: &udp,
				Destination: api.EntityRule{
					Ports: []numorstring.Port{numorstring.SinglePort(53)},
				},
			},
			{
				Destination: api.EntityRule{
					Selector: "has(netset2)",
				},
				Action: api.Allow,
			},
		}
		_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, gnp, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		flowLogsReaders = []flowlogs.FlowLogReader{}
		for _, f := range tc.Felixes {
			flowLogsReaders = append(flowLogsReaders, f)
		}

		// Allow workloads to connect out to the Internet.
		tc.Felixes[0].Exec(
			"iptables", "-w", "-t", "nat",
			"-A", "POSTROUTING",
			"-o", "eth0",
			"-j", "MASQUERADE", "--random-fully",
		)

		// Wait for rules to be programmed.
		time.Sleep(5 * time.Second)
	})

	It("should correctly resolve and connectivity should be based on enforced policy.", func() {
		// Run a few tests for both interesting domains.  These should work immediately and consistently.
		canWgetDomain("fake-microsoft.test")
		cannotWgetDomain("www.fake-google.test")
		canWgetDomain("fake-microsoft.test")
		cannotWgetDomain("www.fake-google.test")
		canWgetDomain("fake-microsoft.test")
		cannotWgetDomain("www.fake-google.test")

		flowlogs.WaitForConntrackScan(bpfEnabled)

		// Delete conntrack state so that we don't keep seeing 0-metric copies of the logs.  This will allow the flows
		// to expire quickly.
		for ii := range tc.Felixes {
			tc.Felixes[ii].Exec("conntrack", "-F")
		}

		Eventually(func() error {
			flowTester := flowlogs.NewFlowTesterDeprecated(flowLogsReaders, true, true, 0)

			// Track all errors before failing. All flows originating from our workload should be going to either
			// the DNS server or the network sets. If bound for the network sets then networkset1 should be denied and
			// networkset2 should be allowed. All should have policy hits from both tiers.
			var errs []string
			var foundDNS, foundNetset1, foundNetset2 bool
			err := flowTester.IterFlows(func(flowLog flowlog.FlowLog) error {
				// Source for every log should be ep1_1.
				if flowLog.SrcMeta.Type != "wep" || flowLog.SrcMeta.Namespace != "default" || flowLog.SrcMeta.Name != ep1_1.Name {
					errs = append(errs, fmt.Sprintf("Unexpected source meta in flow: %#v", flowLog.SrcMeta))
					return nil
				}

				// Handle DNS requests separately. These should have policy hits.
				if flowLog.Tuple.GetDestPort() == 53 {
					foundDNS = true
					if len(flowLog.FlowEnforcedPolicySet) != 1 {
						errs = append(errs, fmt.Sprintf("Unexpected number of policies for DNS: %#v", flowLog.FlowEnforcedPolicySet))
						return nil
					}
					delete(flowLog.FlowEnforcedPolicySet, "0|tier2|tier2.ep1-1-allow-netset2|allow|0")
					if len(flowLog.FlowEnforcedPolicySet) != 0 {
						errs = append(errs, fmt.Sprintf("Unexpected policies for DNS: %#v", flowLog.FlowEnforcedPolicySet))
						return nil
					}
					return nil
				}

				// If not DNS, the destination should be a DNS match to networkset.
				if flowLog.DstMeta.Type != "ns" {
					errs = append(errs, fmt.Sprintf("Unexpected dest meta in flow: %#v", flowLog.DstMeta))
					return nil
				}

				// At aggregation level None, source and destination IP should be included.
				if flowLog.Tuple.DestNet().String() == "0.0.0.0" {
					errs = append(errs, fmt.Sprintf("Empty destination IP: %s", flowLog.Tuple.DestNet().String()))
				}
				if flowLog.Tuple.SourceNet().String() == "0.0.0.0" {
					errs = append(errs, fmt.Sprintf("Empty source IP: %s", flowLog.Tuple.SourceNet().String()))
				}

				if flowLog.DstMeta.Name == "netset1" {
					// Networkset 1 is a match on www.fake-google.test
					domains := destDomainsToSlice(flowLog.FlowDestDomains)
					if len(domains) != 1 || domains[0] != "www.fake-google.test" {
						errs = append(errs, fmt.Sprintf("Unexpected domains for netset1: %#v", domains))
					}

					// Netset1 is matched by the default drop from the enforced policy. The drop
					// by the enforced policy should be an exact match.
					foundNetset1 = true
					if len(flowLog.FlowEnforcedPolicySet) != 1 {
						errs = append(errs, fmt.Sprintf("Unexpected number of policies for netset1: %#v", flowLog.FlowEnforcedPolicySet))
						return nil
					}
					delete(flowLog.FlowEnforcedPolicySet, "0|tier2|tier2.ep1-1-allow-netset2|deny|-1")
					if len(flowLog.FlowEnforcedPolicySet) != 0 {
						errs = append(errs, fmt.Sprintf("Unexpected policies for netset1: %#v", flowLog.FlowEnforcedPolicySet))
						return nil
					}
				}

				if flowLog.DstMeta.Name == "netset2" {
					// Networkset 2 is a match on fake-microsoft.test
					domains := destDomainsToSlice(flowLog.FlowDestDomains)
					if len(domains) != 1 || domains[0] != "fake-microsoft.test" {
						errs = append(errs, fmt.Sprintf("Unexpected domains for netset2 at %s: %#v", flowLog.Tuple.DestNet().String(), domains))
					}

					// Netset2 is matched by the default allow from the enforced policy. The allow
					// by the enforced policy should be an exact match because the policy would
					// otherwise be dropped and packet retry will continue until it is allowed.
					foundNetset2 = true
					if len(flowLog.FlowEnforcedPolicySet) != 1 {
						errs = append(errs, fmt.Sprintf("Unexpected number of policies for netset2: %#v", flowLog.FlowEnforcedPolicySet))
						return nil
					}
					delete(flowLog.FlowEnforcedPolicySet, "0|tier2|tier2.ep1-1-allow-netset2|allow|1")
					if len(flowLog.FlowEnforcedPolicySet) != 0 {
						errs = append(errs, fmt.Sprintf("Unexpected policies for netset2: %#v", flowLog.FlowEnforcedPolicySet))
					}
				}

				return nil
			})
			if err != nil {
				errs = append(errs, err.Error())
			} else {
				if !foundDNS {
					errs = append(errs, "No DNS flow found")
				}
				if !foundNetset1 {
					errs = append(errs, "No flow to GlobalNetworkSet(netset1) found")
				}
				if !foundNetset2 {
					errs = append(errs, "No flow to GlobalNetworkSet(netset2) found")
				}
			}

			if len(errs) == 0 {
				return nil
			}

			return errors.New(strings.Join(errs, "\n==============\n"))
		}, "30s", "3s").ShouldNot(HaveOccurred())
	})

	AfterEach(func() {
		for _, felix := range tc.Felixes {
			if bpfEnabled {
				felix.Exec("calico-bpf", "connect-time", "clean")
			}
		}
	})
})

// This is an extension of the flow_logs_tests.go file to test flow logs for flows with
// DNS queried by different endpoints, and resolving to the same domain.
//
// Felix1
//  EP1-1 ----> gist.fake-github.test (resolves to the same IP as fake-github.test)
//  EP2-1 ----> fake-github.test
//  EP2-1 ----> fake-microsoft.test
//
//

// The main purpose is to check that destination domains are collected and reported in the flow logs
// on a per client basis.
var _ = infrastructure.DatastoreDescribe("flow log with DNS tests by client", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra             infrastructure.DatastoreInfra
		opts              infrastructure.TopologyOptions
		dnsServer         *containers.Container
		externalWorkloads []*containers.Container
		tc                infrastructure.TopologyContainers
		flowLogsReaders   []flowlogs.FlowLogReader
		ep1_1, ep2_1      *workload.Workload
		client            client.Interface

		dnsServerIP string
	)

	bpfEnabled := os.Getenv("FELIX_FV_ENABLE_BPF") == "true"

	logAndReport := func(out string, err error) error {
		log.WithError(err).Infof("test-dns said:\n%v", out)
		return err
	}

	wgetDomainErrFn := func(ep *workload.Workload, domain string) func() error {
		return func() error {
			out, err := ep.ExecCombinedOutput("test-dns", "-", domain, fmt.Sprintf("--dns-server=%s:%d", dnsServerIP, 53))
			return logAndReport(out, err)
		}
	}

	canWgetDomain := func(ep *workload.Workload, domain string) {
		ExpectWithOffset(1, wgetDomainErrFn(ep, domain)()).NotTo(HaveOccurred())
		ConsistentlyWithOffset(1, wgetDomainErrFn(ep, domain), "4s", "1s").ShouldNot(HaveOccurred())
	}

	BeforeEach(func() {
		infra = getInfra()
		opts = infrastructure.DefaultTopologyOptions()
		opts.FlowLogSource = infrastructure.FlowLogSourceFile

		externalWorkloads = infrastructure.StartExternalWorkloads(infra, "dns-external-workload", 2)
		dnsRecords := map[string][]dns.RecordIP{
			"fake-microsoft.test":   {{TTL: 20, IP: externalWorkloads[0].IP}},
			"gist.fake-github.test": {{TTL: 20, IP: externalWorkloads[1].IP}},
			"fake-github.test":      {{TTL: 20, IP: externalWorkloads[1].IP}},
		}
		dnsServer = dns.StartServer(infra, dnsRecords)
		dnsServerIP = dnsServer.IP

		opts.IPIPMode = api.IPIPModeNever
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEENABLED"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "5"
		opts.ExtraEnvVars["FELIX_FLOWLOGSENABLEHOSTENDPOINT"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSENABLENETWORKSETS"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEINCLUDELABELS"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEINCLUDEPOLICIES"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEAGGREGATIONKINDFORALLOWED"] = strconv.Itoa(int(AggrNone))
		opts.ExtraEnvVars["FELIX_FLOWLOGSCOLLECTORDEBUGTRACE"] = "true"
		opts.ExtraEnvVars["FELIX_DNSTRUSTEDSERVERS"] = dnsServerIP
		opts.ExtraEnvVars["FELIX_DNSLOGSFILEENABLED"] = "false"
		opts.ExtraEnvVars["FELIX_DNSLOGSLATENCY"] = "false"
		opts.ExtraEnvVars["FELIX_FLOWLOGSDESTDOMAINSBYCLIENT"] = "true"
		opts.ExtraEnvVars["FELIX_DNSEXTRATTL"] = "300"

		// Start felix instances.
		tc, client = infrastructure.StartNNodeTopology(2, opts, infra)

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		// Create ep1 workload on host 1.
		infrastructure.AssignIP("ep1-1", "10.65.0.0", tc.Felixes[0].Hostname, client)
		ep1_1 = workload.Run(tc.Felixes[0], "ep1-1", "default", "10.65.0.0", "8055", "tcp")
		ep1_1.ConfigureInInfra(infra)

		// Create ep2 workload on host 1.
		infrastructure.AssignIP("ep2-1", "10.65.0.1", tc.Felixes[1].Hostname, client)
		ep2_1 = workload.Run(tc.Felixes[1], "ep2-1", "default", "10.65.0.1", "8056", "tcp")
		ep2_1.ConfigureInInfra(infra)

		flowLogsReaders = []flowlogs.FlowLogReader{}
		for _, f := range tc.Felixes {
			flowLogsReaders = append(flowLogsReaders, f)
		}

		// Allow workloads to connect out to the Internet.
		for ii := range tc.Felixes {
			tc.Felixes[ii].Exec(
				"iptables", "-w", "-t", "nat",
				"-A", "POSTROUTING",
				"-o", "eth0",
				"-j", "MASQUERADE", "--random-fully",
			)
		}

		// Wait for rules to be programmed.
		time.Sleep(5 * time.Second)
	})

	// When FELIX_FLOWLOGSDESTDOMAINSBYCLIENT is true, domains that are queried by different endpoints
	// and that resolve to the same IP should not be reported in the destination domains together.
	It("should correctly resolve and domains should be listed by client", func() {
		// Run a few tests for both interesting domains. These should work immediately and consistently.
		canWgetDomain(ep1_1, "gist.fake-github.test")
		canWgetDomain(ep2_1, "fake-github.test")
		canWgetDomain(ep2_1, "fake-microsoft.test")

		flowlogs.WaitForConntrackScan(bpfEnabled)

		Eventually(func() error {
			flowTester := flowlogs.NewFlowTesterDeprecated(flowLogsReaders, true, true, 0)

			errs := []string{}
			// Track all errors before failing
			_ = flowTester.IterFlows(func(flowLog flowlog.FlowLog) error {
				if flowLog.SrcMeta.Type == "wep" && flowLog.DstMeta.Type == "net" && flowLog.DstMeta.AggregatedName == "pub" {
					log.Debugf("FlowLog: %#v", flowLog)
					if strings.Contains(flowLog.SrcMeta.AggregatedName, ep1_1.Name) {
						// dest_domains should only report gist.fake-github.test for ep1_1
						domains := destDomainsToSlice(flowLog.FlowDestDomains)
						for _, domain := range domains {
							if domain != "gist.fake-github.test" {
								errs = append(errs, fmt.Sprintf("Unexpected domains for ep1_1: %#v", domains))
							}
						}
					}
					if strings.Contains(flowLog.SrcMeta.AggregatedName, ep2_1.Name) {
						domains := destDomainsToSlice(flowLog.FlowDestDomains)
						// dest_domains should either report fake-github.test and/or fake-microsoft.test for ep2_1
						for _, domain := range domains {
							if domain != "fake-github.test" && domain != "fake-microsoft.test" {
								errs = append(errs, fmt.Sprintf("Unexpected domains for ep2_1: %#v", domains))
							}
						}
					}
				}

				return nil
			})

			if len(errs) == 0 {
				return nil
			}

			return errors.New(strings.Join(errs, "\n==============\n"))
		}, "30s", "3s").ShouldNot(HaveOccurred())
	})

	AfterEach(func() {
		for _, felix := range tc.Felixes {
			if bpfEnabled {
				felix.Exec("calico-bpf", "connect-time", "clean")
			}
		}
	})
})

// NetworkSet flow log tests.
var _ = infrastructure.DatastoreDescribe(
	"flow log with networkset tests",
	[]apiconfig.DatastoreType{apiconfig.Kubernetes},
	func(getInfra infrastructure.InfraFactory) {
		const (
			wepPort         = 8055
			testIP1         = "10.65.0.0"
			testIP2         = "10.65.0.1"
			testIP3         = "10.65.1.0"
			destinationIP   = "10.65.3.0"
			destinationCIDR = "10.65.3.0/32"
			numFlowTests    = 15
		)
		wepPortStr := fmt.Sprintf("%d", wepPort)

		var (
			infra                              infrastructure.DatastoreInfra
			opts                               infrastructure.TopologyOptions
			tc                                 infrastructure.TopologyContainers
			client                             client.Interface
			ep1_1, ep1_2, ep2_1                *workload.Workload
			ns1, ns2, ns3                      *corev1.Namespace
			netset1, netset2, netset3, netset4 *api.NetworkSet
			gns, gns2, gns3                    *api.GlobalNetworkSet
			k8sClient                          *kubernetes.Clientset
			externalWorkloads                  []*containers.Container
			dnsServer                          *containers.Container
			dnsServerIP                        string
		)

		bpfEnabled := os.Getenv("FELIX_FV_ENABLE_BPF") == "true"

		// Helper functions
		createMetadata := func(epType endpoint.Type, name, namespace string) endpoint.Metadata {
			return endpoint.Metadata{
				Type:           epType,
				Namespace:      namespace,
				Name:           name,
				AggregatedName: name,
			}
		}

		// Helper function to create namespaces
		createNamespace := func(name string) *corev1.Namespace {
			ns, err := k8sClient.CoreV1().Namespaces().Create(context.TODO(), &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: name,
					Labels: map[string]string{
						"namespace": name,
					},
				},
			}, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			return ns
		}

		createTier := func(name string, order float64) error {
			tier := api.NewTier()
			tier.Name = name
			tier.Spec.Order = &order
			_, err := client.Tiers().Create(utils.Ctx, tier, utils.NoOptions)
			return err
		}

		// Helper function to create NetworkSets
		createNetworkSet := func(name, namespace string, nets, domains []string, labels map[string]string) *api.NetworkSet {
			ns := api.NewNetworkSet()
			ns.Name = name
			ns.Namespace = namespace
			ns.Labels = labels
			if ns.Labels == nil {
				ns.Labels = make(map[string]string)
			}
			ns.Labels["namespace"] = namespace
			ns.Spec.Nets = nets
			ns.Spec.AllowedEgressDomains = domains
			_, err := client.NetworkSets().Create(utils.Ctx, ns, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
			return ns
		}

		// Helper function to create GlobalNetworkSet
		createGlobalNetworkSet := func(name string, nets, domains []string, labels map[string]string) *api.GlobalNetworkSet {
			gns := api.NewGlobalNetworkSet()
			gns.Name = name
			gns.Labels = labels
			gns.Spec.Nets = nets
			gns.Spec.AllowedEgressDomains = domains
			_, err := client.GlobalNetworkSets().Create(utils.Ctx, gns, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
			return gns
		}

		parseIP := func(ipStr string) [16]byte {
			parsedIP, ok := ip.ParseIPAs16Byte(ipStr)
			Expect(ok).To(BeTrue())
			return parsedIP
		}

		createGlobalNetworkPolicy := func(name, tier, selector string, order float64, ruleSelector []string) error {
			udp := numorstring.ProtocolFromString(numorstring.ProtocolUDP)
			tcp := numorstring.ProtocolFromString(numorstring.ProtocolTCP)
			gnp := api.NewGlobalNetworkPolicy()
			gnp.Name = name
			gnp.Spec.Selector = selector
			gnp.Spec.Order = &order
			gnp.Spec.Tier = tier
			gnp.Spec.Types = []api.PolicyType{api.PolicyTypeEgress}
			gnp.Spec.Egress = []api.Rule{
				{
					Action:   api.Allow,
					Protocol: &udp,
					Destination: api.EntityRule{
						Ports: []numorstring.Port{numorstring.SinglePort(53)},
					},
				},
				{
					Action:   api.Allow,
					Protocol: &tcp,
					Destination: api.EntityRule{
						Selector: strings.Join(ruleSelector, " || "),
					},
				},
			}
			_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, gnp, utils.NoOptions)
			return err
		}

		// Helper function to create expected flow logs
		createExpectedFlow := func(tuple tuple.Tuple, srcMeta, dstMeta endpoint.Metadata) flowlog.FlowLog {
			return flowlog.FlowLog{
				FlowMeta: flowlog.FlowMeta{
					Tuple:      tuple,
					SrcMeta:    srcMeta,
					DstMeta:    dstMeta,
					DstService: flowlog.EmptyService,
					Action:     "allow",
					Reporter:   "src",
				},
				FlowProcessReportedStats: flowlog.FlowProcessReportedStats{
					FlowReportedStats: flowlog.FlowReportedStats{
						NumFlowsStarted: numFlowTests,
					},
				},
			}
		}

		logAndReport := func(out string, err error) error {
			log.WithError(err).Infof("test-dns said:\n%v", out)
			return err
		}

		wgetDomainErrFn := func(ep *workload.Workload, domain string) func() error {
			return func() error {
				out, err := ep.ExecCombinedOutput("test-dns", "-", domain, fmt.Sprintf("--dns-server=%s:%d", dnsServerIP, 53))
				return logAndReport(out, err)
			}
		}

		canWgetDomain := func(ep *workload.Workload, domain string) {
			ExpectWithOffset(1, wgetDomainErrFn(ep, domain)()).NotTo(HaveOccurred())
			ConsistentlyWithOffset(1, wgetDomainErrFn(ep, domain), "4s", "1s").ShouldNot(HaveOccurred())
		}

		BeforeEach(func() {
			if NFTMode() {
				Skip("Not supported in NFT mode")
			}

			infra = getInfra()

			// Instead of relying on external websites for DNS tests, we use an internally hosted HTTP service,
			// and internal dns server, making functional validation tests more self-contained and reliable.
			externalWorkloads = infrastructure.StartExternalWorkloads(infra, "dns-external-workload", 5)
			dnsRecords := map[string][]dns.RecordIP{
				"fake-microsoft.test":    {{TTL: 20, IP: externalWorkloads[0].IP}},
				"www.fake-google.test":   {{TTL: 20, IP: externalWorkloads[1].IP}},
				"mail.fake-yahoo.test":   {{TTL: 20, IP: externalWorkloads[2].IP}},
				"middle.fake-bing.test":  {{TTL: 20, IP: externalWorkloads[3].IP}},
				"deep.a.b.fake-ask.test": {{TTL: 20, IP: externalWorkloads[4].IP}},
			}
			dnsServer = dns.StartServer(infra, dnsRecords)
			dnsServerIP = dnsServer.IP

			opts = infrastructure.DefaultTopologyOptions()
			opts.FlowLogSource = infrastructure.FlowLogSourceFile
			opts.IPIPMode = api.IPIPModeNever
			opts.ExternalIPs = true
			opts.EnableIPv6 = false
			opts.NATOutgoingEnabled = true
			opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "5"
			opts.ExtraEnvVars["FELIX_FLOWLOGSENABLENETWORKSETS"] = "true"
			opts.ExtraEnvVars["FELIX_FLOWLOGSENABLEHOSTENDPOINT"] = "true"
			opts.ExtraEnvVars["FELIX_FLOWLOGSFILEINCLUDELABELS"] = "true"
			opts.ExtraEnvVars["FELIX_FLOWLOGSFILEINCLUDEPOLICIES"] = "true"
			opts.ExtraEnvVars["FELIX_FLOWLOGSFILEAGGREGATIONKINDFORALLOWED"] = strconv.Itoa(int(AggrNone))
			opts.ExtraEnvVars["FELIX_FLOWLOGSFILEAGGREGATIONKINDFORDENIED"] = strconv.Itoa(int(AggrNone))
			opts.ExtraEnvVars["FELIX_FLOWLOGSCOLLECTORDEBUGTRACE"] = "true"
			opts.ExtraEnvVars["FELIX_FLOWLOGSFILEENABLED"] = "true"
			opts.ExtraEnvVars["FELIX_FLOWLOGSFILEINCLUDESERVICE"] = "true"
			opts.ExtraEnvVars["FELIX_DNSTRUSTEDSERVERS"] = dnsServerIP
			opts.ExtraEnvVars["FELIX_DNSLOGSFILEENABLED"] = "false"
			opts.ExtraEnvVars["FELIX_DNSLOGSLATENCY"] = "false"
			opts.ExtraEnvVars["FELIX_FLOWLOGSDESTDOMAINSBYCLIENT"] = "true"
			opts.ExtraEnvVars["FELIX_DNSEXTRATTL"] = "300"
			opts.ExtraEnvVars["FELIX_BPFConnectTimeLoadBalancing"] = string(api.BPFConnectTimeLBDisabled)
			opts.ExtraEnvVars["FELIX_BPFHostNetworkedNATWithoutCTLB"] = string(api.BPFHostNetworkedNATEnabled)

			k8sClient = infra.(*infrastructure.K8sDatastoreInfra).K8sClient
			_ = k8sClient
		})

		JustBeforeEach(func() {
			tc, client = infrastructure.StartNNodeTopology(2, opts, infra)

			if bpfEnabled {
				ensureBPFProgramsAttached(tc.Felixes[0])
				ensureBPFProgramsAttached(tc.Felixes[1])
			}

			infra.AddDefaultAllow()

			// Create test namespaces
			ns1 = createNamespace("ns-1")
			ns2 = createNamespace("ns-2")
			ns3 = createNamespace("ns-3")

			// Create domain-based NetworkSets for testing egress to domains
			// Add labels to the NetworkSets so we can reference them in policies
			netset1 = createNetworkSet("domain-netset-1", ns1.Name, nil, []string{"fake-microsoft.test"},
				map[string]string{"domain-netset-1": "", "domain-netset-2": "domain-gns-1"})

			netset2 = createNetworkSet("domain-netset-2", ns2.Name, nil, []string{"fake-microsoft.test"},
				map[string]string{"domain-netset-1": "", "domain-netset-2": "domain-gns-1"})

			gns = createGlobalNetworkSet("domain-gns-1", nil, []string{"fake-microsoft.test"},
				map[string]string{"domain-netset-1": "", "domain-netset-2": "domain-gns-1"})

			netset3 = createNetworkSet("domain-netset-3", ns1.Name, nil, []string{"*.fake-google.test"},
				map[string]string{"domain-netset-3": ""})

			netset4 = createNetworkSet("domain-netset-4", ns1.Name, nil, []string{"middle.*.test"},
				map[string]string{"domain-netset-4": ""})

			gns2 = createGlobalNetworkSet("domain-gns-2", nil, []string{"*.fake-yahoo.test"},
				map[string]string{"domain-gns-2": ""})

			gns3 = createGlobalNetworkSet("domain-gns-3", nil, []string{"deep.a.*.fake-ask.test"},
				map[string]string{"domain-gns-3": ""})

			// Create tiers tier1 and tier2
			err := createTier("tier1", 1.0)
			Expect(err).NotTo(HaveOccurred())

			// Create workload endpoints
			ep1_1 = workload.Run(tc.Felixes[0], "ep1-1", ns1.Name, testIP1, wepPortStr, "tcp")
			ep1_1.ConfigureInInfra(infra)

			ep1_2 = workload.Run(tc.Felixes[0], "ep1-2", ns2.Name, testIP2, wepPortStr, "tcp")
			ep1_2.ConfigureInInfra(infra)

			ep2_1 = workload.Run(tc.Felixes[1], "ep2-1", ns3.Name, testIP3, wepPortStr, "tcp")
			ep2_1.ConfigureInInfra(infra)

			// Create domain-trigger policy to allow egress to domains in networksets.
			err = createGlobalNetworkPolicy(
				"tier1.ep1-1-allow-to-netsets",
				"tier1",
				ep1_1.NameSelector(),
				1.0,
				[]string{"has(domain-netset-1) || has(domain-netset-2) || has(domain-gns-1) || has(domain-netset-3) || has(domain-gns-2) || has(domain-netset-4) || has(domain-gns-3)"},
			)
			Expect(err).NotTo(HaveOccurred())

			err = createGlobalNetworkPolicy(
				"tier1.ep1-2-allow-to-netsets",
				"tier1",
				ep1_2.NameSelector(),
				2.0,
				[]string{"has(domain-netset-1) || has(domain-netset-2) || has(domain-gns-1) || has(domain-netset-3) || has(domain-gns-2) || has(domain-netset-4) || has(domain-gns-3)"},
			)
			Expect(err).NotTo(HaveOccurred())

			err = createGlobalNetworkPolicy(
				"tier1.ep2-1-allow-to-netsets",
				"tier1",
				ep2_1.NameSelector(),
				3.0,
				[]string{"has(domain-netset-1) || has(domain-netset-2) || has(domain-gns-1) || has(domain-netset-3) || has(domain-gns-2) || has(domain-netset-4) || has(domain-gns-3)"},
			)
			Expect(err).NotTo(HaveOccurred())

			// Wait for rules to be programmed.
			if !bpfEnabled {
				Eventually(getRuleFuncTable(tc.Felixes[0], "tier1.ep1-1-allow-to-netsets", "filter"), "10s", "1s").ShouldNot(HaveOccurred())
				Eventually(getRuleFuncTable(tc.Felixes[0], "tier1.ep1-2-allow-to-netsets", "filter"), "10s", "1s").ShouldNot(HaveOccurred())
				Eventually(getRuleFuncTable(tc.Felixes[1], "tier1.ep2-1-allow-to-netsets", "filter"), "10s", "1s").ShouldNot(HaveOccurred())
			} else {
				bpfWaitForPolicyRule(tc.Felixes[0], ep1_1.InterfaceName, "ingress", "tier1.ep1-1-allow-to-netsets", `action:"allow"`)
				bpfWaitForPolicyRule(tc.Felixes[0], ep1_2.InterfaceName, "ingress", "tier1.ep1-2-allow-to-netsets", `action:"allow"`)
				bpfWaitForPolicyRule(tc.Felixes[1], ep2_1.InterfaceName, "ingress", "tier1.ep2-1-allow-to-netsets", `action:"allow"`)
			}
		})

		It("maps traffic to network sets with domain-based egress", func() {
			// Generate traffic from each endpoint to the domain IP to create flow logs
			By("Generating traffic to external domain IP to create flow logs")
			for i := 0; i < 3; i++ {
				canWgetDomain(ep1_1, "fake-microsoft.test")
				canWgetDomain(ep1_2, "fake-microsoft.test")
				canWgetDomain(ep2_1, "fake-microsoft.test")
				// Wait a short time before next iteration to ensure flows are flushed to file
				time.Sleep(500 * time.Millisecond)
			}
			flowlogs.WaitForConntrackScan(bpfEnabled)

			// Clear conntrack tables
			for _, f := range tc.Felixes {
				f.Exec("conntrack", "-F")
			}

			// Configure flow tester for domain-based flows
			flowTester := flowlogs.NewFlowTester(flowlogs.FlowTesterOptions{
				ExpectLabels:            true,
				MatchLabels:             false,
				ExcludeEnforcedPolicies: true,
				ExcludePendingPolicies:  true,
				Includes:                []flowlogs.IncludeFilter{flowlogs.IncludeByDestPort(80)},
				CheckNumFlowsStarted:    true,
			})

			// Create endpoint metadata
			ep1_1_Meta := createMetadata("wep", ep1_1.Name, ns1.Name)
			ep1_2_Meta := createMetadata("wep", ep1_2.Name, ns2.Name)
			ep2_1_Meta := createMetadata("wep", ep2_1.Name, ns3.Name)
			netset_1_Meta := createMetadata("ns", netset1.Name, netset1.Namespace)
			netset_2_Meta := createMetadata("ns", netset2.Name, netset2.Namespace)
			gns_1_Meta := createMetadata("ns", gns.Name, "-")

			// Parse IP addresses
			ip1_1 := parseIP(testIP1)
			ip1_2 := parseIP(testIP2)
			ip2_1 := parseIP(testIP3)
			ipDomainDest := parseIP(externalWorkloads[0].IP)

			// Create tuples for domain traffic
			ep1_1_to_domain_Tuple := tuple.Make(ip1_1, ipDomainDest, 6, flowlogs.SourcePortIsIncluded, 80)
			ep1_2_to_domain_Tuple := tuple.Make(ip1_2, ipDomainDest, 6, flowlogs.SourcePortIsIncluded, 80)
			ep2_1_to_domain_Tuple := tuple.Make(ip2_1, ipDomainDest, 6, flowlogs.SourcePortIsIncluded, 80)

			Eventually(func() error {
				// Check flows on Felix[0] for domain-based NetworkSets
				if err := flowTester.PopulateFromFlowLogs(tc.Felixes[0]); err != nil {
					return fmt.Errorf("Unable to populate flow tester from flow logs: %v", err)
				}

				// Check expected flows for domain egress from Felix[0]
				flowTester.CheckFlow(createExpectedFlow(ep1_1_to_domain_Tuple, ep1_1_Meta, netset_1_Meta))
				flowTester.CheckFlow(createExpectedFlow(ep1_2_to_domain_Tuple, ep1_2_Meta, netset_2_Meta))

				if err := flowTester.Finish(); err != nil {
					return fmt.Errorf("Domain flows incorrect on Felix[0]:\n%v", err)
				}

				// Check flows on Felix[1] for domain-based GlobalNetworkSet
				if err := flowTester.PopulateFromFlowLogs(tc.Felixes[1]); err != nil {
					return fmt.Errorf("Unable to populate flow tester from flow logs: %v", err)
				}

				// Check expected flows for domain egress from Felix[1]
				flowTester.CheckFlow(createExpectedFlow(ep2_1_to_domain_Tuple, ep2_1_Meta, gns_1_Meta))

				if err := flowTester.Finish(); err != nil {
					return fmt.Errorf("Domain flows incorrect on Felix[1]:\n%v", err)
				}

				return nil
			}, "20s", "1s").ShouldNot(HaveOccurred())
		})

		It("maps traffic to network sets with wildcard domain-based egress", func() {
			// Generate traffic from each endpoint to the domain IP to create flow logs
			By("Generating traffic to external domain IP to create flow logs")
			for i := 0; i < 3; i++ {
				canWgetDomain(ep1_1, "www.fake-google.test")
				canWgetDomain(ep2_1, "mail.fake-yahoo.test")
				canWgetDomain(ep1_1, "middle.fake-bing.test")
				canWgetDomain(ep2_1, "deep.a.b.fake-ask.test")
				// Wait a short time before next iteration to ensure flows are flushed to file
				time.Sleep(500 * time.Millisecond)
			}
			flowlogs.WaitForConntrackScan(bpfEnabled)

			// Clear conntrack tables
			for _, f := range tc.Felixes {
				f.Exec("conntrack", "-F")
			}

			// Configure flow tester for domain-based flows
			flowTester := flowlogs.NewFlowTester(flowlogs.FlowTesterOptions{
				ExpectLabels:            true,
				MatchLabels:             false,
				ExcludeEnforcedPolicies: true,
				ExcludePendingPolicies:  true,
				Includes:                []flowlogs.IncludeFilter{flowlogs.IncludeByDestPort(80)},
				CheckNumFlowsStarted:    true,
			})

			// Create endpoint metadata
			ep1_1_Meta := createMetadata("wep", ep1_1.Name, ns1.Name)
			ep2_1_Meta := createMetadata("wep", ep2_1.Name, ns3.Name)
			netset_3_Meta := createMetadata("ns", netset3.Name, netset3.Namespace)
			netset_4_Meta := createMetadata("ns", netset4.Name, netset4.Namespace)
			gns_2_Meta := createMetadata("ns", gns2.Name, "-")
			gns_3_Meta := createMetadata("ns", gns3.Name, "-")

			// Parse IP addresses
			ip1_1 := parseIP(testIP1)
			ip2_1 := parseIP(testIP3)
			ipGoogle := parseIP(externalWorkloads[1].IP)
			ipYahoo := parseIP(externalWorkloads[2].IP)
			ipBing := parseIP(externalWorkloads[3].IP)
			ipAsk := parseIP(externalWorkloads[4].IP)

			// Create tuples for domain traffic
			ep1_1_to_google_Tuple := tuple.Make(ip1_1, ipGoogle, 6, flowlogs.SourcePortIsIncluded, 80)
			ep1_1_to_bing_Tuple := tuple.Make(ip1_1, ipBing, 6, flowlogs.SourcePortIsIncluded, 80)
			ep2_1_to_yahoo_Tuple := tuple.Make(ip2_1, ipYahoo, 6, flowlogs.SourcePortIsIncluded, 80)
			ep2_1_to_ask_Tuple := tuple.Make(ip2_1, ipAsk, 6, flowlogs.SourcePortIsIncluded, 80)

			Eventually(func() error {
				// Check flows on Felix[0] for domain-based NetworkSets
				if err := flowTester.PopulateFromFlowLogs(tc.Felixes[0]); err != nil {
					return fmt.Errorf("Unable to populate flow tester from flow logs: %v", err)
				}

				// Check expected flows for domain egress from Felix[0]
				flowTester.CheckFlow(createExpectedFlow(ep1_1_to_google_Tuple, ep1_1_Meta, netset_3_Meta))
				flowTester.CheckFlow(createExpectedFlow(ep1_1_to_bing_Tuple, ep1_1_Meta, netset_4_Meta))

				if err := flowTester.Finish(); err != nil {
					return fmt.Errorf("Domain flows incorrect on Felix[0]:\n%v", err)
				}

				// Check flows on Felix[1] for domain-based GlobalNetworkSet
				if err := flowTester.PopulateFromFlowLogs(tc.Felixes[1]); err != nil {
					return fmt.Errorf("Unable to populate flow tester from flow logs: %v", err)
				}

				// Check expected flows for domain egress from Felix[1]
				flowTester.CheckFlow(createExpectedFlow(ep2_1_to_yahoo_Tuple, ep2_1_Meta, gns_2_Meta))
				flowTester.CheckFlow(createExpectedFlow(ep2_1_to_ask_Tuple, ep2_1_Meta, gns_3_Meta))

				if err := flowTester.Finish(); err != nil {
					return fmt.Errorf("Domain flows incorrect on Felix[1]:\n%v", err)
				}

				return nil
			}, "20s", "1s").ShouldNot(HaveOccurred())
		})
	},
)

func destDomainsToSlice(domains flowlog.FlowDestDomains) []string {
	var res []string
	for k := range domains.Domains {
		res = append(res, k)
	}
	if len(res) > 0 {
		sort.Strings(res)
	}
	return res
}
