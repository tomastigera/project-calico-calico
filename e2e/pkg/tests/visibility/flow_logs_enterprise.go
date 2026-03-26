// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package visibility

import (
	"context"
	"errors"
	"fmt"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	"github.com/olivere/elastic/v7"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	cclient "github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	esutil "github.com/projectcalico/calico/e2e/pkg/utils/elasticsearch"
	"github.com/projectcalico/calico/e2e/pkg/utils/flowlogs"
)

// DESCRIPTION: Test Calico Enterprise flow logs.
// DOCS_URL: https://docs.tigera.io/calico-enterprise/latest/visibility/elastic/flow/
// PRECONDITIONS: No specific preconditions.
var _ = describe.EnterpriseDescribe(
	describe.WithTeam(describe.EV),
	describe.WithFeature("Flow-Logs"),
	describe.WithCategory(describe.Visibility),
	describe.WithSerial(),
	"flow logs",
	func() {
		var (
			f          = utils.NewDefaultFramework("cnx-flowlogs-es")
			cli        client.Client
			esclient   *elastic.Client
			checker    conncheck.ConnectionTester
			pf         *esutil.PortForwardInfo
			originalFC *v3.FelixConfiguration
		)

		BeforeEach(func() {
			ctx := context.Background()
			var err error

			cli, err = cclient.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())

			// Configure Felix for flow log testing.
			Eventually(func() error {
				originalFC = v3.NewFelixConfiguration()
				return cli.Get(ctx, types.NamespacedName{Name: "default"}, originalFC)
			}, 10*time.Second, 1*time.Second).Should(Succeed())

			Eventually(func() error {
				return utils.UpdateFelixConfig(cli, func(spec *v3.FelixConfigurationSpec) {
					spec.FlowLogsFlushInterval = &metav1.Duration{Duration: 15 * time.Second}
					spec.FlowLogsCollectProcessInfo = ptr.To(true)
					spec.FlowLogsCollectTcpStats = ptr.To(false)
				})
			}, 10*time.Second, 1*time.Second).Should(Succeed())

			DeferCleanup(func() {
				Eventually(func() error {
					return utils.UpdateFelixConfig(cli, func(spec *v3.FelixConfigurationSpec) {
						spec.FlowLogsFlushInterval = originalFC.Spec.FlowLogsFlushInterval
						spec.FlowLogsCollectProcessInfo = originalFC.Spec.FlowLogsCollectProcessInfo
						spec.FlowLogsCollectTcpStats = originalFC.Spec.FlowLogsCollectTcpStats
					})
				}, 10*time.Second, 1*time.Second).Should(Succeed())
			})

			// Initialize connection tester.
			checker = conncheck.NewConnectionTester(f)

			// Set up ES port forwarding and client.
			pf = esutil.PortForward()
			esclient = esutil.InitClient(f, pf.ElasticsearchURL)
			esutil.WaitForElastic(esclient)
		})

		AfterEach(func() {
			if pf != nil {
				pf.Stop()
			}
		})

		Context("Pod to Service Flowlogs e2e", func() {
			var (
				clientPod *conncheck.Client
				server    *conncheck.Server
			)

			BeforeEach(func() {
				server = conncheck.NewServer("server", f.Namespace,
					conncheck.WithServerLabels(map[string]string{"role": "server"}))
				clientPod = conncheck.NewClient("client", f.Namespace,
					conncheck.WithClientLabels(map[string]string{"role": "client"}))
				checker.AddServer(server)
				checker.AddClient(clientPod)
				checker.Deploy()
			})

			AfterEach(func() {
				checker.Stop()

				// If the test fails, list out the flow logs for debugging.
				if CurrentSpecReport().Failed() {
					logrus.Info("[DIAGS] Listing flow logs for debugging")
					query := esutil.BuildElasticQueryWithTerms(
						elastic.NewTermsQuery("source_namespace", f.Namespace.Name),
						elastic.NewTermsQuery("dest_namespace", f.Namespace.Name),
					)
					queryResult := esutil.SearchInEs(esclient, query, esutil.FlowlogsIndex)
					for _, log := range esutil.GetFlowlogsFromESSearchResult(queryResult) {
						logrus.Infof("[FLOWLOG] %+v", log)
					}
				}
			})

			It("Captures HTTP traffic from a pod source to a service destination with no policy applied", func() {
				checker.ExpectSuccess(clientPod, server.ClusterIPs()...)
				checker.Execute()
				checker.ResetExpectations()

				By("validating flow logs pushed to elasticsearch where reporter=src", func() {
					validateFlowLogs(esclient,
						flowLogQuery(f.Namespace.Name, "src", "client", "server", ""),
						flowExpectation{
							action:    "allow",
							profileNS: f.Namespace.Name,
						})
				})

				By("validating flow logs pushed to elasticsearch where reporter=dst", func() {
					validateFlowLogs(esclient,
						flowLogQuery(f.Namespace.Name, "dst", "client", "server", ""),
						flowExpectation{
							action:    "allow",
							profileNS: f.Namespace.Name,
						})
				})
			})

			It("Captures HTTP traffic from a pod source to a service destination with deny egress (outgoing) policy on src applied", func() {
				dnsPort, err := numorstring.NamedPort("dns")
				Expect(err).ToNot(HaveOccurred())

				// Apply deny egress policy on the client: allow DNS but deny everything else.
				denyClientEgress := &v3.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default.deny-client-egress",
						Namespace: f.Namespace.Name,
					},
					Spec: v3.NetworkPolicySpec{
						Selector: "role == 'client'",
						Order:    ptr.To(10.0),
						Types:    []v3.PolicyType{v3.PolicyTypeEgress},
						Egress: []v3.Rule{
							{
								Action:   v3.Allow,
								Protocol: protocolUDP(),
								Destination: v3.EntityRule{
									Ports: []numorstring.Port{
										dnsPort,
										numorstring.SinglePort(5353),
										numorstring.SinglePort(53),
									},
								},
							},
						},
					},
				}
				err = cli.Create(context.Background(), denyClientEgress)
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(func() {
					_ = cli.Delete(context.Background(), denyClientEgress)
				})

				checker.ExpectFailure(clientPod, server.ClusterIPs()...)
				checker.Execute()
				checker.ResetExpectations()

				By("validating flow logs pushed to elasticsearch have action as deny where reporter=src", func() {
					validateFlowLogs(esclient,
						flowLogQuery(f.Namespace.Name, "src", "client", "server", ""),
						flowExpectation{
							action: "deny",
							policy: denyClientEgress,
						})
				})
			})

			It("Captures HTTP traffic from a pod source to a service destination with deny ingress (incoming) policy on dst applied", func() {
				// Apply deny ingress policy on the server.
				denyServerIngress := &v3.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default.deny-server-ingress",
						Namespace: f.Namespace.Name,
					},
					Spec: v3.NetworkPolicySpec{
						Selector: "role == 'server'",
						Order:    ptr.To(10.0),
						Types:    []v3.PolicyType{v3.PolicyTypeIngress},
						Ingress: []v3.Rule{
							{
								Action:   v3.Deny,
								Protocol: protocolTCP(),
								Source: v3.EntityRule{
									Selector: "role == 'client'",
								},
							},
						},
					},
				}
				err := cli.Create(context.Background(), denyServerIngress)
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(func() {
					_ = cli.Delete(context.Background(), denyServerIngress)
				})

				checker.ExpectFailure(clientPod, server.ClusterIPs()...)
				checker.Execute()
				checker.ResetExpectations()

				By("validating flow logs pushed to elasticsearch where reporter=src still displays action=allow", func() {
					validateFlowLogs(esclient,
						flowLogQuery(f.Namespace.Name, "src", "client", "server", ""),
						flowExpectation{
							action:    "allow",
							profileNS: f.Namespace.Name,
						})
				})

				By("validating flow logs pushed to elasticsearch where reporter=dst still displays action=deny", func() {
					validateFlowLogs(esclient,
						flowLogQuery(f.Namespace.Name, "dst", "client", "server", ""),
						flowExpectation{
							action: "deny",
							policy: denyServerIngress,
						})
				})
			})

			It("Captures HTTP traffic from a pod source to a service destination with allow ingress (incoming) policy on dst applied", func() {
				// Apply allow ingress policy on the server.
				allowServerIngress := &v3.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default.allow-server-ingress",
						Namespace: f.Namespace.Name,
					},
					Spec: v3.NetworkPolicySpec{
						Selector: "role == 'server'",
						Order:    ptr.To(10.0),
						Types:    []v3.PolicyType{v3.PolicyTypeIngress},
						Ingress: []v3.Rule{
							{
								Action:   v3.Allow,
								Protocol: protocolTCP(),
							},
						},
					},
				}
				err := cli.Create(context.Background(), allowServerIngress)
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(func() {
					err = cli.Delete(context.Background(), allowServerIngress)
					if err != nil {
						logrus.WithError(err).Warnf("Error deleting allow server ingress network policy")
					}
				})

				checker.ExpectSuccess(clientPod, server.ClusterIPs()...)
				checker.Execute()
				checker.ResetExpectations()

				By("validating flow logs pushed to elasticsearch where reporter=src", func() {
					validateFlowLogs(esclient,
						flowLogQuery(f.Namespace.Name, "src", "client", "server", ""),
						flowExpectation{
							action:    "allow",
							profileNS: f.Namespace.Name,
						})
				})

				By("validating flow logs pushed to elasticsearch where reporter=dst", func() {
					validateFlowLogs(esclient,
						flowLogQuery(f.Namespace.Name, "dst", "client", "server", ""),
						flowExpectation{
							action: "allow",
							policy: allowServerIngress,
						})
				})
			})
		})

		Context("Pod to Service Flowlogs e2e with process info aggregation", func() {
			var (
				clientPod *conncheck.Client
				server    *conncheck.Server
			)

			BeforeEach(func() {
				server = conncheck.NewServer("server", f.Namespace,
					conncheck.WithServerLabels(map[string]string{"role": "server"}))
				clientPod = conncheck.NewClient("client", f.Namespace,
					conncheck.WithClientLabels(map[string]string{"role": "client"}))
				checker.AddServer(server)
				checker.AddClient(clientPod)
				checker.Deploy()
			})

			AfterEach(func() {
				checker.Stop()
			})

			It("aggregates process ID information for allowed traffic", func() {
				// Generate traffic to produce flow logs with process information.
				checker.ExpectSuccess(clientPod, server.ClusterIPs()...)
				checker.Execute()
				checker.ResetExpectations()

				By("validating flow logs pushed to elasticsearch where reporter=src", func() {
					validateFlowLogs(esclient,
						flowLogQuery(f.Namespace.Name, "src", "client", "server", ""),
						flowExpectation{
							action:    "allow",
							profileNS: f.Namespace.Name,
							process:   "wget",
						})
				})

				By("validating flow logs pushed to elasticsearch where reporter=dst", func() {
					validateFlowLogs(esclient,
						flowLogQuery(f.Namespace.Name, "dst", "client", "server", ""),
						flowExpectation{
							action:    "allow",
							profileNS: f.Namespace.Name,
							process:   "test-webserver",
						})
				})
			})
		})
	},
)

// protocolTCP returns a TCP protocol for use in network policy rules.
func protocolTCP() *numorstring.Protocol {
	p := numorstring.ProtocolFromString("TCP")
	return &p
}

// protocolUDP returns a UDP protocol for use in network policy rules.
func protocolUDP() *numorstring.Protocol {
	p := numorstring.ProtocolFromString("UDP")
	return &p
}

// flowLogQuery builds an ES query for flow logs filtered by namespace, reporter,
// source and destination name prefixes, and optionally a process name.
func flowLogQuery(namespace, reporter, sourceName, destName, process string) *elastic.BoolQuery {
	terms := []elastic.Query{
		elastic.NewTermsQuery("source_namespace", namespace),
		elastic.NewPrefixQuery("source_name_aggr", sourceName),
		elastic.NewTermsQuery("dest_namespace", namespace),
		elastic.NewPrefixQuery("dest_name_aggr", destName),
		elastic.NewTermsQuery("reporter", reporter),
	}
	if process != "" {
		terms = append(terms, elastic.NewRegexpQuery("process_name", fmt.Sprintf(".*%s.*", process)))
	}
	return esutil.BuildElasticQueryWithTerms(terms...)
}

type flowExpectation struct {
	action       string
	policy       runtime.Object // expected policy object (mutually exclusive with profileNS)
	profileNS    string         // expected profile namespace (mutually exclusive with policy)
	process      string
	sourceLabels []string
	destLabels   []string
}

func validateFlowLogs(esclient *elastic.Client, esquery *elastic.BoolQuery, expectation flowExpectation) {
	var queryResult *elastic.SearchResult
	var flowLogs []esutil.FlowLog

	// Time window in which to try polling for logs.
	// Fluentd flushes to Linseed every 5s by default.
	// The test configures Felix to flush every 15s.
	// So, we can expect logs to be available within 60s.
	EventuallyWithOffset(1, func() error {
		logrus.Infof("Query %+v", esquery)
		queryResult = esutil.SearchInEs(esclient, esquery, esutil.FlowlogsIndex)
		flowLogs = esutil.GetFlowlogsFromESSearchResult(queryResult)
		if len(flowLogs) == 0 {
			return errors.New("no flow logs found")
		}
		return nil
	}, 120*time.Second, 5*time.Second).ShouldNot(HaveOccurred())

	Expect(flowLogs).NotTo(BeEmpty(), "expected flow logs from ES query but got none")
	for _, fl := range flowLogs {
		policies := fl.Policies.EnforcedPolicies

		// Flowlog entries should only have a single policy string.
		Expect(policies).To(HaveLen(1), "expected exactly 1 enforced policy, got %d: %v", len(policies), policies)

		// Validate the enforced policy using structured PolicyHit parsing.
		if expectation.policy != nil {
			flowlogs.ExpectPolicyInFlowLogs(policies, expectation.policy)
		} else if expectation.profileNS != "" {
			flowlogs.ExpectProfileInFlowLogs(policies, expectation.profileNS)
		}
		Expect(fl.Action).To(Equal(expectation.action), "flow log action was %q, expected %q", fl.Action, expectation.action)

		// If process name is given in the expectation, verify process information.
		// In some cases, like reporter=dst with action=deny, packets do not reach the destination
		// process, so destination process information is not populated in flowlogs.
		if expectation.process != "" {
			Expect(fl.ProcessName).To(ContainSubstring(expectation.process), "process name %q does not contain %q", fl.ProcessName, expectation.process)
			Expect(fl.NumProcessNames).To(Equal(1), "expected 1 process name, got %d", fl.NumProcessNames)
			if fl.NumProcessIDs > 1 {
				Expect(fl.ProcessID).To(Equal("*"), "expected aggregated process ID '*' when NumProcessIDs=%d, got %q", fl.NumProcessIDs, fl.ProcessID)
			} else {
				Expect(fl.ProcessID).NotTo(Equal("*"), "expected specific process ID when NumProcessIDs=1, got '*'")
			}
		}

		// Check if the flow log has the expected labels.
		for _, label := range expectation.sourceLabels {
			Expect(fl.SourceLabels.Labels).To(ContainElement(label), "source labels %v missing expected label %q", fl.SourceLabels.Labels, label)
		}
		for _, label := range expectation.destLabels {
			Expect(fl.DestLabels.Labels).To(ContainElement(label), "dest labels %v missing expected label %q", fl.DestLabels.Labels, label)
		}
	}
}
