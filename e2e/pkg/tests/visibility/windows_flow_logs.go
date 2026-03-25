// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package visibility

import (
	"context"
	"fmt"
	"strings"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	"github.com/olivere/elastic/v7"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/kubernetes/test/e2e/framework/kubectl"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	cclient "github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	esutil "github.com/projectcalico/calico/e2e/pkg/utils/elasticsearch"
	"github.com/projectcalico/calico/e2e/pkg/utils/windows"
)

// DESCRIPTION: Test Calico Enterprise flow logs on Windows.
// DOCS_URL: https://docs.tigera.io/calico-enterprise/latest/visibility/elastic/flow/
// PRECONDITIONS: Runs only on Windows clusters. The client and server docker images should have been present on the Windows nodes.
var _ = describe.EnterpriseDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("Flow-Logs"),
	describe.WithCategory(describe.Visibility),
	describe.WithWindows(),
	describe.WithSerial(),
	"windows flow logs",
	func() {
		var (
			f          = utils.NewDefaultFramework("windows-flowlogs")
			cli        client.Client
			esclient   *elastic.Client
			checker    conncheck.ConnectionTester
			clientPod  *conncheck.Client
			server     *conncheck.Server
			pf         *esutil.PortForwardInfo
			originalFC *v3.FelixConfiguration
		)

		BeforeEach(func() {
			ctx := context.Background()
			var err error

			cli, err = cclient.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())

			// Set up ES port forwarding and client.
			pf = esutil.PortForward()
			esclient = esutil.InitClient(f, pf.ElasticsearchURL)
			esutil.WaitForElastic(esclient)

			// Create a connection tester for the test.
			checker = conncheck.NewConnectionTester(f)

			// Save original Felix config and apply test-specific settings.
			// Use Eventually to retry on conflict (the felixconfig may be modified
			// by other controllers between our Get and Update).
			Eventually(func() error {
				originalFC = v3.NewFelixConfiguration()
				return cli.Get(ctx, types.NamespacedName{Name: "default"}, originalFC)
			}, 10*time.Second, 1*time.Second).Should(Succeed())

			Eventually(func() error {
				return utils.UpdateFelixConfig(cli, func(spec *v3.FelixConfigurationSpec) {
					spec.FlowLogsFlushInterval = &metav1.Duration{Duration: 1 * time.Second}
					spec.FlowLogsFileAggregationKindForAllowed = ptr.To(0)
					spec.FlowLogsDynamicAggregationEnabled = ptr.To(false)
				})
			}, 10*time.Second, 1*time.Second).Should(Succeed())

			DeferCleanup(func() {
				Eventually(func() error {
					return utils.UpdateFelixConfig(cli, func(spec *v3.FelixConfigurationSpec) {
						spec.FlowLogsFlushInterval = originalFC.Spec.FlowLogsFlushInterval
						spec.FlowLogsFileAggregationKindForAllowed = originalFC.Spec.FlowLogsFileAggregationKindForAllowed
						spec.FlowLogsDynamicAggregationEnabled = originalFC.Spec.FlowLogsDynamicAggregationEnabled
					})
				}, 10*time.Second, 1*time.Second).Should(Succeed())
			})
		})

		AfterEach(func() {
			if pf != nil {
				pf.Stop()
			}

			// If windows pods hung on termination, the code below fails quickly so we don't wait for framework to
			// timeout on deleting the pods (which can take a very long time).
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Explicitly delete the client and server pods created by this test.
			if clientPod != nil && clientPod.Pod() != nil {
				if err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Delete(ctx, clientPod.Pod().Name, metav1.DeleteOptions{}); err != nil {
					logrus.WithError(err).Infof("unable to cleanup client pod %v in namespace %v", clientPod.Pod().Name, f.Namespace.Name)
				}
			}
			if server != nil && server.Pod() != nil {
				if err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Delete(ctx, server.Pod().Name, metav1.DeleteOptions{}); err != nil {
					logrus.WithError(err).Infof("unable to cleanup server pod %v in namespace %v", server.Pod().Name, f.Namespace.Name)
				}
			}
		})

		esQuery := func(reporter string) *elastic.BoolQuery {
			return windowsFlowLogQuery(
				f.Namespace.Name,
				"client",
				"server",
				80,
				reporter)
		}

		Context("Windows flow logs", func() {
			// Before each test, perform the following steps:
			// - Create a server pod and corresponding service in the main namespace for the test.
			// - Create a client pod and assert that it can connect to the service.
			BeforeEach(func() {
				By(fmt.Sprintf("Creating server pod in namespace %s", f.Namespace))
				server = conncheck.NewServer("server", f.Namespace, conncheck.WithServerLabels(map[string]string{"role": "server"}))
				clientPod = conncheck.NewClient("client", f.Namespace, conncheck.WithClientLabels(map[string]string{"role": "client"}))
				checker.AddServer(server)
				checker.AddClient(clientPod)
				checker.Deploy()
			})

			AfterEach(func() {
				checker.Stop()

				if CurrentSpecReport().Failed() {
					windows.DumpFelixDiags()
				}
			})

			It("should generate flow logs when no policy applies", func() {
				By("generating continuous traffic from client to server")
				cp := checker.ExpectContinuously(clientPod, server.ClusterIPs()...)
				defer cp.Stop()

				By("checking flow log file on client node")
				Eventually(testFlowLogsPresent, 120*time.Second, 10*time.Second).WithArguments(
					clientPod.Pod().Spec.NodeName, f.Namespace.Name, clientPod.Pod().Status.PodIP, server.Pod().Status.PodIP).Should(Succeed())
				By("checking flow log file on server node")
				Eventually(testFlowLogsPresent, 120*time.Second, 10*time.Second).WithArguments(
					server.Pod().Spec.NodeName, f.Namespace.Name, clientPod.Pod().Status.PodIP, server.Pod().Status.PodIP).Should(Succeed())

				By("validating flow logs pushed to elasticsearch where reporter=src", func() {
					validateFlowLogs(esclient,
						esQuery("src"),
						flowExpectation{
							action: "allow",
							policy: "pro:kns." + f.Namespace.Name + "|allow",
						})
				})

				By("validating flow logs pushed to elasticsearch where reporter=dst", func() {
					validateFlowLogs(esclient,
						esQuery("dst"),
						flowExpectation{
							action: "allow",
							policy: "pro:kns." + f.Namespace.Name + "|allow",
						})
				})
			})

			Context("with policy denying client egress", func() {
				var denyClientEgress *v3.NetworkPolicy

				BeforeEach(func() {
					denyClientEgress = &v3.NetworkPolicy{
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
									Action:   v3.Deny,
									Protocol: protocolTCP(),
									Destination: v3.EntityRule{
										Selector: "role == 'server'",
									},
								},
							},
						},
					}
					logrus.Info("Create deny client egress policy denying egress from client to server")
					err := cli.Create(context.Background(), denyClientEgress)
					Expect(err).NotTo(HaveOccurred())
				})

				AfterEach(func() {
					logrus.Info("Clean up deny client egress policy")
					err := cli.Delete(context.Background(), denyClientEgress)
					Expect(err).NotTo(HaveOccurred())
				})

				It("should generate flow logs when policy denies src", func() {
					By("generating continuous traffic from client to server")
					cp := checker.ExpectContinuously(clientPod, server.ClusterIPs()...)
					defer cp.Stop()

					By("checking flow log file on client node")
					Eventually(testFlowLogsPresent, 120*time.Second, 10*time.Second).WithArguments(
						clientPod.Pod().Spec.NodeName, f.Namespace.Name, clientPod.Pod().Status.PodIP, server.Pod().Status.PodIP).Should(Succeed())

					By("validating flow logs pushed to elasticsearch where reporter=src", func() {
						validateFlowLogs(esclient,
							esQuery("src"),
							flowExpectation{
								action: "deny",
								policy: fmt.Sprintf("default|np:%s/default.deny-client-egress|deny", f.Namespace.Name),
							})
					})
				})
			})

			Context("with policy denying server ingress", func() {
				var denyServerIngress *v3.NetworkPolicy

				BeforeEach(func() {
					denyServerIngress = &v3.NetworkPolicy{
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
					logrus.Info("Create deny server ingress policy denying ingress from client")
					err := cli.Create(context.Background(), denyServerIngress)
					Expect(err).NotTo(HaveOccurred())
				})

				AfterEach(func() {
					logrus.Info("Clean up deny server ingress policy")
					err := cli.Delete(context.Background(), denyServerIngress)
					Expect(err).NotTo(HaveOccurred())
				})

				It("should generate flow logs when policy denies dst", func() {
					By("generating continuous traffic from client to server")
					cp := checker.ExpectContinuously(clientPod, server.ClusterIPs()...)
					defer cp.Stop()

					By("checking flow log file on client node")
					Eventually(testFlowLogsPresent, 120*time.Second, 10*time.Second).WithArguments(
						clientPod.Pod().Spec.NodeName, f.Namespace.Name, clientPod.Pod().Status.PodIP, server.Pod().Status.PodIP).Should(Succeed())
					By("checking flow log file on server node")
					Eventually(testFlowLogsPresent, 120*time.Second, 10*time.Second).WithArguments(
						server.Pod().Spec.NodeName, f.Namespace.Name, clientPod.Pod().Status.PodIP, server.Pod().Status.PodIP).Should(Succeed())

					By("validating flow logs pushed to elasticsearch where reporter=src", func() {
						validateFlowLogs(esclient,
							esQuery("src"),
							flowExpectation{
								action: "allow",
								policy: "pro:kns." + f.Namespace.Name + "|allow",
							})
					})

					By("validating flow logs pushed to elasticsearch where reporter=dst", func() {
						validateFlowLogs(esclient,
							esQuery("dst"),
							flowExpectation{
								action: "deny",
								policy: fmt.Sprintf("default|np:%s/default.deny-server-ingress|deny", f.Namespace.Name),
							})
					})
				})
			})
		})
	},
)

// windowsFlowLogQuery builds an ES query for Windows flow logs.
// Uses namespace filtering and PrefixQuery on name_aggr fields (mirroring the Linux
// flow_logs.go flowLogQuery approach) to be resilient against aggregation settings
// not having propagated when the flow was generated.
func windowsFlowLogQuery(namespace, clientBaseName, serverBaseName string, targetPort int, reporter string) *elastic.BoolQuery {
	return esutil.BuildElasticQueryWithTerms(
		elastic.NewTermsQuery("source_namespace", namespace),
		elastic.NewPrefixQuery("source_name_aggr", clientBaseName),
		elastic.NewTermsQuery("dest_namespace", namespace),
		elastic.NewPrefixQuery("dest_name_aggr", serverBaseName),
		elastic.NewTermQuery("dest_port", targetPort),
		elastic.NewTermsQuery("reporter", reporter))
}

// testFlowLogsPresent checks if flow log entries containing the namespace and both searchStr1
// and searchStr2 exist in the flows.log file on the given node. Reads only the tail of the file
// to avoid transferring the entire flows.log (which can be 8MB+). Splits on "start_time" to
// handle multi-line flow log entries where source and dest IPs may be on different lines.
func testFlowLogsPresent(nodeName, namespace, searchStr1, searchStr2 string) error {
	// Find the calico-node-windows pod on this node.
	getPodArgs := []string{
		"get", "pod",
		"-l", "k8s-app=calico-node-windows",
		"--field-selector", "spec.nodeName=" + nodeName,
		"-o", "jsonpath={.items[0].metadata.name}",
	}
	podName, err := kubectl.NewKubectlCommand("calico-system", getPodArgs...).
		WithTimeout(time.After(10 * time.Second)).
		Exec()
	if err != nil {
		return fmt.Errorf("Failed to find calico-node-windows pod on %s: %w", nodeName, err)
	}

	// Read only the last 500 lines to avoid transferring the full file.
	execArgs := []string{
		"exec", strings.TrimSpace(podName), "-c", "node",
		"--", "powershell.exe", "-Command",
		"Get-Content C:\\TigeraCalico\\flowlogs\\flows.log -Tail 500 -ErrorAction SilentlyContinue",
	}
	output, err := kubectl.NewKubectlCommand("calico-system", execArgs...).
		WithTimeout(time.After(30 * time.Second)).
		Exec()
	if err != nil {
		return fmt.Errorf("Failed to get flow logs from node %s: %w", nodeName, err)
	}

	// Split on "start_time" to get per-entry chunks, since flow log entries may
	// span multiple lines.
	for _, entry := range strings.Split(output, "start_time") {
		if strings.Contains(entry, namespace) && strings.Contains(entry, searchStr1) && strings.Contains(entry, searchStr2) {
			logrus.Infof("Found flow log entry on %s containing %q, %q and %q", nodeName, namespace, searchStr1, searchStr2)
			return nil
		}
	}
	return fmt.Errorf("no flow log entry on %s matching namespace=%q, src=%q, dst=%q", nodeName, namespace, searchStr1, searchStr2)
}
