// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package visibility

import (
	"context"
	"fmt"
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
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	cclient "github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	esutil "github.com/projectcalico/calico/e2e/pkg/utils/elasticsearch"
)

// DESCRIPTION: Test Calico Enterprise flow logs on Windows.
// DOCS_URL: https://docs.tigera.io/calico-enterprise/latest/visibility/elastic/flow/
// PRECONDITIONS: Runs only on Windows clusters. The client and server docker images should have been present on the Windows nodes.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("Flow-Logs"),
	describe.WithCategory(describe.Visibility),
	describe.WithWindows(),
	"windows flow logs",
	func() {
		var (
			f          = utils.NewDefaultFramework("windows-flowlogs")
			cli        client.Client
			esclient   *elastic.Client
			checker    conncheck.ConnectionTester
			clientPod  *conncheck.Client
			server     *conncheck.Server
			cancelFunc func()
		)

		BeforeEach(func() {
			ctx := context.Background()
			var err error

			cli, err = cclient.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())

			// Clean datastore to ensure a clean starting environment.
			Expect(utils.CleanDatastore(cli)).ShouldNot(HaveOccurred())

			// Set up ES port forwarding and client.
			cancelFunc = esutil.PortForward()
			esclient = esutil.InitClient(f)
			esutil.WaitForElastic(esclient)

			// Create a connection tester for the test.
			checker = conncheck.NewConnectionTester(f)

			// Save original Felix config and apply test-specific settings.
			originalFC := v3.NewFelixConfiguration()
			err = cli.Get(ctx, types.NamespacedName{Name: "default"}, originalFC)
			Expect(err).NotTo(HaveOccurred())

			testFC := originalFC.DeepCopy()
			testFC.Spec.FlowLogsFlushInterval = &metav1.Duration{Duration: 1 * time.Second}
			testFC.Spec.FlowLogsFileAggregationKindForAllowed = ptr.To(0)
			testFC.Spec.FlowLogsDynamicAggregationEnabled = ptr.To(false)
			err = cli.Update(ctx, testFC)
			Expect(err).NotTo(HaveOccurred())

			DeferCleanup(func() {
				fc := v3.NewFelixConfiguration()
				err := cli.Get(context.Background(), types.NamespacedName{Name: "default"}, fc)
				Expect(err).NotTo(HaveOccurred())
				fc.Spec.FlowLogsFlushInterval = originalFC.Spec.FlowLogsFlushInterval
				fc.Spec.FlowLogsFileAggregationKindForAllowed = originalFC.Spec.FlowLogsFileAggregationKindForAllowed
				fc.Spec.FlowLogsDynamicAggregationEnabled = originalFC.Spec.FlowLogsDynamicAggregationEnabled
				err = cli.Update(context.Background(), fc)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		AfterEach(func() {
			if cancelFunc != nil {
				cancelFunc()
			}

			// There used to be issues on deleting windows pods.
			// If windows pods hung on termination, the code below fails quickly so we don't wait for framework to
			// timeout on deleting the pods (which can take a very long time).
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Delete(ctx, f.Namespace.Name, metav1.DeleteOptions{}); err != nil {
				logrus.WithError(err).Infof("unable to cleanup pods in the client namespace %v", f.Namespace.Name)
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
			})

			It("should generate flow logs when no policy applies", func() {
				By("generating continuous traffic from client to server")
				cp := checker.ExpectContinuously(clientPod, server.ClusterIPs()...)
				defer cp.Stop()

				By("validating flow logs pushed to elasticsearch where reporter=src", func() {
					validateFlowLogs(esclient,
						esQuery("src"),
						flowExpectation{
							action: "allow",
							policy: ".kns." + f.Namespace.Name + "|allow",
						})
				})

				By("validating flow logs pushed to elasticsearch where reporter=dst", func() {
					validateFlowLogs(esclient,
						esQuery("dst"),
						flowExpectation{
							action: "allow",
							policy: ".kns." + f.Namespace.Name + "|allow",
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

					By("validating flow logs pushed to elasticsearch where reporter=src", func() {
						validateFlowLogs(esclient,
							esQuery("src"),
							flowExpectation{
								action: "deny",
								policy: fmt.Sprintf("default|%s/default.deny-client-egress|deny", f.Namespace.Name),
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

					By("validating flow logs pushed to elasticsearch where reporter=src", func() {
						validateFlowLogs(esclient,
							esQuery("src"),
							flowExpectation{
								action: "allow",
								policy: ".kns." + f.Namespace.Name + "|allow",
							})
					})

					By("validating flow logs pushed to elasticsearch where reporter=dst", func() {
						validateFlowLogs(esclient,
							esQuery("dst"),
							flowExpectation{
								action: "deny",
								policy: fmt.Sprintf("default|%s/default.deny-server-ingress|deny", f.Namespace.Name),
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
