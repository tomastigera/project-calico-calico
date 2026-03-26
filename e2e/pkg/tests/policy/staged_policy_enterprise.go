// Copyright (c) 2025 Tigera, Inc. All rights reserved.
package policy

import (
	"context"
	"fmt"
	"time"

	"github.com/olivere/elastic/v7"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/e2e/pkg/utils/elasticsearch"
	"github.com/projectcalico/calico/e2e/pkg/utils/flowlogs"
)

// DESCRIPTION: This test verifies the staged network policy feature.
//
// DOCS_URL: https://docs.tigera.io/calico-enterprise/latest/reference/resources/stagednetworkpolicy
// PRECONDITIONS:
var _ = describe.EnterpriseDescribe(
	describe.WithSerial(),
	describe.WithTeam(describe.EV),
	describe.WithCategory(describe.Policy),
	"staged network policy",
	func() {
		var (
			esclient   *elastic.Client
			cli        ctrlclient.Client
			err        error
			customTier string
			checker    conncheck.ConnectionTester
			pf         *elasticsearch.PortForwardInfo

			f                   = utils.NewDefaultFramework("staged-policy")
			serverPodNamePrefix = "server-pod"
			clientPodNamePrefix = "client-pod"
			serverPort          = 80
		)

		BeforeEach(func() {
			// We read flow logs from ES, and access Kibana via Manager. We start port forward so we can query the flows.
			pf = elasticsearch.PortForward()

			// initialize esclient
			esclient = initializeSetup(f, pf.ElasticsearchURL)
			elasticsearch.WaitForElastic(esclient)

			cli, err = client.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())

			checker = conncheck.NewConnectionTester(f)
		})

		AfterEach(func() {
			pf.Stop()
		})

		Context("Test presence in flow logs", func() {
			var (
				tierObj *v3.Tier

				client1 *conncheck.Client
				server  *conncheck.Server
			)

			BeforeEach(func() {
				// create tier
				customTier = utils.GenerateRandomName("e2e-staged-tier")
				tierObj = v3.NewTier()
				tierObj.Name = customTier
				tierObj.Spec.Order = ptr.To[float64](200)
				Expect(cli.Create(context.TODO(), tierObj)).ToNot(HaveOccurred())

				client1 = conncheck.NewClient(clientPodNamePrefix, f.Namespace)
				server = conncheck.NewServer(utils.GenerateRandomName(serverPodNamePrefix), f.Namespace)
				checker.AddClient(client1)
				checker.AddServer(server)
				checker.Deploy()
			})

			AfterEach(func() {
				checker.Stop()

				// delete tier
				Expect(cli.Delete(context.TODO(), tierObj)).ShouldNot(HaveOccurred())
			})

			Describe("for StagedKubernetesNetworkPolicies", func() {
				var sknpAllow *v3.StagedKubernetesNetworkPolicy
				BeforeEach(func() {
					// create policy
					labelSelector := metav1.LabelSelector{
						MatchLabels: map[string]string{"pod-name": server.Name()},
					}
					protocolTCP := v1.ProtocolTCP
					ingress := []networkingv1.NetworkPolicyIngressRule{{
						Ports: []networkingv1.NetworkPolicyPort{{
							Protocol: &protocolTCP,
							Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: int32(serverPort)},
						}},
					}}
					sknpAllow = CreateStagedKubernetesNetworkPolicyAllow("sknp-allow", server.Pod().Namespace, labelSelector, ingress, nil)
					Expect(cli.Create(context.TODO(), sknpAllow)).ShouldNot(HaveOccurred())

					// create client pod and connect from client to server
					checker.ExpectSuccess(client1, server.ClusterIP().Port(serverPort))
					checker.Execute()
				})

				It("Validate actions, names, and orders", func() {
					flowLogs := fetchFlowlogs(esclient, client1.Pod().Namespace, server.Pod().Namespace, client1.Name(), server.Name(), "dst")
					Expect(len(flowLogs)).To(Equal(1))
					item := flowLogs[0]

					// The PendingPolicies should include the first of the two staged policies defined above.
					Expect(len(item.Policies.PendingPolicies)).To(Equal(1), "Expected 1 pending policies but got: %v", item.Policies.PendingPolicies)
					flowlogs.ExpectPolicyInFlowLogs(item.Policies.PendingPolicies, sknpAllow)

					// The EnforcedPolicies should include the __PROFILE__ only.
					Expect(len(item.Policies.EnforcedPolicies)).To(Equal(1), "Expected 1 enforced policy but got: %v", item.Policies.EnforcedPolicies)
					flowlogs.ExpectProfileInFlowLogs(item.Policies.EnforcedPolicies, client1.Pod().Namespace)
				})

				AfterEach(func() {
					Expect(cli.Delete(context.TODO(), sknpAllow)).ShouldNot(HaveOccurred())
				})
			})

			Describe("for StagedNetworkPolicies", func() {
				var policy1, policy2, policy3, policy4 *v3.StagedNetworkPolicy

				BeforeEach(func() {
					selector := fmt.Sprintf("pod-name==\"%s\"", server.Name())

					// Each policy gets its own ingress rules to avoid sharing the same
					// slice backing array, which would cause all policies to end up with
					// the last-assigned action.
					policy1 = CreateStagedNetworkPolicy("snp-deny-1", tierObj.Name, server.Pod().Namespace, 10, selector, []v3.Rule{{Action: v3.Deny}}, nil)
					Expect(cli.Create(context.TODO(), policy1)).ShouldNot(HaveOccurred())

					policy2 = CreateStagedNetworkPolicy("snp-allow-2", tierObj.Name, server.Pod().Namespace, 11, selector, []v3.Rule{{Action: v3.Allow}}, nil)
					Expect(cli.Create(context.TODO(), policy2)).ShouldNot(HaveOccurred())

					policy3 = CreateStagedNetworkPolicy("snp-pass-3", tierObj.Name, server.Pod().Namespace, 12, selector, []v3.Rule{{Action: v3.Pass}}, nil)
					Expect(cli.Create(context.TODO(), policy3)).ShouldNot(HaveOccurred())

					policy4 = CreateStagedNetworkPolicy("snp-invisible-4", tierObj.Name, server.Pod().Namespace, 13, selector, []v3.Rule{{Action: v3.Allow}}, nil)
					Expect(cli.Create(context.TODO(), policy4)).ShouldNot(HaveOccurred())

					// Connect to all the server's cluster IPs.
					for _, t := range server.ClusterIPs() {
						checker.ExpectSuccess(client1, t.Port(serverPort))
					}
					checker.Execute()
				})

				It("Validate actions, names, and orders", func() {
					// validate the staged policy applied to the client-server traffic in flowlogs
					flowLogs := fetchFlowlogs(esclient, f.Namespace.Name, f.Namespace.Name, client1.Name(), server.Name(), "dst")
					Expect(len(flowLogs)).To(BeNumerically(">", 0))

					item := flowLogs[0]

					// Staged policies appear in PendingPolicies. The first policy is a Deny which
					// terminates staged evaluation, so only 1 pending policy is recorded.
					Expect(len(item.Policies.PendingPolicies)).To(BeNumerically(">=", 1), "Expected at least 1 pending policy but got: %v", item.Policies.PendingPolicies)
					hit1 := flowlogs.FindPolicyInFlowLogs(item.Policies.PendingPolicies, policy1)
					Expect(string(hit1.Action())).To(Equal("deny"))

					// EnforcedPolicies should include just the __PROFILE__.
					Expect(len(item.Policies.EnforcedPolicies)).To(BeNumerically(">=", 1), "Expected at least 1 enforced policy but got: %v", item.Policies.EnforcedPolicies)
					flowlogs.ExpectProfileInFlowLogs(item.Policies.EnforcedPolicies, f.Namespace.Name)
				})

				AfterEach(func() {
					Expect(cli.Delete(context.TODO(), policy1)).ShouldNot(HaveOccurred())
					Expect(cli.Delete(context.TODO(), policy2)).ShouldNot(HaveOccurred())
					Expect(cli.Delete(context.TODO(), policy3)).ShouldNot(HaveOccurred())
					Expect(cli.Delete(context.TODO(), policy4)).ShouldNot(HaveOccurred())
				})
			})

			Describe("for StagedGlobalNetworkPolicies", func() {
				var policy1, policy2, policy3, policy4 *v3.StagedGlobalNetworkPolicy

				BeforeEach(func() {
					selector := fmt.Sprintf("pod-name == \"%s\"", server.Name())

					// Each policy gets its own ingress rules to avoid sharing the same
					// slice backing array, which would cause all policies to end up with
					// the last-assigned action.
					policy1 = CreateStagedGlobalNetworkPolicy("sgnp-deny-1", tierObj.Name, 10, selector, []v3.Rule{{Action: v3.Deny}}, nil)
					Expect(cli.Create(context.TODO(), policy1)).ShouldNot(HaveOccurred())

					policy2 = CreateStagedGlobalNetworkPolicy("sgnp-allow-2", tierObj.Name, 11, selector, []v3.Rule{{Action: v3.Allow}}, nil)
					Expect(cli.Create(context.TODO(), policy2)).ShouldNot(HaveOccurred())

					policy3 = CreateStagedGlobalNetworkPolicy("sgnp-pass-3", tierObj.Name, 12, selector, []v3.Rule{{Action: v3.Pass}}, nil)
					Expect(cli.Create(context.TODO(), policy3)).ShouldNot(HaveOccurred())

					policy4 = CreateStagedGlobalNetworkPolicy("sgnp-invisible-4", tierObj.Name, 13, selector, []v3.Rule{{Action: v3.Allow}}, nil)
					Expect(cli.Create(context.TODO(), policy4)).ShouldNot(HaveOccurred())

					// create client pod and connect from client to server
					checker.ExpectSuccess(client1, server.ClusterIP().Port(serverPort))
					checker.Execute()
				})

				It("Validate actions, names, and orders", func() {
					// validate the staged policy applied to the client-server traffic in flowlogs
					flowLogs := fetchFlowlogs(esclient, f.Namespace.Name, f.Namespace.Name, clientPodNamePrefix, server.Name(), "dst")
					Expect(len(flowLogs)).To(BeNumerically(">", 0))

					item := flowLogs[0]

					// Staged policies appear in PendingPolicies. The first policy is a Deny which
					// terminates staged evaluation, so only 1 pending policy is recorded.
					Expect(len(item.Policies.PendingPolicies)).To(BeNumerically(">=", 1), "Expected at least 1 pending policy but got: %v", item.Policies.PendingPolicies)
					hit1 := flowlogs.FindPolicyInFlowLogs(item.Policies.PendingPolicies, policy1)
					Expect(string(hit1.Action())).To(Equal("deny"))

					// EnforcedPolicies should include just the __PROFILE__.
					Expect(len(item.Policies.EnforcedPolicies)).To(BeNumerically(">=", 1), "Expected at least 1 enforced policy but got: %v", item.Policies.EnforcedPolicies)
					flowlogs.ExpectProfileInFlowLogs(item.Policies.EnforcedPolicies, f.Namespace.Name)
				})

				AfterEach(func() {
					Expect(cli.Delete(context.TODO(), policy1)).ShouldNot(HaveOccurred())
					Expect(cli.Delete(context.TODO(), policy2)).ShouldNot(HaveOccurred())
					Expect(cli.Delete(context.TODO(), policy3)).ShouldNot(HaveOccurred())
					Expect(cli.Delete(context.TODO(), policy4)).ShouldNot(HaveOccurred())
				})
			})
		})

		Context("Test enforcing staged-policies", func() {
			var (
				tierObj *v3.Tier
				server  *conncheck.Server
				client1 *conncheck.Client
			)

			BeforeEach(func() {
				// create tier
				customTier = utils.GenerateRandomName("e2e-staged-tier")
				tierObj = v3.NewTier()
				tierObj.Name = customTier
				tierObj.Spec.Order = ptr.To[float64](200)
				Expect(cli.Create(context.TODO(), tierObj)).ToNot(HaveOccurred())

				// Create server
				server = conncheck.NewServer(utils.GenerateRandomName(serverPodNamePrefix), f.Namespace)
				client1 = conncheck.NewClient(clientPodNamePrefix, f.Namespace)
				checker.AddServer(server)
				checker.AddClient(client1)
				checker.Deploy()
			})

			AfterEach(func() {
				checker.Stop()

				// delete tier
				Expect(cli.Delete(context.TODO(), tierObj)).ShouldNot(HaveOccurred())
			})

			Describe("when enforcing StagedKubernetesNetworkPolicy", func() {
				It("enforce a deny policy", func() {
					// test connection from client to server - it should NOT fail
					checker.ExpectSuccess(client1, server.ClusterIP().Port(serverPort))
					checker.Execute()

					// create policy
					podSelector := metav1.LabelSelector{MatchLabels: server.Pod().Labels}
					policy := CreateStagedKubernetesNetworkPolicyIngressDeny("service-deny-in", server.Pod().Namespace, podSelector)
					Expect(cli.Create(context.TODO(), policy)).ShouldNot(HaveOccurred())

					// enforce the policy
					_, enforced := v3.ConvertStagedKubernetesPolicyToK8SEnforced(policy)
					Expect(cli.Create(context.TODO(), enforced)).ShouldNot(HaveOccurred())

					// test connection from client to server - it should fail
					checker.ResetExpectations()
					checker.ExpectFailure(client1, server.ClusterIP().Port(serverPort))
					checker.Execute()

					// delete policies
					// TODO: This should be deferred after create.
					Expect(cli.Delete(context.TODO(), policy)).ShouldNot(HaveOccurred())
					Expect(cli.Delete(context.TODO(), enforced)).ShouldNot(HaveOccurred())
				})
			})

			Describe("when enforcing StagedNetworkPolicy", func() {
				It("enforce a deny policy", func() {
					// test connection from client to server - it should NOT fail
					checker.ExpectSuccess(client1, server.ClusterIP().Port(serverPort))
					checker.Execute()

					// create policy
					ingress := []v3.Rule{{Action: v3.Deny}}
					selector := fmt.Sprintf("pod-name==\"%s\"", server.Name())
					order := 200.0
					policy := CreateStagedNetworkPolicy("service-deny-in", tierObj.Name, server.Pod().Namespace, order, selector, ingress, nil)
					Expect(cli.Create(context.TODO(), policy)).ShouldNot(HaveOccurred())

					// enforce the policy
					_, enforced := v3.ConvertStagedPolicyToEnforced(policy)
					Expect(cli.Create(context.TODO(), enforced)).ShouldNot(HaveOccurred())

					// test connection from client to server - it should fail
					checker.ResetExpectations()
					checker.ExpectFailure(client1, server.ClusterIP().Port(serverPort))
					checker.Execute()

					// delete policies
					Expect(cli.Delete(context.TODO(), policy)).ShouldNot(HaveOccurred())
					Expect(cli.Delete(context.TODO(), enforced)).ShouldNot(HaveOccurred())
				})
			})

			Describe("when enforcing StagedGlobalNetworkPolicy", func() {
				It("enforce a deny policy", func() {
					// test connection from client to server - it should NOT fail
					checker.ExpectSuccess(client1, server.ClusterIP().Port(serverPort))
					checker.Execute()

					// create policy
					ingress := []v3.Rule{{Action: v3.Deny}}
					selector := fmt.Sprintf("pod-name==\"%s\"", server.Name())
					order := 200.0
					policy := CreateStagedGlobalNetworkPolicy("service-deny-in", tierObj.Name, order, selector, ingress, nil)
					Expect(cli.Create(context.TODO(), policy)).ShouldNot(HaveOccurred())

					// enforce the policy
					_, enforced := v3.ConvertStagedGlobalPolicyToEnforced(policy)
					Expect(cli.Create(context.TODO(), enforced)).ShouldNot(HaveOccurred())

					// test connection from client to server - it should fail
					checker.ResetExpectations()
					checker.ExpectFailure(client1, server.ClusterIP().Port(serverPort))
					checker.Execute()

					// delete policies
					Expect(cli.Delete(context.TODO(), policy)).ShouldNot(HaveOccurred())
					Expect(cli.Delete(context.TODO(), enforced)).ShouldNot(HaveOccurred())
				})
			})
		})

		Context("Test staged-policies with network sets used in ", func() {
			var (
				tierObj *v3.Tier
				client1 *conncheck.Client
			)

			BeforeEach(func() {
				// create tier
				customTier = utils.GenerateRandomName("e2e-staged-tier")
				tierObj = v3.NewTier()
				tierObj.Name = customTier
				tierObj.Spec.Order = ptr.To[float64](200)
				Expect(cli.Create(context.TODO(), tierObj)).ToNot(HaveOccurred())

				// Create client pod using conncheck.
				client1 = conncheck.NewClient("clientpod", f.Namespace)
				checker.AddClient(client1)
				checker.Deploy()
			})

			AfterEach(func() {
				checker.Stop()
				Expect(cli.Delete(context.TODO(), tierObj)).ShouldNot(HaveOccurred())
			})

			Describe("StagedNetworkPolicy", func() {
				var (
					policyName   string
					stagedPolicy *v3.StagedNetworkPolicy
					networkSet   *v3.NetworkSet
				)

				BeforeEach(func() {
					// Create namespacesd networkset
					networkSet = v3.NewNetworkSet()
					networkSet.Name = "networkset-google"
					networkSet.Namespace = f.Namespace.Name
					networkSet.Labels = map[string]string{"destination": "google"}
					networkSet.Spec.Nets = []string{"142.251.215.228", "142.250.69.206"}
					err = cli.Create(context.TODO(), networkSet)
					Expect(err).ShouldNot(HaveOccurred())

					// create staged network policy
					policyName = "snp-deny-networkset"
					egress := []v3.Rule{{Action: v3.Deny, Destination: v3.EntityRule{Selector: "destination==\"google\""}}}
					selector := "all()"
					stagedPolicy = CreateStagedNetworkPolicy(
						policyName,
						tierObj.Name,
						client1.Pod().Namespace,
						100,
						selector,
						nil,
						egress,
					)
					Expect(cli.Create(context.TODO(), stagedPolicy)).ShouldNot(HaveOccurred())
				})

				AfterEach(func() {
					Expect(cli.Delete(context.TODO(), stagedPolicy)).ShouldNot(HaveOccurred())
					Expect(cli.Delete(context.TODO(), networkSet)).ShouldNot(HaveOccurred())
				})

				It("where clientpod connects to ip defined in networkset", func() {
					// curl ip defined in the networkset
					target := conncheck.NewTarget("142.251.215.228", "", conncheck.TCP)
					checker.ExpectSuccess(client1, target.Port(80))
					checker.Execute()

					// Get the relevant flow logs and check for the staged policy.
					flowLogs := fetchFlowlogs(esclient, client1.Pod().Namespace, "", client1.Pod().Name, "networkset-google", "src")
					flog := flowLogs[0]

					// PendingPolicies should include the staged policy defined above.
					msg := fmt.Sprintf("Expected 1 pending policies but got %d: %v", len(flog.Policies.PendingPolicies), flog.Policies.PendingPolicies)
					Expect(len(flog.Policies.PendingPolicies)).To(Equal(1), msg)
					flowlogs.ExpectPolicyInFlowLogs(flog.Policies.PendingPolicies, stagedPolicy)

					// EnforcedPolicies should have a single entry: the __PROFILE__
					msg = fmt.Sprintf("Expected 1 enforced policy but got %d: %v", len(flog.Policies.EnforcedPolicies), flog.Policies.EnforcedPolicies)
					Expect(len(flog.Policies.EnforcedPolicies)).To(Equal(1), msg)
					flowlogs.ExpectProfileInFlowLogs(flog.Policies.EnforcedPolicies, client1.Pod().Namespace)
				})
			})

			Describe("StagedGlobalNetworkPolicy", func() {
				var (
					policyName   string
					policy       *v3.StagedGlobalNetworkPolicy
					globalNetSet *v3.GlobalNetworkSet
				)
				BeforeEach(func() {
					globalNetSet = v3.NewGlobalNetworkSet()
					globalNetSet.Name = "global-networkset-microsoft"
					globalNetSet.Namespace = ""
					globalNetSet.Labels = map[string]string{"destination": "microsoft"}
					globalNetSet.Spec.Nets = []string{"23.59.156.241", "20.70.246.20"}

					err = cli.Create(context.TODO(), globalNetSet)
					Expect(err).ShouldNot(HaveOccurred())

					// create staged global network policy
					policyName = "snp-deny-globalnetworkset"
					egress := []v3.Rule{{Action: v3.Deny, Destination: v3.EntityRule{Selector: "destination==\"microsoft\""}}}
					policy = CreateStagedGlobalNetworkPolicy(
						policyName,
						tierObj.Name,
						100,
						"all()",
						nil,
						egress,
					)
					Expect(cli.Create(context.TODO(), policy)).ShouldNot(HaveOccurred())
				})

				AfterEach(func() {
					Expect(cli.Delete(context.TODO(), policy)).ShouldNot(HaveOccurred())
					Expect(cli.Delete(context.TODO(), globalNetSet)).ShouldNot(HaveOccurred())
				})

				It("where clientpod connects to ip defined in globalnetworkset", func() {
					// curl ip defined in the globalnetworkset. We expect it to fail as a bad request, but
					// the connection will be made and logged in flowlogs.
					target := conncheck.NewTarget("23.59.156.241", "", conncheck.TCP)
					checker.ExpectFailure(client1, target.Port(80))
					checker.Execute()

					flowLogs := fetchFlowlogs(esclient, client1.Pod().Namespace, "", client1.Pod().Name, "global-networkset-microsoft", "src")
					flog := flowLogs[0]

					// PendingPolicies should include the staged policy defined above.
					msg := fmt.Sprintf("Expected 1 pending policies but got %d: %v", len(flog.Policies.PendingPolicies), flog.Policies.PendingPolicies)
					Expect(len(flog.Policies.PendingPolicies)).To(Equal(1), msg)
					flowlogs.ExpectPolicyInFlowLogs(flog.Policies.PendingPolicies, policy)

					// EnforcedPolicies should have a single entry: the __PROFILE__
					msg = fmt.Sprintf("Expected 1 enforced policy but got %d: %v", len(flog.Policies.EnforcedPolicies), flog.Policies.EnforcedPolicies)
					Expect(len(flog.Policies.EnforcedPolicies)).To(Equal(1), msg)
					flowlogs.ExpectProfileInFlowLogs(flog.Policies.EnforcedPolicies, client1.Pod().Namespace)
				})
			})
		})
	})

func initializeSetup(f *framework.Framework, esURL string) *elastic.Client {
	esclient := elasticsearch.InitClient(f, esURL)

	cli, err := client.New(f.ClientConfig())
	Expect(err).NotTo(HaveOccurred())

	felixConfig := v3.NewFelixConfiguration()
	err = cli.Get(context.TODO(), ctrlclient.ObjectKey{Name: "default"}, felixConfig)
	Expect(err).NotTo(HaveOccurred())

	felixConfig.Spec.FlowLogsFlushInterval = &metav1.Duration{Duration: 10 * time.Second}

	err = cli.Update(context.TODO(), felixConfig)
	Expect(err).NotTo(HaveOccurred())

	return esclient
}

func fetchFlowlogs(esclient *elastic.Client, srcNamespace, dstNamespace, clientPodNamePrefix, serverPodNamePrefix, reporter string) []elasticsearch.FlowLog {
	var flowLogs []elasticsearch.FlowLog

	logQuery := elastic.NewBoolQuery()

	if srcNamespace != "" {
		logQuery.Must(elastic.NewTermsQuery("source_namespace", srcNamespace))
	}

	if dstNamespace != "" {
		logQuery.Must(elastic.NewTermsQuery("dest_namespace", dstNamespace))
	}

	if clientPodNamePrefix != "" {
		logQuery.Must(elastic.NewPrefixQuery("source_name_aggr", clientPodNamePrefix))
	}

	if serverPodNamePrefix != "" {
		logQuery.Must(elastic.NewPrefixQuery("dest_name_aggr", serverPodNamePrefix))
	}

	if reporter != "" {
		logQuery.Must(elastic.NewTermsQuery("reporter", reporter))
	}

	// Compile the query for logging.
	src, err := logQuery.Source()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	logrus.WithField("src", src).Info("Running flow log query")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// refresh indices for both single tenant and multi-tenant / single-index elastic deployments
	EventuallyWithOffset(1, func() error {
		result, err := esclient.Refresh("_all").Do(ctx)
		if err != nil {
			return err
		}
		if result.Shards.Failed != 0 {
			return fmt.Errorf("expected no failed shards when refreshing index but got %d", result.Shards.Failed)
		}
		if result.Shards.Successful == 0 {
			return fmt.Errorf("expected successful shard refresh but got none")
		}
		return nil
	}, 1*time.Minute, 5*time.Second).ShouldNot(HaveOccurred(), "Error refreshing elasticsearch index")

	EventuallyWithOffset(1, func() bool {
		queryResult := elasticsearch.SearchInEs(esclient, logQuery, elasticsearch.FlowlogsIndex)
		flowLogs = elasticsearch.GetFlowlogsFromESSearchResult(queryResult)
		return len(flowLogs) > 0
	}, 3*time.Minute, 5*time.Second).Should(BeTrue(), fmt.Sprintf("Failed to find flow logs matching query %s", src))

	ExpectWithOffset(1, len(flowLogs) > 0).To(BeTrue(), "Expected to find at least 1 flow log matching query")

	return flowLogs
}

// CreateStagedKubernetesNetworkPolicyAllow does not have an explicit Action: passing in a
// non-empty ingress / engress behaves as allow for the traffic selected by ingress / egress rules.
func CreateStagedKubernetesNetworkPolicyAllow(
	policyName, namespace string,
	podSelector metav1.LabelSelector,
	ingressRules []networkingv1.NetworkPolicyIngressRule,
	egressRules []networkingv1.NetworkPolicyEgressRule,
) *v3.StagedKubernetesNetworkPolicy {
	var policyType []networkingv1.PolicyType
	if ingressRules != nil {
		policyType = append(policyType, networkingv1.PolicyTypeIngress)
	}
	if egressRules != nil {
		policyType = append(policyType, networkingv1.PolicyTypeEgress)
	}
	policy := v3.NewStagedKubernetesNetworkPolicy()
	policy.ObjectMeta = metav1.ObjectMeta{Name: policyName, Namespace: namespace}
	policy.Spec = v3.StagedKubernetesNetworkPolicySpec{
		PodSelector: podSelector,
		Ingress:     ingressRules,
		Egress:      egressRules,
		PolicyTypes: policyType,
	}

	return policy
}
