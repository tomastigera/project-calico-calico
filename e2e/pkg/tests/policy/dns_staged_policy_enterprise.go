// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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
	"github.com/tigera/api/pkg/lib/numorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	cclient "github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/e2e/pkg/utils/elasticsearch"
	"github.com/projectcalico/calico/e2e/pkg/utils/flowlogs"
)

// DESCRIPTION: testing staged dns policy by creating various staged dns policies, generating traffic to the domains or
// networksets referred to in the staged dns policies, and finally validating the impact of the staged policies on the traffic in flowlogs.
// DOCS_URL: https://docs.tigera.io/calico-enterprise/latest/network-policy/domain-based-policy
// PRECONDITIONS: no specific precondition.
var _ = describe.EnterpriseDescribe(
	describe.WithTeam(describe.EV),
	describe.WithFeature("DNS-Staged-Policy"),
	describe.WithCategory(describe.Policy),
	describe.WithSerial(),
	"DNS staged policy",
	func() {
		var (
			cli      ctrlclient.Client
			esclient *elastic.Client

			namespaceBaseName = "dns-staged-policy"
			f                 = utils.NewDefaultFramework(namespaceBaseName)

			checker    conncheck.ConnectionTester
			client1    *conncheck.Client
			customTier *v3.Tier
			order      = 10.0

			pfInfo *elasticsearch.PortForwardInfo

			oldFlowLogsFlushInterval *metav1.Duration
			oldDNSPolicyMode         *v3.DNSPolicyMode
		)

		validateFlowLogs := func(clientName, destination, policyName string) {
			By("Validating flowlogs")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// refresh indices for both single tenant and multi-tenant / single-index elastic deployments
			result, err := esclient.Refresh("tigera_secure_ee_flows.*", "calico_flowlogs.*").Do(ctx)
			Expect(err).ShouldNot(HaveOccurred(), "failed to refresh elasticsearch indices")
			Expect(result.Shards.Successful).ToNot(Equal(0), "expected at least one successful shard refresh")

			flowLogs := fetchDNSStagedFlowlogs(esclient, f.Namespace.Name, clientName, destination, "src", "tcp")
			Expect(flowLogs).NotTo(BeEmpty(), "expected flow logs to be non-empty")

			for _, item := range flowLogs {
				hit := flowlogs.FindPolicyHitByName(item.Policies.PendingPolicies, policyName)
				Expect(string(hit.Action())).To(Equal("allow"), "expected policy hit action to be allow")
				flowlogs.ExpectProfileInFlowLogs(item.Policies.EnforcedPolicies, f.Namespace.Name)
			}
		}

		BeforeEach(func() {
			By("Initializing...")
			var err error
			cli, err = cclient.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred(), "failed to create controller-runtime client")

			pfInfo = elasticsearch.PortForward()
			DeferCleanup(func() { pfInfo.Stop() })

			esclient = elasticsearch.InitClient(f, pfInfo.ElasticsearchURL)
			elasticsearch.WaitForElastic(esclient)

			By("Updating felix configurations.")
			ctx := context.TODO()
			var originalFC *v3.FelixConfiguration
			Eventually(func() error {
				originalFC = v3.NewFelixConfiguration()
				return cli.Get(ctx, types.NamespacedName{Name: "default"}, originalFC)
			}, 10*time.Second, 1*time.Second).Should(Succeed())

			oldFlowLogsFlushInterval = originalFC.Spec.FlowLogsFlushInterval
			oldDNSPolicyMode = originalFC.Spec.DNSPolicyMode

			Eventually(func() error {
				return utils.UpdateFelixConfig(cli, func(spec *v3.FelixConfigurationSpec) {
					spec.FlowLogsFlushInterval = &metav1.Duration{Duration: 10 * time.Second}
					spec.DNSPolicyMode = ptr.To(v3.DNSPolicyModeDelayDNSResponse)
				})
			}, 10*time.Second, 1*time.Second).Should(Succeed())

			DeferCleanup(func() {
				Eventually(func() error {
					return utils.UpdateFelixConfig(cli, func(spec *v3.FelixConfigurationSpec) {
						spec.FlowLogsFlushInterval = oldFlowLogsFlushInterval
						spec.DNSPolicyMode = oldDNSPolicyMode
					})
				}, 10*time.Second, 1*time.Second).Should(Succeed())
			})

			By("Creating a custom tier.")
			customTier = v3.NewTier()
			customTier.Name = utils.GenerateRandomName("dns-staged-tier")
			customTier.Spec.Order = &order

			Expect(cli.Create(context.TODO(), customTier)).NotTo(HaveOccurred(), "failed to create custom tier")
			DeferCleanup(func() {
				Expect(cli.Delete(context.TODO(), customTier)).NotTo(HaveOccurred(), "failed to delete custom tier")
			})

			checker = conncheck.NewConnectionTester(f)
			client1 = conncheck.NewClient("client", f.Namespace)
			checker.AddClient(client1)
			checker.Deploy()
			DeferCleanup(func() { checker.Stop() })
		})

		Context("Test DNS in staged network policies ", func() {
			var stagedNetworkPolicy *v3.StagedNetworkPolicy

			BeforeEach(func() {
				selector := ""
				egress := []v3.Rule{
					createDNSAllowRule(),
				}

				stagedNetworkPolicy = CreateStagedNetworkPolicy(
					"snp-with-networkset", customTier.Name,
					f.Namespace.Name, order, selector, nil, egress,
				)
				Expect(cli.Create(context.TODO(), stagedNetworkPolicy)).NotTo(
					HaveOccurred(), "failed to create staged network policy",
				)
				DeferCleanup(func() {
					Expect(cli.Delete(context.TODO(), stagedNetworkPolicy)).NotTo(
						HaveOccurred(), "failed to delete staged network policy",
					)
				})
			})

			It("should use domain name in a staged network policy", func() {
				domain := "www.example.com"

				stagedNetworkPolicy.Spec.Egress = append(
					stagedNetworkPolicy.Spec.Egress,
					createDestinationDomainsRule(v3.Allow, []string{domain}),
				)
				Expect(cli.Update(context.TODO(), stagedNetworkPolicy)).NotTo(
					HaveOccurred(), "failed to update staged network policy with domain",
				)

				checker.ExpectSuccess(client1, conncheck.NewDomainTarget(domain))
				checker.Execute()

				validateFlowLogs(client1.Name(), "", stagedNetworkPolicy.Name)
			})

			It("should use networkset in a staged network policy", func() {
				domains := []string{"example.com"}
				networksetName := "ns-example"
				labels := map[string]string{"destination": "example"}

				networkset := v3.NewNetworkSet()
				networkset.Name = networksetName
				networkset.Namespace = f.Namespace.Name
				networkset.Labels = labels
				networkset.Spec.Nets = nil
				networkset.Spec.AllowedEgressDomains = domains

				Expect(cli.Create(context.TODO(), networkset)).NotTo(
					HaveOccurred(), "failed to create network set",
				)
				DeferCleanup(func() {
					Expect(cli.Delete(context.TODO(), networkset)).NotTo(
						HaveOccurred(), "failed to delete network set",
					)
				})

				stagedNetworkPolicy.Spec.Egress = append(
					stagedNetworkPolicy.Spec.Egress,
					createDestinationSelector(v3.Allow, "destination==\"example\""),
				)
				Expect(cli.Update(context.TODO(), stagedNetworkPolicy)).NotTo(
					HaveOccurred(), "failed to update staged network policy with networkset selector",
				)

				checker.ExpectSuccess(client1, conncheck.NewDomainTarget("example.com"))
				checker.Execute()

				validateFlowLogs(client1.Name(), "", stagedNetworkPolicy.Name)
			})
		})

		Context("Test DNS in staged global network policies ", func() {
			var stagedGlobalNetworkPolicy *v3.StagedGlobalNetworkPolicy

			BeforeEach(func() {
				selector := ""
				egress := []v3.Rule{
					createDNSAllowRule(),
				}

				stagedGlobalNetworkPolicy = CreateStagedGlobalNetworkPolicy(
					"dns-sgnp", customTier.Name,
					order, selector, nil, egress,
				)
				Expect(cli.Create(context.TODO(), stagedGlobalNetworkPolicy)).NotTo(
					HaveOccurred(), "failed to create staged global network policy",
				)
				DeferCleanup(func() {
					Expect(cli.Delete(context.TODO(), stagedGlobalNetworkPolicy)).NotTo(
						HaveOccurred(), "failed to delete staged global network policy",
					)
				})
			})

			It("should use domain name in a staged global network policy", func() {
				domain := "www.google.com"

				stagedGlobalNetworkPolicy.Spec.Egress = append(
					stagedGlobalNetworkPolicy.Spec.Egress,
					createDestinationDomainsRule(v3.Allow, []string{domain}),
				)
				Expect(cli.Update(context.TODO(), stagedGlobalNetworkPolicy)).NotTo(
					HaveOccurred(), "failed to update staged global network policy with domain",
				)

				checker.ExpectSuccess(client1, conncheck.NewDomainTarget(domain))
				checker.Execute()

				validateFlowLogs(client1.Name(), "", stagedGlobalNetworkPolicy.Name)
			})

			It("should use global networkset in a staged global network policy", func() {
				domains := []string{"google.com"}
				globalNetworkSetName := utils.GenerateRandomName("global-ns-ggl")

				networkset := v3.NewGlobalNetworkSet()
				networkset.Name = globalNetworkSetName
				networkset.Labels = map[string]string{"destination": "global-ggl"}
				networkset.Spec.Nets = nil
				networkset.Spec.AllowedEgressDomains = domains

				Expect(cli.Create(context.TODO(), networkset)).NotTo(
					HaveOccurred(), "failed to create global network set",
				)
				DeferCleanup(func() {
					Expect(cli.Delete(context.TODO(), networkset)).NotTo(
						HaveOccurred(), "failed to delete global network set",
					)
				})

				stagedGlobalNetworkPolicy.Spec.Egress = append(
					stagedGlobalNetworkPolicy.Spec.Egress,
					createDestinationSelector(v3.Allow, "destination=='global-ggl'"),
				)
				Expect(cli.Update(context.TODO(), stagedGlobalNetworkPolicy)).NotTo(
					HaveOccurred(), "failed to update staged global network policy with networkset selector",
				)

				checker.ExpectSuccess(client1, conncheck.NewDomainTarget("google.com"))
				checker.Execute()

				validateFlowLogs(client1.Name(), globalNetworkSetName, stagedGlobalNetworkPolicy.Name)
			})
		})
	})

func createDestinationDomainsRule(action v3.Action, destinationDomains []string) v3.Rule {
	return v3.Rule{
		Action: action,
		Destination: v3.EntityRule{
			Domains: destinationDomains,
		},
	}
}

func createDestinationSelector(action v3.Action, selector string) v3.Rule {
	return v3.Rule{
		Action: action,
		Destination: v3.EntityRule{
			Selector: selector,
		},
	}
}

func createDNSAllowRule() v3.Rule {
	protocol := numorstring.ProtocolFromString("UDP")

	// On OpenShift DNS is mapped to a named "dns" port, so allow that too.
	dnsPort, err := numorstring.NamedPort("dns")
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "failed to create named dns port")

	return v3.Rule{
		Action:   v3.Allow,
		Protocol: &protocol,
		Destination: v3.EntityRule{
			Ports: []numorstring.Port{
				numorstring.SinglePort(53),
				dnsPort,
			},
		},
	}
}

func fetchDNSStagedFlowlogs(
	esclient *elastic.Client,
	srcNamespace, clientPodNamePrefix, serverPodNamePrefix, reporter, protocol string,
) []elasticsearch.FlowLog {
	var queryResult *elastic.SearchResult
	var flowLogs []elasticsearch.FlowLog

	logQuery := elastic.NewBoolQuery()

	if srcNamespace != "" {
		logQuery.Must(elastic.NewTermsQuery("source_namespace", srcNamespace))
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

	if protocol != "" {
		logQuery.Must(elastic.NewTermsQuery("proto", protocol))
	}

	// Compile the query for logging.
	src, err := logQuery.Source()
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "failed to compile flow log query")
	logrus.WithField("src", src).Info("Running DNS staged flow log query")

	Eventually(func() error {
		queryResult = elasticsearch.SearchInEs(esclient, logQuery, elasticsearch.FlowlogsIndex)
		flowLogs = elasticsearch.GetFlowlogsFromESSearchResult(queryResult)
		if len(flowLogs) == 0 {
			return fmt.Errorf("no flow logs found matching query %+v", src)
		}
		return nil
	}, 2*time.Minute, 5*time.Second).Should(Succeed())

	return flowLogs
}
