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

			err error

			nameSpaceBaseName = "dns-staged-policy"
			f                 = utils.NewDefaultFramework(nameSpaceBaseName)

			checker conncheck.ConnectionTester
			client1 *conncheck.Client
			// tier
			customTier *v3.Tier
			order      = 10.0

			pfInfo *elasticsearch.PortForwardInfo
		)

		validateFlowLogs := func(clientName, destination, policyName string) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// refresh indices for both single tenant and multi-tenant / single-index elastic deployments
			result, err := esclient.Refresh("tigera_secure_ee_flows.*", "calico_flowlogs.*").Do(ctx)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result.Shards.Successful).ToNot(Equal(0))

			flowLogs := fetchDNSStagedFlowlogs(esclient, f.Namespace.Name, clientName, destination, "src", "tcp")
			Expect(flowLogs).NotTo(BeEmpty())

			for _, item := range flowLogs {
				hit := flowlogs.FindPolicyHitByName(item.Policies.PendingPolicies, policyName)
				Expect(string(hit.Action())).To(Equal("allow"))
				flowlogs.ExpectProfileInFlowLogs(item.Policies.EnforcedPolicies, f.Namespace.Name)
			}
		}

		BeforeEach(func() {
			By("Initializing...")
			// initialize controller-runtime client
			cli, err = cclient.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())

			// initialize esclient
			pfInfo = elasticsearch.PortForward()
			esclient = elasticsearch.InitClient(f, pfInfo.ElasticsearchURL)
			elasticsearch.WaitForElastic(esclient)

			// configure felix
			By("Updating felix configurations.")
			Eventually(func() error {
				return utils.UpdateFelixConfig(cli, func(spec *v3.FelixConfigurationSpec) {
					spec.FlowLogsFlushInterval = &metav1.Duration{Duration: 10 * time.Second}
					mode := v3.DNSPolicyModeDelayDNSResponse
					spec.DNSPolicyMode = &mode
				})
			}, 10*time.Second, 1*time.Second).Should(Succeed())

			DeferCleanup(func() {
				Eventually(func() error {
					return utils.UpdateFelixConfig(cli, func(spec *v3.FelixConfigurationSpec) {
						spec.FlowLogsFlushInterval = nil
						spec.DNSPolicyMode = nil
					})
				}, 10*time.Second, 1*time.Second).Should(Succeed())
			})

			By("Creating a custom tier.")
			// create custom tier
			customTierName := "dns-staged-tier"
			customTier = v3.NewTier()
			customTier.Name = customTierName
			customTier.Spec.Order = &order

			Expect(cli.Create(context.TODO(), customTier)).NotTo(HaveOccurred())

			checker = conncheck.NewConnectionTester(f)
			client1 = conncheck.NewClient("client", f.Namespace)
			checker.AddClient(client1)
			checker.Deploy()
		})

		AfterEach(func() {
			checker.Stop()
			pfInfo.Stop()

			// delete custom tier
			Expect(cli.Delete(context.TODO(), customTier)).ShouldNot(HaveOccurred())
		})

		Context("Test DNS in staged network policies ", func() {
			var stagedNetworkPolicy *v3.StagedNetworkPolicy

			BeforeEach(func() {
				By("Creating a staged network policy.")
				// create staged network policy
				selector := ""
				egress := []v3.Rule{
					createDNSAllowRule(),
				}

				stagedNetworkPolicy = CreateStagedNetworkPolicy("snp-with-networkset", customTier.Name,
					f.Namespace.Name, order, selector, nil, egress)
				Expect(cli.Create(context.TODO(), stagedNetworkPolicy)).NotTo(HaveOccurred())
			})

			AfterEach(func() {
				// delete staged network policy
				Expect(cli.Delete(context.TODO(), stagedNetworkPolicy)).ShouldNot(HaveOccurred())
			})

			It("Use domain name in a staged network policy", func() {
				domains := []string{"www.example.com"}

				By("Updating staged global network policy with destination domain: " + domains[0])
				// update the policy with egress domains
				stagedNetworkPolicy.Spec.Egress = append(stagedNetworkPolicy.Spec.Egress,
					createDestinationDomainsRule(v3.Allow, domains))

				Expect(cli.Update(context.TODO(), stagedNetworkPolicy)).NotTo(HaveOccurred())

				By("Connecting to domain: " + domains[0])
				for _, domain := range domains {
					checker.ExpectSuccess(client1, conncheck.NewDomainTarget(domain))
				}
				checker.Execute()

				By("Validating flowlogs.")
				validateFlowLogs(client1.Name(), "", stagedNetworkPolicy.Name)
			})

			It("Use networkset in a staged network policy", func() {
				domains := []string{"example.com"}
				networksetName := "ns-example"

				By("Creating a networkset: " + networksetName)
				// create networkset
				labels := map[string]string{"destination": "example"}

				networkset := v3.NewNetworkSet()
				networkset.Name = networksetName
				networkset.Namespace = f.Namespace.Name
				networkset.Labels = labels
				networkset.Spec.Nets = nil
				networkset.Spec.AllowedEgressDomains = domains

				err = cli.Create(context.TODO(), networkset)
				Expect(err).ShouldNot(HaveOccurred())

				By("Updating staged network policy with networkset selector.")
				// update the policy with referring network set in the egress rules
				stagedNetworkPolicy.Spec.Egress = append(stagedNetworkPolicy.Spec.Egress,
					createDestinationSelector(v3.Allow, "destination==\"example\""))

				Expect(cli.Update(context.TODO(), stagedNetworkPolicy)).NotTo(HaveOccurred())

				By("Connecting to domain: " + domains[0])
				for _, domain := range domains {
					checker.ExpectSuccess(client1, conncheck.NewDomainTarget(domain))
				}
				checker.Execute()

				// delete networkset
				Expect(cli.Delete(context.TODO(), networkset)).NotTo(HaveOccurred())

				By("Validating flowlogs.")
				validateFlowLogs(client1.Name(), "", stagedNetworkPolicy.Name)
			})
		})

		Context("Test DNS in staged global network policies ", func() {
			var stagedGlobalNetworkPolicy *v3.StagedGlobalNetworkPolicy
			BeforeEach(func() {
				// create staged global network policy
				selector := ""
				egress := []v3.Rule{
					createDNSAllowRule(),
				}

				stagedGlobalNetworkPolicy = CreateStagedGlobalNetworkPolicy("dns-sgnp", customTier.Name,
					order, selector, nil, egress)
				Expect(cli.Create(context.TODO(), stagedGlobalNetworkPolicy)).NotTo(HaveOccurred())
			})

			AfterEach(func() {
				// delete staged global network policy
				Expect(cli.Delete(context.TODO(), stagedGlobalNetworkPolicy)).ShouldNot(HaveOccurred())
			})

			It("Use domain name in a staged global network policy", func() {
				domains := []string{"www.google.com"}

				By("Updating staged global network policy with destination domain: " + domains[0])
				// update the policy with egress domains
				stagedGlobalNetworkPolicy.Spec.Egress = append(stagedGlobalNetworkPolicy.Spec.Egress,
					createDestinationDomainsRule(v3.Allow, domains))

				Expect(cli.Update(context.TODO(), stagedGlobalNetworkPolicy)).NotTo(HaveOccurred())

				By("Connecting to domain: " + domains[0])
				for _, domain := range domains {
					checker.ExpectSuccess(client1, conncheck.NewDomainTarget(domain))
				}
				checker.Execute()

				By("Validating flowlogs.")
				validateFlowLogs(client1.Name(), "", stagedGlobalNetworkPolicy.Name)
			})

			It("Use global networkset in a staged global network policy", func() {
				domains := []string{"google.com"}
				networksetName := "global-ns-ggl"

				By("Creating a global networkset: " + networksetName)
				// create global networkset
				networkset := v3.NewGlobalNetworkSet()
				networkset.Name = networksetName
				networkset.Labels = map[string]string{"destination": "global-ggl"}
				networkset.Spec.Nets = nil
				networkset.Spec.AllowedEgressDomains = domains

				err = cli.Create(context.TODO(), networkset)
				Expect(err).ShouldNot(HaveOccurred())

				By("Updating staged global network policy with networkset selector.")
				// update the policy with referring network set in the egress rules
				stagedGlobalNetworkPolicy.Spec.Egress = append(stagedGlobalNetworkPolicy.Spec.Egress,
					createDestinationSelector(v3.Allow, "destination=='global-ggl'"))

				Expect(cli.Update(context.TODO(), stagedGlobalNetworkPolicy)).NotTo(HaveOccurred())

				By("Connecting to domain: " + domains[0])
				for _, domain := range domains {
					checker.ExpectSuccess(client1, conncheck.NewDomainTarget(domain))
				}
				checker.Execute()

				// delete networkset
				Expect(cli.Delete(context.TODO(), networkset)).NotTo(HaveOccurred())

				By("Validating flowlogs.")
				validateFlowLogs(client1.Name(), networksetName, stagedGlobalNetworkPolicy.Name)
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

	dnsPort, err := numorstring.NamedPort("dns")
	if err != nil {
		panic(fmt.Sprintf("failed to create named port: %v", err))
	}

	return v3.Rule{
		Action:   v3.Allow,
		Protocol: &protocol,
		Destination: v3.EntityRule{
			Ports: []numorstring.Port{
				numorstring.SinglePort(53),
				// On OpenShift DNS is mapped to a named "dns" port, so allow that too.
				dnsPort,
			},
		},
	}
}

func fetchDNSStagedFlowlogs(esclient *elastic.Client, srcNamespace, clientPodNamePrefix, serverPodNamePrefix, reporter, protocol string) []elasticsearch.FlowLog {
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
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	logrus.WithField("src", src).Info("Running DNS staged flow log query")

	Eventually(func() bool {
		queryResult = elasticsearch.SearchInEs(esclient, logQuery, elasticsearch.FlowlogsIndex)
		flowLogs = elasticsearch.GetFlowlogsFromESSearchResult(queryResult)

		return len(flowLogs) > 0
	}, 5*time.Minute, 5*time.Second).Should(BeTrue())

	Expect(len(flowLogs) > 0).To(BeTrue())

	return flowLogs
}

