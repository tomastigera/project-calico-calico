// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package visibility

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/olivere/elastic/v7"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	"gopkg.in/yaml.v3"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	cclient "github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	esutil "github.com/projectcalico/calico/e2e/pkg/utils/elasticsearch"
	"github.com/projectcalico/calico/e2e/pkg/utils/externalnode"
	"github.com/projectcalico/calico/e2e/pkg/utils/flowlogs"
	"github.com/projectcalico/calico/e2e/pkg/utils/splunk"
)

// DESCRIPTION: Test Calico Enterprise flow logs for non-cluster-host.
// DOCS_URL: https://docs.tigera.io/calico-enterprise/latest/getting-started/bare-metal/about.
// PRECONDITIONS: non-cluster hosts have been created by banzai and non-cluster-hosts.yaml holds the information.

const nonClusterHostsYamlFile = "/non-cluster-hosts.yaml"

var (
	//go:embed test-manifests/logcollector-splunk.yaml
	logCollectorSplunkTemplate string

	//go:embed test-manifests/logcollector-default.yaml
	logCollectorDefault string

	//go:embed test-manifests/logcollector-splunk-non-cluster-patch.yaml
	logCollectorSplunkNonClusterOnlyPatch string
)

var _ = describe.EnterpriseDescribe(
	describe.WithTeam(describe.EV),
	describe.WithFeature("Non-Cluster-Host"),
	describe.WithCategory(describe.Visibility),
	describe.WithExternalNode(),
	describe.WithSerial(),
	"non-cluster host flow logs",
	func() {
		var (
			f = utils.NewDefaultFramework("non-cluster-host")

			cli        client.Client
			esclient   *elastic.Client
			host       nonClusterHost
			nodeClient *externalnode.Client
			server     *conncheck.Server
			target     conncheck.Target
			destIP     string
			destPort   int
			checker    conncheck.ConnectionTester
			pf         *esutil.PortForwardInfo
			originalFC *v3.FelixConfiguration
		)

		BeforeEach(func() {
			ctx := context.Background()

			// Check if non-cluster hosts configuration yaml file exists.
			if _, err := os.Stat(getNonClusterHostsFilePath()); os.IsNotExist(err) {
				Skip("Configuration yaml for non-cluster hosts not exists, skipping the test...")
			}

			var err error
			cli, err = cclient.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())

			// Save original FelixConfiguration for cleanup.
			Eventually(func() error {
				originalFC = v3.NewFelixConfiguration()
				return cli.Get(ctx, types.NamespacedName{Name: "default"}, originalFC)
			}, 10*time.Second, 1*time.Second).Should(Succeed())

			Eventually(func() error {
				return utils.UpdateFelixConfig(cli, func(spec *v3.FelixConfigurationSpec) {
					spec.FlowLogsFlushInterval = &metav1.Duration{Duration: 15 * time.Second}
				})
			}, 10*time.Second, 1*time.Second).Should(Succeed())

			DeferCleanup(func() {
				Eventually(func() error {
					return utils.UpdateFelixConfig(cli, func(spec *v3.FelixConfigurationSpec) {
						spec.FlowLogsFlushInterval = originalFC.Spec.FlowLogsFlushInterval
					})
				}, 10*time.Second, 1*time.Second).Should(Succeed())
			})

			// Get a node within the cluster.
			nodeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			nodes, err := e2enode.GetBoundedReadySchedulableNodes(nodeCtx, f.ClientSet, 1)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(nodes.Items).NotTo(BeEmpty(), "no schedulable nodes found")

			// Find the internal IP of the first node.
			for _, addr := range nodes.Items[0].Status.Addresses {
				if addr.Type == v1.NodeInternalIP {
					destIP = addr.Address
					break
				}
			}
			Expect(destIP).NotTo(BeEmpty(), "could not find InternalIP for node %s", nodes.Items[0].Name)

			By("getting and validating non-cluster hosts")
			hostsConfig := getNonClusterHosts()
			Expect(hostsConfig.Hosts).NotTo(BeEmpty(), "no non-cluster hosts configured; ensure non-cluster host configuration YAML defines at least one host")
			host = hostsConfig.Hosts[0]
			nodeClient = externalnode.NewClientManualConfig(host.IP, host.Key, host.User)

			By("creating a server pod with a NodePort service")
			checker = conncheck.NewConnectionTester(f)
			server = conncheck.NewServer("server", f.Namespace,
				conncheck.WithPorts(8080),
				conncheck.WithServerSvcCustomizer(
					func(svc *v1.Service) {
						svc.Spec.Type = v1.ServiceTypeNodePort
					},
				))
			checker.AddServer(server)
			checker.Deploy()
			DeferCleanup(func() { checker.Stop() })

			destPort = server.NodePortPort()
			target = server.NodePort(destIP)
			logrus.Infof("Created pod %v with NodePort service. Target: %s", server.Name(), target.Destination())

			By("initialising esclient and updating felix configuration for a shorter flow log flush interval")
			pf = esutil.PortForward()
			esclient = esutil.InitClient(f, pf.ElasticsearchURL)
			esutil.WaitForElastic(esclient)
			DeferCleanup(func() {
				if pf != nil {
					pf.Stop()
				}
			})

			// We need to wait for calico-service on non-cluster host to become ready since
			// it is restarted by felix configuration updates from last step.
			By("waiting for calico-node service to become ready after felix configuration update")
			Eventually(func() error {
				return nodeClient.TestCalicoServiceReady("calico-node")
			}, 2*time.Minute, 5*time.Second).ShouldNot(HaveOccurred())

			By("waiting for calico-fluent-bit service to become ready and forward logs to the cluster")
			Eventually(func() error {
				return nodeClient.TestCalicoServiceReady("calico-fluent-bit")
			}, 2*time.Minute, 5*time.Second).ShouldNot(HaveOccurred())
			Eventually(func() error {
				return nodeClient.TestFluentBitForwardLogs()
			}, 7*time.Minute, 5*time.Second).ShouldNot(HaveOccurred())

			By("validating host endpoint labels are set correctly")
			var hep v3.HostEndpoint
			err = cli.Get(ctx, types.NamespacedName{Name: host.Name}, &hep)
			Expect(err).NotTo(HaveOccurred())
			Expect(hep.ObjectMeta.Labels).To(HaveKeyWithValue("hostendpoint.projectcalico.org/type", "nonclusterhost"))
		})

		Context("Host to Service Flowlogs e2e", func() {
			It("Captures HTTP traffic from non-cluster host to a NodePort service with no policy applied", func() {
				err := testConnect(nodeClient, target)
				Expect(err).NotTo(HaveOccurred())

				By("waiting for flows.log file on the node")
				Eventually(func() error {
					return nodeClient.TestFlowLogFilePopulated()
				}, 30*time.Second, 5*time.Second).ShouldNot(HaveOccurred())

				By("validating flow logs pushed to elasticsearch have action as allow to node port", func() {
					validateNCHFlowLogs(esclient, hepNodePortQueryAggregation(host.Name, destPort),
						"projectcalico-default-allow", "__PROFILE__", "allow",
						[]string{"hostendpoint.projectcalico.org/type=nonclusterhost"})
				})
			})

			It("Captures HTTP traffic from non-cluster host to a NodePort service with deny egress policy applied", func() {
				err := testConnect(nodeClient, target)
				Expect(err).NotTo(HaveOccurred())

				By("waiting for flows.log file on the node")
				Eventually(func() error {
					return nodeClient.TestFlowLogFilePopulated()
				}, 30*time.Second, 5*time.Second).ShouldNot(HaveOccurred())

				protocol := numorstring.ProtocolFromString("TCP")
				gnp := &v3.GlobalNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "deny-egress"},
					Spec: v3.GlobalNetworkPolicySpec{
						Selector: "non-cluster-host == 'true'",
						Types:    []v3.PolicyType{v3.PolicyTypeEgress},
						Egress: []v3.Rule{
							{
								Action:      v3.Deny,
								Protocol:    &protocol,
								Destination: v3.EntityRule{Ports: []numorstring.Port{numorstring.SinglePort(uint16(destPort))}},
							},
							{Action: v3.Allow},
						},
					},
				}
				logrus.Infof("Creating deny egress policy for port %d", destPort)
				Expect(cli.Create(context.Background(), gnp)).NotTo(HaveOccurred())
				DeferCleanup(func() {
					Expect(cli.Delete(context.TODO(), gnp)).NotTo(HaveOccurred())
				})

				// Wait for the host to make a connection that is denied.
				Eventually(testConnect, 15*time.Second, 3*time.Second).WithArguments(nodeClient, target).Should(HaveOccurred())

				By("validating flow logs pushed to elasticsearch have action as deny to node port", func() {
					validateNCHFlowLogs(esclient, hepNodePortQuery(host.Name, host.Name, destIP, destPort),
						"default.deny-egress", "default", "deny", nil)
				})
			})
		})

		Context("Log archival of non-cluster host flows", func() {
			var splunkManager *splunk.Manager
			BeforeEach(func() {
				splunkManager = splunk.NewManager(f, logCollectorSplunkTemplate, logCollectorDefault)
				splunkManager.Deploy(context.Background())
			})
			AfterEach(func() {
				splunkManager.Cleanup()
			})

			It("Captures HTTP traffic in Splunk from non-cluster host to a NodePort service with no policy applied", func() {
				err := testConnect(nodeClient, target)
				Expect(err).NotTo(HaveOccurred())

				By("waiting for flows.log file on the node")
				Eventually(func() error {
					return nodeClient.TestFlowLogFilePopulated()
				}, 30*time.Second, 5*time.Second).ShouldNot(HaveOccurred())

				By("validating flow logs pushed to splunk have action as allow to node port", func() {
					spathQuery := fmt.Sprintf("search (source_name_aggr=\"%s\") AND (dest_port=\"%d\") AND (reporter=\"src\") AND (action=\"allow\") AND (\"policies.enforced_policies{}\"=\"*projectcalico-default-allow*\")", host.Name, destPort)
					Eventually(splunkManager.SearchLogs).
						WithArguments(fmt.Sprintf("search=search index=* %s earliest=-5m latest=now | spath | %s", f.Namespace.Name, spathQuery)).
						WithTimeout(5 * time.Minute).
						Should(BeNumerically(">", 0))
				})
			})

			It("Captures HTTP traffic in Splunk from non-cluster host to a NodePort service with deny egress policy applied", func() {
				err := testConnect(nodeClient, target)
				Expect(err).NotTo(HaveOccurred())

				By("waiting for flows.log file on the node")
				Eventually(func() error {
					return nodeClient.TestFlowLogFilePopulated()
				}, 30*time.Second, 5*time.Second).ShouldNot(HaveOccurred())

				protocol := numorstring.ProtocolFromString("TCP")
				gnp := &v3.GlobalNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "deny-egress"},
					Spec: v3.GlobalNetworkPolicySpec{
						Selector: "non-cluster-host == 'true'",
						Types:    []v3.PolicyType{v3.PolicyTypeEgress},
						Egress: []v3.Rule{
							{
								Action:      v3.Deny,
								Protocol:    &protocol,
								Destination: v3.EntityRule{Ports: []numorstring.Port{numorstring.SinglePort(uint16(destPort))}},
							},
							{Action: v3.Allow},
						},
					},
				}
				logrus.Infof("Creating deny egress policy for port %d", destPort)
				Expect(cli.Create(context.Background(), gnp)).NotTo(HaveOccurred())
				DeferCleanup(func() {
					Expect(cli.Delete(context.TODO(), gnp)).NotTo(HaveOccurred())
				})

				// Wait for the host to make a connection that is denied.
				Eventually(testConnect, 15*time.Second, 3*time.Second).WithArguments(nodeClient, target).Should(HaveOccurred())

				By("validating flow logs pushed to splunk have action as deny to node port", func() {
					spathQuery := fmt.Sprintf("search (source_name=\"%s\") AND (source_name_aggr=\"%s\") AND (dest_ip=\"%s\") AND (dest_port=\"%d\") AND (reporter=\"src\") AND (action=\"deny\") AND (\"policies.enforced_policies{}\"=\"*deny-egress*\")", host.Name, host.Name, destIP, destPort)
					Eventually(splunkManager.SearchLogs).
						WithArguments(fmt.Sprintf("search=search index=* %s earliest=-5m latest=now | spath | %s", f.Namespace.Name, spathQuery)).
						WithTimeout(5 * time.Minute).
						Should(BeNumerically(">", 0))
				})
			})

			It("Capture only HTTP traffic from non-cluster hosts in splunk when host scope is set to non-cluster only", func() {
				By("configuring log collector for non-cluster splunk logs only")
				splunkManager.ApplyLogCollectorPatch(logCollectorSplunkNonClusterOnlyPatch)

				err := testConnect(nodeClient, target)
				Expect(err).NotTo(HaveOccurred())

				By("waiting for flows.log file on the node")
				Eventually(func() error {
					return nodeClient.TestFlowLogFilePopulated()
				}, 30*time.Second, 5*time.Second).ShouldNot(HaveOccurred())

				By("validating flow logs pushed to splunk are only from non-cluster hosts", func() {
					// Wait for flow logs from the non-cluster host to appear
					nonClusterHostQuery := fmt.Sprintf("search (host=\"%s\") AND (action=*)", host.Name)
					Eventually(splunkManager.SearchLogs).
						WithArguments(fmt.Sprintf("search=search index=* %s earliest=-5m latest=now | spath | %s", f.Namespace.Name, nonClusterHostQuery)).
						WithTimeout(5 * time.Minute).
						Should(BeNumerically(">", 0))

					// Ensure that there are no flow logs from other hosts
					clusterHostQuery := fmt.Sprintf("search (host!=\"%s\") AND (action=*)", host.Name)
					Consistently(splunkManager.SearchLogs).
						WithArguments(fmt.Sprintf("search=search index=* %s earliest=-5m latest=now | spath | %s", f.Namespace.Name, clusterHostQuery)).
						WithTimeout(3 * time.Minute).
						Should(BeNumerically("==", 0))
				})
			})
		})
	})

// validateNCHFlowLogs polls Elasticsearch for flow logs matching the given query and validates
// that the enforced policy matches the expected name, tier, and action. If expectedSourceLabels
// is non-nil, it also asserts that the source labels contain the expected values.
func validateNCHFlowLogs(esclient *elastic.Client, esquery *elastic.BoolQuery, expectedName, expectedTier, expectedAction string, expectedSourceLabels []string) {
	var queryResult *elastic.SearchResult
	var flowLogs []esutil.FlowLog

	EventuallyWithOffset(1, func() error {
		logrus.Infof("Query %+v", esquery)
		queryResult = esutil.SearchInEs(esclient, esquery, esutil.FlowlogsIndex)
		flowLogs = esutil.GetFlowlogsFromESSearchResult(queryResult)
		if len(flowLogs) == 0 {
			return errors.New("no flow logs found")
		}
		return nil
	}, 120*time.Second, 5*time.Second).ShouldNot(HaveOccurred())

	ExpectWithOffset(1, flowLogs).NotTo(BeEmpty(), "expected flow logs from ES query but got none")
	for _, fl := range flowLogs {
		policies := fl.Policies.EnforcedPolicies
		ExpectWithOffset(1, policies).To(HaveLen(1), "expected exactly 1 enforced policy, got %d: %v", len(policies), policies)

		hit := flowlogs.FindPolicyHitByName(policies, expectedName)
		ExpectWithOffset(1, string(hit.Action())).To(Equal(expectedAction),
			"policy action was %q, expected %q", hit.Action(), expectedAction)
		ExpectWithOffset(1, hit.Tier()).To(Equal(expectedTier),
			"policy tier was %q, expected %q", hit.Tier(), expectedTier)

		ExpectWithOffset(1, fl.Action).To(Equal(expectedAction),
			"flow log action was %q, expected %q", fl.Action, expectedAction)

		for _, label := range expectedSourceLabels {
			ExpectWithOffset(1, fl.SourceLabels.Labels).To(ContainElement(label),
				"source labels %v missing expected label %q", fl.SourceLabels.Labels, label)
		}
	}
}

func hepNodePortQueryAggregation(host string, targetPort int) *elastic.BoolQuery {
	return esutil.BuildElasticQueryWithTerms(
		elastic.NewTermQuery("source_name_aggr", host),
		elastic.NewTermQuery("dest_port", targetPort),
		elastic.NewTermsQuery("reporter", "src"))
}

func hepNodePortQuery(hepName, host, targetIP string, targetPort int) *elastic.BoolQuery {
	return esutil.BuildElasticQueryWithTerms(
		elastic.NewTermQuery("source_name", hepName),
		elastic.NewTermQuery("source_name_aggr", host),
		elastic.NewTermQuery("dest_ip", targetIP),
		elastic.NewTermQuery("dest_port", targetPort),
		elastic.NewTermsQuery("reporter", "src"))
}

// nonClusterHost represents a single host's data from non-cluster-hosts.yaml file.
type nonClusterHost struct {
	Name       string `yaml:"name"`
	User       string `yaml:"user"`
	IP         string `yaml:"ip"`
	Key        string `yaml:"key"`
	InternalIP string `yaml:"internalIP"`
}

// hostsConfig represents the entire YAML structure with hosts.
type hostsConfig struct {
	Hosts []nonClusterHost `yaml:"hosts"`
}

func getNonClusterHostsFilePath() string {
	yamlFile := os.Getenv("NON_CLUSTER_HOSTS_YAML")
	if yamlFile == "" {
		return nonClusterHostsYamlFile
	}
	return yamlFile
}

func getNonClusterHosts() hostsConfig {
	fileContent, err := os.ReadFile(getNonClusterHostsFilePath())
	Expect(err).NotTo(HaveOccurred())

	var config hostsConfig
	err = yaml.Unmarshal(fileContent, &config)
	Expect(err).NotTo(HaveOccurred())

	// We would run e2e from a docker container. Key file has been mounted at /key.
	// If running in a local dev machine, the original key file path should be used.
	if _, err := os.Stat("/key"); !os.IsNotExist(err) {
		for i := range config.Hosts {
			config.Hosts[i].Key = "/key"
		}
	}

	for _, host := range config.Hosts {
		logrus.Infof("Host Name: %s, User: %s, IP: %s, SSH Key: %s, InternalIP: %s",
			host.Name, host.User, host.IP, host.Key, host.InternalIP)
	}

	return config
}

func testConnect(node *externalnode.Client, target conncheck.Target) error {
	shell := "/bin/sh"
	opt := "-c"
	cmd := fmt.Sprintf("curl -sS %s", target.Destination())
	output, err := node.Exec(shell, opt, cmd)
	if err != nil {
		return err
	}
	if !strings.Contains(output, "test-webserver") {
		return fmt.Errorf("expected 'test-webserver' in output, got: %s", output)
	}
	return nil
}
