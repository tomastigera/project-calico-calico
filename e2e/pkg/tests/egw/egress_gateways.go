// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package egw

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	uuid2 "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/e2e/pkg/utils/externalnode"
)

const (
	shellBash       = "/bin/bash"
	shellCmdOpt     = "-c"
	egressGatewayNS = "calico-egress" // Expect banzai to populate the NS with a couple of egress gateways.
	pullSecret      = "tigera-pull-secret"
)

func findNodeMatchingFilter(f *framework.Framework, filterFn func(node *v1.Node) bool) *v1.Node {
	nodes, err := e2enode.GetReadySchedulableNodes(context.Background(), f.ClientSet)
	Expect(err).NotTo(HaveOccurred())
	Expect(len(nodes.Items)).To(BeNumerically(">=", 2),
		"Test requires at least 2 ready nodes")
	for _, n := range nodes.Items {
		n := n
		if filterFn(&n) {
			return &n
		}
	}
	return nil
}

func deleteAllPodsInNS(f *framework.Framework) {
	if f.Namespace == nil {
		return
	}
	logrus.Infof("Deleting all pods in NS: %s", f.Namespace.Name)
	podClient := e2epod.NewPodClient(f)
	pods, err := podClient.List(context.Background(), metav1.ListOptions{})
	Expect(err).NotTo(HaveOccurred())
	err = podClient.DeleteCollection(context.Background(), metav1.DeleteOptions{}, metav1.ListOptions{})
	Expect(err).NotTo(HaveOccurred())
	for _, p := range pods.Items {
		Expect(e2epod.WaitForPodNotFoundInNamespace(context.Background(), f.ClientSet, p.Name, p.Namespace, 60*time.Second)).To(Succeed(), "wait for pod %q to disappear", p.Name)
	}
	logrus.Infof("Deleted all pods in NS: %s", f.Namespace.Name)
}

// getSourceIPFromNGINXLogs SSHes to the external node, greps the NGINX access log for the
// given UUID, and returns the source IP from the matching log line.
func getSourceIPFromNGINXLogs(extClient *externalnode.Client, uuid string) string {
	var out string
	EventuallyWithOffset(2, func() string {
		out, _ = extClient.ExecTimeout(10, shellBash, shellCmdOpt, fmt.Sprintf("grep %s /var/log/nginx/access.log", uuid))
		return out
	}, "30s").Should(ContainSubstring(uuid),
		fmt.Sprintf("Unable to find NGINX access log matching UUID %s", uuid))
	// NGINX log line format:
	//   100.64.1.147 - - [04/Nov/2021:16:29:51 +0000] "GET /?<uuid> HTTP/1.1" 200 ...
	return strings.Split(out, " ")[0]
}

// connectToNGINXAndGetSourceIP makes an HTTP request from the client pod to the external
// node's NGINX server and returns the source IP seen by NGINX. The filePath can be empty for
// the index page or "large.txt" for the large file download.
func connectToNGINXAndGetSourceIP(
	checker conncheck.ConnectionTester,
	cc *conncheck.Client,
	extNode *externalnode.Client,
	extIP string,
	filePath string,
	timeout string,
) string {
	uuid := uuid2.NewV4().String()
	target := conncheck.NewDomainTarget(fmt.Sprintf("http://%s/%s?%s", extIP, filePath, uuid))
	EventuallyWithOffset(2, func() error {
		_, err := checker.Connect(cc, target)
		return err
	}, timeout, "3s").ShouldNot(HaveOccurred(),
		"Failed to download %s from NGINX on external node", filePath)
	return getSourceIPFromNGINXLogs(extNode, uuid)
}

// expectGatewaySourceIP makes an HTTP request from the client to the external node's NGINX
// server and verifies the source IP in NGINX logs matches the expected gateway pod IP.
func expectGatewaySourceIP(
	checker conncheck.ConnectionTester,
	cc *conncheck.Client,
	extNode *externalnode.Client,
	extIP string,
	gatewayPod *v1.Pod,
	filePath string,
) {
	clientPod := cc.Pod()
	By(fmt.Sprintf("checking that pod %s node=%s goes via gateway %s (%s) node=%s",
		clientPod.Name, clientPod.Spec.NodeName, gatewayPod.Name, gatewayPod.Status.PodIP, gatewayPod.Spec.NodeName))

	timeout := "15s"
	if filePath == "large.txt" {
		timeout = "60s"
	}
	sourceIP := connectToNGINXAndGetSourceIP(checker, cc, extNode, extIP, filePath, timeout)
	ExpectWithOffset(1, sourceIP).To(Equal(gatewayPod.Status.PodIP),
		fmt.Sprintf("Expected pod %s node=%s to go via gateway %s (%s) node=%s, but source IP was %s",
			clientPod.Name, clientPod.Spec.NodeName, gatewayPod.Name, gatewayPod.Status.PodIP, gatewayPod.Spec.NodeName, sourceIP))
}

// expectElasticIP makes an HTTPS request to api.ipify.org and verifies the returned
// public IP matches one of the gateway's elastic IPs.
func expectElasticIP(
	checker conncheck.ConnectionTester,
	cc *conncheck.Client,
	gatewayPod *v1.Pod,
) {
	clientPod := cc.Pod()
	eipAnnot := gatewayPod.Annotations["cni.projectcalico.org/awsElasticIPs"]
	By(fmt.Sprintf("checking that pod %s node=%s goes via gateway %s elastic IP (%s) node=%s",
		clientPod.Name, clientPod.Spec.NodeName, gatewayPod.Name, eipAnnot, gatewayPod.Spec.NodeName))

	var expectedIPs []net.IP
	err := json.Unmarshal([]byte(eipAnnot), &expectedIPs)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(),
		"Failed to parse cni.projectcalico.org/awsElasticIPs annotation (%q) on pod %s", eipAnnot, gatewayPod.Name)
	ExpectWithOffset(1, expectedIPs).NotTo(HaveLen(0),
		"Gateway pod %s has empty elastic IP list", gatewayPod.Name)

	expectExternalConnectivityWithElasticIP(checker, cc, expectedIPs)
}

// checkConnectivityViaGateway verifies connectivity through an egress gateway by checking
// the small index page, the large file download, and (if configured) the elastic IP.
func checkConnectivityViaGateway(
	checker conncheck.ConnectionTester,
	cc *conncheck.Client,
	gatewayPod *v1.Pod,
	extClient *externalnode.Client,
	extIP string,
) {
	By("Getting small index page from NGINX server...")
	expectGatewaySourceIP(checker, cc, extClient, extIP, gatewayPod, "")
	By("Getting large file from NGINX server...")
	expectGatewaySourceIP(checker, cc, extClient, extIP, gatewayPod, "large.txt")

	if gatewayPod.Annotations["cni.projectcalico.org/awsElasticIPs"] != "" {
		By("Accessing external service via elastic IP")
		expectElasticIP(checker, cc, gatewayPod)
	}
}

// expectExternalConnectivityWithElasticIP checks connectivity to an external IP echo service,
// which returns the IP address that it sees as the source. Checks that the IP is one of the expectedIPs.
// Returns the source IP seen by the external service.
func expectExternalConnectivityWithElasticIP(
	checker conncheck.ConnectionTester,
	cc *conncheck.Client,
	expectedIPs []net.IP,
) net.IP {
	clientPod := cc.Pod()
	By(fmt.Sprintf("checking that pod %s node=%s has connectivity with its elastic IP",
		clientPod.Name, clientPod.Spec.NodeName))

	ipifyTarget := conncheck.NewDomainTarget("https://api.ipify.org")
	var addr net.IP
	EventuallyWithOffset(1, func() error {
		out, err := checker.Connect(cc, ipifyTarget)
		if err != nil {
			return fmt.Errorf("failed to connect from pod %s to ipify: %w", clientPod.Name, err)
		}
		addr = net.ParseIP(strings.TrimSpace(out))
		if addr == nil {
			return fmt.Errorf("failed to parse %q as an IP", out)
		}
		for _, exp := range expectedIPs {
			if exp.Equal(addr) {
				return nil
			}
		}
		/* Long timeout because AWS updates can be slow. */
		return fmt.Errorf("returned IP %v wasn't in the expected list %v", addr, expectedIPs)
	}, "60s", "3s").ShouldNot(HaveOccurred())
	return addr
}

func findGWPod(gatewayPods map[string]v1.Pod, color string) *v1.Pod {
	gp, ok := gatewayPods[color]
	ExpectWithOffset(1, ok).To(BeTrue(), "no gateway pod found with color %q", color)
	return &gp
}

func randomGatewayPod(gatewayPods map[string]v1.Pod) *v1.Pod {
	for _, gp := range gatewayPods {
		return &gp
	}
	framework.Fail("no gateway pods available", 1)
	return nil
}

func findPodAZ(f *framework.Framework, pod *v1.Pod) string {
	podsNode, err := f.ClientSet.CoreV1().Nodes().Get(context.Background(), pod.Spec.NodeName, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred())
	podsAZ := podsNode.Labels["topology.kubernetes.io/zone"]
	Expect(podsAZ).NotTo(BeEmpty(), "Node missing expected topology.kubernetes.io/zone label")
	return podsAZ
}

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("EgressGateway"),
	describe.WithCategory(describe.Networking),
	describe.WithExternalNode(),
	"Egress Gateway",
	func() {
		f := utils.NewDefaultFramework("egress-gateway")

		var cli ctrlclient.Client
		var gatewayPods map[string]v1.Pod
		var extNode *externalnode.Client
		var checker conncheck.ConnectionTester

		BeforeEach(func() {
			checker = conncheck.NewConnectionTester(f)

			var err error
			cli, err = client.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred(), "Failed to get Calico client")

			// Banzai sets up a pair of egress gateways for us. Find them.
			gatewayPods = map[string]v1.Pod{}
			pods, err := f.ClientSet.CoreV1().Pods(egressGatewayNS).List(context.Background(), metav1.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			for _, p := range pods.Items {
				if p.GetLabels()["egress-code"] != "" {
					logrus.Infof("Found egress gateway pod %s on node %s with IP %s",
						p.Name, p.Spec.NodeName, p.Status.PodIP)
					gatewayPods[p.GetLabels()["egress-code"]] = p
				}
			}
			if len(gatewayPods) == 0 {
				Skip("No egress gateway pods configured, unable to run egress gateway tests")
			}

			// Sanity check that the expected gateways are there.
			Expect(len(gatewayPods)).To(BeNumerically(">=", 2), "expected >=2 egress gateway pods")

			extNode = externalnode.NewClient()

			extNode.InstallNGINX()
		})

		AfterEach(func() {
			checker.Stop()
			// Since we use resource reservations to claim AWS IPs, it's important that we wait for pods to fully disappear
			// between tests.  Otherwise, we can have a deleted pod claiming a resource (which is a problem for
			// the "should handle the maximum number of pods per node" test).
			deleteAllPodsInNS(f)
		})

		It("should route egress traffic via egress gateway on same node", Label("RunsOnAWS"), func() {
			gatewayPod := randomGatewayPod(gatewayPods)
			cc := conncheck.NewClient(fmt.Sprintf("%s-client", gatewayPod.Labels["egress-code"]), f.Namespace,
				conncheck.WithClientCustomizer(func(pod *v1.Pod) {
					pod.Spec.NodeName = gatewayPod.Spec.NodeName
					pod.Annotations = map[string]string{
						"egress.projectcalico.org/selector":          fmt.Sprintf(`egress-code == "%s"`, gatewayPod.Labels["egress-code"]),
						"egress.projectcalico.org/namespaceSelector": fmt.Sprintf(`projectcalico.org/name == "%s"`, egressGatewayNS),
					}
				}),
			)
			checker.AddClient(cc)
			checker.Deploy()
			checkConnectivityViaGateway(checker, cc, gatewayPod, extNode, extNode.IP())
		})

		It("should route egress traffic via egress gateway on different node (same Region)", func() {
			gatewayPod := randomGatewayPod(gatewayPods)
			var nodeToUse *v1.Node
			if gatewayPod.Annotations["cni.projectcalico.org/awsElasticIPs"] == "" {
				// Azure cluster, the annotation is present only on AWS
				// Find a node in the same region
				nodeToUse = findNodeMatchingFilter(f, func(node *v1.Node) bool {
					return node.Name != gatewayPod.Spec.NodeName
				})
			} else if gatewayPod.Annotations["cni.projectcalico.org/awsElasticIPs"] != "" {
				// AWS cluster
				// Figure out the AZ of the gateway pod.
				gatewayPodsAZ := findPodAZ(f, gatewayPod)

				// Find a node in the same AZ that is _not_ the gateway's node.
				nodeToUse = findNodeMatchingFilter(f, func(node *v1.Node) bool {
					return node.Labels["topology.kubernetes.io/zone"] == gatewayPodsAZ &&
						node.Name != gatewayPod.Spec.NodeName
				})
			}
			Expect(nodeToUse).NotTo(BeNil(), "Couldn't find a second node in the same AZ/region as the gateway pod")
			cc := conncheck.NewClient(fmt.Sprintf("%s-client", gatewayPod.Labels["egress-code"]), f.Namespace,
				conncheck.WithClientCustomizer(func(pod *v1.Pod) {
					pod.Spec.NodeName = nodeToUse.Name
					pod.Annotations = map[string]string{
						"egress.projectcalico.org/selector":          fmt.Sprintf(`egress-code == "%s"`, gatewayPod.Labels["egress-code"]),
						"egress.projectcalico.org/namespaceSelector": fmt.Sprintf(`projectcalico.org/name == "%s"`, egressGatewayNS),
					}
				}),
			)
			checker.AddClient(cc)
			checker.Deploy()
			checkConnectivityViaGateway(checker, cc, gatewayPod, extNode, extNode.IP())
		})

		It("should route egress traffic via egress gateway on different node (different AZ)", Label("RunsOnAWS"), func() {
			gatewayPod := randomGatewayPod(gatewayPods)

			// Figure out the AZ of the gateway pod.
			gatewayPodsAZ := findPodAZ(f, gatewayPod)

			// Find a node in a different AZ.
			nodeToUse := findNodeMatchingFilter(f, func(node *v1.Node) bool {
				nodeAZ := node.Labels["topology.kubernetes.io/zone"]
				return nodeAZ != gatewayPodsAZ && nodeAZ != ""
			})
			if nodeToUse == nil {
				// Many configurations we run only use one AZ, skip if we can't find a valid node.
				Skip("Test requires cluster spanning multiple AZs")
			}

			cc := conncheck.NewClient(fmt.Sprintf("%s-client", gatewayPod.Labels["egress-code"]), f.Namespace,
				conncheck.WithClientCustomizer(func(pod *v1.Pod) {
					pod.Spec.NodeName = nodeToUse.Name
					pod.Annotations = map[string]string{
						"egress.projectcalico.org/selector":          fmt.Sprintf(`egress-code == "%s"`, gatewayPod.Labels["egress-code"]),
						"egress.projectcalico.org/namespaceSelector": fmt.Sprintf(`projectcalico.org/name == "%s"`, egressGatewayNS),
					}
				}),
			)
			checker.AddClient(cc)
			checker.Deploy()
			checkConnectivityViaGateway(checker, cc, gatewayPod, extNode, extNode.IP())
		})

		It("should route egress traffic via different egress gateways based on destination", func() {
			extClientIPs := extNode.IPs()
			Expect(len(extClientIPs)).Should(BeNumerically(">", 2), "External node needs at least 3 IPs for dest based routing tests")

			egwPolicy := v3.NewEgressGatewayPolicy()
			egwPolicy.Name = "egw-policy"
			egwPolicy.Spec.Rules = []v3.EgressGatewayRule{
				{
					Description: "Gateway to the first IP of external node",
					Destination: &v3.EgressGatewayPolicyDestinationSpec{
						CIDR: fmt.Sprintf("%s/32", extClientIPs[0]),
					},
					Gateway: &v3.EgressSpec{
						NamespaceSelector: "projectcalico.org/name == 'calico-egress'",
						Selector:          "egress-code == 'blue'",
					},
				},
				{
					Description: "Gateway to the second IP of external node",
					Destination: &v3.EgressGatewayPolicyDestinationSpec{
						CIDR: fmt.Sprintf("%s/32", extClientIPs[1]),
					},
					Gateway: &v3.EgressSpec{
						NamespaceSelector: "all()",
						Selector:          "egress-code == 'blue'",
					},
				},
				{
					Description: "default gateway like to the 3rd IP of external node",
					Gateway: &v3.EgressSpec{
						NamespaceSelector: "projectcalico.org/name == 'calico-egress'",
						Selector:          "egress-code == 'red'",
					},
				},
			}
			err := cli.Create(context.Background(), egwPolicy)
			Expect(err).NotTo(HaveOccurred(), "Failed to create egw policy")
			defer func() {
				err := cli.Delete(context.Background(), egwPolicy)
				Expect(err).NotTo(HaveOccurred())
			}()

			// Find a node in the same region
			gwRed := findGWPod(gatewayPods, "red")
			nodeToUse := findNodeMatchingFilter(f, func(node *v1.Node) bool {
				return node.Name != gwRed.Spec.NodeName
			})
			// Very unexpected to have only one node in the AZ; fail in that case...
			Expect(nodeToUse).NotTo(BeNil(), "Couldn't find a second node in the same AZ as the gateway pod")

			cc := conncheck.NewClient("client", f.Namespace,
				conncheck.WithClientCustomizer(func(pod *v1.Pod) {
					pod.Spec.NodeName = nodeToUse.Name
					pod.Annotations = map[string]string{
						"egress.projectcalico.org/egressGatewayPolicy": "egw-policy",
					}
				}),
			)
			checker.AddClient(cc)
			checker.Deploy()
			gwBlue := findGWPod(gatewayPods, "blue")

			By("checking access to the 1st IP of external node via gateway blue")
			checkConnectivityViaGateway(checker, cc, gwBlue, extNode, extClientIPs[0])

			By("checking access to the 2nd IP of external node via gateway blue")
			checkConnectivityViaGateway(checker, cc, gwBlue, extNode, extClientIPs[1])

			By("checking access to the 3rd IP of external node via gateway red")
			checkConnectivityViaGateway(checker, cc, gwRed, extNode, extClientIPs[2])
		})

		It("should balance between multiple egress gateways", func() {
			expectedSourceIPs := map[string]bool{}
			for _, gw := range gatewayPods {
				expectedSourceIPs[gw.Status.PodIP] = true
			}

			// Create multiple pods to test load balancing. Linux default load balancing is based on
			// hash of (source IP, dest IP). We create multiple pods so each gets a different IP
			// and a different roll of the dice for gateway selection.
			var clients []*conncheck.Client
			for i := 0; i < 20; i++ {
				cc := conncheck.NewClient(fmt.Sprintf("multi-client-%d", i), f.Namespace,
					conncheck.WithClientCustomizer(func(pod *v1.Pod) {
						pod.Annotations = map[string]string{
							"egress.projectcalico.org/selector":          "has(egress-code)", // any of the gateways
							"egress.projectcalico.org/namespaceSelector": fmt.Sprintf(`projectcalico.org/name == "%s"`, egressGatewayNS),
						}
					}),
				)
				checker.AddClient(cc)
				clients = append(clients, cc)
			}
			checker.Deploy()

			sourceIPsSeen := map[string]bool{}
			for _, cc := range clients {
				sourceIPSeen := connectToNGINXAndGetSourceIP(checker, cc, extNode, extNode.IP(), "", "15s")
				logrus.Infof("External node saw source IP: %s", sourceIPSeen)
				Expect(expectedSourceIPs).To(HaveKey(sourceIPSeen),
					"Expected the external server to see one of the egress gateway's IPs.")

				sourceIPsSeen[sourceIPSeen] = true
				if len(sourceIPsSeen) == len(expectedSourceIPs) {
					break
				}
			}
			Expect(sourceIPsSeen).To(HaveLen(len(expectedSourceIPs)),
				"Expected all egress gateways to be used after multiple test connections.")
		})

		It("should use local egw pod when gatewayPreference is set to nodeLocal", func() {
			gwRed := findGWPod(gatewayPods, "red")
			gwBlue := findGWPod(gatewayPods, "blue")
			if gwRed.Spec.NodeName == gwBlue.Spec.NodeName {
				Skip("Skipping the test as both the gateway pods are in the same node")
			}
			nodeGWRed := findNodeMatchingFilter(f, func(node *v1.Node) bool {
				return node.Name == gwRed.Spec.NodeName
			})

			nodeGWBlue := findNodeMatchingFilter(f, func(node *v1.Node) bool {
				return node.Name == gwBlue.Spec.NodeName
			})
			extClientIPs := extNode.IPs()
			preferNodeLocal := v3.GatewayPreferenceNodeLocal
			egwPolicy := v3.NewEgressGatewayPolicy()
			egwPolicy.Name = "egw-policy"
			egwPolicy.Spec.Rules = []v3.EgressGatewayRule{
				{
					Description: "Gateway to the first IP of external node",
					Destination: &v3.EgressGatewayPolicyDestinationSpec{
						CIDR: fmt.Sprintf("%s/32", extClientIPs[0]),
					},
					Gateway: &v3.EgressSpec{
						NamespaceSelector: "projectcalico.org/name == 'calico-egress'",
						Selector:          "egress-code in {'red', 'blue'}",
					},
					GatewayPreference: &preferNodeLocal,
				},
				{
					Description: "default gateway",
					Gateway: &v3.EgressSpec{
						NamespaceSelector: "projectcalico.org/name == 'calico-egress'",
						Selector:          "egress-code in {'red', 'blue'}",
					},
					GatewayPreference: &preferNodeLocal,
				},
			}
			err := cli.Create(context.Background(), egwPolicy)
			Expect(err).NotTo(HaveOccurred(), "Failed to create egw policy")
			defer func() {
				err := cli.Delete(context.Background(), egwPolicy)
				Expect(err).NotTo(HaveOccurred())
			}()

			// Create client pod in same node as EGW red.
			cc := conncheck.NewClient("client-red", f.Namespace,
				conncheck.WithClientCustomizer(func(pod *v1.Pod) {
					pod.Spec.NodeName = nodeGWRed.Name
					pod.Annotations = map[string]string{
						"egress.projectcalico.org/egressGatewayPolicy": "egw-policy",
					}
				}),
			)
			checker.AddClient(cc)
			checker.Deploy()
			checkConnectivityViaGateway(checker, cc, gwRed, extNode, extClientIPs[0])

			checker.StopClient(cc)

			// Move the client pod to same node as EGW blue.
			cc = conncheck.NewClient("client-blue", f.Namespace,
				conncheck.WithClientCustomizer(func(pod *v1.Pod) {
					pod.Spec.NodeName = nodeGWBlue.Name
					pod.Annotations = map[string]string{
						"egress.projectcalico.org/egressGatewayPolicy": "egw-policy",
					}
				}),
			)
			checker.AddClient(cc)
			checker.Deploy()
			checkConnectivityViaGateway(checker, cc, gwBlue, extNode, extClientIPs[0])
		})
	})
