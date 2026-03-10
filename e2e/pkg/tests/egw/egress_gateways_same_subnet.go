// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package egw

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	opermeta "github.com/tigera/operator/pkg/render/common/meta"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/e2e/pkg/utils/externalnode"
	"github.com/projectcalico/calico/e2e/pkg/utils/images"
)

type icmpProbe struct {
	ips      []string
	interval int
	timeout  int
}

type gatewayOpts struct {
	labels      map[string]string
	gracePeriod *int64
	icmpProbe   *icmpProbe
}

// DESCRIPTION: The tests in this file test egress gateways using an external node in the same AWS subnet (so that we can
// manually set up routes back to the egress gateway pods).  There are similar tests in the adjacent
// egress_gateways_aws_backend.go file, which rely on the banzai egress-gateway add-on to create a secondary VPC.
// The duplication was unintentional but the two groups of tests are still both valuable.  These tests cover
// the core egress gateway function along with the namespace annotations.  The other tests cover AWS backed IP pools.

// DOCS_URL: https://docs.tigera.io/calico-enterprise/latest/networking/egress/egress-gateway-on-prem
// PRECONDITIONS: This test requires an extra node in the same subnet as Kubernetes nodes.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithCategory(describe.Networking),
	describe.WithFeature("EgressGateway"),
	describe.WithSerial(),
	describe.WithExternalNode(),
	describe.WithAWS(),
	"Egress IP by namespace",
	func() {
		var nodesInfoGetter utils.NodesInfoGetter
		var cli ctrlclient.Client
		var checker conncheck.ConnectionTester

		f := utils.NewDefaultFramework("egress-gateway")

		Context("Egress IP network test", func() {
			BeforeEach(func() {
				cli, nodesInfoGetter = setupEgressIPTest(f, "!all()")
				checker = conncheck.NewConnectionTester(f)
			})
			AfterEach(func() {
				checker.Stop()
				teardownEgressIPTest(cli)
			})

			It("should route egress traffic via local gateway if present", func() {
				By("create external server")
				extNode := externalnode.NewClient()
				Expect(extNode).NotTo(BeNil(), "No external node configured, unable to run egress gateway tests")
				extClientIP := extNode.IP()
				defer startEchoserver(extNode)()

				By("Create red gateway pods")
				var gwRed [2]*v1.Pod
				redLabel := map[string]string{"color": "red"}

				opts := gatewayOpts{labels: redLabel}
				gwRed[0] = createGateway(f, cli, f.Namespace.Name, nodesInfoGetter.GetNames()[0], "gwred0", "egress-ippool-1", opts)
				gwRed[1] = createGateway(f, cli, f.Namespace.Name, nodesInfoGetter.GetNames()[1], "gwred1", "egress-ippool-1", opts)

				extNode.MustExec(shell, shellOpt, fmt.Sprintf("sudo ip r a %s/32 via %s", gwRed[0].Status.PodIP, gwRed[0].Status.HostIP))
				defer extNode.MustExec(shell, shellOpt, fmt.Sprintf(" sudo ip r del %s", gwRed[0].Status.PodIP))
				extNode.MustExec(shell, shellOpt, fmt.Sprintf("sudo ip r a %s/32 via %s", gwRed[1].Status.PodIP, gwRed[1].Status.HostIP))
				defer extNode.MustExec(shell, shellOpt, fmt.Sprintf(" sudo ip r del %s", gwRed[1].Status.PodIP))
				By("create EGW policy")
				preferNodeLocal := v3.GatewayPreferenceNodeLocal
				egwPolicy := v3.NewEgressGatewayPolicy()
				egwPolicy.Name = "egw-policy"
				egwPolicy.Spec.Rules = []v3.EgressGatewayRule{
					{
						Description: "Gateway to the external node",
						Destination: &v3.EgressGatewayPolicyDestinationSpec{
							CIDR: fmt.Sprintf("%s/32", extClientIP),
						},
						Gateway: &v3.EgressSpec{
							NamespaceSelector: "all()",
							Selector:          "color == 'red'",
						},
						GatewayPreference: &preferNodeLocal,
					},
				}
				err := cli.Create(context.Background(), egwPolicy)
				Expect(err).NotTo(HaveOccurred(), "Failed to create egw policy")
				DeferCleanup(func() {
					err := cli.Delete(context.Background(), egwPolicy)
					Expect(err).NotTo(HaveOccurred())
				})

				clientAnnotations := map[string]string{
					"egress.projectcalico.org/egressGatewayPolicy": "egw-policy",
				}

				// Create client on node 0 — should use local gateway gwRed[0].
				cc := conncheck.NewClient("client-0", f.Namespace,
					conncheck.WithClientCustomizer(func(pod *v1.Pod) {
						pod.Spec.NodeName = nodesInfoGetter.GetNames()[0]
						pod.Annotations = clientAnnotations
					}),
				)
				checker.AddClient(cc)
				checker.Deploy()
				extNode.MustExec(shell, shellOpt, fmt.Sprintf("sudo ip r a %s/32 via %s", cc.Pod().Status.PodIP, cc.Pod().Status.HostIP))
				defer extNode.MustExec(shell, shellOpt, fmt.Sprintf(" sudo ip r del %s", cc.Pod().Status.PodIP))

				checkEgressIPs(checker, cc, extClientIP, echoserverPort, []*v1.Pod{gwRed[0]})

				// Delete the client pod and recreate it on node 1 — should use local gateway gwRed[1].
				checker.StopClient(cc)
				cc = conncheck.NewClient("client-1", f.Namespace,
					conncheck.WithClientCustomizer(func(pod *v1.Pod) {
						pod.Spec.NodeName = nodesInfoGetter.GetNames()[1]
						pod.Annotations = clientAnnotations
					}),
				)
				checker.AddClient(cc)
				checker.Deploy()

				checkEgressIPs(checker, cc, extClientIP, echoserverPort, []*v1.Pod{gwRed[1]})

				// Delete the gw pod in node1 — should fall back to gwRed[0].
				removeGateway(f, cli, gwRed[1].Status.PodIP, []*v1.Pod{gwRed[1]}, true)

				checkEgressIPs(checker, cc, extClientIP, echoserverPort, []*v1.Pod{gwRed[0]})
			})

			It("should route egress traffic via different egress gateways based on destination", func() {
				By("create external server")
				extNode := externalnode.NewClient()
				Expect(extNode).NotTo(BeNil(), "No external node configured, unable to run egress gateway tests")
				extClientIPs := extNode.IPs()
				Expect(len(extClientIPs)).Should(BeNumerically(">", 2), "External node needs at least 3 IPs for dest based routing tests")
				defer startEchoserver(extNode)()

				By("create red and blue gateway pods")
				var gwRed, gwBlue *v1.Pod
				redLabel := map[string]string{"color": "red"}
				blueLabel := map[string]string{"color": "blue"}

				opts := gatewayOpts{labels: redLabel}
				gwRed = createGateway(f, cli, f.Namespace.Name, nodesInfoGetter.GetNames()[0], "gwred", "egress-ippool-1", opts)

				opts = gatewayOpts{labels: blueLabel}
				gwBlue = createGateway(f, cli, f.Namespace.Name, nodesInfoGetter.GetNames()[1], "gwblue", "egress-ippool-1", opts)

				extNode.MustExec(shell, shellOpt, fmt.Sprintf("sudo ip r a %s/32 via %s", gwRed.Status.PodIP, gwRed.Status.HostIP))
				defer extNode.MustExec(shell, shellOpt, fmt.Sprintf(" sudo ip r del %s", gwRed.Status.PodIP))
				extNode.MustExec(shell, shellOpt, fmt.Sprintf("sudo ip r a %s/32 via %s", gwBlue.Status.PodIP, gwBlue.Status.HostIP))
				defer extNode.MustExec(shell, shellOpt, fmt.Sprintf(" sudo ip r del %s", gwBlue.Status.PodIP))

				By("create EGW policy")
				egwPolicy := v3.NewEgressGatewayPolicy()
				egwPolicy.Name = "egw-policy"
				egwPolicy.Spec.Rules = []v3.EgressGatewayRule{
					{
						Description: "Gateway to the first IP of external node",
						Destination: &v3.EgressGatewayPolicyDestinationSpec{
							CIDR: fmt.Sprintf("%s/32", extClientIPs[0]),
						},
						Gateway: &v3.EgressSpec{
							NamespaceSelector: "all()",
							Selector:          "color == 'blue'",
						},
					},
					{
						Description: "Gateway to the second IP of external node",
						Destination: &v3.EgressGatewayPolicyDestinationSpec{
							CIDR: fmt.Sprintf("%s/32", extClientIPs[1]),
						},
						Gateway: &v3.EgressSpec{
							NamespaceSelector: "all()",
							Selector:          "color == 'blue'",
						},
					},
					{
						Description: "default route locally not via a gateway",
						Gateway: &v3.EgressSpec{
							NamespaceSelector: "all()",
							Selector:          "color == 'red'",
						},
					},
				}
				err := cli.Create(context.Background(), egwPolicy)
				Expect(err).NotTo(HaveOccurred(), "Failed to create egw policy")
				DeferCleanup(func() {
					err := cli.Delete(context.Background(), egwPolicy)
					Expect(err).NotTo(HaveOccurred())
				})

				clientAnnotations := map[string]string{
					"egress.projectcalico.org/egressGatewayPolicy": "egw-policy",
				}
				cc := conncheck.NewClient("client", f.Namespace,
					conncheck.WithClientCustomizer(func(pod *v1.Pod) {
						pod.Spec.NodeName = nodesInfoGetter.GetNames()[2]
						pod.Annotations = clientAnnotations
					}),
				)
				checker.AddClient(cc)
				checker.Deploy()
				extNode.MustExec(shell, shellOpt, fmt.Sprintf("sudo ip r a %s/32 via %s", cc.Pod().Status.PodIP, cc.Pod().Status.HostIP))
				defer extNode.MustExec(shell, shellOpt, fmt.Sprintf(" sudo ip r del %s", cc.Pod().Status.PodIP))

				By("checking access to the 1st IP of external node via gateway blue")
				checkEgressIPs(checker, cc, extClientIPs[0], echoserverPort, []*v1.Pod{gwBlue})

				By("checking access to the 2nd IP of external node via gateway blue")
				checkEgressIPs(checker, cc, extClientIPs[1], echoserverPort, []*v1.Pod{gwBlue})

				By("checking access to the 3rd IP of external node via gateway red")
				checkEgressIPs(checker, cc, extClientIPs[2], echoserverPort, []*v1.Pod{gwRed})
			})

			It("should support multiple gateways", func() {
				By("create external server")
				extNode := externalnode.NewClient()
				Expect(extNode).NotTo(BeNil(), "No external node configured, unable to run egress gateway tests")
				extIP := extNode.IP()
				defer startEchoserver(extNode)()

				By("create a gateway pod on node 0")
				gatewayRoutes := map[string]string{}
				redLabel := map[string]string{"color": "red"}
				opts := gatewayOpts{labels: redLabel}
				gw := createGateway(f, cli, f.Namespace.Name, nodesInfoGetter.GetNames()[0], "gw", "egress-ippool-1", opts)
				extNode.MustExec(shell, shellOpt, fmt.Sprintf("sudo ip r a %s/32 via %s", gw.Status.PodIP, gw.Status.HostIP))
				defer extNode.MustExec(shell, shellOpt, fmt.Sprintf(" sudo ip r del %s", gw.Status.PodIP))
				gatewayRoutes[gw.Status.PodIP] = gw.Status.HostIP
				gw0 := gw

				By("create a client pod on node 1")
				redAnnotations := map[string]string{
					"egress.projectcalico.org/selector":          "color == 'red'",
					"egress.projectcalico.org/namespaceSelector": "all()",
				}
				cc := conncheck.NewClient("client", f.Namespace,
					conncheck.WithClientCustomizer(func(pod *v1.Pod) {
						pod.Spec.NodeName = nodesInfoGetter.GetNames()[1]
						pod.Annotations = redAnnotations
					}),
				)
				checker.AddClient(cc)
				checker.Deploy()

				By("check connection and client address")
				Eventually(func() string {
					return checkEgressIPs(checker, cc, extIP, echoserverPort, []*v1.Pod{gw0})
				}, "30s", "2s").ShouldNot(BeEmpty())

				By("create second gateway pod on node 1")
				gw = createGateway(f, cli, f.Namespace.Name, nodesInfoGetter.GetNames()[1], "gw1", "egress-ippool-1", opts)
				extNode.MustExec(shell, shellOpt, fmt.Sprintf("sudo ip r a %s/32 via %s", gw.Status.PodIP, gw.Status.HostIP))
				defer extNode.MustExec(shell, shellOpt, fmt.Sprintf(" sudo ip r del %s", gw.Status.PodIP))
				gatewayRoutes[gw.Status.PodIP] = gw.Status.HostIP
				gw1 := gw

				checkEgressIPs(checker, cc, extIP, echoserverPort, []*v1.Pod{gw0, gw1})

				By("create third gateway pod on node 2")
				gw = createGateway(f, cli, f.Namespace.Name, nodesInfoGetter.GetNames()[2], "gw2", "egress-ippool-1", opts)
				extNode.MustExec(shell, shellOpt, fmt.Sprintf("sudo ip r a %s/32 via %s", gw.Status.PodIP, gw.Status.HostIP))
				defer extNode.MustExec(shell, shellOpt, fmt.Sprintf(" sudo ip r del %s", gw.Status.PodIP))
				gatewayRoutes[gw.Status.PodIP] = gw.Status.HostIP
				gw2 := gw

				egressIP := checkEgressIPs(checker, cc, extIP, echoserverPort, []*v1.Pod{gw0, gw1, gw2})

				By("remove the gateway pod used for latest egress traffic and check egress ip")
				gwList := removeGateway(f, cli, egressIP, []*v1.Pod{gw0, gw1, gw2}, true)

				egressIP = checkEgressIPs(checker, cc, extIP, echoserverPort, gwList)

				By("remove the gateway pod used for latest egress traffic and check egress ip")
				gwList = removeGateway(f, cli, egressIP, gwList, true)

				egressIP = checkEgressIPs(checker, cc, extIP, echoserverPort, gwList)

				By("remove the gateway pod used for latest egress traffic and check egress ip")
				removeGateway(f, cli, egressIP, gwList, true)

				// All gateways removed — connection should fail.
				fetchExtClientIP(checker, cc, extIP, echoserverPort, true)

				By("create a gateway pod on node 0 again")
				gw = createGateway(f, cli, f.Namespace.Name, nodesInfoGetter.GetNames()[0], "gw", "egress-ippool-1", opts)
				if _, ok := gatewayRoutes[gw.Status.PodIP]; ok {
					extNode.MustExec(shell, shellOpt, fmt.Sprintf("sudo ip r replace %s/32 via %s", gw.Status.PodIP, gw.Status.HostIP))
				} else {
					extNode.MustExec(shell, shellOpt, fmt.Sprintf("sudo ip r a %s/32 via %s", gw.Status.PodIP, gw.Status.HostIP))
					defer extNode.MustExec(shell, shellOpt, fmt.Sprintf(" sudo ip r del %s", gw.Status.PodIP))
				}
				gw0 = gw

				By("check connection and client address")
				checkEgressIPs(checker, cc, extIP, echoserverPort, []*v1.Pod{gw0})
			})

			Context("EGW readiness: with two EGWs and ICMP readiness probes enabled and a client pod", func() {
				var gw1, gw2, client *v1.Pod
				redLabel := map[string]string{"color": "red"}
				var extNode *externalnode.Client

				readyAndHopped := func() error {
					if hops, err := getNextHopsForPod(f, f.Namespace.Name, client); err != nil {
						return fmt.Errorf("failed to get number of hops: %w", err)
					} else if hops != 2 {
						return fmt.Errorf("pod should use all hops, found %d", hops)
					}

					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					pod, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Get(ctx, client.Name, metav1.GetOptions{})
					if err != nil {
						return fmt.Errorf("failed to get pod to check its status: %w", err)
					}
					for _, c := range pod.Status.Conditions {
						if c.Type == v1.PodReady {
							if c.Status == v1.ConditionTrue {
								return nil
							} else {
								return fmt.Errorf("pod wasn't ready: %s", pod)
							}
						}
					}
					return fmt.Errorf("couldn't find readiness in pod status: %s", pod)
				}

				BeforeEach(func() {
					extNode = externalnode.NewClient()
					Expect(extNode).NotTo(BeNil(), "No external node configured, unable to run egress gateway tests")
					opts := gatewayOpts{
						labels:    redLabel,
						icmpProbe: &icmpProbe{ips: []string{extNode.IP()}, timeout: 3, interval: 1},
					}
					gw1 = createGateway(f, cli, f.Namespace.Name, nodesInfoGetter.GetNames()[0], "gw1", "egress-ippool-1", opts)
					gw2 = createGateway(f, cli, f.Namespace.Name, nodesInfoGetter.GetNames()[0], "gw2", "egress-ippool-1", opts)

					extNode.MustExec(shell, shellOpt, fmt.Sprintf("sudo ip route add %s/32 via %s", gw1.Status.PodIP, gw1.Status.HostIP))
					extNode.MustExec(shell, shellOpt, fmt.Sprintf("sudo ip route add %s/32 via %s", gw2.Status.PodIP, gw2.Status.HostIP))

					By("creating a client pod")
					redAnnotations := map[string]string{
						"egress.projectcalico.org/selector":          "color == 'red'",
						"egress.projectcalico.org/namespaceSelector": "all()",
					}
					cc := conncheck.NewClient("client", f.Namespace,
						conncheck.WithClientCustomizer(func(pod *v1.Pod) {
							pod.Spec.NodeName = nodesInfoGetter.GetNames()[1]
							pod.Annotations = redAnnotations
						}),
					)
					checker.AddClient(cc)
					checker.Deploy()
					client = cc.Pod()

					Eventually(readyAndHopped, "10s", "1s").ShouldNot(HaveOccurred())
				})

				AfterEach(func() {
					extNode.MustExec(shell, shellOpt, fmt.Sprintf("sudo ip route del %s/32 via %s", gw1.Status.PodIP, gw1.Status.HostIP))
				})
				AfterEach(func() {
					extNode.MustExec(shell, shellOpt, fmt.Sprintf("sudo ip route del %s/32 via %s", gw2.Status.PodIP, gw2.Status.HostIP))
				})

				It("should consistently report ready and use all the hops", func() {
					Consistently(readyAndHopped, "20s", "1s").ShouldNot(HaveOccurred())
				})

				Context("with external node blocking one gateway's ICMP", func() {
					var ruleActive bool

					BeforeEach(func() {
						extNode.MustExec(shell, shellOpt, fmt.Sprintf("sudo iptables -A INPUT -p icmp -s %s -j DROP", gw1.Status.PodIP))
						ruleActive = true
					})
					AfterEach(func() {
						if ruleActive {
							extNode.MustExec(shell, shellOpt, fmt.Sprintf("sudo iptables -D INPUT -p icmp -s %s -j DROP", gw1.Status.PodIP))
						}
					})

					It("gateway should go non-ready and be removed from the hops", func() {
						err := e2epod.WaitForPodCondition(context.Background(), f.ClientSet, f.Namespace.Name, gw1.Name, "not ready", 30*time.Second, func(pod *v1.Pod) (bool, error) {
							for _, c := range pod.Status.Conditions {
								if c.Type == v1.PodReady {
									if c.Status == v1.ConditionFalse {
										logrus.Infof("Pod %s not ready, as expected", pod.Name)
										return true, nil
									} else {
										logrus.Infof("Pod %s ready but shouldn't be", pod.Name)
										return false, nil
									}
								}
							}
							return false, fmt.Errorf("couldn't find readiness in pod status: %s", pod)
						})
						Expect(err).NotTo(HaveOccurred())

						Eventually(func() int {
							if hops, err := getNextHopsForPod(f, f.Namespace.Name, client); err != nil {
								return -1
							} else {
								return hops
							}
						}, "60s", "1s").Should(Equal(1))

						By("Removing the ICMP drop rule, should become ready again")
						extNode.MustExec(shell, shellOpt, fmt.Sprintf("sudo iptables -D INPUT -p icmp -s %s -j DROP", gw1.Status.PodIP))
						ruleActive = false

						err = e2epod.WaitTimeoutForPodReadyInNamespace(context.Background(), f.ClientSet, gw1.Name, gw1.Namespace, 60*time.Second)
						Expect(err).NotTo(HaveOccurred())

						Eventually(func() int {
							if hops, err := getNextHopsForPod(f, f.Namespace.Name, client); err != nil {
								return -1
							} else {
								return hops
							}
						}, "30s", "1s").Should(Equal(2))
					})
				})
			})
		})

		Context("Egress IP Maintenance Annotations", func() {
			BeforeEach(func() {
				cli, nodesInfoGetter = setupEgressIPTest(f, "all()")
				checker = conncheck.NewConnectionTester(f)
			})
			AfterEach(func() {
				checker.Stop()
				teardownEgressIPTest(cli)
			})

			It("should add gateway maintenance annotations to dependent pods when a gateway begins termination HA-EG", func() {
				By("creating a gateway pod")
				redLabel := map[string]string{"color": "red"}
				// create a gateway with a 60s termination grace period
				var gracePeriod int64 = 60
				opts := gatewayOpts{labels: redLabel, gracePeriod: &gracePeriod}
				gw := createGateway(f, cli, f.Namespace.Name, nodesInfoGetter.GetNames()[0], "gw", "egress-ippool-1", opts)

				By("creating a client pod")
				redAnnotations := map[string]string{
					"egress.projectcalico.org/selector":          "color == 'red'",
					"egress.projectcalico.org/namespaceSelector": "all()",
				}
				cc := conncheck.NewClient("client", f.Namespace,
					conncheck.WithClientCustomizer(func(pod *v1.Pod) {
						pod.Spec.NodeName = nodesInfoGetter.GetNames()[1]
						pod.Annotations = redAnnotations
					}),
				)
				checker.AddClient(cc)
				checker.Deploy()

				By("deleting a gateway pod")
				removeGateway(f, cli, gw.Status.PodIP, []*v1.Pod{gw}, false) // delete and don't wait to disappear

				By("waiting for gateway maintenance annotations on the client pod")
				Eventually(func() error {
					return checkClientMaintenanceAnnotations(f, f.Namespace.Name, cc.Pod())
				}, "30s", "2s").Should(Succeed(), "expected gateway maintenance annotations on client pod")
			})

			It("should restrict number of routetable nextHops based on maxNextHops annotation HA-EG", func() {
				By("creating 2 gateways")
				redLabel := map[string]string{"color": "red"}
				opts := gatewayOpts{labels: redLabel}
				createGateway(f, cli, f.Namespace.Name, nodesInfoGetter.GetNames()[0], "gw1", "egress-ippool-1", opts)
				createGateway(f, cli, f.Namespace.Name, nodesInfoGetter.GetNames()[0], "gw2", "egress-ippool-1", opts)

				By("creating a client pod with 1 maxNextHops")
				redAnnotationsMaxNextHops := map[string]string{
					"egress.projectcalico.org/selector":          "color == 'red'",
					"egress.projectcalico.org/namespaceSelector": "all()",
					"egress.projectcalico.org/maxNextHops":       "1",
				}
				cc := conncheck.NewClient("client", f.Namespace,
					conncheck.WithClientCustomizer(func(pod *v1.Pod) {
						pod.Spec.NodeName = nodesInfoGetter.GetNames()[1]
						pod.Annotations = redAnnotationsMaxNextHops
					}),
				)
				checker.AddClient(cc)
				checker.Deploy()

				By("checking nextHops for client pod")
				Eventually(func() (int, error) {
					return getNextHopsForPod(f, f.Namespace.Name, cc.Pod())
				}, 30*time.Second, 1*time.Second).Should(BeNumerically("==", 1), "didn't find expected number of next hops in client egress networking")
			})
		})
	})

// setupEgressIPTest initialises the client, cleans the datastore, fetches nodes,
// enables egress-IP support, and creates the egress IPPool with the given nodeSelector.
func setupEgressIPTest(f *framework.Framework, nodeSelector string) (ctrlclient.Client, utils.NodesInfoGetter) {
	cli, err := client.NewAPIClient(f.ClientConfig())
	Expect(err).ShouldNot(HaveOccurred())

	// Get ipipMode, vxlanMode for the default IPPool.
	ipipMode, vxlanMode := getPoolNetworkingMode(cli, "default-ipv4-ippool")

	// Get three nodes.
	nodes, err := e2enode.GetReadySchedulableNodes(context.Background(), f.ClientSet)
	Expect(err).ShouldNot(HaveOccurred())
	if len(nodes.Items) == 0 {
		framework.Failf("No nodes exist, can't continue test.")
	}
	if len(nodes.Items) < 3 {
		framework.Failf("Less than three schedulable nodes exist, can't continue test.")
	}
	nodesInfoGetter := utils.GetNodesInfo(f, nodes, false)
	logrus.Infof("Cache nodeNames %v, nodeIPs %v", nodesInfoGetter.GetNames(), append(nodesInfoGetter.GetIPv4s(), nodesInfoGetter.GetIPv6s()...))

	// Enable egress IP support; CleanDatastore at the start of each test resets this.
	err = utils.UpdateFelixConfig(cli, func(spec *v3.FelixConfigurationSpec) {
		spec.EgressIPSupport = "EnabledPerNamespaceOrPerPod"
	})
	Expect(err).ShouldNot(HaveOccurred())
	WaitForCalicoReady(f.ClientSet)

	pool := v3.NewIPPool()
	pool.Name = "egress-ippool-1"
	pool.Spec.CIDR = "10.10.10.0/29"
	pool.Spec.BlockSize = 29
	pool.Spec.IPIPMode = ipipMode
	pool.Spec.VXLANMode = vxlanMode
	pool.Spec.NodeSelector = nodeSelector
	pool.Spec.NATOutgoing = false
	err = cli.Create(context.Background(), pool)
	Expect(err).NotTo(HaveOccurred())

	return cli, nodesInfoGetter
}

// teardownEgressIPTest deletes the egress IPPool created by setup.
func teardownEgressIPTest(cli ctrlclient.Client) {
	err := cli.Delete(context.Background(), &v3.IPPool{ObjectMeta: metav1.ObjectMeta{Name: "egress-ippool-1"}})
	Expect(err).NotTo(HaveOccurred())
}

// removeGateway removes a gateway pod with a given IP and returns the list of remaining gateway pods.
func removeGateway(f *framework.Framework, cli ctrlclient.Client, ip string, gws []*v1.Pod, waitToDisappear bool) []*v1.Pod {
	var gw *v1.Pod
	remainPods := []*v1.Pod{}
	for _, pod := range gws {
		if pod.Status.PodIP == ip {
			gw = pod
		} else {
			remainPods = append(remainPods, pod)
		}
	}

	Expect(gw).NotTo(BeNil())

	deployName := gw.Labels["app.kubernetes.io/name"]
	ns := gw.Namespace
	err := cli.Delete(context.Background(), &operatorv1.EgressGateway{
		ObjectMeta: metav1.ObjectMeta{Name: deployName, Namespace: ns},
	})
	Expect(err).NotTo(HaveOccurred())
	if waitToDisappear {
		err = e2epod.WaitForPodNotFoundInNamespace(context.Background(), f.ClientSet, gw.Name, f.Namespace.Name, time.Second*45)
		Expect(err).NotTo(HaveOccurred())
	}

	return remainPods
}

// createGateway creates an EgressGateway resource and waits for the resulting pod to be running.
func createGateway(
	f *framework.Framework,
	cli ctrlclient.Client,
	ns, nodeName, podName, egressCIDR string, opts gatewayOpts,
) *v1.Pod {
	// Build the EgressGateway resource as a Go struct.
	nodeSelector := map[string]string{
		"kubernetes.io/os": "linux",
	}
	if nodeName != "" {
		nodeSelector["kubernetes.io/hostname"] = nodeName
	}

	egw := &operatorv1.EgressGateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: ns,
		},
		Spec: operatorv1.EgressGatewaySpec{
			IPPools: []operatorv1.EgressGatewayIPPool{
				{Name: egressCIDR},
			},
			Template: &operatorv1.EgressGatewayDeploymentPodTemplateSpec{
				Metadata: &operatorv1.EgressGatewayMetadata{
					Labels: opts.labels,
				},
				Spec: &operatorv1.EgressGatewayDeploymentPodSpec{
					NodeSelector:                  nodeSelector,
					TerminationGracePeriodSeconds: opts.gracePeriod,
				},
			},
		},
	}

	if opts.icmpProbe != nil {
		intervalSec := int32(opts.icmpProbe.interval)
		timeoutSec := int32(opts.icmpProbe.timeout)
		egw.Spec.EgressGatewayFailureDetection = &operatorv1.EgressGatewayFailureDetection{
			ICMPProbe: &operatorv1.ICMPProbe{
				IPs:             opts.icmpProbe.ips,
				IntervalSeconds: &intervalSec,
				TimeoutSeconds:  &timeoutSec,
			},
		}
	}

	err := cli.Create(context.Background(), egw)
	Expect(err).ToNot(HaveOccurred())

	// Wait for the resulting pod to be running.
	labelSelector := fmt.Sprintf("app.kubernetes.io/name=%s", podName)
	var pod *v1.Pod
	Eventually(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		pods, err := f.ClientSet.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
		if err != nil {
			return fmt.Errorf("failed to list pods: %w", err)
		}
		if len(pods.Items) == 0 {
			return fmt.Errorf("no pods found with label %s", labelSelector)
		}
		err = e2epod.WaitForPodNameRunningInNamespace(context.Background(), f.ClientSet, pods.Items[0].Name, ns)
		if err != nil {
			return fmt.Errorf("pod not running: %w", err)
		}
		if pods.Items[0].Status.PodIP == "" {
			return fmt.Errorf("pod %s has no IP yet", pods.Items[0].Name)
		}
		pod = &pods.Items[0]
		logrus.Infof("Egress gateway pod %q in namespace %q running", pod.Name, ns)
		return nil
	}, "60s", "2s").Should(Succeed(), "egress gateway pod did not become ready")

	return pod
}

// getNextHopsForPod returns the number of next hops in the egress routing table for the given pod.
func getNextHopsForPod(f *framework.Framework, namespace string, pod *v1.Pod) (int, error) {
	cmdGetEgressTableIdx := "ip rule show from %s | cut -d' ' -f6"
	cmdGetEgressTableRouteLineCount := "ip route show table %s | wc -l"

	hostnetPod, err := f.ClientSet.CoreV1().Pods(namespace).Get(context.Background(), "netutils", metav1.GetOptions{})
	if err != nil {
		hostnetPod, err = createHostNetutilsPod(f, namespace, pod.Spec.NodeName, "netutils")
		if err != nil {
			return 0, fmt.Errorf("couldn't create host-networked netutils pod: %w", err)
		}
	}

	// find the egress table for pod in the host network
	egressTableIdx, _, err := e2epod.ExecShellInPodWithFullOutput(context.Background(), f, hostnetPod.Name, fmt.Sprintf(cmdGetEgressTableIdx, pod.Status.PodIP))
	if err != nil {
		return 0, fmt.Errorf("couldn't exec cmd in netutils pod: %w", err)
	}
	_, err = strconv.Atoi(egressTableIdx)
	if err != nil {
		return 0, fmt.Errorf("couldn't parse egress table index as int: %w", err)
	}

	// follow the referenced table index and count the number of lines in it
	numLinesStr, _, err := e2epod.ExecShellInPodWithFullOutput(context.Background(), f, hostnetPod.Name, fmt.Sprintf(cmdGetEgressTableRouteLineCount, egressTableIdx))
	if err != nil {
		return 0, fmt.Errorf("couldn't exec cmd in netutils pod: %w", err)
	}
	numLines, err := strconv.Atoi(numLinesStr)
	if err != nil {
		return 0, fmt.Errorf("couldn't parse cmd output as int: %w", err)
	}
	if numLines < 1 {
		return 0, errors.New("parsed 0 lines from pod egress routetable")
	}

	// number of nextHops is 1 when numLines is 1, but every other number of nextHops will be numLines-1
	// (parent route followed by all the nextHops)
	if numLines == 1 {
		return 1, nil
	}
	return numLines - 1, nil
}

const (
	echoserverPort = "9000"
	shell          = "/bin/sh"
	shellOpt       = "-c"
)

// startEchoserver starts an echoserver container on the external node, listening on echoserverPort.
// Returns a cleanup function that stops the container.
func startEchoserver(extNode *externalnode.Client) func() {
	cmd := fmt.Sprintf("sudo docker run -d --rm --name echoserver -p %s:8080 gcr.io/kubernetes-e2e-test-images/echoserver:2.2", echoserverPort)
	extNode.MustExec(shell, shellOpt, cmd)
	return func() {
		extNode.MustExec(shell, shellOpt, "sudo docker stop echoserver")
	}
}

// parseEchoserverSourceIP extracts client_address from echoserver:2.2 response body.
func parseEchoserverSourceIP(output string) string {
	re := regexp.MustCompile(`client_address=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)`)
	m := re.FindStringSubmatch(output)
	ExpectWithOffset(1, m).To(HaveLen(2),
		"Failed to parse client_address from echoserver response: %s", output)
	return m[1]
}

// fetchExtClientIP connects to the echoserver on the external node and returns the
// source IP seen by the server. If expectToFail is true, it expects the connection to fail.
func fetchExtClientIP(checker conncheck.ConnectionTester, cc *conncheck.Client, ip, port string, expectToFail bool) string {
	target := conncheck.NewDomainTarget(fmt.Sprintf("http://%s", net.JoinHostPort(ip, port)))
	out, err := checker.Connect(cc, target)
	if err != nil {
		if expectToFail {
			logrus.Infof("connection to %s:%s failed as expected", ip, port)
			return ""
		}
		framework.Failf("Cannot connect to %s:%s: %v", ip, port, err)
	}

	if expectToFail {
		framework.Failf("unexpectedly connected to %s:%s with output %s", ip, port, out)
	}

	logrus.Infof("echoserver output:\n%v", out)
	return parseEchoserverSourceIP(out)
}

// checkEgressIPs verifies the echoserver sees a source IP matching one of the expected gateway IPs.
func checkEgressIPs(checker conncheck.ConnectionTester, cc *conncheck.Client, destination, port string, gws []*v1.Pod) string {
	expectedIPs := map[string]bool{}
	for _, gw := range gws {
		expectedIPs[gw.Status.PodIP] = true
	}

	ip := fetchExtClientIP(checker, cc, destination, port, false)
	ExpectWithOffset(1, expectedIPs).To(HaveKey(ip),
		"Source IP %s is not one of the expected gateway IPs %v", ip, expectedIPs)
	By(fmt.Sprintf("Server has seen egress ip %s", ip))
	return ip
}

// createHostNetutilsPod creates a host-networked pod running the netutils image on the given node.
func createHostNetutilsPod(f *framework.Framework, ns, nodeName, podName string) (*v1.Pod, error) {
	var zero int64
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      podName,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:    podName,
					Image:   images.Netutils,
					Command: []string{"tail", "-f", "/dev/null"},
				},
			},
			HostNetwork:                   true,
			NodeName:                      nodeName,
			RestartPolicy:                 v1.RestartPolicyNever,
			TerminationGracePeriodSeconds: &zero,
			Tolerations:                   []v1.Toleration{opermeta.TolerateGKEARM64NoSchedule},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pod, err := f.ClientSet.CoreV1().Pods(ns).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	logrus.Infof("Created host-networked pod %q in namespace %q", pod.Name, ns)

	err = e2epod.WaitForPodNameRunningInNamespace(context.Background(), f.ClientSet, podName, ns)
	if err != nil {
		return pod, err
	}

	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return f.ClientSet.CoreV1().Pods(ns).Get(ctx, podName, metav1.GetOptions{})
}

func checkClientMaintenanceAnnotations(f *framework.Framework, ns string, clientPod *v1.Pod) error {
	podClient := f.ClientSet.CoreV1().Pods(ns)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pod, err := podClient.Get(ctx, clientPod.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get client pod %s: %w", clientPod.Name, err)
	}

	annotations := pod.GetAnnotations()
	for _, key := range []string{
		"egress.projectcalico.org/gatewayMaintenanceGatewayIP",
		"egress.projectcalico.org/gatewayMaintenanceStartedTimestamp",
		"egress.projectcalico.org/gatewayMaintenanceFinishedTimestamp",
	} {
		if _, ok := annotations[key]; !ok {
			return fmt.Errorf("client pod %s missing annotation %s", clientPod.Name, key)
		}
	}
	return nil
}

func getPoolNetworkingMode(client ctrlclient.Client, poolName string) (v3.IPIPMode, v3.VXLANMode) {
	var pool v3.IPPool
	err := client.Get(context.Background(), ctrlclient.ObjectKey{Name: poolName}, &pool)
	Expect(err).NotTo(HaveOccurred())
	logrus.Infof("Get pool %s config, ipipMode %s, vxlanMode %s", poolName, pool.Spec.IPIPMode, pool.Spec.VXLANMode)
	return pool.Spec.IPIPMode, pool.Spec.VXLANMode
}

func WaitForCalicoReady(clientset clientset.Interface) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	calicoSystemPodsList, err := clientset.CoreV1().Pods("calico-system").List(ctx, metav1.ListOptions{})
	Expect(err).ToNot(HaveOccurred())
	numCaliSys := len(calicoSystemPodsList.Items)
	err = e2epod.WaitForPodsRunningReady(context.Background(), clientset, "calico-system", numCaliSys, 5*time.Minute)
	Expect(err).ToNot(HaveOccurred())
}
