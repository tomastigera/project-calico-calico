// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package egw

import (
	"context"
	"fmt"
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/e2e/pkg/utils/externalnode"
)

// DESCRIPTION: Tests egress gateway behavior when natOutgoing is enabled on the egress IPPool.
// When natOutgoing=true, traffic leaving through the gateway is SNAT'd to the node IP of the
// host running the gateway pod, so the external destination sees the node IP as source.
//
// PRECONDITIONS: Requires an external node in the same subnet as Kubernetes nodes.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithCategory(describe.Networking),
	describe.WithFeature("EgressGateway"),
	describe.WithSerial(),
	describe.WithExternalNode(),
	"Egress gateway host IP",
	func() {
		var nodesInfoGetter utils.NodesInfoGetter
		var cli ctrlclient.Client
		var checker conncheck.ConnectionTester
		var extClientIP string

		f := utils.NewDefaultFramework("egress-gateway")

		Context("natOutgoing enabled", func() {
			BeforeEach(func() {
				cli, nodesInfoGetter = setupEgressIPTest(f, "!all()", egressHostIP)
				checker = conncheck.NewConnectionTester(f)

				extNode := externalnode.NewClient()
				Expect(extNode).NotTo(BeNil(), "No external node configured, unable to run egress gateway tests")
				extClientIP = extNode.IP()
				stopEchoserver := startEchoserver(extNode)
				DeferCleanup(stopEchoserver)
			})
			AfterEach(func() {
				checker.Stop()
				teardownEgressIPTest(cli)
			})

			// Verify that gateways on different nodes produce their respective host IPs.
			It("should egress with correct host IP per gateway node", func() {
				By("create gateway on node 0 with label red")
				redLabel := map[string]string{"color": "red"}
				gwRed := createGateway(f, cli, f.Namespace.Name, nodesInfoGetter.GetNames()[0], "gw-red", "egress-ippool-1", gatewayOpts{labels: redLabel})

				By("create gateway on node 1 with label blue")
				blueLabel := map[string]string{"color": "blue"}
				gwBlue := createGateway(f, cli, f.Namespace.Name, nodesInfoGetter.GetNames()[1], "gw-blue", "egress-ippool-1", gatewayOpts{labels: blueLabel})

				By("create client selecting red gateway")
				ccRed := conncheck.NewClient("client-red", f.Namespace,
					conncheck.WithClientCustomizer(func(pod *v1.Pod) {
						pod.Annotations = map[string]string{
							"egress.projectcalico.org/selector":          "color == 'red'",
							"egress.projectcalico.org/namespaceSelector": "all()",
						}
					}),
				)
				checker.AddClient(ccRed)

				By("create client selecting blue gateway")
				ccBlue := conncheck.NewClient("client-blue", f.Namespace,
					conncheck.WithClientCustomizer(func(pod *v1.Pod) {
						pod.Annotations = map[string]string{
							"egress.projectcalico.org/selector":          "color == 'blue'",
							"egress.projectcalico.org/namespaceSelector": "all()",
						}
					}),
				)
				checker.AddClient(ccBlue)
				checker.Deploy()

				By("checking that red client traffic comes from red gateway's host IP")
				redIP := checkEgressIPs(checker, ccRed, extClientIP, echoserverPort, []*v1.Pod{gwRed}, egressHostIP)
				Expect(redIP).To(Equal(gwRed.Status.HostIP),
					"Expected red client to egress via node %s, got %s", gwRed.Status.HostIP, redIP)

				By("checking that blue client traffic comes from blue gateway's host IP")
				blueIP := checkEgressIPs(checker, ccBlue, extClientIP, echoserverPort, []*v1.Pod{gwBlue}, egressHostIP)
				Expect(blueIP).To(Equal(gwBlue.Status.HostIP),
					"Expected blue client to egress via node %s, got %s", gwBlue.Status.HostIP, blueIP)
			})

			// Verify that preferNodeLocal causes traffic to use the local gateway's host IP.
			It("should use local gateway host IP with preferNodeLocal", func() {
				By("create gateway pods on node 0 and node 1")
				redLabel := map[string]string{"color": "red"}
				opts := gatewayOpts{labels: redLabel}
				gwNode0 := createGateway(f, cli, f.Namespace.Name, nodesInfoGetter.GetNames()[0], "gw0", "egress-ippool-1", opts)
				gwNode1 := createGateway(f, cli, f.Namespace.Name, nodesInfoGetter.GetNames()[1], "gw1", "egress-ippool-1", opts)

				By("create EGW policy with preferNodeLocal")
				preferNodeLocal := v3.GatewayPreferenceNodeLocal
				egwPolicy := v3.NewEgressGatewayPolicy()
				egwPolicy.Name = utils.GenerateRandomName("egw-policy")
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
					if err != nil {
						framework.Logf("WARNING: Failed to delete EgressGatewayPolicy %s", egwPolicy.Name)
					}
				})

				clientAnnotations := map[string]string{
					"egress.projectcalico.org/egressGatewayPolicy": egwPolicy.Name,
				}

				// Client on node 0 should use local gateway on node 0.
				By("create client on node 0")
				cc := conncheck.NewClient("client-0", f.Namespace,
					conncheck.WithClientCustomizer(func(pod *v1.Pod) {
						pod.Spec.NodeName = nodesInfoGetter.GetNames()[0]
						pod.Annotations = clientAnnotations
					}),
				)
				checker.AddClient(cc)
				checker.Deploy()

				// EgressGatewayPolicy routes need time to propagate through Felix
				// (unlike direct pod annotations which are ready at pod creation).
				By("checking that traffic uses node 0 host IP")
				target := conncheck.NewDomainTarget(fmt.Sprintf("http://%s", net.JoinHostPort(extClientIP, echoserverPort)))
				Eventually(func() error {
					out, err := checker.Connect(cc, target)
					if err != nil {
						return fmt.Errorf("connection to echoserver failed: %w", err)
					}
					ip := parseEchoserverSourceIP(out)
					if ip != gwNode0.Status.HostIP {
						return fmt.Errorf("expected egress IP %s, got %s", gwNode0.Status.HostIP, ip)
					}
					return nil
				}, "30s", "2s").Should(Succeed(),
					"Expected client on node %s to egress via host IP %s", nodesInfoGetter.GetNames()[0], gwNode0.Status.HostIP)

				// Client on node 1 should use local gateway on node 1.
				By("create client on node 1")
				checker.StopClient(cc)
				cc = conncheck.NewClient("client-1", f.Namespace,
					conncheck.WithClientCustomizer(func(pod *v1.Pod) {
						pod.Spec.NodeName = nodesInfoGetter.GetNames()[1]
						pod.Annotations = clientAnnotations
					}),
				)
				checker.AddClient(cc)
				checker.Deploy()

				By("checking that traffic uses node 1 host IP")
				Eventually(func() error {
					out, err := checker.Connect(cc, target)
					if err != nil {
						return fmt.Errorf("connection to echoserver failed: %w", err)
					}
					ip := parseEchoserverSourceIP(out)
					if ip != gwNode1.Status.HostIP {
						return fmt.Errorf("expected egress IP %s, got %s", gwNode1.Status.HostIP, ip)
					}
					return nil
				}, "30s", "2s").Should(Succeed(),
					"Expected client on node %s to egress via host IP %s", nodesInfoGetter.GetNames()[1], gwNode1.Status.HostIP)
			})

			// Verify that when a gateway is removed, traffic fails over to another gateway
			// on a different node, and the source IP changes to the new node's host IP.
			It("should failover to other host IP when gateway is removed", func() {
				By("create two gateways on different nodes")
				opts := gatewayOpts{labels: map[string]string{"color": "red"}}
				gw0 := createGateway(f, cli, f.Namespace.Name, nodesInfoGetter.GetNames()[0], "gw0", "egress-ippool-1", opts)
				gw1 := createGateway(f, cli, f.Namespace.Name, nodesInfoGetter.GetNames()[1], "gw1", "egress-ippool-1", opts)

				By("create client pod")
				cc := conncheck.NewClient("client", f.Namespace,
					conncheck.WithClientCustomizer(func(pod *v1.Pod) {
						pod.Annotations = map[string]string{
							"egress.projectcalico.org/selector":          "color == 'red'",
							"egress.projectcalico.org/namespaceSelector": "all()",
						}
					}),
				)
				checker.AddClient(cc)
				checker.Deploy()

				By("checking initial connectivity via one of the gateways")
				egressIP := checkEgressIPs(checker, cc, extClientIP, echoserverPort, []*v1.Pod{gw0, gw1}, egressHostIP)

				// Determine which gateway was used and remove it.
				var removedGW, remainingGW *v1.Pod
				if egressIP == gw0.Status.HostIP {
					removedGW = gw0
					remainingGW = gw1
				} else {
					removedGW = gw1
					remainingGW = gw0
				}

				By(fmt.Sprintf("removing gateway on node %s", removedGW.Spec.NodeName))
				removeGateway(f, cli, removedGW.Status.PodIP, []*v1.Pod{removedGW, remainingGW}, true)

				By("checking that traffic fails over to remaining gateway's host IP")
				target := conncheck.NewDomainTarget(fmt.Sprintf("http://%s", net.JoinHostPort(extClientIP, echoserverPort)))
				Eventually(func() error {
					out, err := checker.Connect(cc, target)
					if err != nil {
						return fmt.Errorf("connection to echoserver failed: %w", err)
					}
					ip := parseEchoserverSourceIP(out)
					if ip != remainingGW.Status.HostIP {
						return fmt.Errorf("expected egress IP %s, got %s", remainingGW.Status.HostIP, ip)
					}
					return nil
				}, "30s", "2s").Should(Succeed(), "Expected failover to node %s (%s)", remainingGW.Spec.NodeName, remainingGW.Status.HostIP)
			})
		})
	},
)
