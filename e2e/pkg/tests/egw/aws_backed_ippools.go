// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package egw

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/operator/pkg/ptr"
	opermeta "github.com/tigera/operator/pkg/render/common/meta"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/kubernetes/test/e2e/framework"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/config"
	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/e2e/pkg/utils/externalnode"
	"github.com/projectcalico/calico/e2e/pkg/utils/images"
)

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("EgressGateway"),
	describe.WithCategory(describe.Networking),
	describe.WithExternalNode(),
	describe.WithSerial(),
	describe.WithAWS(),
	"AWS-backed IP pools tests",
	func() {
		f := utils.NewDefaultFramework("egress-gateway")

		var cli ctrlclient.Client
		var podClient *e2epod.PodClient
		var extNode *externalnode.Client
		var checker conncheck.ConnectionTester

		var zoneToUse string
		var nodesByZone map[string][]v1.Node
		var numEGWsByNode map[string]int
		var ipPoolsByZone map[string]v3.IPPool

		BeforeEach(func() {
			checker = conncheck.NewConnectionTester(f)

			// Banzai sets up some AWS-backed IP pools to use for egress gateways.  We'll piggyback on those.
			var err error
			cli, err = client.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred(), "Failed to get Calico client")
			ipPools := v3.IPPoolList{}
			err = cli.List(context.Background(), &ipPools)
			Expect(err).NotTo(HaveOccurred())

			// Find the AWS-backed IP pools that banzai created and index by zone.
			haveSomeAWSPools := false
			ipPoolsByZone = map[string]v3.IPPool{}
			for _, pool := range ipPools.Items {
				// We only need one IP pool per zone so grab the "red" pools created by banzai.
				if strings.HasPrefix(pool.Name, "egress-ip-red-pool-") {
					zone := strings.TrimPrefix(pool.Name, "egress-ip-red-pool-")
					ipPoolsByZone[zone] = pool
				}
				if pool.Spec.AWSSubnetID != "" {
					haveSomeAWSPools = true
				}
			}
			if !haveSomeAWSPools {
				Skip("Cluster doesn't have any AWS-backed IP pools")
			}
			Expect(ipPoolsByZone).NotTo(HaveLen(0),
				"Cluster has some AWS-backed IP pools configured but failed to parse their names")

			// Find a zone with an IP pool and at least two nodes.
			nodes, err := f.ClientSet.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
			Expect(err).NotTo(HaveOccurred())

			nodesByZone = map[string][]v1.Node{}
			numEGWsByNode = map[string]int{}
			for _, n := range nodes.Items {
				zone := n.Labels["topology.kubernetes.io/zone"]
				if zone == "" {
					logrus.Infof("node %s has no zone label", n.Name)
					continue
				}
				nodesByZone[zone] = append(nodesByZone[zone], n)
				numEGWsByNode[n.Name] = numEGWsOnNode(f, n.Name)
			}

			// Banzai sets up some EGWs, which use available AWS IP capacity, sort the nodes by number of EGWs
			// so that, even in ENI-per-pod mode we should find a node with enough capacity to run a couple of
			// AWS-backed pods.
			for _, ns := range nodesByZone {
				sort.Slice(ns, func(i, j int) bool {
					return numEGWsByNode[ns[i].Name] < numEGWsByNode[ns[j].Name]
				})
			}
			zoneToUse = ""
			for zone, ns := range nodesByZone {
				minCap := 1000
				maxCap := 0
				for _, n := range ns {
					capc64, ok := n.Status.Allocatable.Name("projectcalico.org/aws-secondary-ipv4", resource.DecimalSI).AsInt64()
					Expect(ok).To(BeTrue(), "Failed to read the aws-secondary-ipv4 capacity from a node")
					capc := int(capc64) - numEGWsByNode[n.Name]
					if capc < minCap {
						minCap = capc
					}
					if capc > maxCap {
						maxCap = capc
					}
				}

				if len(ns) >= 2 && minCap >= 1 && maxCap >= 2 {
					zoneToUse = zone
				}
			}
			Expect(zoneToUse).NotTo(BeEmpty(), "Failed to find a zone with >= 2 nodes and enough spare AWS-backed pod capacity")

			// Install NGINX on the external node.
			extNode = externalnode.NewClient()
			extNode.InstallNGINX()

			podClient = e2epod.NewPodClient(f)
		})

		AfterEach(func() {
			checker.Stop()
			// Since we use resource reservations to claim AWS IPs, it's important that we wait for pods to fully disappear
			// between tests.  Otherwise, we can have a deleted pod claiming a resource (which is a problem for
			// the "should handle the maximum number of pods per node" test).
			deleteAllPodsInNS(f)
		})

		It("should allow IPs to move from one node to another", func() {
			// Create client pod on first node and check it has connectivity with its own IP.
			nodes := nodesByZone[zoneToUse]
			cc := conncheck.NewClient("client-0", f.Namespace,
				conncheck.WithClientCustomizer(awsClientCustomizer(podSpec{NodeName: nodes[0].Name})),
			)
			checker.AddClient(cc)
			checker.Deploy()
			expectInternalConnectivityWithOwnIP(checker, cc, extNode)
			clientPodIP := cc.Pod().Status.PodIP

			// Delete the pod and create a new copy on a different node, reusing the same IP.  The IP should
			// move to the other node, giving _that_ pod connectivity.
			checker.StopClient(cc)
			cc = conncheck.NewClient("client-1", f.Namespace,
				conncheck.WithClientCustomizer(awsClientCustomizer(podSpec{NodeName: nodes[1].Name, IP: clientPodIP})),
			)
			checker.AddClient(cc)
			checker.Deploy()
			expectInternalConnectivityWithOwnIP(checker, cc, extNode)

			// Delete _that_ pod and move it back to the first node.
			checker.StopClient(cc)
			cc = conncheck.NewClient("client-2", f.Namespace,
				conncheck.WithClientCustomizer(awsClientCustomizer(podSpec{NodeName: nodes[0].Name, IP: clientPodIP})),
			)
			checker.AddClient(cc)
			checker.Deploy()
			expectInternalConnectivityWithOwnIP(checker, cc, extNode)
		})

		It("should block assignment of IP from wrong zone", func() {
			// Create client pod in one zone but request an IP from a different zone.
			nodes := nodesByZone[zoneToUse]
			var wrongPool string
			for zone, pool := range ipPoolsByZone {
				if zone == zoneToUse {
					continue
				}
				wrongPool = pool.Name
				break
			}
			if wrongPool == "" {
				Skip("Only one zone has AWS-backed IP pools, cannot test cross-zone rejection")
			}
			clientPod := generateClientPod(podSpec{
				NodeName:    nodes[0].Name,
				IPPoolNames: []string{wrongPool},
			})
			clientPod = podClient.Create(context.Background(), clientPod)
			evt, err := waitForFailedPodSandbox(f, clientPod)
			Expect(err).NotTo(HaveOccurred())
			Expect(evt).NotTo(BeNil())
		})

		It("should block assignment of IP from AWS pool without the corresponding resource request", func() {
			// Create client pod in one zone but request an IP from a different zone.
			nodes := nodesByZone[zoneToUse]
			clientPod := generateClientPod(podSpec{
				NodeName:    nodes[0].Name,
				IPPoolNames: []string{ipPoolsByZone[zoneToUse].Name},
			})
			clientPod.Spec.Containers[0].Resources.Requests = nil
			clientPod.Spec.Containers[0].Resources.Limits = nil
			clientPod = podClient.Create(context.Background(), clientPod)
			evt, err := waitForFailedPodSandbox(f, clientPod)
			Expect(err).NotTo(HaveOccurred())
			Expect(evt).NotTo(BeNil())
		})

		Context("AWS Elastic IPs", func() {
			var elasticIPs []net.IP

			BeforeEach(func() {
				elasticIPs = config.AWSElasticIPs()
				if len(elasticIPs) < 2 {
					Skip("Not enough AWS elastic IPs configured, unable to run elastic IP tests")
				}
			})

			It("should attach an elastic IP, mainline, single pod", func() {
				// Create client pod on first node with an elastic IP.
				nodes := nodesByZone[zoneToUse]
				cc := conncheck.NewClient("client", f.Namespace,
					conncheck.WithClientCustomizer(awsClientCustomizer(podSpec{NodeName: nodes[0].Name, ElasticIPs: elasticIPs})),
				)
				checker.AddClient(cc)
				checker.Deploy()
				// Should have connectivity within AWS using its own IP.
				expectInternalConnectivityWithOwnIP(checker, cc, extNode)
				// Should have connectivity to outside AWS with its elastic IP.
				expectExternalConnectivityWithElasticIP(checker, cc, elasticIPs)
			})

			for secondNodeIdx := 0; secondNodeIdx < 2; secondNodeIdx++ {
				secondNodeIdx := secondNodeIdx
				var description string
				if secondNodeIdx == 0 {
					description = "on same node"
				} else {
					description = "on different nodes"
				}

				It(fmt.Sprintf("should give different elastic IPs to different pods %s", description), func() {
					// Create client pod on first node with an elastic IP.
					nodes := nodesByZone[zoneToUse]
					cc1 := conncheck.NewClient("client-1", f.Namespace,
						conncheck.WithClientCustomizer(awsClientCustomizer(podSpec{NodeName: nodes[0].Name, ElasticIPs: elasticIPs})),
					)
					// Create a second client pod with the *same* list of elastic IPs.  Felix should choose
					// a different IP from the list for each of the two pods.
					cc2 := conncheck.NewClient("client-2", f.Namespace,
						conncheck.WithClientCustomizer(awsClientCustomizer(podSpec{NodeName: nodes[secondNodeIdx].Name, ElasticIPs: elasticIPs})),
					)
					checker.AddClient(cc1)
					checker.AddClient(cc2)
					checker.Deploy()
					// Both pods should have connectivity within AWS using its own IP.
					expectInternalConnectivityWithOwnIP(checker, cc1, extNode)
					expectInternalConnectivityWithOwnIP(checker, cc2, extNode)
					// Should have connectivity to outside AWS with their elastic IPs.
					eipPod1 := expectExternalConnectivityWithElasticIP(checker, cc1, elasticIPs)
					eipPod2 := expectExternalConnectivityWithElasticIP(checker, cc2, elasticIPs)
					Expect(eipPod1.Equal(eipPod2)).To(BeFalse(), "both client pods got same elastic IP")
				})

				It(fmt.Sprintf("should allow moving elastic IPs between pods %s", description), func() {
					// Create client pod on first node with an elastic IP.
					nodes := nodesByZone[zoneToUse]
					cc1 := conncheck.NewClient("client-1", f.Namespace,
						conncheck.WithClientCustomizer(awsClientCustomizer(podSpec{NodeName: nodes[0].Name, ElasticIPs: elasticIPs[:1]})),
					)
					// Create a second client pod with a different elastic IP.
					cc2 := conncheck.NewClient("client-2", f.Namespace,
						conncheck.WithClientCustomizer(awsClientCustomizer(podSpec{NodeName: nodes[secondNodeIdx].Name, ElasticIPs: elasticIPs[1:2]})),
					)
					checker.AddClient(cc1)
					checker.AddClient(cc2)
					checker.Deploy()
					// Both pods should have connectivity within AWS using its own IP.
					expectInternalConnectivityWithOwnIP(checker, cc1, extNode)
					expectInternalConnectivityWithOwnIP(checker, cc2, extNode)
					// Should have connectivity to outside AWS with their elastic IPs.
					expectExternalConnectivityWithElasticIP(checker, cc1, elasticIPs[:1])
					expectExternalConnectivityWithElasticIP(checker, cc2, elasticIPs[1:2])

					// Update the pods to switch the elastic IPs.
					eipAnnot1 := cc1.Pod().Annotations["cni.projectcalico.org/awsElasticIPs"]
					eipAnnot2 := cc2.Pod().Annotations["cni.projectcalico.org/awsElasticIPs"]
					podClient.Update(context.Background(), cc1.Pod().Name, func(pod *v1.Pod) {
						pod.Annotations["cni.projectcalico.org/awsElasticIPs"] = eipAnnot2
					})
					podClient.Update(context.Background(), cc2.Pod().Name, func(pod *v1.Pod) {
						pod.Annotations["cni.projectcalico.org/awsElasticIPs"] = eipAnnot1
					})

					// Should have connectivity to outside AWS with switched elastic IPs.
					expectExternalConnectivityWithElasticIP(checker, cc1, elasticIPs[1:2])
					expectExternalConnectivityWithElasticIP(checker, cc2, elasticIPs[:1])
				})
			}
		})

		Context("with maxBlocksPerHost increased", func() {
			var ipamConf *v3.IPAMConfiguration

			BeforeEach(func() {
				ipamConf = v3.NewIPAMConfiguration()
				ipamConf.Name = "default"
				ipamConf.Spec.StrictAffinity = true
				ipamConf.Spec.AutoAllocateBlocks = true
				ipamConf.Spec.MaxBlocksPerHost = 128
				err := cli.Create(context.Background(), ipamConf)
				if apierrors.IsAlreadyExists(err) {
					// Resource already exists (e.g. from a previous failed run); update it.
					existing := v3.NewIPAMConfiguration()
					Expect(cli.Get(context.Background(), ctrlclient.ObjectKeyFromObject(ipamConf), existing)).NotTo(HaveOccurred(),
						"Failed to get existing IPAMConfiguration")
					existing.Spec = ipamConf.Spec
					Expect(cli.Update(context.Background(), existing)).NotTo(HaveOccurred(),
						"Failed to update existing IPAMConfiguration")
					ipamConf = existing
				} else {
					Expect(err).NotTo(HaveOccurred(), "Failed to create IPAMConfiguration")
				}
			})

			AfterEach(func() {
				if ipamConf != nil {
					err := cli.Delete(context.Background(), ipamConf)
					Expect(err).NotTo(HaveOccurred())
				}
			})

			It("should handle the maximum number of pods per node", func() {
				node := nodesByZone[zoneToUse][0]
				capc64, ok := node.Status.Allocatable.Name("projectcalico.org/aws-secondary-ipv4", resource.DecimalSI).AsInt64()
				Expect(ok).To(BeTrue(), "Failed to read the aws-secondary-ipv4 capacity from a node")
				capc := int(capc64)

				// Account for any egress gateway pods already on the node; these will have claimed some IPs.
				capc -= numEGWsByNode[node.Name]

				var clients []*conncheck.Client
				for i := 0; i < capc; i++ {
					cc := conncheck.NewClient(fmt.Sprintf("client-%d", i), f.Namespace,
						conncheck.WithClientCustomizer(awsClientCustomizer(podSpec{NodeName: node.Name})),
					)
					checker.AddClient(cc)
					clients = append(clients, cc)
				}
				checker.Deploy()
				for _, cc := range clients {
					expectInternalConnectivityWithOwnIP(checker, cc, extNode)
				}
			})
		})
	})

// expectInternalConnectivityWithOwnIP verifies the pod can reach the external node's
// NGINX server and that NGINX sees the pod's own IP as the source.
func expectInternalConnectivityWithOwnIP(
	checker conncheck.ConnectionTester,
	cc *conncheck.Client,
	extNode *externalnode.Client,
) {
	clientPod := cc.Pod()
	By(fmt.Sprintf("checking that pod %s node=%s has connectivity with its own IP",
		clientPod.Name, clientPod.Spec.NodeName))

	sourceIP := connectToNGINXAndGetSourceIP(checker, cc, extNode, extNode.IP(), "", "60s")
	ExpectWithOffset(1, sourceIP).To(Equal(clientPod.Status.PodIP),
		"Expected pod %s node=%s to have connectivity with its own IP, but source IP was %s",
		clientPod.Name, clientPod.Spec.NodeName, sourceIP)
}

func numEGWsOnNode(f *framework.Framework, nodeName string) int {
	egPods, err := f.ClientSet.CoreV1().Pods(egressGatewayNS).List(context.Background(), metav1.ListOptions{})
	Expect(err).NotTo(HaveOccurred())
	numEGWs := 0
	for _, p := range egPods.Items {
		if p.GetLabels()["egress-code"] != "" {
			logrus.Infof("Found egress gateway pod %s on node %s with IP %s",
				p.Name, p.Spec.NodeName, p.Status.PodIP)
			if p.Spec.NodeName == nodeName {
				numEGWs++
			}
		}
	}
	return numEGWs
}

type podSpec struct {
	// NodeName is the name of the node to schedule the pod on (required)
	NodeName string

	Zone        string
	IPPoolNames []string
	IP          string
	ElasticIPs  []net.IP
}

// awsClientCustomizer returns a pod customizer that applies AWS-specific configuration
// (resource requests, ImagePullSecrets, annotations for IP pools/elastic IPs/DNS).
func awsClientCustomizer(spec podSpec) func(*v1.Pod) {
	return func(pod *v1.Pod) {
		pod.Spec.NodeName = spec.NodeName
		pod.Spec.ImagePullSecrets = []v1.LocalObjectReference{{Name: pullSecret}}
		pod.Spec.Containers[0].Resources = v1.ResourceRequirements{
			Limits: map[v1.ResourceName]resource.Quantity{
				"projectcalico.org/aws-secondary-ipv4": resource.MustParse("1"),
			},
			Requests: map[v1.ResourceName]resource.Quantity{
				"projectcalico.org/aws-secondary-ipv4": resource.MustParse("1"),
			},
		}
		pod.Spec.Tolerations = append(pod.Spec.Tolerations, opermeta.TolerateGKEARM64NoSchedule)
		pod.Spec.TerminationGracePeriodSeconds = ptr.Int64ToPtr(1)

		if pod.Annotations == nil {
			pod.Annotations = map[string]string{}
		}
		if len(spec.IPPoolNames) > 0 {
			poolsJSON, err := json.Marshal(spec.IPPoolNames)
			Expect(err).NotTo(HaveOccurred())
			pod.Annotations["cni.projectcalico.org/ipv4pools"] = string(poolsJSON)
		}
		if spec.IP != "" {
			pod.Annotations["cni.projectcalico.org/ipAddrs"] = fmt.Sprintf("[\"%s\"]", spec.IP)
		}
		if len(spec.ElasticIPs) > 0 {
			eipsJSON, err := json.Marshal(spec.ElasticIPs)
			Expect(err).NotTo(HaveOccurred())
			pod.Annotations["cni.projectcalico.org/awsElasticIPs"] = string(eipsJSON)

			// Workaround the fact that AWS-backed pods in our particular set-up don't have connectivity to
			// non-AWS-backed pods.  This is because we set up the IP pools with encap disabled, which is the right
			// setting for egress gateways, which never make outbound connections to in-cluster pods.  With encap
			// disabled, traffic to other pods takes an asymmetric path.
			pod.Spec.DNSConfig = &v1.PodDNSConfig{
				Nameservers: []string{"8.8.8.8"},
			}
		}
	}
}

// generateClientPod creates a standalone AWS-backed client pod spec. Used only for tests
// that expect pod creation to fail (e.g., wrong zone, missing resource requests).
func generateClientPod(spec podSpec) *v1.Pod {
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "client-",
		},
		Spec: v1.PodSpec{
			RestartPolicy: v1.RestartPolicyNever,
			Containers: []v1.Container{
				{
					Name:  "client",
					Image: images.Alpine,
					Args:  []string{"/bin/sh", "-c", "while true; do sleep 60; done"},
				},
			},
		},
	}
	awsClientCustomizer(spec)(pod)
	return pod
}

func waitForFailedPodSandbox(f *framework.Framework, pod *v1.Pod) (*v1.Event, error) {
	var ev *v1.Event
	err := wait.PollUntilContextTimeout(context.Background(), 2*time.Second, framework.PodStartTimeout, false,
		func(context.Context) (bool, error) {
			evnts, err := f.ClientSet.CoreV1().Events(pod.Namespace).SearchWithContext(context.TODO(), scheme.Scheme, pod)
			if err != nil {
				return false, fmt.Errorf("error in listing events: %s", err)
			}
			for _, e := range evnts.Items {
				switch e.Reason {
				case "FailedCreatePodSandBox":
					ev = &e
					return true, nil
				case "Started":
					return true, fmt.Errorf("pod started up instead of failing as expected")
				default:
					// ignore all other errors
				}
			}
			return false, nil
		})
	return ev, err
}
