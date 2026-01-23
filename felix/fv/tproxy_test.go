// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package fv_test

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	. "github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/tproxy"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/felix/tproxydefs"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

var (
	_ = describeTProxyTest(false, "Enabled")
	_ = describeTProxyTest(true, "Enabled")
	_ = describeTProxyTest(false, "EnabledAllServices")
)

const (
	// duration is how long to wait for a condition to become true.
	duration = 1 * time.Second

	// retry is how often to check the condition.
	retry = 250 * time.Millisecond
)

func tablesWaitForPolicy(policy string, felixes ...*infrastructure.Felix) error {
	for _, f := range felixes {
		var out string
		var err error
		if NFTMode() {
			out, err = f.ExecOutput("nft", "list", "ruleset")
		} else {
			out, err = f.ExecOutput("iptables-save", "-t", "filter")
		}
		if err != nil {
			return err
		}
		if strings.Count(out, policy) == 0 {
			return fmt.Errorf("policy %s is not yet in dataplane in felix %s\n%s", policy, f.Name, out)
		}
	}
	return nil
}

func tablesWaitForPolicyFn(policy string, felixes ...*infrastructure.Felix) func() error {
	return func() error {
		return tablesWaitForPolicy(policy, felixes...)
	}
}

func describeTProxyTest(ipip bool, TPROXYMode string) bool {
	const (
		l7LoggingAnnotation = "projectcalico.org/l7-logging"
		TPROXYPodToSelf     = "cali40tproxy-pod-self"
	)

	var (
		TPROXYServiceIPsIPSetV4 = fmt.Sprintf("cali40%s", tproxydefs.ServiceIPsIPSet)
		TPROXYNodeportsSet      = fmt.Sprintf("cali40%s", tproxydefs.NodePortsIPSet)
	)

	var expectedFelix0IP, expectedFelix1IP ExpectationOption

	tunnel := "none"
	if ipip {
		tunnel = "ipip"
	}

	return infrastructure.DatastoreDescribe("tproxy tests tunnel="+tunnel+" TPROXYMode="+TPROXYMode,
		[]apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
			const numNodes = 2
			const clusterIP = "10.101.0.10"

			var (
				infra        infrastructure.DatastoreInfra
				tc           infrastructure.TopologyContainers
				proxies      []*tproxy.TProxy
				cc           *Checker
				options      infrastructure.TopologyOptions
				calicoClient client.Interface
				w            [numNodes][2]*workload.Workload
				hostW        [numNodes]*workload.Workload
				clientset    *kubernetes.Clientset
			)

			createPolicy := func(policy *api.GlobalNetworkPolicy) *api.GlobalNetworkPolicy {
				log.WithField("policy", dumpResource(policy)).Info("Creating policy")
				policy, err := calicoClient.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())
				return policy
			}

			createService := func(service *v1.Service, client *kubernetes.Clientset) *v1.Service {
				log.WithField("service", dumpResource(service)).Info("Creating service")
				svc, err := client.CoreV1().Services(service.Namespace).Create(context.Background(), service, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(k8sGetEpsForServiceFunc(client, service), "10s").Should(HaveLen(1),
					"Service endpoints didn't get created? Is controller-manager happy?")
				log.WithField("service", dumpResource(svc)).Info("created service")

				return svc
			}

			assertIPPortInIPSetErr := func(ipSetID string,
				ip string,
				port string,
				felixes []*infrastructure.Felix,
				exists bool,
				canErr bool,
			) {
				results := make(map[*infrastructure.Felix]struct{}, len(felixes))
				Eventually(func() bool {
					for _, felix := range felixes {
						var out string
						var err error
						if NFTMode() {
							out, err = felix.ExecOutput("nft", "list", "set", "ip", "calico", ipSetID)
						} else {
							out, err = felix.ExecOutput("ipset", "list", ipSetID)
						}
						log.Infof("felix ipset list output %s", out)
						if canErr && err != nil {
							continue
						}
						Expect(err).NotTo(HaveOccurred())
						if (strings.Contains(out, ip) && strings.Contains(out, port)) == exists {
							results[felix] = struct{}{}
						}
					}
					return len(results) == len(tc.Felixes)
				}, "90s", "5s").Should(BeTrue())
			}

			assertIPPortInIPSet := func(ipSetID string,
				ip string,
				port string,
				felixes []*infrastructure.Felix,
				exists bool,
			) {
				assertIPPortInIPSetErr(ipSetID, ip, port, tc.Felixes, exists, false)
			}

			assertPortInIPSet := func(ipSetID string, port string, felixes []*infrastructure.Felix, exists bool) {
				results := make(map[*infrastructure.Felix]struct{}, len(tc.Felixes))
				Eventually(func() bool {
					for _, felix := range tc.Felixes {
						var out string
						var err error
						if NFTMode() {
							out, err = felix.ExecOutput("nft", "list", "set", "ip", "calico", ipSetID)
						} else {
							out, err = felix.ExecOutput("ipset", "list", ipSetID)
						}
						log.Infof("felix ipset list output %s", out)
						Expect(err).NotTo(HaveOccurred())
						if strings.Contains(out, port) == exists {
							results[felix] = struct{}{}
						}
					}
					return len(results) == len(tc.Felixes)
				}, "90s", "5s").Should(BeTrue())
			}

			BeforeEach(func() {
				options = infrastructure.DefaultTopologyOptions()

				cc = &Checker{
					CheckSNAT: true,
				}
				cc.Protocol = "tcp"

				options.NATOutgoingEnabled = true
				options.AutoHEPsEnabled = true
				options.DelayFelixStart = true
				options.TriggerDelayedFelixStart = true

				// XXX until we can safely remove roting rules and not break other tests
				options.EnableIPv6 = false

				if !ipip {
					options.IPIPMode = api.IPIPModeNever
				}

				options.ExtraEnvVars["FELIX_DEFAULTENDPOINTTOHOSTACTION"] = "Accept"
				// XXX until we can safely remove roting rules and not break other tests
				options.EnableIPv6 = false

				config := api.NewFelixConfiguration()
				config.SetName("default")
				config.Spec.TPROXYMode = TPROXYMode

				options.InitialFelixConfiguration = config

				infra = getInfra()
				clientset = infra.(*infrastructure.K8sDatastoreInfra).K8sClient

				tc, calicoClient = infrastructure.StartNNodeTopology(numNodes, options, infra)

				if !ipip {
					expectedFelix0IP = ExpectWithSrcIPs(tc.Felixes[0].IP)
					expectedFelix1IP = ExpectWithSrcIPs(tc.Felixes[1].IP)
				} else {
					expectedFelix0IP = ExpectWithSrcIPs(tc.Felixes[0].ExpectedIPIPTunnelAddr)
					expectedFelix1IP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedIPIPTunnelAddr)
				}

				proxies = []*tproxy.TProxy{}
				for _, felix := range tc.Felixes {
					proxy := tproxy.New(felix, 16001)
					proxy.Start()
					proxies = append(proxies, proxy)
				}

				addWorkload := func(ii, wi, port int, labels map[string]string) *workload.Workload {
					if labels == nil {
						labels = make(map[string]string)
					}

					wIP := fmt.Sprintf("10.65.%d.%d", ii, wi+2)
					wName := fmt.Sprintf("w%d%d", ii, wi)

					infrastructure.AssignIP(wName, wIP, tc.Felixes[ii].Hostname, calicoClient)
					w := workload.New(tc.Felixes[ii], wName, "default",
						wIP, strconv.Itoa(port), "tcp")
					Expect(w.Start(infra)).To(Succeed())

					labels["name"] = w.Name
					labels["workload"] = "regular"

					w.WorkloadEndpoint.Labels = labels
					w.ConfigureInInfra(infra)
					return w
				}

				for ii := range tc.Felixes {
					hostW[ii] = workload.Run(
						tc.Felixes[ii],
						fmt.Sprintf("host%d", ii),
						"default",
						tc.Felixes[ii].IP, // Same IP as felix means "run in the host's namespace"
						"8055",
						"tcp")
					hostW[ii].ConfigureInInfra(infra)

					// Two workloads on each host so we can check the same host and other host cases.
					w[ii][0] = addWorkload(ii, 0, 8055, nil)
					w[ii][1] = addWorkload(ii, 1, 8055, nil)
				}

				var (
					pol       *api.GlobalNetworkPolicy
					k8sClient *kubernetes.Clientset
				)

				pol = api.NewGlobalNetworkPolicy()
				pol.Namespace = "fv"
				pol.Name = "policy-1"
				pol.Spec.Ingress = []api.Rule{
					{
						Action: "Allow",
						Source: api.EntityRule{
							Selector: "workload=='regular'",
						},
					},
				}
				pol.Spec.Egress = []api.Rule{
					{
						Action: "Allow",
						Source: api.EntityRule{
							Selector: "workload=='regular'",
						},
					},
				}
				pol.Spec.Selector = "workload=='regular'"
				hundred := float64(100)
				pol.Spec.Order = &hundred

				pol = createPolicy(pol)

				k8sClient = infra.(*infrastructure.K8sDatastoreInfra).K8sClient
				_ = k8sClient

				// Make sure the ipsets exist before we do testing. This means
				// that we can sync with the content of the maps.
				Eventually(func() bool {
					for _, felix := range tc.Felixes {
						if NFTMode() {
							if _, err := felix.ExecOutput("nft", "list", "set", "ip", "calico", "cali40tproxy-svc-ips"); err != nil {
								return false
							}
						} else {
							if _, err := felix.ExecOutput("ipset", "list", "cali40tproxy-svc-ips"); err != nil {
								return false
							}
						}
					}
					return true
				}, "20s", "1s").Should(BeTrue(), "cali40tproxy-svc-ips IP sets didn't show up?")
			})

			JustAfterEach(func() {
				for _, p := range proxies {
					p.Stop()
				}

				if CurrentGinkgoTestDescription().Failed {
					for _, felix := range tc.Felixes {
						logNFTDiags(felix)
						felix.Exec("iptables-save", "-c")
						felix.Exec("ipset", "list", TPROXYServiceIPsIPSetV4)
						felix.Exec("ipset", "list", TPROXYNodeportsSet)
						felix.Exec("ipset", "list", TPROXYPodToSelf)
						felix.Exec("ip", "route")
					}
				}
			})

			Context("Pod-Pod", func() {
				It("should have connectivity from all workloads via w[0][0].IP", func() {
					cc.Expect(Some, w[0][1], w[0][0], ExpectWithPorts(8055))
					cc.Expect(Some, w[1][0], w[0][0], ExpectWithPorts(8055))
					cc.Expect(Some, w[1][1], w[0][0], ExpectWithPorts(8055))
					cc.CheckConnectivity()
				})
			})

			Context("ClusterIP", func() {
				var pod, svc string

				JustBeforeEach(func() {
					pod = w[0][0].IP + ":8055"
					svc = clusterIP + ":8090"

					for _, f := range tc.Felixes {
						if NFTMode() {
							f.Exec("nft", "add", "table", "ip", "services")

							// Mimic the kube-proxy service iptable clusterIP rule.
							f.Exec("nft", "add", "chain", "ip", "services", "PREROUTING", "{ type nat hook prerouting priority -100; }")
							f.Exec("nft", "add", "rule", "ip", "services", "PREROUTING", "ip", "daddr", clusterIP, "tcp", "dport", "8090", "counter", "dnat", "to", pod)

							// Mimic the kube-proxy MASQ rule based on the kube-proxy bit
							f.Exec("nft", "add", "chain", "ip", "services", "POSTROUTING", "{ type nat hook postrouting priority 100 ; }")
							f.Exec("nft", "add", "rule", "ip", "services", "POSTROUTING", "mark", "and", "0x4000", "==", "0x4000", "counter", "masquerade", "fully-random")
						} else {
							// Mimic the kube-proxy service iptable clusterIP rule.
							f.Exec("iptables", "-t", "nat", "-A", "PREROUTING",
								"-w", "10", // Retry this for 10 seconds, e.g. if something else is holding the lock
								"-W", "100000", // How often to probe the lock in microsecs.
								"-p", "tcp",
								"-d", clusterIP,
								"-m", "tcp", "--dport", "8090",
								"-j", "DNAT", "--to-destination",
								pod)
							// Mimic the kube-proxy MASQ rule based on the kube-proxy bit
							f.Exec("iptables", "-t", "nat", "-A", "POSTROUTING",
								"-w", "10", // Retry this for 10 seconds, e.g. if something else is holding the lock
								"-W", "100000", // How often to probe the lock in microsecs.
								"-m", "mark", "--mark", "0x4000/0x4000", // 0x4000 is the deault --iptables-masquerade-bit
								"-j", "MASQUERADE", "--random-fully")
						}
					}
					// for this context create service before each test
					v1Svc := k8sService("service-with-annotation", clusterIP, w[0][0], 8090, 8055, 0, "tcp")
					if TPROXYMode == "Enabled" {
						v1Svc.Annotations = map[string]string{l7LoggingAnnotation: "true"}
					}
					createService(v1Svc, clientset)
				})

				It("should have connectivity from all workloads via ClusterIP", func() {
					By("asserting that ipaddress, port exists in ipset")
					assertIPPortInIPSet(TPROXYServiceIPsIPSetV4, clusterIP, "8090", tc.Felixes, true)

					cc.Expect(Some, w[0][0], TargetIP(clusterIP), ExpectWithPorts(8090), expectedFelix0IP)
					cc.Expect(Some, w[0][1], TargetIP(clusterIP), ExpectWithPorts(8090))
					cc.Expect(Some, w[1][0], TargetIP(clusterIP), ExpectWithPorts(8090))
					cc.Expect(Some, w[1][1], TargetIP(clusterIP), ExpectWithPorts(8090))
					cc.CheckConnectivity()

					// Connection should be proxied on the pod's local node
					Eventually(proxies[0].ProxiedCountFn(w[0][0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
					Eventually(proxies[0].ProxiedCountFn(w[0][1].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
					Eventually(proxies[1].ProxiedCountFn(w[1][0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
					Eventually(proxies[1].ProxiedCountFn(w[1][1].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))

					// Connection should not be proxied on the backend pod's node
					Consistently(proxies[0].ProxiedCountFn(w[1][0].IP, pod, svc), duration, retry).Should(BeZero())
					Consistently(proxies[0].ProxiedCountFn(w[1][1].IP, pod, svc), duration, retry).Should(BeZero())
				})

				Context("With ingress traffic denied from w[0][1] and w[1][1]", func() {
					It("should have connectivity only from w[1][0]", func() {
						By("Denying traffic from w[1][1] and w[0][1]", func() {
							pol := api.NewGlobalNetworkPolicy()
							pol.Namespace = "fv"
							pol.Name = "policy-deny-1-1"
							pol.Spec.Ingress = []api.Rule{
								{
									Action: "Deny",
									Source: api.EntityRule{
										Selector: "(name=='" + w[1][1].Name + "') || (name=='" + w[0][1].Name + "')",
									},
								},
							}
							pol.Spec.Selector = "name=='" + w[0][0].Name + "'"
							one := float64(1)
							pol.Spec.Order = &one

							pol = createPolicy(pol)
						})
						By("asserting that ipaddress, port exists in ipset ")
						assertIPPortInIPSet(TPROXYServiceIPsIPSetV4, clusterIP, "8090", tc.Felixes, true)
						assertIPPortInIPSet(TPROXYServiceIPsIPSetV4, w[0][0].IP, "8090", tc.Felixes, true)

						By("waiting for deny policy to be programmed")
						Eventually(tablesWaitForPolicyFn("gnp/policy-deny-1-1", tc.Felixes[0]), "10s", "1s").Should(Succeed())

						cc.Expect(Some, w[0][0], TargetIP(clusterIP), ExpectWithPorts(8090), expectedFelix0IP)
						cc.Expect(Some, w[1][0], TargetIP(clusterIP), ExpectWithPorts(8090))
						cc.Expect(None, w[0][1], TargetIP(clusterIP), ExpectWithPorts(8090))
						cc.Expect(None, w[1][1], TargetIP(clusterIP), ExpectWithPorts(8090))
						cc.CheckConnectivity()

						// w[0][0] goes through the proxy and back to itself.  No policy to block it.
						Eventually(proxies[0].AcceptedCountFn(w[0][0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
						Eventually(proxies[0].ProxiedCountFn(w[0][0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
						Consistently(proxies[1].AcceptedCountFn(w[0][0].IP, pod, svc), duration, retry).Should(BeZero(),
							"w[0][0]'s traffic should go to its local proxy only")

						// w[0][1] reaches the local proxy but the proxy's connection gets blocked by the ingress policy.
						Eventually(proxies[0].AcceptedCountFn(w[0][1].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
						Consistently(proxies[0].ProxiedCountFn(w[0][1].IP, pod, svc), duration, retry).Should(BeZero())
						Consistently(proxies[1].AcceptedCountFn(w[0][1].IP, pod, svc), duration, retry).Should(BeZero(),
							"w[0][0]'s traffic should go to its local proxy only")

						// w[1][0] goes through both proxies and reaches w[0][0].
						Eventually(proxies[1].AcceptedCountFn(w[1][0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
						Eventually(proxies[1].ProxiedCountFn(w[1][0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
						Eventually(proxies[0].AcceptedCountFn(w[1][0].IP, pod, pod), duration, retry).Should(BeNumerically(">", 0))
						Eventually(proxies[0].ProxiedCountFn(w[1][0].IP, pod, pod), duration, retry).Should(BeNumerically(">", 0))

						// w[1][1] reaches its local proxy, which successfully connects to the remote proxy
						// but its connection is blocked by policy.
						Eventually(proxies[1].AcceptedCountFn(w[1][1].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
						Eventually(proxies[1].ProxiedCountFn(w[1][1].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
						Eventually(proxies[0].AcceptedCountFn(w[1][1].IP, pod, pod), duration, retry).Should(BeNumerically(">", 0))
						Consistently(proxies[0].ProxiedCountFn(w[1][1].IP, pod, pod), duration, retry).Should(BeZero())
					})
				})

				Context("With egress traffic denied from w[1][1]", func() {
					It("should have connectivity only from w[0][1] and w[1][0]", func() {
						By("Denying traffic from w[1][1]", func() {
							pol := api.NewGlobalNetworkPolicy()
							pol.Namespace = "fv"
							pol.Name = "policy-deny-1-1"
							pol.Spec.Egress = []api.Rule{
								{
									Action: "Deny",
									Destination: api.EntityRule{
										Selector: "name=='" + w[0][0].Name + "'",
									},
								},
							}
							pol.Spec.Selector = "name=='" + w[1][1].Name + "'"
							one := float64(1)
							pol.Spec.Order = &one

							pol = createPolicy(pol)
						})

						By("asserting that ipaddress, port exists in ipset ")
						assertIPPortInIPSet(TPROXYServiceIPsIPSetV4, clusterIP, "8090", tc.Felixes, true)

						By("waiting for deny policy to be programmed")
						Eventually(tablesWaitForPolicyFn("gnp/policy-deny-1-1", tc.Felixes[1]), "10s", "1s").Should(Succeed())

						cc.Expect(Some, w[0][0], TargetIP(clusterIP), ExpectWithPorts(8090), expectedFelix0IP)
						cc.Expect(Some, w[0][1], TargetIP(clusterIP), ExpectWithPorts(8090))
						cc.Expect(Some, w[1][0], TargetIP(clusterIP), ExpectWithPorts(8090))
						cc.Expect(None, w[1][1], TargetIP(clusterIP), ExpectWithPorts(8090))
						cc.CheckConnectivity()

						// Connection should be proxied on the pod's local node
						Eventually(proxies[0].AcceptedCountFn(w[0][0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
						Eventually(proxies[0].AcceptedCountFn(w[0][1].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
						Eventually(proxies[1].AcceptedCountFn(w[1][0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
						Consistently(proxies[1].AcceptedCountFn(w[1][1].IP, pod, svc), duration, retry).Should(BeZero())

						Eventually(proxies[0].ProxiedCountFn(w[0][0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
						Eventually(proxies[0].ProxiedCountFn(w[0][1].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
						Eventually(proxies[1].ProxiedCountFn(w[1][0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
						Consistently(proxies[1].ProxiedCountFn(w[1][1].IP, pod, svc), duration, retry).Should(BeZero())
					})
				})

				Context("With ingress traffic denied from w[0]0] to self", func() {
					It("should have connectivity from all but self", func() {
						By("Denying traffic from w[1][1]", func() {
							pol := api.NewGlobalNetworkPolicy()
							pol.Namespace = "fv"
							pol.Name = "policy-deny-1-1"
							pol.Spec.Ingress = []api.Rule{
								{
									Action: "Deny",
									Source: api.EntityRule{
										Selector: "(name=='" + w[0][0].Name + "')",
									},
								},
							}
							pol.Spec.Selector = "name=='" + w[0][0].Name + "'"
							one := float64(1)
							pol.Spec.Order = &one

							pol = createPolicy(pol)
						})
						By("asserting that ipaddress, port exists in ipset ")
						assertIPPortInIPSet(TPROXYServiceIPsIPSetV4, clusterIP, "8090", tc.Felixes, true)

						By("waiting for deny policy to be programmed")
						Eventually(tablesWaitForPolicyFn("gnp/policy-deny-1-1", tc.Felixes[0]), "10s", "1s").Should(Succeed())

						cc.Expect(None, w[0][0], TargetIP(clusterIP), ExpectWithPorts(8090))
						cc.Expect(Some, w[0][1], TargetIP(clusterIP), ExpectWithPorts(8090))
						cc.Expect(Some, w[1][0], TargetIP(clusterIP), ExpectWithPorts(8090))
						cc.Expect(Some, w[1][1], TargetIP(clusterIP), ExpectWithPorts(8090))
						cc.CheckConnectivity()

						// Connection should be proxied on the pod's local node

						Eventually(proxies[0].AcceptedCountFn(w[0][0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
						Eventually(proxies[0].AcceptedCountFn(w[0][1].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
						Eventually(proxies[1].AcceptedCountFn(w[1][0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
						Eventually(proxies[1].AcceptedCountFn(w[1][1].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))

						Consistently(proxies[0].ProxiedCountFn(w[0][0].IP, pod, svc), duration, retry).Should(BeZero())
						Eventually(proxies[0].ProxiedCountFn(w[0][1].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
						Eventually(proxies[1].ProxiedCountFn(w[1][0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
						Eventually(proxies[1].ProxiedCountFn(w[1][1].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
					})
				})

				Context("With egress traffic denied from w[0]0] to self", func() {
					It("should have connectivity from all but self", func() {
						By("Denying traffic from w[1][1]", func() {
							pol := api.NewGlobalNetworkPolicy()
							pol.Namespace = "fv"
							pol.Name = "policy-deny-1-1"
							pol.Spec.Egress = []api.Rule{
								{
									Action: "Deny",
									Source: api.EntityRule{
										Selector: "(name=='" + w[0][0].Name + "')",
									},
								},
							}
							pol.Spec.Selector = "name=='" + w[0][0].Name + "'"
							one := float64(1)
							pol.Spec.Order = &one

							pol = createPolicy(pol)
						})
						By("asserting that ipaddress, port exists in ipset ")
						assertIPPortInIPSet(TPROXYServiceIPsIPSetV4, clusterIP, "8090", tc.Felixes, true)

						By("waiting for deny policy to be programmed")
						Eventually(tablesWaitForPolicyFn("gnp/policy-deny-1-1", tc.Felixes[0]), "10s", "1s").Should(Succeed())

						cc.Expect(None, w[0][0], TargetIP(clusterIP), ExpectWithPorts(8090))
						cc.Expect(Some, w[0][1], TargetIP(clusterIP), ExpectWithPorts(8090))
						cc.Expect(Some, w[1][0], TargetIP(clusterIP), ExpectWithPorts(8090))
						cc.Expect(Some, w[1][1], TargetIP(clusterIP), ExpectWithPorts(8090))
						cc.CheckConnectivity()

						// Connection should be proxied on the pod's local node

						Consistently(proxies[0].AcceptedCountFn(w[0][0].IP, pod, svc), duration, retry).Should(BeZero())
						Eventually(proxies[0].AcceptedCountFn(w[0][1].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
						Eventually(proxies[1].AcceptedCountFn(w[1][0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
						Eventually(proxies[1].AcceptedCountFn(w[1][1].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))

						Consistently(proxies[0].ProxiedCountFn(w[0][0].IP, pod, svc), duration, retry).Should(BeZero())
						Eventually(proxies[0].ProxiedCountFn(w[0][1].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
						Eventually(proxies[1].ProxiedCountFn(w[1][0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
						Eventually(proxies[1].ProxiedCountFn(w[1][1].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
					})
				})
			})

			Context("NodePorts", func() {
				var pod, svc string

				nodeport := uint16(30333)

				var opts []ExpectationOption

				tcpProto := numorstring.ProtocolFromString("tcp")

				JustBeforeEach(func() {
					pod = w[0][0].IP + ":8055"
					pod = w[0][0].IP + ":8055"
					svc = tc.Felixes[0].IP + ":" + strconv.Itoa(int(nodeport))

					// Mimic the kube-proxy service iptable nodeport rule.
					for _, f := range tc.Felixes {
						if NFTMode() {
							f.Exec("nft", "add", "table", "ip", "services")
							f.Exec("nft", "add", "chain", "ip", "services", "PREROUTING", "{ type nat hook prerouting priority -100; }")
							f.Exec("nft", "add", "rule", "ip", "services", "PREROUTING", "fib", "daddr", "type", "local", "tcp", "dport", strconv.Itoa(int(nodeport)), "counter", "meta", "mark", "set", "mark", "or", "0x4000")
							f.Exec("nft", "add", "rule", "ip", "services", "PREROUTING", "fib", "daddr", "type", "local", "tcp", "dport", strconv.Itoa(int(nodeport)), "counter", "dnat", "to", pod)
							f.Exec("nft", "add", "chain", "ip", "services", "POSTROUTING", "{ type nat hook postrouting priority 100 ; }")
							f.Exec("nft", "add", "rule", "ip", "services", "POSTROUTING", "mark", "and", "0x4000", "==", "0x4000", "counter", "masquerade", "fully-random")
						} else {
							f.Exec("iptables", "-t", "nat",
								"-w", "10", // Retry this for 10 seconds, e.g. if something else is holding the lock
								"-W", "100000", // How often to probe the lock in microsecs.
								"-A", "PREROUTING",
								"-p", "tcp",
								"-m", "addrtype", "--dst-type", "LOCAL",
								"-m", "tcp", "--dport", strconv.Itoa(int(nodeport)),
								"-j", "MARK", "--set-xmark", "0x4000/0x4000")
							f.Exec("iptables", "-t", "nat",
								"-w", "10", // Retry this for 10 seconds, e.g. if something else is holding the lock
								"-W", "100000", // How often to probe the lock in microsecs.
								"-A", "PREROUTING",
								"-p", "tcp",
								"-m", "addrtype", "--dst-type", "LOCAL",
								"-m", "tcp", "--dport", strconv.Itoa(int(nodeport)),
								"-j", "DNAT", "--to-destination", pod)
							f.Exec("iptables", "-t", "nat",
								"-w", "10", // Retry this for 10 seconds, e.g. if something else is holding the lock
								"-W", "100000", // How often to probe the lock in microsecs.
								"-A", "POSTROUTING",
								"-m", "mark", "--mark", "0x4000/0x4000",
								"-j", "MASQUERADE")
						}
					}

					// for this context create service before each test
					v1Svc := k8sService("service-with-annotation", clusterIP, w[0][0], 8090, 8055, int32(nodeport), "tcp")
					if TPROXYMode == "Enabled" {
						v1Svc.Annotations = map[string]string{l7LoggingAnnotation: "true"}
					}
					createService(v1Svc, clientset)

					assertPortInIPSet(TPROXYNodeportsSet, "30333", tc.Felixes, true)

					for _, f := range tc.Felixes {
						if NFTMode() {
							Eventually(func() string {
								out, err := f.ExecOutput("nft", "list", "ruleset")
								Expect(err).NotTo(HaveOccurred())
								return out
							}, "10s").Should(ContainSubstring("tproxy to"))
						} else {
							Eventually(func() string {
								out, err := f.ExecOutput("iptables-save")
								Expect(err).NotTo(HaveOccurred())
								return out
							}, "10s").Should(ContainSubstring("TPROXY"))
						}
					}

					pol := api.NewGlobalNetworkPolicy()
					pol.Namespace = "fv"
					pol.Name = "policy-allow-8055-from-any"
					pol.Spec.Ingress = []api.Rule{
						{
							Action:   "Allow",
							Protocol: &tcpProto,
							Destination: api.EntityRule{
								Ports: []numorstring.Port{numorstring.SinglePort(8055)},
							},
						},
					}
					pol.Spec.Selector = "name=='" + w[0][0].Name + "'"
					hundred := float64(100)
					pol.Spec.Order = &hundred

					pol = createPolicy(pol)

					opts = []ExpectationOption{ExpectWithPorts(nodeport), expectedFelix0IP}
				})

				It("should have connectivity from all workloads via NodePort on node 0", func() {
					cc.Expect(Some, w[0][0], TargetIP(tc.Felixes[0].IP), opts...)
					cc.Expect(Some, w[0][1], TargetIP(tc.Felixes[0].IP), opts...)
					cc.Expect(Some, w[1][0], TargetIP(tc.Felixes[0].IP), opts...)
					cc.Expect(Some, w[1][1], TargetIP(tc.Felixes[0].IP), opts...)
					cc.CheckConnectivity()

					// Connection should be proxied at the nodeport's node
					Eventually(proxies[0].ProxiedCountFn(w[0][0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
					Eventually(proxies[0].ProxiedCountFn(w[0][1].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
					// Due to NAT outgoing
					Eventually(proxies[0].ProxiedCountFn(tc.Felixes[1].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))

					// Connection should not be proxied on the client pod's node
					Consistently(proxies[1].AcceptedCountFn(w[1][0].IP, pod, svc), duration, retry).Should(BeZero())
					Consistently(proxies[1].AcceptedCountFn(w[1][1].IP, pod, svc), duration, retry).Should(BeZero())
				})

				It("should have connectivity from all workloads via NodePort on node 1", func() {
					svc = tc.Felixes[1].IP + ":" + strconv.Itoa(int(nodeport))
					opts = []ExpectationOption{ExpectWithPorts(nodeport), expectedFelix1IP}

					cc.Expect(Some, w[0][0], TargetIP(tc.Felixes[1].IP), opts...)
					cc.Expect(Some, w[0][1], TargetIP(tc.Felixes[1].IP), opts...)
					cc.Expect(Some, w[1][0], TargetIP(tc.Felixes[1].IP), opts...)
					cc.Expect(Some, w[1][1], TargetIP(tc.Felixes[1].IP), opts...)
					cc.CheckConnectivity()

					// Connection should be proxied at the nodeport's node
					Eventually(proxies[1].ProxiedCountFn(w[1][0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
					Eventually(proxies[1].ProxiedCountFn(w[1][1].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
					// Due to NAT outgoing
					Eventually(proxies[1].ProxiedCountFn(tc.Felixes[0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))

					// Connection should not be proxied on the client pod's node
					Consistently(proxies[0].AcceptedCountFn(w[0][0].IP, pod, svc), duration, retry).Should(BeZero())
					Consistently(proxies[0].AcceptedCountFn(w[0][1].IP, pod, svc), duration, retry).Should(BeZero())
				})

				// The ingress policy tests are not realistinc policies for NodePorts.
				// These test should only demonstrate, that the upstream connections go
				// through an ingress policy in OUTPUT chain and codify the behavior. That
				// is the same as if there was no proxy at all.
				//
				// There are no egress policy tests because that path is the same as for
				// regular services.

				Context("With ingress traffic denied from pod IPs to nodeport", func() {
					It("local pods should have no connectivity to w[0][0]", func() {
						By("Denying traffic from pods to nodeport", func() {
							pol := api.NewGlobalNetworkPolicy()
							pol.Namespace = "fv"
							pol.Name = "policy-deny-1-1"
							pol.Spec.Ingress = []api.Rule{
								{
									Action:   "Deny",
									Protocol: &tcpProto,
									Source: api.EntityRule{
										Nets: []string{"10.65.0.0/16"},
									},
									Destination: api.EntityRule{
										Ports: []numorstring.Port{numorstring.SinglePort(8055)},
									},
								},
							}
							pol.Spec.Selector = "name=='" + w[0][0].Name + "'"
							one := float64(1)
							pol.Spec.Order = &one

							pol = createPolicy(pol)
						})

						By("waiting for deny policy to be programmed")
						Eventually(tablesWaitForPolicyFn("gnp/policy-deny-1-1", tc.Felixes[0]), "10s", "1s").Should(Succeed())

						cc.Expect(None, w[0][0], TargetIP(tc.Felixes[0].IP), opts...)
						cc.Expect(None, w[0][1], TargetIP(tc.Felixes[0].IP), opts...)
						cc.Expect(Some, w[1][0], TargetIP(tc.Felixes[0].IP), opts...)
						cc.Expect(Some, w[1][1], TargetIP(tc.Felixes[0].IP), opts...)
						cc.CheckConnectivity()

						// Connection should be proxied at the nodeport's node
						Eventually(proxies[0].AcceptedCountFn(w[0][0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
						Eventually(proxies[0].AcceptedCountFn(w[0][1].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
						Consistently(proxies[0].ProxiedCountFn(w[0][0].IP, pod, svc), duration, retry).Should(BeZero())
						Consistently(proxies[0].ProxiedCountFn(w[0][1].IP, pod, svc), duration, retry).Should(BeZero())
						// Due to NAT outgoing
						Eventually(proxies[0].ProxiedCountFn(tc.Felixes[1].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))

						// Connection should not be proxied on the client pod's node
						Consistently(proxies[1].AcceptedCountFn(w[1][0].IP, pod, svc), duration, retry).Should(BeZero())
						Consistently(proxies[1].AcceptedCountFn(w[1][1].IP, pod, svc), duration, retry).Should(BeZero())
					})
				})

				Context("With ingress traffic denied from testContainers.Felix[1].IP to nodeport", func() {
					It("pods should have no connectivity to w[0][0]", func() {
						svc = tc.Felixes[1].IP + ":" + strconv.Itoa(int(nodeport))
						opts = []ExpectationOption{ExpectWithPorts(nodeport), expectedFelix1IP}

						felix1IP := tc.Felixes[1].IP
						if ipip {
							felix1IP = tc.Felixes[1].ExpectedIPIPTunnelAddr
						}

						By("Denying traffic from testContainers.Felix[0].IP to nodeport", func() {
							pol := api.NewGlobalNetworkPolicy()
							pol.Namespace = "fv"
							pol.Name = "policy-deny-1-1"
							pol.Spec.Ingress = []api.Rule{
								{
									Action:   "Deny",
									Protocol: &tcpProto,
									Source: api.EntityRule{
										Nets: []string{felix1IP + "/32"},
									},
									Destination: api.EntityRule{
										Ports: []numorstring.Port{numorstring.SinglePort(8055)},
									},
								},
							}
							pol.Spec.Selector = "name=='" + w[0][0].Name + "'"
							one := float64(1)
							pol.Spec.Order = &one

							pol = createPolicy(pol)
						})

						cc.Expect(None, w[0][0], TargetIP(tc.Felixes[1].IP), opts...)
						cc.Expect(None, w[0][1], TargetIP(tc.Felixes[1].IP), opts...)
						cc.Expect(None, w[1][0], TargetIP(tc.Felixes[1].IP), opts...)
						cc.Expect(None, w[1][1], TargetIP(tc.Felixes[1].IP), opts...)
						cc.CheckConnectivity()

						// Connection should be proxied at the nodeport's node
						Eventually(proxies[1].AcceptedCountFn(w[1][0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
						Eventually(proxies[1].AcceptedCountFn(w[1][1].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
						// Due to NAT outgoing
						Eventually(proxies[1].AcceptedCountFn(tc.Felixes[0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))

						// Connection should not be proxied on the client pod's node
						Consistently(proxies[0].AcceptedCountFn(w[0][1].IP, pod, svc), duration, retry).Should(BeZero())
						Consistently(proxies[0].AcceptedCountFn(w[0][1].IP, pod, svc), duration, retry).Should(BeZero())
					})
				})

				Context("With external client", func() {
					var externalClient *containers.Container

					BeforeEach(func() {
						externalClient = infrastructure.RunExtClient(infra, "ext-client")
					})

					AfterEach(func() {
						externalClient.Stop()
					})

					It("should have connectivity via node 0", func() {
						cc.Expect(Some, externalClient, TargetIP(tc.Felixes[0].IP),
							ExpectWithSrcIPs(tc.Felixes[0].IP), ExpectWithPorts(nodeport), expectedFelix0IP)
						cc.CheckConnectivity()

						Eventually(proxies[0].ProxiedCountFn(externalClient.IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
					})

					It("should have connectivity via node 1", func() {
						svc = tc.Felixes[1].IP + ":" + strconv.Itoa(int(nodeport))
						cc.Expect(Some, externalClient, TargetIP(tc.Felixes[1].IP),
							expectedFelix1IP, ExpectWithPorts(nodeport))
						cc.CheckConnectivity()
						Eventually(proxies[1].ProxiedCountFn(externalClient.IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
						Consistently(proxies[0].AcceptedCountFn(externalClient.IP, pod, svc), duration, retry).Should(BeZero())
						Consistently(proxies[0].AcceptedCountFn(tc.Felixes[1].IP, pod, svc), duration, retry).Should(BeZero())
					})

					It("should not have connectivity when denied by preDNAT policy", func() {
						By("Denying traffic from ext client to nodeport using preDNAT policy", func() {
							pol := api.NewGlobalNetworkPolicy()
							pol.Namespace = "fv"
							pol.Name = "policy-deny-prednat"
							pol.Spec.Ingress = []api.Rule{
								{
									Action:   "Deny",
									Protocol: &tcpProto,
									Source: api.EntityRule{
										Nets: []string{externalClient.IP + "/32"},
									},
									Destination: api.EntityRule{
										Ports: []numorstring.Port{numorstring.SinglePort(nodeport)},
									},
								},
							}
							pol.Spec.Selector = "has(host-endpoint)"
							pol.Spec.PreDNAT = true
							pol.Spec.ApplyOnForward = true
							one := float64(1)
							pol.Spec.Order = &one

							pol = createPolicy(pol)
						})
						cc.Expect(Some, externalClient, TargetIP(tc.Felixes[0].IP),
							ExpectWithSrcIPs(tc.Felixes[0].IP), ExpectWithPorts(nodeport), expectedFelix0IP)
						cc.Expect(Some, externalClient, TargetIP(tc.Felixes[1].IP),
							ExpectWithSrcIPs(tc.Felixes[1].IP), ExpectWithPorts(nodeport), expectedFelix1IP)
						cc.CheckConnectivity()
					})
				})
			})

			Context("Host networked backend", func() {
				var pod, svc string

				nodeport := uint16(30333)

				JustBeforeEach(func() {
					pod = hostW[0].IP + ":8055"
					svc = clusterIP + ":8090"

					for _, f := range tc.Felixes {
						if NFTMode() {
							f.Exec("nft", "add", "table", "ip", "services")
							f.Exec("nft", "add", "chain", "ip", "services", "PREROUTING", "{ type nat hook prerouting priority -100; }")
							f.Exec("nft", "add", "rule", "ip", "services", "PREROUTING", "ip", "daddr", clusterIP, "tcp", "dport", "8090", "counter", "dnat", "to", pod)
							f.Exec("nft", "add", "rule", "ip", "services", "PREROUTING", "fib", "daddr", "type", "local", "tcp", "dport", strconv.Itoa(int(nodeport)), "counter", "meta", "mark", "set", "mark", "or", "0x4000")
							f.Exec("nft", "add", "rule", "ip", "services", "PREROUTING", "fib", "daddr", "type", "local", "tcp", "dport", strconv.Itoa(int(nodeport)), "counter", "dnat", "to", pod)
							f.Exec("nft", "add", "chain", "ip", "services", "POSTROUTING", "{ type nat hook postrouting priority 100 ; }")
							f.Exec("nft", "add", "rule", "ip", "services", "POSTROUTING", "mark", "and", "0x4000", "==", "0x4000", "masquerade")
						} else {
							// Mimic the kube-proxy service iptable clusterIP rule.
							f.Exec("iptables", "-t", "nat", "-A", "PREROUTING",
								"-w", "10", // Retry this for 10 seconds, e.g. if something else is holding the lock
								"-W", "100000", // How often to probe the lock in microsecs.
								"-p", "tcp",
								"-d", clusterIP,
								"-m", "tcp", "--dport", "8090",
								"-j", "DNAT", "--to-destination",
								pod)
							f.Exec("iptables", "-t", "nat",
								"-w", "10", // Retry this for 10 seconds, e.g. if something else is holding the lock
								"-W", "100000", // How often to probe the lock in microsecs.
								"-A", "PREROUTING",
								"-p", "tcp",
								"-m", "addrtype", "--dst-type", "LOCAL",
								"-m", "tcp", "--dport", strconv.Itoa(int(nodeport)),
								"-j", "MARK", "--set-xmark", "0x4000/0x4000")
							f.Exec("iptables", "-t", "nat",
								"-w", "10", // Retry this for 10 seconds, e.g. if something else is holding the lock
								"-W", "100000", // How often to probe the lock in microsecs.
								"-A", "PREROUTING",
								"-p", "tcp",
								"-m", "addrtype", "--dst-type", "LOCAL",
								"-m", "tcp", "--dport", strconv.Itoa(int(nodeport)),
								"-j", "DNAT", "--to-destination", pod)
							// Mimic the kube-proxy MASQ rule based on the kube-proxy bit
							f.Exec("iptables", "-t", "nat", "-A", "POSTROUTING",
								"-w", "10", // Retry this for 10 seconds, e.g. if something else is holding the lock
								"-W", "100000", // How often to probe the lock in microsecs.
								"-m", "mark", "--mark", "0x4000/0x4000", // 0x4000 is the deault --iptables-masquerade-bit
								"-j", "MASQUERADE", "--random-fully")
						}
					}
					// for this context create service before each test
					v1Svc := k8sService("service-with-annotation", clusterIP, w[0][0], 8090, 8055, int32(nodeport), "tcp")
					if TPROXYMode == "Enabled" {
						v1Svc.Annotations = map[string]string{l7LoggingAnnotation: "true"}
					}
					createService(v1Svc, clientset)
				})

				It("should have connectivity via ClusterIP", func() {
					By("asserting that ipaddress, port exists in ipset ")
					assertIPPortInIPSet(TPROXYServiceIPsIPSetV4, clusterIP, "8090", tc.Felixes, true)

					cc.Expect(Some, w[0][0], TargetIP(clusterIP), ExpectWithPorts(8090), expectedFelix0IP)
					cc.Expect(Some, w[1][0], TargetIP(clusterIP), ExpectWithPorts(8090), ExpectWithSrcIPs(tc.Felixes[1].IP))
					cc.CheckConnectivity()

					Eventually(proxies[0].AcceptedCountFn(w[0][0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
					Eventually(proxies[0].ProxiedCountFn(w[0][0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))

					Eventually(proxies[1].AcceptedCountFn(w[1][0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
					Eventually(proxies[1].ProxiedCountFn(w[1][0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
				})

				It("should have connectivity via NodePorts", func() {
					By("asserting that nodeport is programmed in ipsets ")
					assertPortInIPSet(TPROXYNodeportsSet, "30333", tc.Felixes, true)

					opts := []ExpectationOption{ExpectWithPorts(nodeport), expectedFelix0IP}

					cc.Expect(Some, w[0][0], TargetIP(tc.Felixes[0].IP), opts...)
					cc.Expect(Some, w[1][0], TargetIP(tc.Felixes[0].IP), opts...)

					opts = []ExpectationOption{ExpectWithPorts(nodeport), ExpectWithSrcIPs(tc.Felixes[1].IP)}

					cc.Expect(Some, w[0][0], TargetIP(tc.Felixes[1].IP), opts...)
					cc.Expect(Some, w[1][0], TargetIP(tc.Felixes[1].IP), opts...)
					cc.CheckConnectivity()

					svc = tc.Felixes[0].IP + ":" + strconv.Itoa(int(nodeport))

					// Connection should be proxied at the nodeport's node
					Eventually(proxies[0].ProxiedCountFn(w[0][0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
					Eventually(proxies[0].ProxiedCountFn(tc.Felixes[1].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))

					svc = tc.Felixes[1].IP + ":" + strconv.Itoa(int(nodeport))

					Eventually(proxies[1].ProxiedCountFn(tc.Felixes[0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
					Eventually(proxies[1].ProxiedCountFn(w[1][0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
				})
			})

			Context("Select Traffic ClusterIP", func() {
				servicePort := "8090"

				It("Should propagate annotated service update and deletions to tproxy ip set", func() {
					By("setting up annotated service for the end points ")
					// create service resource that has annotation at creation
					v1Svc := k8sService("l7-service", clusterIP, w[0][0], 8090, 8055, 0, "tcp")
					v1Svc.Annotations = map[string]string{l7LoggingAnnotation: "true"}
					annotatedSvc := createService(v1Svc, clientset)

					By("asserting that ipaddress, port of service updated in ipset ")
					assertIPPortInIPSet(TPROXYServiceIPsIPSetV4, clusterIP, servicePort, tc.Felixes, true)

					By("updating the service to not have l7 annotation ")
					annotatedSvc.Annotations = map[string]string{}
					_, err := clientset.CoreV1().Services(annotatedSvc.Namespace).Update(context.Background(), annotatedSvc, metav1.UpdateOptions{})
					Expect(err).NotTo(HaveOccurred())

					By("asserting that ip, port exists for EnabledAllServices case and doesn't exist for others case when l7 annotation removed")
					assertIPPortInIPSet(TPROXYServiceIPsIPSetV4, clusterIP, servicePort, tc.Felixes, TPROXYMode == "EnabledAllServices")

					By("deleting the now unannotated service")
					err = clientset.CoreV1().Services(v1Svc.Namespace).Delete(context.Background(), v1Svc.Name, metav1.DeleteOptions{})
					Expect(err).NotTo(HaveOccurred())

					By("assert that ip, port is removed from ipset when service is deleted")
					assertIPPortInIPSet(TPROXYServiceIPsIPSetV4, clusterIP, servicePort, tc.Felixes, false)

					// In this second stage we create a service resource that does not have annotation at creation
					// and repeat similar process as above again.

					// this case ensures that the process of annotating is repeatable and certain IPSet callbacks are
					// not called ex. IPSetAdded (Felix fails if a IPSetAdded call to already existing ipset is made)
					By("creating unannotated service, to verify the ipset created callbacks")
					v1Svc.Annotations = map[string]string{}
					unannotatedSvc := createService(v1Svc, clientset)

					By("asserting that ip, port exists for EnabledAllServices and doesn't exist for others case when l7 annotation not present")
					assertIPPortInIPSet(TPROXYServiceIPsIPSetV4, clusterIP, servicePort, tc.Felixes, TPROXYMode == "EnabledAllServices")

					By("updating the service to have l7 annotation ")
					unannotatedSvc.Annotations = map[string]string{l7LoggingAnnotation: "true"}
					_, err = clientset.CoreV1().Services(unannotatedSvc.Namespace).Update(context.Background(), unannotatedSvc, metav1.UpdateOptions{})
					Expect(err).NotTo(HaveOccurred())

					By("asserting that ipaddress, port of service propagated to ipset")
					assertIPPortInIPSet(TPROXYServiceIPsIPSetV4, clusterIP, servicePort, tc.Felixes, true)

					By("deleting the annotated service")
					err = clientset.CoreV1().Services(v1Svc.Namespace).Delete(context.Background(), v1Svc.Name, metav1.DeleteOptions{})
					Expect(err).NotTo(HaveOccurred())

					By("asserting that ipaddress, port of service removed from ipset")
					assertIPPortInIPSet(TPROXYServiceIPsIPSetV4, clusterIP, servicePort, tc.Felixes, false)
				})
			})

			Context("Enabling TPROXY with life connections", func() {
				var pod, svc string

				BeforeEach(func() {
					utils.UpdateFelixConfig(calicoClient, func(fc *api.FelixConfiguration) {
						fc.Spec.TPROXYMode = "Disabled"
					})

					// Wait until the ipsets disappear
					Eventually(func() bool {
						for _, felix := range tc.Felixes {
							if NFTMode() {
								if _, err := felix.ExecOutput("nft", "list", "set", "ip", "calico", "cali40tproxy-svc-ips"); err == nil {
									return false
								}
							} else {
								if _, err := felix.ExecOutput("ipset", "list", "cali40tproxy-svc-ips"); err == nil {
									return false
								}
							}
						}
						return true
					}, "20s", "1s").Should(BeTrue(), "cali40tproxy-svc-ips ipset still exists")
				})

				JustBeforeEach(func() {
					pod = w[0][0].IP + ":8055"
					svc = clusterIP + ":8090"

					for _, f := range tc.Felixes {
						if NFTMode() {
							f.Exec("nft", "add", "table", "ip", "services")
							f.Exec("nft", "add", "chain", "ip", "services", "PREROUTING", "{ type nat hook prerouting priority -100; }")
							f.Exec("nft", "add", "rule", "ip", "services", "PREROUTING", "ip", "daddr", clusterIP, "tcp", "dport", "8090", "counter", "dnat", "to", pod)
							f.Exec("nft", "add", "chain", "ip", "services", "POSTROUTING", "{ type nat hook postrouting priority 100 ; }")
							f.Exec("nft", "add", "rule", "ip", "services", "POSTROUTING", "mark", "and", "0x4000", "==", "0x4000", "masquerade")
						} else {
							// Mimic the kube-proxy service iptable clusterIP rule.
							f.Exec("iptables", "-t", "nat", "-A", "PREROUTING",
								"-w", "10", // Retry this for 10 seconds, e.g. if something else is holding the lock
								"-W", "100000", // How often to probe the lock in microsecs.
								"-p", "tcp",
								"-d", clusterIP,
								"-m", "tcp", "--dport", "8090",
								"-j", "DNAT", "--to-destination",
								pod)
							// Mimic the kube-proxy MASQ rule based on the kube-proxy bit
							f.Exec("iptables", "-t", "nat", "-A", "POSTROUTING",
								"-w", "10", // Retry this for 10 seconds, e.g. if something else is holding the lock
								"-W", "100000", // How often to probe the lock in microsecs.
								"-m", "mark", "--mark", "0x4000/0x4000", // 0x4000 is the deault --iptables-masquerade-bit
								"-j", "MASQUERADE", "--random-fully")
						}
					}
					// for this context create service before each test
					v1Svc := k8sService("service-with-annotation", clusterIP, w[0][0], 8090, 8055, 0, "tcp")
					if TPROXYMode == "Enabled" {
						v1Svc.Annotations = map[string]string{l7LoggingAnnotation: "true"}
					}
					createService(v1Svc, clientset)
				})

				It("should not break existing connections", func() {
					pc := w[1][0].StartPersistentConnection(
						clusterIP, 8090, workload.PersistentConnectionOpts{
							MonitorConnectivity: true,
						})
					defer pc.Stop()

					Eventually(pc.PongCount, "5s").Should(
						BeNumerically(">", 0),
						"Expected to see pong responses on the connection but didn't receive any")
					log.Info("Pongs received within last 1s")

					// Connection should be proxied on the pod's local node
					Consistently(proxies[1].AcceptedCountFn(w[1][0].IP, pod, svc), duration, retry).Should(BeZero())
					Consistently(proxies[1].ProxiedCountFn(w[1][0].IP, pod, svc), duration, retry).Should(BeZero())

					By("Enabling TPROXY")
					utils.UpdateFelixConfig(calicoClient, func(fc *api.FelixConfiguration) {
						fc.Spec.TPROXYMode = TPROXYMode
					})

					By("asserting that ipaddress, port exists in ipset ")
					assertIPPortInIPSetErr(TPROXYServiceIPsIPSetV4, clusterIP, "8090", tc.Felixes, true, true)

					cc.Expect(Some, w[1][1], TargetIP(clusterIP), ExpectWithPorts(8090))
					cc.CheckConnectivity()

					// Check the we did not break the persistent connection.
					prevCount := pc.PongCount()
					Eventually(pc.PongCount, "5s").Should(
						BeNumerically(">", prevCount),
						"Expected to see pong responses on the connection but didn't receive any")
					log.Info("Pongs received within last 1s")

					// Connection should be proxied on the pod's local node
					Eventually(proxies[1].ProxiedCountFn(w[1][1].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
					Consistently(proxies[1].AcceptedCountFn(w[1][0].IP, pod, svc), duration, retry).Should(BeZero())
					Consistently(proxies[1].ProxiedCountFn(w[1][0].IP, pod, svc), duration, retry).Should(BeZero())

					// New connection should be proxied
					cc.ResetExpectations()
					cc.Expect(Some, w[1][0], TargetIP(clusterIP), ExpectWithPorts(8090))
					cc.CheckConnectivity()

					Eventually(proxies[1].AcceptedCountFn(w[1][0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
					Eventually(proxies[1].ProxiedCountFn(w[1][0].IP, pod, svc), duration, retry).Should(BeNumerically(">", 0))
				})
			})
		})
}
