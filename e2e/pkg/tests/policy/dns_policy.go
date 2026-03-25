// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package policy

import (
	"context"
	"fmt"
	"strings"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	e2ekubectl "k8s.io/kubernetes/test/e2e/framework/kubectl"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	cclient "github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/images"
	"github.com/projectcalico/calico/e2e/pkg/utils/windows"
)

// The [not-ccc] indicates that this test is not compatible with cloud-controller (amazon cloud integration)
// DESCRIPTION: DNS policy test cases.
// DOCS_URL:
// PRECONDITIONS: Calico Enterprise.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.EV),
	describe.WithFeature("DNS-Policy"),
	describe.WithCategory(describe.Policy),
	describe.WithSerial(),
	"DNS policy",
	func() {
		var (
			namespace                       string
			blockedService, externalService string
			runOnWindows                    bool
		)

		f := utils.NewDefaultFramework("calico-policy")

		testDNSPolicy := func(cli ctrlclient.Client, allowObjs []ctrlclient.Object, external, blocked string, cleanups func()) {
			namespace = f.Namespace.Name
			ctx := context.TODO()

			By("Checking... Cannot reach external service")
			Eventually(curlServiceFromNamespace(external, namespace, runOnWindows), "30s", "3s").Should(HaveOccurred())

			By("Allowing egress to external service domains")
			for _, obj := range allowObjs {
				logrus.Infof("Creating %T: %s", obj, obj.GetName())
				Expect(cli.Create(ctx, obj)).NotTo(HaveOccurred())
			}
			if cleanups != nil {
				cleanups()
			}

			By("Checking... Can reach allowed external service")
			if runOnWindows {
				// On Windows, Felix must intercept DNS responses to learn domain-to-IP
				// mappings for the allow policy. We flush the DNS cache and resolve the
				// domain before each curl attempt, so Felix has multiple chances to
				// intercept the DNS response (it may miss the first one if it hasn't
				// finished processing the dnsCacheEpoch or policy updates yet).
				Eventually(func() error {
					e2ekubectl.RunKubectl(namespace, "exec", "test-client", "--",
						"ipconfig", "/flushdns")
					e2ekubectl.RunKubectl(namespace, "exec", "test-client", "--",
						"nslookup", external)
					return curlServiceFromNamespace(external, namespace, runOnWindows)()
				}, "30s", "3s").ShouldNot(HaveOccurred())
			} else {
				Eventually(curlServiceFromNamespace(external, namespace, runOnWindows), "30s", "3s").ShouldNot(HaveOccurred())
			}

			By("Checking... Cannot reach blocked service")
			Eventually(curlServiceFromNamespace(blocked, namespace, runOnWindows), "30s", "3s").Should(HaveOccurred())
		}

		Context("[RunsOnWindows] Test DNS policy of a workload. ", func() {
			var (
				cli              ctrlclient.Client
				dnsPolicyMode    *v3.DNSPolicyMode
				oldDNSPolicyMode *v3.DNSPolicyMode
			)

			JustBeforeEach(func() {
				runOnWindows = windows.ClusterIsWindows()

				By("From workload")
				namespace = f.Namespace.Name
				var err error
				cli, err = cclient.New(f.ClientConfig())
				Expect(err).NotTo(HaveOccurred())

				By("Starting a client pod that can curl")
				startCurlPod(namespace, runOnWindows)

				By("Waiting until service is ready")
				waitForClient(namespace, runOnWindows)

				By("Making any needed FelixConfiguration updates")
				ctx := context.TODO()
				var originalFC *v3.FelixConfiguration
				Eventually(func() error {
					originalFC = v3.NewFelixConfiguration()
					return cli.Get(ctx, types.NamespacedName{Name: "default"}, originalFC)
				}, 10*time.Second, 1*time.Second).Should(Succeed())

				if dnsPolicyMode != nil && !runOnWindows {
					// Save the original DNS policy mode.
					oldDNSPolicyMode = originalFC.Spec.DNSPolicyMode
				}

				Eventually(func() error {
					return utils.UpdateFelixConfig(cli, func(spec *v3.FelixConfigurationSpec) {
						if dnsPolicyMode != nil && !runOnWindows {
							// Apply the specified DNS policy mode.
							spec.DNSPolicyMode = dnsPolicyMode
						}

						// Increment dnsCacheEpoch so that Felix discards any DNS mapping info that
						// it learned in earlier test cases.  This ensures that DNS policy in this
						// test case must be using DNS information that is collected within this
						// test case.
						dnsCacheEpoch := 0
						if originalFC.Spec.DNSCacheEpoch != nil {
							dnsCacheEpoch = *(originalFC.Spec.DNSCacheEpoch)
						}
						dnsCacheEpoch += 1
						logrus.Infof("Changing dnsCacheEpoch to %v...", dnsCacheEpoch)
						spec.DNSCacheEpoch = &dnsCacheEpoch
					})
				}, 10*time.Second, 1*time.Second).Should(Succeed())

				DeferCleanup(func() {
					if CurrentSpecReport().Failed() && runOnWindows {
						windows.DumpFelixDiags()
					}

					if dnsPolicyMode != nil && !runOnWindows {
						// Restore FelixConfiguration.
						Eventually(func() error {
							return utils.UpdateFelixConfig(cli, func(spec *v3.FelixConfigurationSpec) {
								spec.DNSPolicyMode = oldDNSPolicyMode
							})
						}, 10*time.Second, 1*time.Second).Should(Succeed())
					}

					ctx := context.TODO()
					if !runOnWindows {
						// Restore FelixConfiguration.
						fc := v3.NewFelixConfiguration()
						err := cli.Get(ctx, types.NamespacedName{Name: "default"}, fc)
						Expect(err).NotTo(HaveOccurred())

						if dnsPolicyMode != nil {
							// Restore original DNSPolicyMode.
							fc.Spec.DNSPolicyMode = oldDNSPolicyMode
						}

						err = cli.Update(ctx, fc)
						Expect(err).NotTo(HaveOccurred())
					}

					// Clean up policies created during the test.
					np := v3.NewNetworkPolicy()
					np.Name = "allow-egress-to-domains"
					np.Namespace = namespace
					err = cli.Delete(ctx, np)
					if err != nil {
						logrus.WithError(err).Warnf("Error deleting allow egress network policy")
					}

					// Possibly deleting a non-existent NetworkSet, as it is not created in every test.
					ns := v3.NewNetworkSet()
					ns.Name = "allow-egress-to-domains"
					ns.Namespace = namespace
					err = cli.Delete(ctx, ns)
					if err != nil {
						logrus.WithError(err).Warnf("Error deleting allow egress NetworkSet")
					}

					denyNP := v3.NewNetworkPolicy()
					denyNP.Name = "deny-all-egress-except-dns"
					denyNP.Namespace = namespace
					err = cli.Delete(ctx, denyNP)
					if err != nil {
						logrus.WithError(err).Warnf("Error deleting deny egress network policy")
					}
				})
			})

			Context("with pre-existing DNSPolicyMode setting (or default)", func() {
				BeforeEach(func() {
					dnsPolicyMode = nil
				})

				It("Test connectivity to specific allowed egress domains, where the domains are defined in the NetworkPolicy", func() {
					blockedService = "yahoo.com"
					externalService = "example.com"
					allowedDomains := []string{"example.com", "www.example.com"}

					By("Checking... Initially, connectivity to external service succeeds")
					Eventually(curlServiceFromNamespace(externalService, namespace, runOnWindows), "30s", "3s").ShouldNot(HaveOccurred())

					By("Denying all pod egress except for DNS lookups")
					denyPolicy := denyAllEgressExceptDnsWorkloadNP(namespace, runOnWindows)
					logrus.Infof("Creating deny policy: %s", denyPolicy.Name)
					Expect(cli.Create(context.TODO(), denyPolicy)).NotTo(HaveOccurred())

					allowPolicy := allowEgressToDomainsWorkloadNP(namespace, allowedDomains)
					testDNSPolicy(cli, []ctrlclient.Object{allowPolicy}, externalService, blockedService, nil)
				})
			})

			Context("with DNSPolicyMode=DelayDeniedPacket", func() {
				BeforeEach(func() {
					dnsPolicyMode = ptr.To(v3.DNSPolicyModeDelayDeniedPacket)
				})

				It("Test the connectivity to wildcard allowed egress domains, where the domains are defined in the NetworkPolicy", func() {
					blockedService = "google.co.uk"
					externalService = "example.com"
					allowedDomains := []string{"*.com"}

					By("Checking... Initially, connectivity to external service succeeds")
					Eventually(curlServiceFromNamespace(externalService, namespace, runOnWindows), "30s", "3s").ShouldNot(HaveOccurred())

					By("Denying all pod egress except for DNS lookups")
					denyPolicy := denyAllEgressExceptDnsWorkloadNP(namespace, runOnWindows)
					logrus.Infof("Creating deny policy: %s", denyPolicy.Name)
					Expect(cli.Create(context.TODO(), denyPolicy)).NotTo(HaveOccurred())

					allowPolicy := allowEgressToDomainsWorkloadNP(namespace, allowedDomains)
					testDNSPolicy(cli, []ctrlclient.Object{allowPolicy}, externalService, blockedService, nil)
				})
			})

			Context("with DNSPolicyMode=DelayDNSResponse", func() {
				BeforeEach(func() {
					dnsPolicyMode = ptr.To(v3.DNSPolicyModeDelayDNSResponse)
				})

				It("Test connectivity to specific allowed egress domains, where the domains are defined in the NetworkSet", func() {
					blockedService = "yahoo.com"
					externalService = "example.com"
					allowedDomains := []string{"example.com", "www.example.com"}

					By("Checking... Initially, connectivity to external service succeeds")
					Eventually(curlServiceFromNamespace(externalService, namespace, runOnWindows), "30s", "3s").ShouldNot(HaveOccurred())

					By("Denying all pod egress except for DNS lookups")
					denyPolicy := denyAllEgressExceptDnsWorkloadNP(namespace, runOnWindows)
					logrus.Infof("Creating deny policy: %s", denyPolicy.Name)
					Expect(cli.Create(context.TODO(), denyPolicy)).NotTo(HaveOccurred())

					netSet, allowPolicy := allowEgressToDomainsWorkloadNS(namespace, allowedDomains)
					testDNSPolicy(cli, []ctrlclient.Object{netSet, allowPolicy}, externalService, blockedService, nil)
				})
			})

			Context("with DNSPolicyMode=NoDelay", func() {
				BeforeEach(func() {
					dnsPolicyMode = ptr.To(v3.DNSPolicyModeNoDelay)
				})

				It("Test the connectivity to wildcard allowed egress domains, where the domains are defined in the NetworkSet", func() {
					blockedService = "google.co.uk"
					externalService = "example.com"
					allowedDomains := []string{"*.com"}

					By("Checking... Initially, connectivity to external service succeeds")
					Eventually(curlServiceFromNamespace(externalService, namespace, runOnWindows), "30s", "3s").ShouldNot(HaveOccurred())

					By("Denying all pod egress except for DNS lookups")
					denyPolicy := denyAllEgressExceptDnsWorkloadNP(namespace, runOnWindows)
					logrus.Infof("Creating deny policy: %s", denyPolicy.Name)
					Expect(cli.Create(context.TODO(), denyPolicy)).NotTo(HaveOccurred())

					netSet, allowPolicy := allowEgressToDomainsWorkloadNS(namespace, allowedDomains)
					testDNSPolicy(cli, []ctrlclient.Object{netSet, allowPolicy}, externalService, blockedService, nil)
				})
			})
		})

		Context("Test DNS policy of a host for a 'GlobalNetworkPolicy'", func() {
			var cli ctrlclient.Client
			var oldDNSTrustedServers *[]string
			var dnsPolicyMode *v3.DNSPolicyMode
			var oldDNSPolicyMode *v3.DNSPolicyMode

			JustBeforeEach(func() {
				if runOnWindows {
					// windows node does not support host endpoints and host networked pod.
					Skip("Test is not possible with windows nodes")
				}
				By("From host")
				namespace = f.Namespace.Name
				var err error
				cli, err = cclient.New(f.ClientConfig())
				Expect(err).NotTo(HaveOccurred())

				By("Starting a client pod that can curl")
				startCurlPodHost(namespace)

				By("Waiting until service is ready")
				waitForClient(namespace, runOnWindows)

				By("Setting trusted servers")
				fc := v3.NewFelixConfiguration()
				err = cli.Get(context.TODO(), types.NamespacedName{Name: "default"}, fc)
				Expect(err).NotTo(HaveOccurred())

				ctx := context.TODO()
				var originalFC *v3.FelixConfiguration
				Eventually(func() error {
					originalFC = v3.NewFelixConfiguration()
					return cli.Get(ctx, types.NamespacedName{Name: "default"}, originalFC)
				}, 10*time.Second, 1*time.Second).Should(Succeed())

				if dnsPolicyMode != nil {
					// Save the original DNS policy mode.
					oldDNSPolicyMode = originalFC.Spec.DNSPolicyMode
				}

				// Set DNSTrustedServers to include the host's DNS servers.
				oldDNSTrustedServers = originalFC.Spec.DNSTrustedServers
				newDNSTrustedServers := []string{}
				if oldDNSTrustedServers != nil {
					logrus.Infof("Old DNS trusted servers are %v", *oldDNSTrustedServers)
					newDNSTrustedServers = append(newDNSTrustedServers, (*oldDNSTrustedServers)...)
				}
				resolvConf := e2ekubectl.RunKubectlOrDie(namespace, "exec",
					"test-client",
					"--",
					"cat",
					"/etc/resolv.conf",
				)
				for _, line := range strings.Split(resolvConf, "\n") {
					if strings.HasPrefix(line, "nameserver") {
						nameserver := strings.TrimSpace(strings.TrimPrefix(line, "nameserver"))
						logrus.Infof("Will trust nameserver %v", nameserver)
						newDNSTrustedServers = append(newDNSTrustedServers, nameserver)
					}
				}
				logrus.Infof("New DNS trusted servers are %v", newDNSTrustedServers)

				Eventually(func() error {
					return utils.UpdateFelixConfig(cli, func(spec *v3.FelixConfigurationSpec) {
						spec.DNSTrustedServers = &newDNSTrustedServers

						if dnsPolicyMode != nil {
							// Apply the specified DNS policy mode.
							spec.DNSPolicyMode = dnsPolicyMode
						}

						// Increment dnsCacheEpoch so that Felix discards any DNS mapping info that
						// it learned in earlier test cases.  This ensures that DNS policy in this
						// test case must be using DNS information that is collected within this
						// test case.
						dnsCacheEpoch := 0
						if originalFC.Spec.DNSCacheEpoch != nil {
							dnsCacheEpoch = *(originalFC.Spec.DNSCacheEpoch)
						}
						dnsCacheEpoch += 1
						logrus.Infof("Changing dnsCacheEpoch to %v...", dnsCacheEpoch)
						spec.DNSCacheEpoch = &dnsCacheEpoch
					})
				}, 10*time.Second, 1*time.Second).Should(Succeed())

				DeferCleanup(func() {
					Eventually(func() error {
						return utils.UpdateFelixConfig(cli, func(spec *v3.FelixConfigurationSpec) {
							// Restore DNSTrustedServers.
							spec.DNSTrustedServers = oldDNSTrustedServers

							if dnsPolicyMode != nil {
								// Restore original DNSPolicyMode.
								spec.DNSPolicyMode = oldDNSPolicyMode
							}
						})
					}, 10*time.Second, 1*time.Second).Should(Succeed())
				})
			})

			// Common setup steps for the DNS policy for a host test cases.
			hostTestCaseSetup := func() {
				ctx := context.TODO()

				By("Checking... Initially, connectivity to external service succeeds")
				Eventually(curlServiceFromNamespace(externalService, namespace, runOnWindows), "30s", "3s").ShouldNot(HaveOccurred())

				// First configure allow policy to ensure that host endpoints do not
				// block access to and from the Kubernetes API.
				//
				// Some e2e test setups have ENABLE_AUTOHEP, which means there is already an
				// auto-HEP present, which will start denying traffic as soon as _any_
				// policy is defined that applies to it.
				By("Ensuring access to API server through host endpoints")
				apiServerGNP := allowAPIServerGNP()
				logrus.Infof("Creating GNP: %s", apiServerGNP.Name)
				Expect(cli.Create(ctx, apiServerGNP)).NotTo(HaveOccurred())
				DeferCleanup(func() {
					Expect(cli.Delete(context.TODO(), apiServerGNP)).NotTo(HaveOccurred())
				})

				By("Denying all egress except for DNS lookups")
				denyPolicy := denyAllEgressExceptDnsHostGNP(runOnWindows)
				logrus.Infof("Creating deny GNP: %s", denyPolicy.Name)
				Expect(cli.Create(ctx, denyPolicy)).NotTo(HaveOccurred())
				DeferCleanup(func() {
					Expect(cli.Delete(context.TODO(), denyPolicy)).NotTo(HaveOccurred())
				})

				// Get the pod to find out its nodeName, as that information isn't available until
				// it is running.
				podCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				DeferCleanup(cancel)
				pod, err := f.ClientSet.CoreV1().Pods(namespace).Get(podCtx, "test-client", metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())

				// Now create the host endpoint.
				time.Sleep(2 * time.Second)
				hep := newHostEndpoint(pod.Spec.NodeName, pod.Status.HostIP)
				logrus.Infof("Creating HEP: %s", hep.Name)
				Expect(cli.Create(ctx, hep)).NotTo(HaveOccurred())
				DeferCleanup(func() {
					Expect(cli.Delete(context.TODO(), hep)).NotTo(HaveOccurred())
				})
			}

			Context("with pre-existing DNSPolicyMode setting (or default)", func() {
				BeforeEach(func() {
					dnsPolicyMode = nil
				})

				It("Test connectivity to specific allowed egress domains, where the domains are defined in the GlobalNetworkPolicy", func() {
					blockedService = "yahoo.com"
					externalService = "example.com"
					allowedDomains := []string{"example.com", "www.example.com"}

					// Call hostTestCaseSetup.
					hostTestCaseSetup()

					allowPolicy := allowEgressToDomainsHostGNP(allowedDomains)
					testDNSPolicy(cli, []ctrlclient.Object{allowPolicy}, externalService, blockedService, func() {
						DeferCleanup(func() {
							Expect(cli.Delete(context.TODO(), allowPolicy)).NotTo(HaveOccurred())
						})
					})
				})
			})

			Context("with DNSPolicyMode=DelayDeniedPacket", func() {
				BeforeEach(func() {
					dnsPolicyMode = ptr.To(v3.DNSPolicyModeDelayDeniedPacket)
				})

				It("Test the connectivity to wildcard allowed egress domains, where the domains are defined in the GlobalNetworkPolicy", func() {
					blockedService = "google.co.uk"
					externalService = "example.com"
					allowedDomains := []string{"*.com"}

					hostTestCaseSetup()

					allowPolicy := allowEgressToDomainsHostGNP(allowedDomains)
					testDNSPolicy(cli, []ctrlclient.Object{allowPolicy}, externalService, blockedService, func() {
						DeferCleanup(func() {
							Expect(cli.Delete(context.TODO(), allowPolicy)).NotTo(HaveOccurred())
						})
					})
				})
			})

			Context("with DNSPolicyMode=DelayDNSResponse", func() {
				BeforeEach(func() {
					dnsPolicyMode = ptr.To(v3.DNSPolicyModeDelayDNSResponse)
				})

				It("Test connectivity to specific allowed egress domains, where the domains are defined in the GlobalNetworkSet", func() {
					blockedService = "yahoo.com"
					externalService = "example.com"
					allowedDomains := []string{"example.com", "www.example.com"}

					hostTestCaseSetup()

					netSet, allowPolicy := allowEgressToDomainsHostGNS(allowedDomains)
					testDNSPolicy(cli, []ctrlclient.Object{netSet, allowPolicy}, externalService, blockedService, func() {
						DeferCleanup(func() {
							Expect(cli.Delete(context.TODO(), allowPolicy)).NotTo(HaveOccurred())
							Expect(cli.Delete(context.TODO(), netSet)).NotTo(HaveOccurred())
						})
					})
				})
			})

			Context("with DNSPolicyMode=NoDelay", func() {
				BeforeEach(func() {
					dnsPolicyMode = ptr.To(v3.DNSPolicyModeNoDelay)
				})

				It("Test the connectivity to wildcard allowed egress domains, where the domains are defined in the GlobalNetworkSet", func() {
					blockedService = "google.co.uk"
					externalService = "example.com"
					allowedDomains := []string{"*.com"}

					hostTestCaseSetup()

					netSet, allowPolicy := allowEgressToDomainsHostGNS(allowedDomains)
					testDNSPolicy(cli, []ctrlclient.Object{netSet, allowPolicy}, externalService, blockedService, func() {
						DeferCleanup(func() {
							Expect(cli.Delete(context.TODO(), allowPolicy)).NotTo(HaveOccurred())
							Expect(cli.Delete(context.TODO(), netSet)).NotTo(HaveOccurred())
						})
					})
				})
			})
		})
	})

// allowEgressToDomainsWorkloadNP returns a namespaced NetworkPolicy that allows
// egress to the specified domains.
func allowEgressToDomainsWorkloadNP(namespace string, domains []string) *v3.NetworkPolicy {
	np := v3.NewNetworkPolicy()
	np.Name = "allow-egress-to-domains"
	np.Namespace = namespace
	np.Spec = v3.NetworkPolicySpec{
		Order:    ptr.To(float64(1)),
		Selector: "all()",
		Types:    []v3.PolicyType{v3.PolicyTypeEgress},
		Egress: []v3.Rule{
			{
				Action: v3.Allow,
				Destination: v3.EntityRule{
					Domains: domains,
				},
			},
		},
	}
	return np
}

// allowEgressToDomainsHostGNP returns a GlobalNetworkPolicy that allows
// egress to the specified domains for host endpoints.
func allowEgressToDomainsHostGNP(domains []string) *v3.GlobalNetworkPolicy {
	gnp := v3.NewGlobalNetworkPolicy()
	gnp.Name = "allow-egress-to-domains"
	gnp.Spec = v3.GlobalNetworkPolicySpec{
		Order:    ptr.To(float64(1)),
		Selector: "i-am-hep == 't'",
		Types:    []v3.PolicyType{v3.PolicyTypeEgress},
		Egress: []v3.Rule{
			{
				Action: v3.Allow,
				Destination: v3.EntityRule{
					Domains: domains,
				},
			},
		},
	}
	return gnp
}

// allowEgressToDomainsWorkloadNS returns a namespaced NetworkSet with the allowed
// egress domains, plus a NetworkPolicy that selects it.
func allowEgressToDomainsWorkloadNS(namespace string, domains []string) (*v3.NetworkSet, *v3.NetworkPolicy) {
	ns := v3.NewNetworkSet()
	ns.Name = "allow-egress-to-domains"
	ns.Namespace = namespace
	ns.Labels = map[string]string{"role": "allowEgressDomainsRole"}
	ns.Spec = v3.NetworkSetSpec{
		AllowedEgressDomains: domains,
	}

	np := v3.NewNetworkPolicy()
	np.Name = "allow-egress-to-domains"
	np.Namespace = namespace
	np.Spec = v3.NetworkPolicySpec{
		Selector: "all()",
		Order:    ptr.To(float64(1)),
		Types:    []v3.PolicyType{v3.PolicyTypeEgress},
		Egress: []v3.Rule{
			{
				Action: v3.Allow,
				Destination: v3.EntityRule{
					Selector: "role == 'allowEgressDomainsRole'",
				},
			},
		},
	}
	return ns, np
}

// allowEgressToDomainsHostGNS returns a GlobalNetworkSet with the allowed
// egress domains, plus a GlobalNetworkPolicy that selects it for host endpoints.
func allowEgressToDomainsHostGNS(domains []string) (*v3.GlobalNetworkSet, *v3.GlobalNetworkPolicy) {
	gns := v3.NewGlobalNetworkSet()
	gns.Name = "allow-egress-to-domains"
	gns.Labels = map[string]string{"role": "allowEgressDomainsRole"}
	gns.Spec = v3.GlobalNetworkSetSpec{
		AllowedEgressDomains: domains,
	}

	gnp := v3.NewGlobalNetworkPolicy()
	gnp.Name = "allow-egress-to-domains"
	gnp.Spec = v3.GlobalNetworkPolicySpec{
		Selector: "i-am-hep == 't'",
		Order:    ptr.To(float64(1)),
		Types:    []v3.PolicyType{v3.PolicyTypeEgress},
		Egress: []v3.Rule{
			{
				Action: v3.Allow,
				Destination: v3.EntityRule{
					Selector: "role == 'allowEgressDomainsRole'",
				},
			},
		},
	}
	return gns, gnp
}

// denyAllEgressExceptDnsWorkloadNP returns a namespaced NetworkPolicy that denies
// all egress except DNS lookups.
func denyAllEgressExceptDnsWorkloadNP(namespace string, runOnWindows bool) *v3.NetworkPolicy {
	ports := []numorstring.Port{
		numorstring.SinglePort(53),
	}
	if runOnWindows {
		// Windows does not support named ports so allow OpenShift DNS by port number.
		ports = append(ports, numorstring.SinglePort(5353))
	} else {
		// On OpenShift DNS is mapped to a named "dns" port, so allow that too.
		ports = append(ports, numorstring.NamedPort("dns"))
	}

	np := v3.NewNetworkPolicy()
	np.Name = "deny-all-egress-except-dns"
	np.Namespace = namespace
	np.Spec = v3.NetworkPolicySpec{
		Selector: "all()",
		Types:    []v3.PolicyType{v3.PolicyTypeEgress},
		Egress: []v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: ptr.To(numorstring.ProtocolFromString("UDP")),
				Destination: v3.EntityRule{
					Ports: ports,
				},
			},
			{
				Action: v3.Deny,
			},
		},
	}
	return np
}

// denyAllEgressExceptDnsHostGNP returns a GlobalNetworkPolicy that denies all
// egress except DNS lookups for host endpoints.
func denyAllEgressExceptDnsHostGNP(runOnWindows bool) *v3.GlobalNetworkPolicy {
	ports := []numorstring.Port{
		numorstring.SinglePort(53),
	}
	if runOnWindows {
		ports = append(ports, numorstring.SinglePort(5353))
	} else {
		ports = append(ports, numorstring.NamedPort("dns"))
	}

	gnp := v3.NewGlobalNetworkPolicy()
	gnp.Name = "deny-all-egress-except-dns"
	gnp.Spec = v3.GlobalNetworkPolicySpec{
		Selector: "i-am-hep == 't'",
		Types:    []v3.PolicyType{v3.PolicyTypeEgress},
		Egress: []v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: ptr.To(numorstring.ProtocolFromString("UDP")),
				Destination: v3.EntityRule{
					Ports: ports,
				},
			},
			{
				Action: v3.Deny,
			},
		},
	}
	return gnp
}

// allowAPIServerGNP returns a GlobalNetworkPolicy that allows access to the
// Kubernetes API server and kubelet through host endpoints.
func allowAPIServerGNP() *v3.GlobalNetworkPolicy {
	gnp := v3.NewGlobalNetworkPolicy()
	gnp.Name = "allow-api-server"
	gnp.Spec = v3.GlobalNetworkPolicySpec{
		Selector: "i-am-hep == 't'",
		Order:    ptr.To(float64(1)),
		Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
		Ingress: []v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: ptr.To(numorstring.ProtocolFromString("TCP")),
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						numorstring.SinglePort(10250),
					},
				},
			},
		},
		Egress: []v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: ptr.To(numorstring.ProtocolFromString("TCP")),
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						numorstring.SinglePort(443),
						numorstring.SinglePort(6443),
						numorstring.SinglePort(10250),
					},
				},
			},
			{
				Action:   v3.Allow,
				Protocol: ptr.To(numorstring.ProtocolFromString("UDP")),
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						numorstring.SinglePort(53),
						// On OpenShift DNS is mapped to a named "dns" port, so allow that too.
						numorstring.NamedPort("dns"),
					},
				},
			},
		},
	}
	return gnp
}

// newHostEndpoint returns a HostEndpoint resource for the given node name and IP address.
func newHostEndpoint(nodeName, ip string) *v3.HostEndpoint {
	hep := v3.NewHostEndpoint()
	hep.Name = "hep1"
	hep.Labels = map[string]string{"i-am-hep": "t"}
	hep.Spec = v3.HostEndpointSpec{
		Node:        nodeName,
		ExpectedIPs: []string{ip},
	}
	return hep
}

func curlServiceFromNamespace(service, namespace string, runOnWindows bool) func() error {
	return func() error {
		if runOnWindows {
			out, err := e2ekubectl.RunKubectl(namespace, "exec",
				"test-client",
				"--",
				"powershell.exe",
				"-Command",
				"curl",
				"-TimeoutSec 3",
				"-UseBasicParsing",
				service)
			logrus.Infof("curl output:\n%v", out)
			return err
		}
		out, stderr, err := e2ekubectl.RunKubectlWithFullOutput(namespace, "exec",
			"test-client",
			"--",
			"curl",
			"--connect-timeout", "3",
			"-i",
			"-L",
			"-v",
			service)
		logrus.Infof("curl output:\n%v", out)
		logrus.Infof("stderr: %q", stderr)
		return err
	}
}

func waitForClient(namespace string, runOnWindows bool) {
	e2ekubectl.RunKubectlOrDie(namespace, "wait",
		"--for=condition=ready",
		"pod/test-client",
		"--timeout=3m")
	if !runOnWindows {
		// Check that we can really exec into the client pod.  (Experience in other Linux
		// testing setups indicates there is a window after a pod is reported as ready where
		// it still isn't possible to successfully exec into it.)
		//
		// I don't know if the same problem exists on Windows.  If it does, we can add a
		// similar test here for the `runOnWindows` case.
		//
		// The 200s timeout here is huge - but on AKS we see the first `kubectl exec`
		// attempt, after a pod is reportedly ready, taking 130s before failing with a
		// connect timeout!  Assuming that a second attempt would then work, we need a
		// timeout that is clearly larger than 130s.
		By("Check that we can exec into the client pod")
		Eventually(func() error {
			stdout, stderr, err := e2ekubectl.RunKubectlWithFullOutput(namespace, "exec",
				"test-client",
				"--",
				"cat",
				"/etc/resolv.conf",
			)
			logrus.Infof("stdout: %q", stdout)
			logrus.Infof("stderr: %q", stderr)
			return err
		}, "200s", "3s").ShouldNot(HaveOccurred())
	}
}

func startCurlPod(namespace string, runOnWindows bool) {
	if runOnWindows {
		imageURL := images.WindowsClientImage()
		e2ekubectl.RunKubectlOrDie(namespace, "run",
			"test-client",
			"--image="+imageURL,
			`--overrides={"spec": {"nodeSelector": {"kubernetes.io/os": "windows"}}}`,
			"--",
			"powershell.exe",
			"-Command",
			"Start-Sleep",
			"9999")
		return
	}
	e2ekubectl.RunKubectlOrDie(namespace, "run",
		"test-client",
		"--image=laurenceman/alpine",
		`--overrides={"spec": {"nodeSelector": {"kubernetes.io/os": "linux"}}}`)
}

func startCurlPodHost(namespace string) {
	e2ekubectl.RunKubectlOrDie(namespace, "run",
		"test-client",
		"--image=laurenceman/alpine",
		fmt.Sprintf(`--overrides={"apiVersion": "v1", "spec": {"hostNetwork": true}}`))
}
