// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package fv_test

import (
	"fmt"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"

	. "github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/tproxy"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/felix/tproxydefs"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

var (
	_ = describeALPTest(false)
	_ = describeALPTest(true)
)

func describeALPTest(ipip bool) bool {
	TPROXYApplicationLayerPolicyIPSet := fmt.Sprintf("cali40%s", tproxydefs.ApplicationLayerPolicyIPSet)

	tunnel := "none"
	if ipip {
		tunnel = "ipip"
	}

	return infrastructure.DatastoreDescribe("ALP tests tunnel="+tunnel,
		[]apiconfig.DatastoreType{apiconfig.Kubernetes},
		func(getInfra infrastructure.InfraFactory) {
			// if numNodes <= 1 no IPPool is created
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
			)

			createPolicy := func(policy *api.GlobalNetworkPolicy) *api.GlobalNetworkPolicy {
				log.WithField("policy", dumpResource(policy)).Info("Creating policy")
				policy, err := calicoClient.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())
				return policy
			}

			createStagedPolicy := func(spolicy *api.StagedGlobalNetworkPolicy) *api.StagedGlobalNetworkPolicy {
				log.WithField("stagedPolicy", dumpResource(spolicy)).Info("Creating stagedPolicy")
				spolicy, err := calicoClient.StagedGlobalNetworkPolicies().Create(utils.Ctx, spolicy, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())
				return spolicy
			}

			assertIPInIPSetErr := func(ipSetID string,
				ip string,
				felix *infrastructure.Felix,
				exists bool,
				canErr bool,
			) {
				Eventually(func() bool {
					out, err := felix.ExecOutput("ipset", "list", ipSetID)
					log.Infof("felix ipset list output %s", out)
					if canErr && err != nil {
						return true
					}
					Expect(err).NotTo(HaveOccurred())
					return (strings.Contains(out, ip)) == exists
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

				config := api.NewFelixConfiguration()
				config.SetName("default")
				config.Spec.TPROXYMode = "Enabled"

				options.InitialFelixConfiguration = config

				infra = getInfra()
				_ = infra.(*infrastructure.K8sDatastoreInfra).K8sClient

				tc, calicoClient = infrastructure.StartNNodeTopology(numNodes, options, infra)

				proxies = []*tproxy.TProxy{}
				for _, felix := range tc.Felixes {
					proxy := tproxy.New(felix, 16001)
					proxy.Start()
					proxies = append(proxies, proxy)
					infra.AddCleanup(proxy.Stop)
				}

				addWorkload := func(run bool, ii, wi, port int, labels map[string]string) *workload.Workload {
					if labels == nil {
						labels = make(map[string]string)
					}

					wIP := fmt.Sprintf("10.65.%d.%d", ii, wi+2)
					wName := fmt.Sprintf("w%d-%d", ii, wi)

					infrastructure.AssignIP(wName, wIP, tc.Felixes[ii].Hostname, calicoClient)
					w := workload.New(tc.Felixes[ii], wName, "default",
						wIP, strconv.Itoa(port), "tcp")
					if run {
						Expect(w.Start(infra)).To(Succeed())
					}

					labels["name"] = w.Name
					labels["workload-i"] = strconv.Itoa(wi)
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
					w[ii][0] = addWorkload(true, ii, 0, 8055, nil)
					w[ii][1] = addWorkload(true, ii, 1, 8055, nil)
				}

				// Creates Policy with http
				pol := api.NewGlobalNetworkPolicy()
				pol.Namespace = "fv"
				pol.Name = "policy-1"
				pol.Spec.Ingress = []api.Rule{
					{
						Action: "Allow",
						HTTP: &api.HTTPMatch{
							Methods: []string{"GET"},
							Paths: []api.HTTPPath{
								{
									Prefix: "/public",
								},
							},
						},
					},
				}
				pol.Spec.Egress = []api.Rule{
					{
						Action: "Allow",
					},
				}
				pol.Spec.Selector = "workload-i=='1'"

				pol = createPolicy(pol)

				// Creates a Staged Policy with http
				spol := api.NewStagedGlobalNetworkPolicy()
				spol.Namespace = "fv"
				spol.Name = "policy-1"
				spol.Spec.Ingress = []api.Rule{
					{
						Action: "Allow",
						HTTP: &api.HTTPMatch{
							Methods: []string{"GET"},
							Paths: []api.HTTPPath{
								{
									Prefix: "/public",
								},
							},
						},
					},
				}
				spol.Spec.Egress = []api.Rule{
					{
						Action: "Allow",
					},
				}
				spol.Spec.Selector = "workload-i=='0'"

				spol = createStagedPolicy(spol)

				// Make sure the ipsets exist before we do
				// testing. This means that we can sync with the
				// content of the maps.
				Eventually(func() bool {
					for _, felix := range tc.Felixes {
						if NFTMode() {
							if _, err := felix.ExecOutput("nft", "list", "set", "ip", "calico", TPROXYApplicationLayerPolicyIPSet); err != nil {
								return false
							}
						} else {
							if _, err := felix.ExecOutput("ipset", "list", TPROXYApplicationLayerPolicyIPSet); err != nil {
								return false
							}
						}
					}
					return true
				}, "20s", "1s").Should(BeTrue())
			})

			Context("IPs on IPSet", func() {
				It("should have only w[0][1] workload IP in felixes[0]", func() {
					assertIPInIPSetErr(TPROXYApplicationLayerPolicyIPSet, w[0][1].IP, tc.Felixes[0], true, true)
					assertIPInIPSetErr(TPROXYApplicationLayerPolicyIPSet, w[0][0].IP, tc.Felixes[0], false, true)
				})
				It("should have only w[1][1] workload IP in felixes[1]", func() {
					assertIPInIPSetErr(TPROXYApplicationLayerPolicyIPSet, w[1][1].IP, tc.Felixes[1], true, true)
					assertIPInIPSetErr(TPROXYApplicationLayerPolicyIPSet, w[1][0].IP, tc.Felixes[1], false, true)
				})
			})
		})
}
