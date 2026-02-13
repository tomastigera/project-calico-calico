// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fv_test

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/collector/flowlog"
	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/metrics"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

var _ = infrastructure.DatastoreDescribe("_INGRESS-EGRESS_ with initialized Felix, etcd datastore, 3 workloads", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
	var (
		tc     infrastructure.TopologyContainers
		client client.Interface
		infra  infrastructure.DatastoreInfra
		w      [3]*workload.Workload
		cc     *connectivity.Checker
	)

	BeforeEach(func() {
		infra = getInfra()
		opts := infrastructure.DefaultTopologyOptions()
		opts.FlowLogSource = infrastructure.FlowLogSourceFile
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEENABLED"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSENABLEHOSTENDPOINT"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "120"
		tc, client = infrastructure.StartSingleNodeTopology(opts, infra)
		infrastructure.CreateDefaultProfile(client, "default", map[string]string{"default": ""}, "default == ''")

		// Create three workloads, using that profile.
		for ii := range w {
			iiStr := strconv.Itoa(ii)
			w[ii] = workload.Run(tc.Felixes[0], "w"+iiStr, "default", "10.65.0.1"+iiStr, "8055", "tcp")
			w[ii].Configure(client)
		}

		cc = &connectivity.Checker{}
	})

	It("full connectivity to and from workload 0", func() {
		cc.ExpectSome(w[1], w[0])
		cc.ExpectSome(w[2], w[0])
		cc.ExpectSome(w[0], w[1])
		cc.ExpectSome(w[0], w[2])
		cc.CheckConnectivity()

		// Expect flow logs that describe those 4 different flows starting and
		// completing.  Note that each flow is reported twice, for egress from the
		// source workload and for ingress to the destination workload.
		//
		// Timing-wise, there is an interplay between
		//
		// (a) when the conntrack state for a flow times out (120s)
		//
		// (b) how long after that Felix expires the flow (up to 10s)
		//
		// (c) when Felix decides to generate a round of flow logs (every 120s,
		// but possibly offset from the previous timings).
		//
		// Therefore we could see 8 flow logs each saying that its flow both
		// started and completed; or we could see 16 flow logs of which 8 say that
		// the flow started, and the other 8 say that it completed.  The following
		// code is written so as to allow for that variation.
		//
		// FIXME: This test currently fails, most of the time, because (1) we
		// usually get the 16 flow logs case, where flow start and completion are
		// reported separately, and (2) the completion flow logs also -
		// incorrectly - report the flow as having started within the same time
		// interval.
		Eventually(func() error {
			expectedKeys := map[string]bool{
				"start-" + w[0].Name + "--" + w[1].Name + "--dst": true,
				"start-" + w[0].Name + "--" + w[1].Name + "--src": true,
				"start-" + w[0].Name + "--" + w[2].Name + "--dst": true,
				"start-" + w[0].Name + "--" + w[2].Name + "--src": true,
				"start-" + w[1].Name + "--" + w[0].Name + "--dst": true,
				"start-" + w[1].Name + "--" + w[0].Name + "--src": true,
				"start-" + w[2].Name + "--" + w[0].Name + "--dst": true,
				"start-" + w[2].Name + "--" + w[0].Name + "--src": true,
				"end-" + w[0].Name + "--" + w[1].Name + "--dst":   true,
				"end-" + w[0].Name + "--" + w[1].Name + "--src":   true,
				"end-" + w[0].Name + "--" + w[2].Name + "--dst":   true,
				"end-" + w[0].Name + "--" + w[2].Name + "--src":   true,
				"end-" + w[1].Name + "--" + w[0].Name + "--dst":   true,
				"end-" + w[1].Name + "--" + w[0].Name + "--src":   true,
				"end-" + w[2].Name + "--" + w[0].Name + "--dst":   true,
				"end-" + w[2].Name + "--" + w[0].Name + "--src":   true,
			}
			cwlogs, err := tc.Felixes[0].FlowLogs()
			if err != nil {
				return err
			}
			for _, fl := range cwlogs {
				if fl.FlowMeta.Action != flowlog.ActionAllow {
					return errors.New("Unexpected non-allow flow log")
				}
				dir := "dst"
				if fl.Reporter == flowlog.ReporterSrc {
					dir = "src"
				}
				key := fl.SrcMeta.AggregatedName + "--" + fl.DstMeta.AggregatedName + "--" + dir
				if fl.NumFlowsStarted == 1 {
					if _, ok := expectedKeys["start-"+key]; ok {
						// Expected flow log seen.
						delete(expectedKeys, "start-"+key)
						log.Info("Deleted start-" + key)
					} else {
						// Unexpected flow log.
						return fmt.Errorf("Unexpected flow log: %v", fl)
					}
				}
				if fl.NumFlowsCompleted == 1 {
					if _, ok := expectedKeys["end-"+key]; ok {
						// Expected flow log seen.
						delete(expectedKeys, "end-"+key)
						log.Info("Deleted end-" + key)
					} else {
						// Unexpected flow log.
						return fmt.Errorf("Unexpected flow log: %v", fl)
					}
				}
			}
			if len(expectedKeys) != 0 {
				return fmt.Errorf("Expected flow logs not seen: %v", expectedKeys)
			}
			return nil
		}, "300s", "15s").ShouldNot(HaveOccurred())
	})

	Context("with ingress-only restriction for workload 0", func() {
		BeforeEach(func() {
			policy := api.NewNetworkPolicy()
			policy.Namespace = "fv"
			policy.Name = "policy-1"
			allowFromW1 := api.Rule{
				Action: api.Allow,
				Source: api.EntityRule{
					Selector: w[1].NameSelector(),
				},
			}
			policy.Spec.Ingress = []api.Rule{allowFromW1}
			policy.Spec.Selector = w[0].NameSelector()
			_, err := client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		})

		It("only w1 can connect into w0, but egress from w0 is unrestricted", func() {
			cc.ExpectNone(w[2], w[0])
			cc.ExpectSome(w[1], w[0])
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[0], w[2])
			cc.CheckConnectivity()
		})
	})

	Context("with egress-only restriction for workload 0", func() {
		BeforeEach(func() {
			policy := api.NewNetworkPolicy()
			policy.Namespace = "fv"
			policy.Name = "policy-1"
			allowToW1 := api.Rule{
				Action: api.Allow,
				Destination: api.EntityRule{
					Selector: w[1].NameSelector(),
				},
			}
			policy.Spec.Egress = []api.Rule{allowToW1}
			policy.Spec.Selector = w[0].NameSelector()
			_, err := client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		})

		It("ingress to w0 is unrestricted, but w0 can only connect out to w1", func() {
			cc.ExpectNone(w[0], w[2])
			cc.ExpectSome(w[1], w[0])
			cc.ExpectSome(w[2], w[0])
			cc.ExpectSome(w[0], w[1])
			cc.CheckConnectivity()
		})
	})

	Context("with ingress rules and types [ingress,egress]", func() {
		BeforeEach(func() {
			policy := api.NewNetworkPolicy()
			policy.Namespace = "fv"
			policy.Name = "policy-1"
			allowFromW1 := api.Rule{
				Action: api.Allow,
				Source: api.EntityRule{
					Selector: w[1].NameSelector(),
				},
			}
			policy.Spec.Ingress = []api.Rule{allowFromW1}
			policy.Spec.Selector = w[0].NameSelector()
			policy.Spec.Types = []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress}
			_, err := client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		})

		It("only w1 can connect into w0, and all egress from w0 is denied", func() {
			cc.ExpectNone(w[2], w[0])
			cc.ExpectSome(w[1], w[0])
			cc.ExpectNone(w[0], w[1])
			cc.ExpectNone(w[0], w[2])
			cc.CheckConnectivity()
		})
	})

	Context("with an egress deny rule", func() {
		var policy *api.NetworkPolicy

		BeforeEach(func() {
			policy = api.NewNetworkPolicy()
			policy.Namespace = "fv"
			policy.Name = "policy-1"
			allowFromW1 := api.Rule{
				Action: api.Allow,
				Source: api.EntityRule{
					Selector: w[1].NameSelector(),
				},
			}
			policy.Spec.Ingress = []api.Rule{allowFromW1}
			policy.Spec.Egress = []api.Rule{{Action: api.Deny}}
			policy.Spec.Selector = w[0].NameSelector()
		})

		JustBeforeEach(func() {
			_, err := client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		})

		Describe("and types [ingress] (i.e. disabling the egress rule)", func() {
			BeforeEach(func() {
				policy.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
			})

			It("only w1 can connect into w0, and all egress from w0 is allowed", func() {
				cc.ExpectNone(w[2], w[0])
				cc.ExpectSome(w[1], w[0])
				cc.ExpectSome(w[0], w[1])
				cc.ExpectSome(w[0], w[2])
				cc.CheckConnectivity()
			})
		})

		Describe("and types [ingress, egress]", func() {
			BeforeEach(func() {
				policy.Spec.Types = []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress}
			})

			It("only w1 can connect into w0, and all egress from w0 is blocked", func() {
				cc.ExpectNone(w[2], w[0])
				cc.ExpectSome(w[1], w[0])
				cc.ExpectNone(w[0], w[1])
				cc.ExpectNone(w[0], w[2])
				cc.CheckConnectivity()
			})
		})
	})
})

var _ = infrastructure.DatastoreDescribe("_INGRESS-EGRESS_ (iptables-only) with initialized Felix, etcd datastore, 3 workloads", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
	var (
		tc      infrastructure.TopologyContainers
		client  client.Interface
		infra   infrastructure.DatastoreInfra
		w       [3]*workload.Workload
		cc      *connectivity.Checker
		listCmd []string
	)

	BeforeEach(func() {
		infra = getInfra()
		opts := infrastructure.DefaultTopologyOptions()
		opts.FlowLogSource = infrastructure.FlowLogSourceFile
		tc, client = infrastructure.StartSingleNodeTopology(opts, infra)
		infrastructure.CreateDefaultProfile(client, "default", map[string]string{"default": ""}, "default == ''")

		if NFTMode() {
			listCmd = []string{"nft", "list", "table", "calico"}
		} else {
			listCmd = []string{"iptables-save"}
		}

		// Create three workloads, using that profile.
		for ii := range w {
			iiStr := strconv.Itoa(ii)
			w[ii] = workload.Run(tc.Felixes[0], "w"+iiStr, "default", "10.65.0.1"+iiStr, "8055", "tcp")
			w[ii].Configure(client)
		}

		cc = &connectivity.Checker{}
	})

	Context("with an ingress policy with no rules", func() {
		BeforeEach(func() {
			policy := api.NewNetworkPolicy()
			policy.Namespace = "fv"
			policy.Name = "policy-1"
			policy.Spec.Ingress = []api.Rule{}
			policy.Spec.Selector = w[0].NameSelector()
			_, err := client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		})

		It("no-one can connect to w0, but egress from w0 is unrestricted", func() {
			cc.ExpectNone(w[2], w[0])
			cc.ExpectNone(w[1], w[0])
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[0], w[2])
			cc.CheckConnectivity()
		})

		It("should have the expected comment in the dataplane", func() {
			Eventually(func() string {
				out, _ := tc.Felixes[0].ExecOutput(listCmd...)
				return out
			}).Should(ContainSubstring("NetworkPolicy fv/policy-1 ingress"))
		})
	})

	Context("with egress-only restriction for workload 0", func() {
		BeforeEach(func() {
			policy := api.NewNetworkPolicy()
			policy.Namespace = "fv"
			policy.Name = "policy-1"
			allowToW1 := api.Rule{
				Action: api.Allow,
				Destination: api.EntityRule{
					Selector: w[1].NameSelector(),
				},
			}
			policy.Spec.Egress = []api.Rule{allowToW1}
			policy.Spec.Selector = w[0].NameSelector()
			_, err := client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should have the expected comment in the dataplane", func() {
			Eventually(func() string {
				out, _ := tc.Felixes[0].ExecOutput(listCmd...)
				return out
			}).Should(ContainSubstring("NetworkPolicy fv/policy-1 egress"))
		})
	})
})

var _ = infrastructure.DatastoreDescribe("with Typha and Felix-Typha TLS", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
	var (
		tc     infrastructure.TopologyContainers
		client client.Interface
		infra  infrastructure.DatastoreInfra
		w      [3]*workload.Workload
		cc     *connectivity.Checker
	)

	BeforeEach(func() {
		infra = getInfra()
		options := infrastructure.DefaultTopologyOptions()
		options.WithTypha = true
		options.WithFelixTyphaTLS = true
		tc, client = infrastructure.StartSingleNodeTopology(options, infra)
		infrastructure.CreateDefaultProfile(client, "default", map[string]string{"default": ""}, "default == ''")

		// Create three workloads, using that profile.
		for ii := range w {
			iiStr := strconv.Itoa(ii)
			w[ii] = workload.Run(tc.Felixes[0], "w"+iiStr, "default", "10.65.0.1"+iiStr, "8055", "tcp")
			w[ii].Configure(client)
		}

		cc = &connectivity.Checker{}
	})

	It("full connectivity to and from workload 0", func() {
		cc.ExpectSome(w[1], w[0])
		cc.ExpectSome(w[2], w[0])
		cc.ExpectSome(w[0], w[1])
		cc.ExpectSome(w[0], w[2])
		cc.CheckConnectivity()
	})

	Context("with ingress-only restriction for workload 0", func() {
		BeforeEach(func() {
			policy := api.NewNetworkPolicy()
			policy.Namespace = "fv"
			policy.Name = "policy-1"
			allowFromW1 := api.Rule{
				Action: api.Allow,
				Source: api.EntityRule{
					Selector: w[1].NameSelector(),
				},
			}
			policy.Spec.Ingress = []api.Rule{allowFromW1}
			policy.Spec.Selector = w[0].NameSelector()
			_, err := client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		})

		It("only w1 can connect into w0, but egress from w0 is unrestricted", func() {
			cc.ExpectNone(w[2], w[0])
			cc.ExpectSome(w[1], w[0])
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[0], w[2])
			cc.CheckConnectivity()
		})
	})
})

var _ = infrastructure.DatastoreDescribe("with TLS-secured Prometheus ports", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
	var (
		tc      infrastructure.TopologyContainers
		client  client.Interface
		infra   infrastructure.DatastoreInfra
		w       [3]*workload.Workload
		options infrastructure.TopologyOptions
		cc      *connectivity.Checker
	)

	BeforeEach(func() {
		infra = getInfra()
		options = infrastructure.DefaultTopologyOptions()
		options.WithTypha = true
		options.WithPrometheusPortTLS = true
		tc, client = infrastructure.StartSingleNodeTopology(options, infra)
		infrastructure.CreateDefaultProfile(client, "default", map[string]string{"default": ""}, "default == ''")

		// Create three workloads, using that profile.
		for ii := range w {
			iiStr := strconv.Itoa(ii)
			w[ii] = workload.Run(tc.Felixes[0], "w"+iiStr, "default", "10.65.0.1"+iiStr, "8055", "tcp")
			w[ii].Configure(client)
		}

		cc = &connectivity.Checker{}
	})

	It("full connectivity to and from workload 0", func() {
		cc.ExpectSome(w[1], w[0])
		cc.ExpectSome(w[2], w[0])
		cc.ExpectSome(w[0], w[1])
		cc.ExpectSome(w[0], w[2])
		cc.CheckConnectivity()
	})

	testAccess := func(tester func(caFile, certFile, keyFile string) error) func(certKeyName string, canAccess bool) func() {
		return func(certKeyName string, canAccess bool) func() {
			return func() {
				var caFile, certFile, keyFile string
				if certKeyName != "" {
					caFile = filepath.Join(infrastructure.CertDir, "ca.crt")
					certFile = filepath.Join(infrastructure.CertDir, certKeyName+".crt")
					keyFile = filepath.Join(infrastructure.CertDir, certKeyName+".key")
				}
				err := tester(caFile, certFile, keyFile)
				if canAccess {
					Expect(err).NotTo(HaveOccurred())
				} else {
					Expect(err).To(HaveOccurred())
				}
			}
		}
	}

	testFelixReporter := testAccess(func(caFile, certFile, keyFile string) error {
		// Using GetRawMetrics here because the metrics are empty at start of day.
		_, err := metrics.GetRawMetrics(tc.Felixes[0].IP, 9092, caFile, certFile, keyFile)
		return err
	})

	testFelixMetrics := testAccess(func(caFile, certFile, keyFile string) error {
		_, err := metrics.GetMetric(tc.Felixes[0].IP, 9091, "felix_host", caFile, certFile, keyFile)
		return err
	})

	testTyphaMetrics := testAccess(func(caFile, certFile, keyFile string) error {
		_, err := metrics.GetMetric(tc.Felixes[0].TyphaIP, 9093, "typha_connections_active", caFile, certFile, keyFile)
		return err
	})

	It("should not be able to access Felix Reporter port over http", testFelixReporter("", false))

	It("should not be able to access Felix Metrics port over http", testFelixMetrics("", false))

	It("should not be able to access Typha Metrics port over http", testTyphaMetrics("", false))

	It("should not be able to access Felix Reporter port with untrusted cert", testFelixReporter("client-untrusted", false))

	It("should not be able to access Felix Metrics port with untrusted cert", testFelixMetrics("client-untrusted", false))

	It("should not be able to access Typha Metrics port with untrusted cert", testTyphaMetrics("client-untrusted", false))

	It("should be able to access Felix Reporter port with trusted cert", testFelixReporter("client", true))

	It("should be able to access Felix Metrics port with trusted cert", testFelixMetrics("client", true))

	It("should be able to access Typha Metrics port with trusted cert", testTyphaMetrics("client", true))
})
