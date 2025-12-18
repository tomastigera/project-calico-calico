// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.

package fv_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/felix/collector/flowlog"
	"github.com/projectcalico/calico/felix/collector/types/endpoint"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/flowlogs"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// Config variations covered here:
//
// - Non-default group name.
// - Non-default stream name.
// - Include endpoint labels.
//
// With those variations in place,
//
//   - Generate denied flows, as well as allowed.
//   - Generate flows from multiple client pods, sharing a prefix, each
//     of which makes multiple connections to an IP that matches a wep, hep
//     or ns.
//
// Verifications:
//
// - group and stream names
// - endpoint labels included or not
// - aggregation as expected
// - metrics are zero or non-zero as expected
// - correct counts of flows started and completed
// - action allow or deny as expected
//
// Still needed elsewhere:
//
// - Timing variations
// - start_time and end_time fields
//
//	        Host 1                              Host 2
//
//	wl-client-1                              wl-server-1 (allowed)
//	wl-client-2                              wl-server-2 (denied)
//	wl-client-3                              hep-IP
//	wl-client-4
//	      ns-IP
type aggregation int

const (
	AggrNone         aggregation = 0
	AggrBySourcePort aggregation = 1
	AggrByPodPrefix  aggregation = 2
)

type expectation struct {
	labels                bool
	policies              bool
	aggregationForAllowed aggregation
	aggregationForDenied  aggregation
}

type expectedPolicy struct {
	reporter string
	action   string
	policies []string
}

// FIXME!
var (
	networkSetIPsSupported  = true
	applyOnForwardSupported = false
)

// Flow logs have little to do with the backend, and these tests are relatively slow, so
// better to run with one backend only.  etcdv3 is easier because we create a fresh
// datastore for every test and so don't need to worry about cleaning resources up.
var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ flow log tests", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
	bpfEnabled := os.Getenv("FELIX_FV_ENABLE_BPF") == "true"

	var (
		infra             infrastructure.DatastoreInfra
		tc                infrastructure.TopologyContainers
		opts              infrastructure.TopologyOptions
		useInvalidLicense bool
		expectation       expectation
		flowLogsReaders   []flowlogs.FlowLogReader
		client            client.Interface
		wlHost1           [4]*workload.Workload
		wlHost2           [2]*workload.Workload
		hostW             [2]*workload.Workload
		cc                *connectivity.Checker
	)

	BeforeEach(func() {
		useInvalidLicense = false
		infra = getInfra()
		opts = infrastructure.DefaultTopologyOptions()
		opts.IPIPMode = api.IPIPModeNever
		opts.FlowLogSource = infrastructure.FlowLogSourceFile

		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEENABLED"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "120"
		opts.ExtraEnvVars["FELIX_FLOWLOGSCOLLECTORDEBUGTRACE"] = "true"

		if networkSetIPsSupported {
			opts.ExtraEnvVars["FELIX_FLOWLOGSENABLENETWORKSETS"] = "true"
		}
	})

	JustBeforeEach(func() {
		numNodes := 2
		tc, client = infrastructure.StartNNodeTopology(numNodes, opts, infra)

		if useInvalidLicense {
			var felixPIDs []int
			for _, f := range tc.Felixes {
				felixPIDs = append(felixPIDs, f.GetFelixPID())
			}
			infrastructure.ApplyExpiredLicense(client)
			// Wait for felix to restart so we don't accidentally generate a flow log before the license takes effect.
			for i, f := range tc.Felixes {
				Eventually(f.GetFelixPID, "10s", "100ms").ShouldNot(Equal(felixPIDs[i]))
			}
		}

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		// Create workloads on host 1.
		for ii := range wlHost1 {
			wIP := fmt.Sprintf("10.65.0.%d", ii)
			wName := fmt.Sprintf("wl-host1-%d", ii)
			infrastructure.AssignIP(wName, wIP, tc.Felixes[0].Hostname, client)
			wlHost1[ii] = workload.Run(tc.Felixes[0], wName, "default", wIP, "8055", "tcp")
			wlHost1[ii].WorkloadEndpoint.GenerateName = "wl-host1-"
			wlHost1[ii].ConfigureInInfra(infra)
		}

		// Create workloads on host 2.
		for ii := range wlHost2 {
			wIP := fmt.Sprintf("10.65.1.%d", ii)
			wName := fmt.Sprintf("wl-host2-%d", ii)
			infrastructure.AssignIP(wName, wIP, tc.Felixes[1].Hostname, client)
			wlHost2[ii] = workload.Run(tc.Felixes[1], wName, "default", wIP, "8055", "tcp")
			wlHost2[ii].WorkloadEndpoint.GenerateName = "wl-host2-"
			wlHost2[ii].ConfigureInInfra(infra)
		}

		// Create a non-workload server on each host.
		for ii := range hostW {
			hostW[ii] = workload.Run(tc.Felixes[ii], fmt.Sprintf("host%d", ii), "", tc.Felixes[ii].IP, "8055", "tcp")
		}

		// Create a GlobalNetworkSet that includes host 1's IP.
		ns := api.NewGlobalNetworkSet()
		ns.Name = "ns-1"
		ns.Spec.Nets = []string{tc.Felixes[0].IP + "/32"}
		ns.Labels = map[string]string{
			"ips-for": "host1",
		}
		_, err := client.GlobalNetworkSets().Create(utils.Ctx, ns, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// Create a HostEndpoint for host 2, with apply-on-forward ingress policy
		// that denies to the second workload on host 2, but allows everything
		// else.
		gnp := api.NewGlobalNetworkPolicy()
		gnp.Name = "gnp-1"
		gnp.Spec.Selector = "host-endpoint=='true'"
		if applyOnForwardSupported {
			// Use ApplyOnForward policy to generate deny flow logs for
			// connection to wlHost2[1].
			gnp.Spec.Ingress = []api.Rule{
				{
					Action: api.Deny,
					Destination: api.EntityRule{
						Selector: "name=='" + wlHost2[1].Name + "'",
					},
				},
				{
					Action: api.Allow,
				},
			}
		} else {
			// ApplyOnForward policy doesn't generate deny flow logs, so we'll
			// use a regular NetworkPolicy below instead, and just allow
			// through the HostEndpoint.
			gnp.Spec.Ingress = []api.Rule{
				{
					Action: api.Allow,
				},
			}
		}
		gnp.Spec.Egress = []api.Rule{
			{
				Action: api.Allow,
			},
		}
		gnp.Spec.ApplyOnForward = true
		_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, gnp, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		if !applyOnForwardSupported {
			np := api.NewNetworkPolicy()
			np.Name = "default.np-1"
			np.Namespace = "default"
			np.Spec.Tier = "default"
			np.Spec.Selector = "name=='" + wlHost2[1].Name + "'"
			np.Spec.Ingress = []api.Rule{
				{
					Action: api.Deny,
				},
			}
			_, err = client.NetworkPolicies().Create(utils.Ctx, np, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		}

		hep := api.NewHostEndpoint()
		hep.Name = "host2-eth0"
		hep.Labels = map[string]string{
			"name":          hep.Name,
			"host-endpoint": "true",
		}
		hep.Spec.Node = tc.Felixes[1].Hostname
		hep.Spec.ExpectedIPs = []string{tc.Felixes[1].IP}
		_, err = client.HostEndpoints().Create(utils.Ctx, hep, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		if BPFMode() {
			ensureAllNodesBPFProgramsAttached(tc.Felixes)
		}

		count := func() int {
			return countNodesWithNodeIP(client)
		}
		Eventually(count, "1m").Should(BeEquivalentTo(numNodes), "Not all nodes got a NodeIP")

		hostEndpointProgrammed := func() bool {
			if BPFMode() {
				return tc.Felixes[1].NumTCBPFProgsEth0() == 2
			} else if NFTMode() {
				out, err := tc.Felixes[1].ExecOutput("nft", "list", "ruleset")
				Expect(err).NotTo(HaveOccurred())
				return (strings.Count(out, "cali-thfw-eth0") > 0)
			} else {
				out, err := tc.Felixes[1].ExecOutput("iptables-save", "-t", "filter")
				Expect(err).NotTo(HaveOccurred())
				return (strings.Count(out, "cali-thfw-eth0") > 0)
			}
		}
		Eventually(hostEndpointProgrammed, "30s", "1s").Should(BeTrue(),
			"Expected HostEndpoint iptables rules to appear")
		if !BPFMode() {
			rulesProgrammed := func() bool {
				out0, err := tc.Felixes[0].ExecOutput("iptables-save", "-t", "filter")
				Expect(err).NotTo(HaveOccurred())
				out1, err := tc.Felixes[1].ExecOutput("iptables-save", "-t", "filter")
				Expect(err).NotTo(HaveOccurred())
				if strings.Count(out0, "ARE0|default") == 0 {
					return false
				}
				if strings.Count(out1, "gnp-1") == 0 {
					return false
				}
				return true
			}
			if NFTMode() {
				rulesProgrammed = func() bool {
					out0, err := tc.Felixes[0].ExecOutput("nft", "list", "ruleset")
					Expect(err).NotTo(HaveOccurred())
					out1, err := tc.Felixes[1].ExecOutput("nft", "list", "ruleset")
					Expect(err).NotTo(HaveOccurred())
					if strings.Count(out0, "ARE0|default") == 0 {
						return false
					}
					if strings.Count(out1, "gnp-1") == 0 {
						return false
					}
					return true
				}
			}
			Eventually(rulesProgrammed, "10s", "1s").Should(BeTrue(),
				"Expected iptables rules to appear on the correct felix instances")
		} else {
			Eventually(func() bool {
				return bpfCheckIfGlobalNetworkPolicyProgrammed(tc.Felixes[1], "eth0", "egress", "gnp-1", "allow", false)
			}, "5s", "200ms").Should(BeTrue())

			Eventually(func() bool {
				return bpfCheckIfGlobalNetworkPolicyProgrammed(tc.Felixes[1], "eth0", "ingress", "gnp-1", "allow", false)
			}, "5s", "200ms").Should(BeTrue())

			if !applyOnForwardSupported {
				Eventually(func() bool {
					return bpfCheckIfNetworkPolicyProgrammed(tc.Felixes[1], wlHost2[1].InterfaceName, "ingress", "default", "default.np-1", "deny", true)
				}, "5s", "200ms").Should(BeTrue())
			}

			Eventually(func() bool {
				return bpfCheckIfRuleProgrammed(tc.Felixes[0], wlHost1[0].InterfaceName, "ingress", "default", "allow", true)
			}, "15s", "200ms").Should(BeTrue())

			Eventually(func() bool {
				return bpfCheckIfRuleProgrammed(tc.Felixes[0], wlHost1[0].InterfaceName, "egress", "default", "allow", true)
			}, "15s", "200ms").Should(BeTrue())
		}

		// Describe the connectivity that we now expect.
		cc = &connectivity.Checker{}
		for _, source := range wlHost1 {
			// Workloads on host 1 can connect to the first workload on host 2.
			cc.ExpectSome(source, wlHost2[0])
			// But not the second.
			cc.ExpectNone(source, wlHost2[1])
		}
		// A workload on host 1 can connect to a non-workload server on host 2.
		cc.ExpectSome(wlHost1[0], hostW[1])
		// A workload on host 2 can connect to a non-workload server on host 1.
		cc.ExpectSome(wlHost2[0], hostW[0])

		// Do 3 rounds of connectivity checking.
		cc.CheckConnectivity()
		for ii := range tc.Felixes {
			tc.Felixes[ii].Exec("conntrack", "-L")
		}
		cc.CheckConnectivity()
		for ii := range tc.Felixes {
			tc.Felixes[ii].Exec("conntrack", "-L")
		}
		cc.CheckConnectivity()
		for ii := range tc.Felixes {
			tc.Felixes[ii].Exec("conntrack", "-L")
		}

		flowlogs.WaitForConntrackScan(bpfEnabled)

		// Delete conntrack state so that we don't keep seeing 0-metric copies of the logs.  This will allow the flows
		// to expire quickly.
		for ii := range tc.Felixes {
			tc.Felixes[ii].Exec("conntrack", "-F")
		}
		for ii := range tc.Felixes {
			tc.Felixes[ii].Exec("conntrack", "-L")
		}

		flowLogsReaders = []flowlogs.FlowLogReader{}
		for _, f := range tc.Felixes {
			flowLogsReaders = append(flowLogsReaders, f)
		}
	})

	checkFlowLogs := func() {
		// Here, by way of illustrating what we need to check for, are the allowed
		// flow logs that we actually see for this test, as grouped and logged by
		// the code below that includes "started:" and "completed:".
		//
		// With default aggregation:
		// Host 1:
		// started: 3 {{[--] [--] 6 0 8055} {wep default wl-host1-* -} {hep - host2-eth0 -} allow src}
		// started: 24 {{[--] [--] 6 0 8055} {wep default wl-host1-* -} {wep default wl-host2-* -} allow src}
		// completed: 24 {{[--] [--] 6 0 8055} {wep default wl-host1-* -} {wep default wl-host2-* -} allow src}
		// completed: 3 {{[--] [--] 6 0 8055} {wep default wl-host1-* -} {hep - host2-eth0 -} allow src}
		// Host 2:
		// started: 12 {{[--] [--] 6 0 8055} {wep default wl-host1-* -} {wep default wl-host2-* -} allow dst}
		// started: 3 {{[--] [--] 6 0 8055} {wep default wl-host1-* -} {hep - host2-eth0 -} allow dst}
		// started: 3 {{[--] [--] 6 0 8055} {wep default wl-host2-* -} {net - pvt -} allow src}
		// completed: 3 {{[--] [--] 6 0 8055} {wep default wl-host2-* -} {net - pvt -} allow src}
		// completed: 12 {{[--] [--] 6 0 8055} {wep default wl-host1-* -} {wep default wl-host2-* -} allow dst}
		// completed: 3 {{[--] [--] 6 0 8055} {wep default wl-host1-* -} {hep - host2-eth0 -} allow dst}
		//
		// With aggregation none:
		// Host 1:
		// started: 1 {{[10 65 0 3] [10 65 1 0] 6 40849 8055} {wep default wl-host1-3-idx7 -} {wep default wl-host2-0-idx9 -} allow src}
		// started: 1 {{[10 65 0 0] [10 65 1 0] 6 45549 8055} {wep default wl-host1-0-idx1 -} {wep default wl-host2-0-idx9 -} allow src}
		// started: 1 {{[10 65 0 0] [10 65 1 0] 6 46873 8055} {wep default wl-host1-0-idx1 -} {wep default wl-host2-0-idx9 -} allow src}
		// started: 1 {{[10 65 0 2] [10 65 1 1] 6 45995 8055} {wep default wl-host1-2-idx5 -} {wep default wl-host2-1-idx11 -} allow src}
		// started: 1 {{[10 65 0 2] [10 65 1 0] 6 33465 8055} {wep default wl-host1-2-idx5 -} {wep default wl-host2-0-idx9 -} allow src}
		// started: 1 {{[10 65 0 0] [172 17 0 19] 6 33615 8055} {wep default wl-host1-0-idx1 -} {hep - host2-eth0 -} allow src}
		// started: 1 {{[10 65 0 1] [10 65 1 1] 6 38211 8055} {wep default wl-host1-1-idx3 -} {wep default wl-host2-1-idx11 -} allow src}
		// started: 1 {{[10 65 0 1] [10 65 1 0] 6 33455 8055} {wep default wl-host1-1-idx3 -} {wep default wl-host2-0-idx9 -} allow src}
		// started: 1 {{[10 65 0 0] [172 17 0 19] 6 40601 8055} {wep default wl-host1-0-idx1 -} {hep - host2-eth0 -} allow src}
		// started: 1 {{[10 65 0 2] [10 65 1 0] 6 43601 8055} {wep default wl-host1-2-idx5 -} {wep default wl-host2-0-idx9 -} allow src}
		// started: 1 {{[10 65 0 2] [10 65 1 0] 6 46791 8055} {wep default wl-host1-2-idx5 -} {wep default wl-host2-0-idx9 -} allow src}
		// started: 1 {{[10 65 0 3] [10 65 1 0] 6 39177 8055} {wep default wl-host1-3-idx7 -} {wep default wl-host2-0-idx9 -} allow src}
		// started: 1 {{[10 65 0 3] [10 65 1 1] 6 41265 8055} {wep default wl-host1-3-idx7 -} {wep default wl-host2-1-idx11 -} allow src}
		// started: 1 {{[10 65 0 3] [10 65 1 1] 6 38243 8055} {wep default wl-host1-3-idx7 -} {wep default wl-host2-1-idx11 -} allow src}
		// started: 1 {{[10 65 0 1] [10 65 1 1] 6 35933 8055} {wep default wl-host1-1-idx3 -} {wep default wl-host2-1-idx11 -} allow src}
		// started: 1 {{[10 65 0 1] [10 65 1 1] 6 37573 8055} {wep default wl-host1-1-idx3 -} {wep default wl-host2-1-idx11 -} allow src}
		// started: 1 {{[10 65 0 2] [10 65 1 1] 6 38251 8055} {wep default wl-host1-2-idx5 -} {wep default wl-host2-1-idx11 -} allow src}
		// started: 1 {{[10 65 0 0] [172 17 0 19] 6 39371 8055} {wep default wl-host1-0-idx1 -} {hep - host2-eth0 -} allow src}
		// started: 1 {{[10 65 0 3] [10 65 1 1] 6 41429 8055} {wep default wl-host1-3-idx7 -} {wep default wl-host2-1-idx11 -} allow src}
		// started: 1 {{[10 65 0 0] [10 65 1 1] 6 36303 8055} {wep default wl-host1-0-idx1 -} {wep default wl-host2-1-idx11 -} allow src}
		// started: 1 {{[10 65 0 3] [10 65 1 0] 6 42645 8055} {wep default wl-host1-3-idx7 -} {wep default wl-host2-0-idx9 -} allow src}
		// started: 1 {{[10 65 0 0] [10 65 1 0] 6 35515 8055} {wep default wl-host1-0-idx1 -} {wep default wl-host2-0-idx9 -} allow src}
		// started: 1 {{[10 65 0 1] [10 65 1 0] 6 43049 8055} {wep default wl-host1-1-idx3 -} {wep default wl-host2-0-idx9 -} allow src}
		// started: 1 {{[10 65 0 1] [10 65 1 0] 6 37091 8055} {wep default wl-host1-1-idx3 -} {wep default wl-host2-0-idx9 -} allow src}
		// started: 1 {{[10 65 0 0] [10 65 1 1] 6 35479 8055} {wep default wl-host1-0-idx1 -} {wep default wl-host2-1-idx11 -} allow src}
		// started: 1 {{[10 65 0 2] [10 65 1 1] 6 43967 8055} {wep default wl-host1-2-idx5 -} {wep default wl-host2-1-idx11 -} allow src}
		// started: 1 {{[10 65 0 0] [10 65 1 1] 6 40211 8055} {wep default wl-host1-0-idx1 -} {wep default wl-host2-1-idx11 -} allow src}
		// completed: 1 {{[10 65 0 0] [10 65 1 0] 6 35515 8055} {wep default wl-host1-0-idx1 -} {wep default wl-host2-0-idx9 -} allow src}
		// completed: 1 {{[10 65 0 3] [10 65 1 1] 6 41429 8055} {wep default wl-host1-3-idx7 -} {wep default wl-host2-1-idx11 -} allow src}
		// completed: 1 {{[10 65 0 0] [172 17 0 19] 6 33615 8055} {wep default wl-host1-0-idx1 -} {hep - host2-eth0 -} allow src}
		// completed: 1 {{[10 65 0 2] [10 65 1 1] 6 38251 8055} {wep default wl-host1-2-idx5 -} {wep default wl-host2-1-idx11 -} allow src}
		// completed: 1 {{[10 65 0 3] [10 65 1 1] 6 41265 8055} {wep default wl-host1-3-idx7 -} {wep default wl-host2-1-idx11 -} allow src}
		// completed: 1 {{[10 65 0 3] [10 65 1 0] 6 42645 8055} {wep default wl-host1-3-idx7 -} {wep default wl-host2-0-idx9 -} allow src}
		// completed: 1 {{[10 65 0 1] [10 65 1 1] 6 35933 8055} {wep default wl-host1-1-idx3 -} {wep default wl-host2-1-idx11 -} allow src}
		// completed: 1 {{[10 65 0 2] [10 65 1 1] 6 45995 8055} {wep default wl-host1-2-idx5 -} {wep default wl-host2-1-idx11 -} allow src}
		// completed: 1 {{[10 65 0 0] [10 65 1 1] 6 36303 8055} {wep default wl-host1-0-idx1 -} {wep default wl-host2-1-idx11 -} allow src}
		// completed: 1 {{[10 65 0 2] [10 65 1 1] 6 43967 8055} {wep default wl-host1-2-idx5 -} {wep default wl-host2-1-idx11 -} allow src}
		// completed: 1 {{[10 65 0 0] [10 65 1 1] 6 40211 8055} {wep default wl-host1-0-idx1 -} {wep default wl-host2-1-idx11 -} allow src}
		// completed: 1 {{[10 65 0 1] [10 65 1 1] 6 38211 8055} {wep default wl-host1-1-idx3 -} {wep default wl-host2-1-idx11 -} allow src}
		// completed: 1 {{[10 65 0 2] [10 65 1 0] 6 43601 8055} {wep default wl-host1-2-idx5 -} {wep default wl-host2-0-idx9 -} allow src}
		// completed: 1 {{[10 65 0 3] [10 65 1 1] 6 38243 8055} {wep default wl-host1-3-idx7 -} {wep default wl-host2-1-idx11 -} allow src}
		// completed: 1 {{[10 65 0 1] [10 65 1 1] 6 37573 8055} {wep default wl-host1-1-idx3 -} {wep default wl-host2-1-idx11 -} allow src}
		// completed: 1 {{[10 65 0 0] [172 17 0 19] 6 40601 8055} {wep default wl-host1-0-idx1 -} {hep - host2-eth0 -} allow src}
		// completed: 1 {{[10 65 0 3] [10 65 1 0] 6 39177 8055} {wep default wl-host1-3-idx7 -} {wep default wl-host2-0-idx9 -} allow src}
		// completed: 1 {{[10 65 0 2] [10 65 1 0] 6 33465 8055} {wep default wl-host1-2-idx5 -} {wep default wl-host2-0-idx9 -} allow src}
		// completed: 1 {{[10 65 0 0] [10 65 1 0] 6 46873 8055} {wep default wl-host1-0-idx1 -} {wep default wl-host2-0-idx9 -} allow src}
		// completed: 1 {{[10 65 0 0] [10 65 1 0] 6 45549 8055} {wep default wl-host1-0-idx1 -} {wep default wl-host2-0-idx9 -} allow src}
		// completed: 1 {{[10 65 0 1] [10 65 1 0] 6 43049 8055} {wep default wl-host1-1-idx3 -} {wep default wl-host2-0-idx9 -} allow src}
		// completed: 1 {{[10 65 0 0] [10 65 1 1] 6 35479 8055} {wep default wl-host1-0-idx1 -} {wep default wl-host2-1-idx11 -} allow src}
		// completed: 1 {{[10 65 0 1] [10 65 1 0] 6 33455 8055} {wep default wl-host1-1-idx3 -} {wep default wl-host2-0-idx9 -} allow src}
		// completed: 1 {{[10 65 0 2] [10 65 1 0] 6 46791 8055} {wep default wl-host1-2-idx5 -} {wep default wl-host2-0-idx9 -} allow src}
		// completed: 1 {{[10 65 0 1] [10 65 1 0] 6 37091 8055} {wep default wl-host1-1-idx3 -} {wep default wl-host2-0-idx9 -} allow src}
		// completed: 1 {{[10 65 0 3] [10 65 1 0] 6 40849 8055} {wep default wl-host1-3-idx7 -} {wep default wl-host2-0-idx9 -} allow src}
		// completed: 1 {{[10 65 0 0] [172 17 0 19] 6 39371 8055} {wep default wl-host1-0-idx1 -} {hep - host2-eth0 -} allow src}
		// Host 2:
		// started: 1 {{[10 65 1 0] [172 17 0 3] 6 38445 8055} {wep default wl-host2-0-idx9 -} {net - pvt -} allow src}
		// started: 1 {{[10 65 0 3] [10 65 1 0] 6 42645 8055} {wep default wl-host1-3-idx7 -} {wep default wl-host2-0-idx9 -} allow dst}
		// started: 1 {{[10 65 0 0] [172 17 0 19] 6 40601 8055} {wep default wl-host1-0-idx1 -} {hep - host2-eth0 -} allow dst}
		// started: 1 {{[10 65 0 3] [10 65 1 0] 6 40849 8055} {wep default wl-host1-3-idx7 -} {wep default wl-host2-0-idx9 -} allow dst}
		// started: 1 {{[10 65 0 0] [172 17 0 19] 6 33615 8055} {wep default wl-host1-0-idx1 -} {hep - host2-eth0 -} allow dst}
		// started: 1 {{[10 65 0 1] [10 65 1 0] 6 43049 8055} {wep default wl-host1-1-idx3 -} {wep default wl-host2-0-idx9 -} allow dst}
		// started: 1 {{[10 65 0 0] [172 17 0 19] 6 39371 8055} {wep default wl-host1-0-idx1 -} {hep - host2-eth0 -} allow dst}
		// started: 1 {{[10 65 0 0] [10 65 1 0] 6 35515 8055} {wep default wl-host1-0-idx1 -} {wep default wl-host2-0-idx9 -} allow dst}
		// started: 1 {{[10 65 0 0] [10 65 1 0] 6 46873 8055} {wep default wl-host1-0-idx1 -} {wep default wl-host2-0-idx9 -} allow dst}
		// started: 1 {{[10 65 1 0] [172 17 0 3] 6 44977 8055} {wep default wl-host2-0-idx9 -} {net - pvt -} allow src}
		// started: 1 {{[10 65 1 0] [172 17 0 3] 6 36887 8055} {wep default wl-host2-0-idx9 -} {net - pvt -} allow src}
		// started: 1 {{[10 65 0 3] [10 65 1 0] 6 39177 8055} {wep default wl-host1-3-idx7 -} {wep default wl-host2-0-idx9 -} allow dst}
		// started: 1 {{[10 65 0 0] [10 65 1 0] 6 45549 8055} {wep default wl-host1-0-idx1 -} {wep default wl-host2-0-idx9 -} allow dst}
		// started: 1 {{[10 65 0 1] [10 65 1 0] 6 33455 8055} {wep default wl-host1-1-idx3 -} {wep default wl-host2-0-idx9 -} allow dst}
		// started: 1 {{[10 65 0 2] [10 65 1 0] 6 43601 8055} {wep default wl-host1-2-idx5 -} {wep default wl-host2-0-idx9 -} allow dst}
		// started: 1 {{[10 65 0 2] [10 65 1 0] 6 46791 8055} {wep default wl-host1-2-idx5 -} {wep default wl-host2-0-idx9 -} allow dst}
		// started: 1 {{[10 65 0 1] [10 65 1 0] 6 37091 8055} {wep default wl-host1-1-idx3 -} {wep default wl-host2-0-idx9 -} allow dst}
		// started: 1 {{[10 65 0 2] [10 65 1 0] 6 33465 8055} {wep default wl-host1-2-idx5 -} {wep default wl-host2-0-idx9 -} allow dst}
		// completed: 1 {{[10 65 0 3] [10 65 1 0] 6 40849 8055} {wep default wl-host1-3-idx7 -} {wep default wl-host2-0-idx9 -} allow dst}
		// completed: 1 {{[10 65 0 3] [10 65 1 0] 6 39177 8055} {wep default wl-host1-3-idx7 -} {wep default wl-host2-0-idx9 -} allow dst}
		// completed: 1 {{[10 65 1 0] [172 17 0 3] 6 38445 8055} {wep default wl-host2-0-idx9 -} {net - pvt -} allow src}
		// completed: 1 {{[10 65 0 1] [10 65 1 0] 6 33455 8055} {wep default wl-host1-1-idx3 -} {wep default wl-host2-0-idx9 -} allow dst}
		// completed: 1 {{[10 65 0 1] [10 65 1 0] 6 37091 8055} {wep default wl-host1-1-idx3 -} {wep default wl-host2-0-idx9 -} allow dst}
		// completed: 1 {{[10 65 0 0] [172 17 0 19] 6 40601 8055} {wep default wl-host1-0-idx1 -} {hep - host2-eth0 -} allow dst}
		// completed: 1 {{[10 65 0 0] [10 65 1 0] 6 45549 8055} {wep default wl-host1-0-idx1 -} {wep default wl-host2-0-idx9 -} allow dst}
		// completed: 1 {{[10 65 0 1] [10 65 1 0] 6 43049 8055} {wep default wl-host1-1-idx3 -} {wep default wl-host2-0-idx9 -} allow dst}
		// completed: 1 {{[10 65 0 0] [172 17 0 19] 6 39371 8055} {wep default wl-host1-0-idx1 -} {hep - host2-eth0 -} allow dst}
		// completed: 1 {{[10 65 1 0] [172 17 0 3] 6 44977 8055} {wep default wl-host2-0-idx9 -} {net - pvt -} allow src}
		// completed: 1 {{[10 65 1 0] [172 17 0 3] 6 36887 8055} {wep default wl-host2-0-idx9 -} {net - pvt -} allow src}
		// completed: 1 {{[10 65 0 2] [10 65 1 0] 6 33465 8055} {wep default wl-host1-2-idx5 -} {wep default wl-host2-0-idx9 -} allow dst}
		// completed: 1 {{[10 65 0 0] [172 17 0 19] 6 33615 8055} {wep default wl-host1-0-idx1 -} {hep - host2-eth0 -} allow dst}
		// completed: 1 {{[10 65 0 0] [10 65 1 0] 6 35515 8055} {wep default wl-host1-0-idx1 -} {wep default wl-host2-0-idx9 -} allow dst}
		// completed: 1 {{[10 65 0 0] [10 65 1 0] 6 46873 8055} {wep default wl-host1-0-idx1 -} {wep default wl-host2-0-idx9 -} allow dst}
		// completed: 1 {{[10 65 0 2] [10 65 1 0] 6 46791 8055} {wep default wl-host1-2-idx5 -} {wep default wl-host2-0-idx9 -} allow dst}
		// completed: 1 {{[10 65 0 2] [10 65 1 0] 6 43601 8055} {wep default wl-host1-2-idx5 -} {wep default wl-host2-0-idx9 -} allow dst}
		// completed: 1 {{[10 65 0 3] [10 65 1 0] 6 42645 8055} {wep default wl-host1-3-idx7 -} {wep default wl-host2-0-idx9 -} allow dst}
		//
		// With aggregation by source port:
		// Host 1:
		// started: 3 {{[10 65 0 3] [10 65 1 1] 6 0 8055} {wep default wl-host1-3-idx7 -} {wep default wl-host2-1-idx11 -} allow src}
		// started: 3 {{[10 65 0 0] [172 17 0 19] 6 0 8055} {wep default wl-host1-0-idx1 -} {hep - host2-eth0 -} allow src}
		// started: 3 {{[10 65 0 3] [10 65 1 0] 6 0 8055} {wep default wl-host1-3-idx7 -} {wep default wl-host2-0-idx9 -} allow src}
		// started: 3 {{[10 65 0 1] [10 65 1 1] 6 0 8055} {wep default wl-host1-1-idx3 -} {wep default wl-host2-1-idx11 -} allow src}
		// started: 3 {{[10 65 0 1] [10 65 1 0] 6 0 8055} {wep default wl-host1-1-idx3 -} {wep default wl-host2-0-idx9 -} allow src}
		// started: 3 {{[10 65 0 2] [10 65 1 1] 6 0 8055} {wep default wl-host1-2-idx5 -} {wep default wl-host2-1-idx11 -} allow src}
		// started: 3 {{[10 65 0 0] [10 65 1 0] 6 0 8055} {wep default wl-host1-0-idx1 -} {wep default wl-host2-0-idx9 -} allow src}
		// started: 3 {{[10 65 0 0] [10 65 1 1] 6 0 8055} {wep default wl-host1-0-idx1 -} {wep default wl-host2-1-idx11 -} allow src}
		// started: 3 {{[10 65 0 2] [10 65 1 0] 6 0 8055} {wep default wl-host1-2-idx5 -} {wep default wl-host2-0-idx9 -} allow src}
		// completed: 3 {{[10 65 0 0] [10 65 1 1] 6 0 8055} {wep default wl-host1-0-idx1 -} {wep default wl-host2-1-idx11 -} allow src}
		// completed: 3 {{[10 65 0 3] [10 65 1 0] 6 0 8055} {wep default wl-host1-3-idx7 -} {wep default wl-host2-0-idx9 -} allow src}
		// completed: 3 {{[10 65 0 1] [10 65 1 1] 6 0 8055} {wep default wl-host1-1-idx3 -} {wep default wl-host2-1-idx11 -} allow src}
		// completed: 3 {{[10 65 0 1] [10 65 1 0] 6 0 8055} {wep default wl-host1-1-idx3 -} {wep default wl-host2-0-idx9 -} allow src}
		// completed: 3 {{[10 65 0 0] [10 65 1 0] 6 0 8055} {wep default wl-host1-0-idx1 -} {wep default wl-host2-0-idx9 -} allow src}
		// completed: 3 {{[10 65 0 2] [10 65 1 0] 6 0 8055} {wep default wl-host1-2-idx5 -} {wep default wl-host2-0-idx9 -} allow src}
		// completed: 3 {{[10 65 0 3] [10 65 1 1] 6 0 8055} {wep default wl-host1-3-idx7 -} {wep default wl-host2-1-idx11 -} allow src}
		// completed: 3 {{[10 65 0 0] [172 17 0 19] 6 0 8055} {wep default wl-host1-0-idx1 -} {hep - host2-eth0 -} allow src}
		// completed: 3 {{[10 65 0 2] [10 65 1 1] 6 0 8055} {wep default wl-host1-2-idx5 -} {wep default wl-host2-1-idx11 -} allow src}
		// Host 2:
		// started: 3 {{[10 65 0 0] [10 65 1 0] 6 0 8055} {wep default wl-host1-0-idx1 -} {wep default wl-host2-0-idx9 -} allow dst}
		// started: 3 {{[10 65 1 0] [172 17 0 3] 6 0 8055} {wep default wl-host2-0-idx9 -} {net - pvt -} allow src}
		// started: 3 {{[10 65 0 0] [172 17 0 19] 6 0 8055} {wep default wl-host1-0-idx1 -} {hep - host2-eth0 -} allow dst}
		// started: 3 {{[10 65 0 1] [10 65 1 0] 6 0 8055} {wep default wl-host1-1-idx3 -} {wep default wl-host2-0-idx9 -} allow dst}
		// started: 3 {{[10 65 0 2] [10 65 1 0] 6 0 8055} {wep default wl-host1-2-idx5 -} {wep default wl-host2-0-idx9 -} allow dst}
		// started: 3 {{[10 65 0 3] [10 65 1 0] 6 0 8055} {wep default wl-host1-3-idx7 -} {wep default wl-host2-0-idx9 -} allow dst}
		// completed: 3 {{[10 65 0 2] [10 65 1 0] 6 0 8055} {wep default wl-host1-2-idx5 -} {wep default wl-host2-0-idx9 -} allow dst}
		// completed: 3 {{[10 65 0 3] [10 65 1 0] 6 0 8055} {wep default wl-host1-3-idx7 -} {wep default wl-host2-0-idx9 -} allow dst}
		// completed: 3 {{[10 65 0 0] [10 65 1 0] 6 0 8055} {wep default wl-host1-0-idx1 -} {wep default wl-host2-0-idx9 -} allow dst}
		// completed: 3 {{[10 65 1 0] [172 17 0 3] 6 0 8055} {wep default wl-host2-0-idx9 -} {net - pvt -} allow src}
		// completed: 3 {{[10 65 0 0] [172 17 0 19] 6 0 8055} {wep default wl-host1-0-idx1 -} {hep - host2-eth0 -} allow dst}
		// completed: 3 {{[10 65 0 1] [10 65 1 0] 6 0 8055} {wep default wl-host1-1-idx3 -} {wep default wl-host2-0-idx9 -} allow dst}
		//
		// With aggregation by pod prefix (same as default aggregation):
		// Host 1:
		// started: 48 {{[--] [--] 6 0 8055} {wep default wl-host1-* -} {wep default wl-host2-* -} allow src}
		// started: 6 {{[--] [--] 6 0 8055} {wep default wl-host1-* -} {hep - host2-eth0 -} allow src}
		// completed: 3 {{[--] [--] 6 0 8055} {wep default wl-host1-* -} {hep - host2-eth0 -} allow src}
		// completed: 24 {{[--] [--] 6 0 8055} {wep default wl-host1-* -} {wep default wl-host2-* -} allow src}
		// Host 2:
		// started: 3 {{[--] [--] 6 0 8055} {wep default wl-host1-* -} {hep - host2-eth0 -} allow dst}
		// started: 12 {{[--] [--] 6 0 8055} {wep default wl-host1-* -} {wep default wl-host2-* -} allow dst}
		// started: 3 {{[--] [--] 6 0 8055} {wep default wl-host2-* -} {net - pvt -} allow src}
		// completed: 3 {{[--] [--] 6 0 8055} {wep default wl-host1-* -} {hep - host2-eth0 -} allow dst}
		// completed: 12 {{[--] [--] 6 0 8055} {wep default wl-host1-* -} {wep default wl-host2-* -} allow dst}
		// completed: 3 {{[--] [--] 6 0 8055} {wep default wl-host2-* -} {net - pvt -} allow src}

		// Within 30s we should see the complete set of expected allow and deny
		// flow logs.
		Eventually(func() error {
			flowTester := flowlogs.NewFlowTesterDeprecated(flowLogsReaders, expectation.labels, expectation.policies, 8055)
			err := flowTester.PopulateFromFlowLogs()
			if err != nil {
				return fmt.Errorf("error populating from flow logs: %s", err)
			}

			// Only report errors at the end.
			var errs []string

			// Now we tick off each FlowMeta that we expect, and check that
			// the log(s) for each one are present and as expected.
			switch expectation.aggregationForAllowed {
			case AggrNone:
				for _, source := range wlHost1 {
					err = flowTester.CheckFlow(
						"wep default "+source.Name+" "+source.WorkloadEndpoint.GenerateName+"*", source.IP,
						"wep default "+wlHost2[0].Name+" "+wlHost2[0].WorkloadEndpoint.GenerateName+"*", wlHost2[0].IP,
						flowlogs.NoService, 3, 1,
						[]flowlogs.ExpectedPolicy{
							{Reporter: "src", Action: "allow", EnforcedPolicies: []string{"0|__PROFILE__|__PROFILE__.default|allow|0"}},
							{Reporter: "dst", Action: "allow", EnforcedPolicies: []string{"0|__PROFILE__|__PROFILE__.default|allow|0"}},
						})
					if err != nil {
						errs = append(errs, fmt.Sprintf("Error agg for allowed; agg none; source %s; flow 1: %v", source.Name, err))
					}
					err = flowTester.CheckFlow(
						"wep default "+source.Name+" "+source.WorkloadEndpoint.GenerateName+"*", source.IP,
						"wep default "+wlHost2[1].Name+" "+wlHost2[1].WorkloadEndpoint.GenerateName+"*", wlHost2[1].IP,
						flowlogs.NoService, 3, 1,
						[]flowlogs.ExpectedPolicy{
							{Reporter: "src", Action: "allow", EnforcedPolicies: []string{"0|__PROFILE__|__PROFILE__.default|allow|0"}},
							{}, // ""
						})
					if err != nil {
						errs = append(errs, fmt.Sprintf("Error agg for allowed; agg none; source %s; flow 2: %v", source.Name, err))
					}
				}

				err = flowTester.CheckFlow(
					"wep default "+wlHost1[0].Name+" "+wlHost1[0].WorkloadEndpoint.GenerateName+"*", wlHost1[0].IP,
					"hep - host2-eth0 "+tc.Felixes[1].Hostname, tc.Felixes[1].IP,
					flowlogs.NoService, 3, 1,
					[]flowlogs.ExpectedPolicy{
						{Reporter: "src", Action: "allow", EnforcedPolicies: []string{"0|__PROFILE__|__PROFILE__.default|allow|0"}},
						{Reporter: "dst", Action: "allow", EnforcedPolicies: []string{"0|default|gnp-1|allow|0"}},
					})
				if err != nil {
					errs = append(errs, fmt.Sprintf("Error agg for allowed; agg none; flow hep: %v", err))
				}

				if networkSetIPsSupported {
					err = flowTester.CheckFlow(
						"wep default "+wlHost2[0].Name+" "+wlHost2[0].WorkloadEndpoint.GenerateName+"*", wlHost2[0].IP,
						"ns - ns-1 ns-1", tc.Felixes[0].IP,
						flowlogs.NoService, 3, 1,
						[]flowlogs.ExpectedPolicy{
							{}, // ""
							{Reporter: "src", Action: "allow", EnforcedPolicies: []string{"0|__PROFILE__|__PROFILE__.default|allow|0"}},
						})
				} else {
					err = flowTester.CheckFlow(
						"wep default "+wlHost2[0].Name+" "+wlHost2[0].WorkloadEndpoint.GenerateName+"*", wlHost2[0].IP,
						"net - - pvt", tc.Felixes[0].IP,
						flowlogs.NoService, 3, 1,
						[]flowlogs.ExpectedPolicy{
							{}, // ""
							{Reporter: "src", Action: "allow", EnforcedPolicies: []string{"0|__PROFILE__|__PROFILE__.default|allow|0"}},
						})
				}
				if err != nil {
					errs = append(errs, fmt.Sprintf("Error agg for allowed; agg none; netset: %v", err))
				}
			case AggrBySourcePort:
				for _, source := range wlHost1 {
					err = flowTester.CheckFlow(
						"wep default "+source.Name+" "+source.WorkloadEndpoint.GenerateName+"*", source.IP,
						"wep default "+wlHost2[0].Name+" "+wlHost2[0].WorkloadEndpoint.GenerateName+"*", wlHost2[0].IP,
						flowlogs.NoService, 1, 3,
						[]flowlogs.ExpectedPolicy{
							{Reporter: "src", Action: "allow", EnforcedPolicies: []string{"0|__PROFILE__|__PROFILE__.default|allow|0"}},
							{Reporter: "dst", Action: "allow", EnforcedPolicies: []string{"0|__PROFILE__|__PROFILE__.default|allow|0"}},
						})
					if err != nil {
						errs = append(errs, fmt.Sprintf("Error agg for allowed; agg src port; source %s; flow 1: %v", source.Name, err))
					}
					err = flowTester.CheckFlow(
						"wep default "+source.Name+" "+source.WorkloadEndpoint.GenerateName+"*", source.IP,
						"wep default "+wlHost2[1].Name+" "+wlHost2[1].WorkloadEndpoint.GenerateName+"*", wlHost2[1].IP,
						flowlogs.NoService, 1, 3,
						[]flowlogs.ExpectedPolicy{
							{Reporter: "src", Action: "allow", EnforcedPolicies: []string{"0|__PROFILE__|__PROFILE__.default|allow|0"}},
							{},
						})
					if err != nil {
						errs = append(errs, fmt.Sprintf("Error agg for allowed; agg src port; source %s; flow 2: %v", source.Name, err))
					}
				}

				err = flowTester.CheckFlow(
					"wep default "+wlHost1[0].Name+" "+wlHost1[0].WorkloadEndpoint.GenerateName+"*", wlHost1[0].IP,
					"hep - host2-eth0 "+tc.Felixes[1].Hostname, tc.Felixes[1].IP,
					flowlogs.NoService, 1, 3,
					[]flowlogs.ExpectedPolicy{
						{Reporter: "src", Action: "allow", EnforcedPolicies: []string{"0|__PROFILE__|__PROFILE__.default|allow|0"}},
						{Reporter: "dst", Action: "allow", EnforcedPolicies: []string{"0|default|gnp-1|allow|0"}},
					})
				if err != nil {
					errs = append(errs, fmt.Sprintf("Error agg for allowed; agg src port; hep: %v", err))
				}

				if networkSetIPsSupported {
					err = flowTester.CheckFlow(
						"wep default "+wlHost2[0].Name+" "+wlHost2[0].WorkloadEndpoint.GenerateName+"*", wlHost2[0].IP,
						"ns - ns-1 ns-1", tc.Felixes[0].IP,
						flowlogs.NoService, 1, 3,
						[]flowlogs.ExpectedPolicy{
							{}, // ""
							{Reporter: "src", Action: "allow", EnforcedPolicies: []string{"0|__PROFILE__|__PROFILE__.default|allow|0"}},
						})
				} else {
					err = flowTester.CheckFlow(
						"wep default "+wlHost2[0].Name+" "+wlHost2[0].WorkloadEndpoint.GenerateName+"*", wlHost2[0].IP,
						"net - - pvt", tc.Felixes[0].IP,
						flowlogs.NoService, 1, 3,
						[]flowlogs.ExpectedPolicy{
							{}, // ""
							{Reporter: "src", Action: "allow", EnforcedPolicies: []string{"0|__PROFILE__|__PROFILE__.default|allow|0"}},
						})
				}
				if err != nil {
					errs = append(errs, fmt.Sprintf("Error agg for allowed; agg src port; netset: %v", err))
				}
			case AggrByPodPrefix:
				err = flowTester.CheckFlow(
					"wep default - wl-host1-*", "",
					"wep default - wl-host2-*", "",
					flowlogs.NoService, 1, 24,
					[]flowlogs.ExpectedPolicy{
						{Reporter: "src", Action: "allow", EnforcedPolicies: []string{"0|__PROFILE__|__PROFILE__.default|allow|0"}},
						{}, // ""
					})
				if err != nil {
					errs = append(errs, fmt.Sprintf("Error agg for allowed; agg pod prefix; flow 1: %v", err))
				}
				err = flowTester.CheckFlow(
					"wep default - wl-host1-*", "",
					"wep default - wl-host2-*", "",
					flowlogs.NoService, 1, 12,
					[]flowlogs.ExpectedPolicy{
						{}, // ""
						{Reporter: "dst", Action: "allow", EnforcedPolicies: []string{"0|__PROFILE__|__PROFILE__.default|allow|0"}},
					})
				if err != nil {
					errs = append(errs, fmt.Sprintf("Error agg for allowed; agg pod prefix; flow 2: %v", err))
				}

				var policies []flowlogs.ExpectedPolicy

				policies = []flowlogs.ExpectedPolicy{
					{Reporter: "src", Action: "allow", EnforcedPolicies: []string{"0|__PROFILE__|__PROFILE__.default|allow|0"}},
					{Reporter: "dst", Action: "allow", EnforcedPolicies: []string{"0|default|gnp-1|allow|0"}},
				}

				err = flowTester.CheckFlow(
					"wep default - wl-host1-*", "",
					"hep - - "+tc.Felixes[1].Hostname, "",
					flowlogs.NoService, 1, 3, policies)
				if err != nil {
					errs = append(errs, fmt.Sprintf("Error agg for allowed; agg pod prefix; hep: %v", err))
				}

				if networkSetIPsSupported {
					err = flowTester.CheckFlow(
						"wep default - wl-host2-*", "",
						"ns - - ns-1", "",
						flowlogs.NoService, 1, 3,
						[]flowlogs.ExpectedPolicy{
							{}, // ""
							{Reporter: "src", Action: "allow", EnforcedPolicies: []string{"0|__PROFILE__|__PROFILE__.default|allow|0"}},
						})
				} else {
					err = flowTester.CheckFlow(
						"wep default - wl-host2-*", "",
						"net - - pvt", "",
						flowlogs.NoService, 1, 3,
						[]flowlogs.ExpectedPolicy{
							{}, // ""
							{Reporter: "src", Action: "allow", EnforcedPolicies: []string{"0|__PROFILE__|__PROFILE__.default|allow|0"}},
						})
				}
				if err != nil {
					errs = append(errs, fmt.Sprintf("Error agg for allowed; agg pod prefix; netset: %v", err))
				}
			}

			switch expectation.aggregationForDenied {
			case AggrNone:
				for _, source := range wlHost1 {
					err = flowTester.CheckFlow(
						"wep default "+source.Name+" "+source.WorkloadEndpoint.GenerateName+"*", source.IP,
						"wep default "+wlHost2[1].Name+" "+wlHost2[1].WorkloadEndpoint.GenerateName+"*", wlHost2[1].IP,
						flowlogs.NoService, 3, 1,
						[]flowlogs.ExpectedPolicy{
							{}, // ""
							{Reporter: "dst", Action: "deny", EnforcedPolicies: []string{"0|default|default/default.np-1|deny|0"}},
						})
					if err != nil {
						errs = append(errs, fmt.Sprintf("Error agg for denied; agg none: %v", err))
					}
				}
			case AggrBySourcePort:
				for _, source := range wlHost1 {
					err = flowTester.CheckFlow(
						"wep default "+source.Name+" "+source.WorkloadEndpoint.GenerateName+"*", source.IP,
						"wep default "+wlHost2[1].Name+" "+wlHost2[1].WorkloadEndpoint.GenerateName+"*", wlHost2[1].IP,
						flowlogs.NoService, 1, 3,
						[]flowlogs.ExpectedPolicy{
							{}, // ""
							{Reporter: "dst", Action: "deny", EnforcedPolicies: []string{"0|default|default/default.np-1|deny|0"}},
						})
					if err != nil {
						errs = append(errs, fmt.Sprintf("Error agg for denied; agg source port: %v", err))
					}
				}
			case AggrByPodPrefix:
				err = flowTester.CheckFlow(
					"wep default - wl-host1-*", "",
					"wep default - wl-host2-*", "",
					flowlogs.NoService, 1, 12,
					[]flowlogs.ExpectedPolicy{
						{}, // ""
						{Reporter: "dst", Action: "deny", EnforcedPolicies: []string{"0|default|default/default.np-1|deny|0"}},
					})
				if err != nil {
					errs = append(errs, fmt.Sprintf("Error agg for denied; agg pod prefix: %v", err))
				}
			}

			// Finally check that there are no remaining flow logs that we did not expect.
			err = flowTester.CheckAllFlowsAccountedFor()
			if err != nil {
				errs = append(errs, err.Error())
			}

			if len(errs) == 0 {
				return nil
			}

			return errors.New(strings.Join(errs, "\n==============\n"))
		}, "30s", "3s").ShouldNot(HaveOccurred())
	}

	cloudAndFile := func() {
		BeforeEach(func() {
			opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "2"
			opts.ExtraEnvVars["FELIX_FLOWLOGSENABLEHOSTENDPOINT"] = "true"

			// Defaults for how we expect flow logs to be generated.
			expectation.labels = false
			expectation.policies = false
			expectation.aggregationForAllowed = AggrByPodPrefix
			expectation.aggregationForDenied = AggrBySourcePort
		})

		Context("with endpoint labels", func() {
			BeforeEach(func() {
				opts.ExtraEnvVars["FELIX_FLOWLOGSFILEINCLUDELABELS"] = "true"
				expectation.labels = true
			})

			It("should get expected flow logs", func() {
				checkFlowLogs()
			})
		})

		Context("with allowed aggregation none", func() {
			BeforeEach(func() {
				opts.ExtraEnvVars["FELIX_FLOWLOGSFILEAGGREGATIONKINDFORALLOWED"] = strconv.Itoa(int(AggrNone))
				expectation.aggregationForAllowed = AggrNone
			})

			It("should get expected flow logs", func() {
				checkFlowLogs()
			})
		})

		Context("with allowed aggregation by source port", func() {
			BeforeEach(func() {
				opts.ExtraEnvVars["FELIX_FLOWLOGSFILEAGGREGATIONKINDFORALLOWED"] = strconv.Itoa(int(AggrBySourcePort))
				expectation.aggregationForAllowed = AggrBySourcePort
			})

			It("should get expected flow logs", func() {
				checkFlowLogs()
			})
		})

		Context("with allowed aggregation by pod prefix", func() {
			BeforeEach(func() {
				opts.ExtraEnvVars["FELIX_FLOWLOGSFILEAGGREGATIONKINDFORALLOWED"] = strconv.Itoa(int(AggrByPodPrefix))
				expectation.aggregationForAllowed = AggrByPodPrefix
			})

			It("should get expected flow logs", func() {
				checkFlowLogs()
			})
		})

		Context("with denied aggregation none", func() {
			BeforeEach(func() {
				opts.ExtraEnvVars["FELIX_FLOWLOGSFILEAGGREGATIONKINDFORDENIED"] = strconv.Itoa(int(AggrNone))
				expectation.aggregationForDenied = AggrNone
			})

			It("should get expected flow logs", func() {
				checkFlowLogs()
			})
		})

		Context("with denied aggregation by source port", func() {
			BeforeEach(func() {
				opts.ExtraEnvVars["FELIX_FLOWLOGSFILEAGGREGATIONKINDFORDENIED"] = strconv.Itoa(int(AggrBySourcePort))
				expectation.aggregationForDenied = AggrBySourcePort
			})

			It("should get expected flow logs", func() {
				checkFlowLogs()
			})
		})

		Context("with denied aggregation by pod prefix", func() {
			BeforeEach(func() {
				opts.ExtraEnvVars["FELIX_FLOWLOGSFILEAGGREGATIONKINDFORDENIED"] = strconv.Itoa(int(AggrByPodPrefix))
				expectation.aggregationForDenied = AggrByPodPrefix
			})

			It("should get expected flow logs", func() {
				checkFlowLogs()
			})
		})

		Context("with policies", func() {
			BeforeEach(func() {
				opts.ExtraEnvVars["FELIX_FLOWLOGSFILEINCLUDEPOLICIES"] = "true"
				expectation.policies = true
			})

			It("should get expected flow logs", func() {
				checkFlowLogs()
			})
		})
	}

	Context("File flow logs", func() {
		Context("File output", func() { cloudAndFile() })
	})

	Context("File flow logs only", func() {
		BeforeEach(func() {
			// Defaults for how we expect flow logs to be generated.
			expectation.labels = false
			expectation.policies = false
			expectation.aggregationForAllowed = AggrByPodPrefix
			expectation.aggregationForDenied = AggrBySourcePort

			opts.ExtraEnvVars["FELIX_FLOWLOGSFILEENABLED"] = "true"
			opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "2"
			opts.ExtraEnvVars["FELIX_FLOWLOGSENABLEHOSTENDPOINT"] = "true"
		})

		It("should get expected flow logs", func() {
			checkFlowLogs()
		})

		Context("with an expired license", func() {
			BeforeEach(func() {
				useInvalidLicense = true
				// Reduce license poll interval so felix won't generate any flow logs before it spots the bad license.
				opts.ExtraEnvVars["FELIX_DebugUseShortPollIntervals"] = "true"
			})

			It("should get no flow logs", func() {
				endTime := time.Now().Add(30 * time.Second)
				// Check at least twice and for at least 30s.
				attempts := 0
				for time.Now().Before(endTime) || attempts < 2 {
					for _, f := range tc.Felixes {
						_, err := f.FlowLogs()
						Expect(err).To(BeAssignableToTypeOf(&os.PathError{}))
					}
					time.Sleep(1 * time.Second)
					attempts++
				}
			})
		})
	})

	AfterEach(func() {
		for _, felix := range tc.Felixes {
			if bpfEnabled {
				felix.Exec("calico-bpf", "connect-time", "clean")
			}
		}
	})
})

var _ = infrastructure.DatastoreDescribe("nat outgoing flow log tests", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra  infrastructure.DatastoreInfra
		tc     infrastructure.TopologyContainers
		client client.Interface

		workload1 *workload.Workload
		workload2 *workload.Workload
	)

	BeforeEach(func() {
		var err error

		infra = getInfra()
		opts := infrastructure.DefaultTopologyOptions()
		opts.FlowLogSource = infrastructure.FlowLogSourceFile

		opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "2"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEENABLED"] = "true"

		tc, client = infrastructure.StartSingleNodeTopology(opts, infra)

		ctx := context.Background()

		// Create an IPPool and assign an IP from that pool to workload1 so the packets are SNAT'd when a connection is
		// made from workload1 to workload2
		ippool := api.NewIPPool()
		ippool.Name = "nat-pool"
		ippool.Spec.CIDR = "10.244.255.0/24"
		ippool.Spec.NATOutgoing = true
		ippool, err = client.IPPools().Create(ctx, ippool, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		workload1 = workload.Run(tc.Felixes[0], "w1", "default", "10.244.255.1", "8055", "tcp")
		workload1.ConfigureInInfra(infra)

		workload2 = workload.Run(tc.Felixes[0], "w2", "default", "10.65.0.2", "8055", "tcp")
		workload2.ConfigureInInfra(infra)
	})

	It("Should report the nat outgoing ports for an SNAT'd flow", func() {
		cc := &connectivity.Checker{
			Protocol: "tcp",
		}

		cc.ExpectSome(workload1, workload2)
		cc.CheckConnectivity()

		var flows []flowlog.FlowLog
		var err error
		Eventually(func() error {
			flows, err = tc.Felixes[0].FlowLogs()
			return err
		}, "20s", "1s").ShouldNot(HaveOccurred())

		Expect(flows).ShouldNot(BeEmpty())

		numExpectedFlows := 0
		// Test that flows from workload1 to workload2 have nat_outgoing_ports set.
		for _, flow := range flows {
			if flow.SrcMeta.AggregatedName == workload1.Name &&
				flow.DstMeta.AggregatedName == workload2.Name {
				numExpectedFlows++
				Expect(flow.NatOutgoingPorts).ShouldNot(BeEmpty())
			}
		}

		// Ensure that there was at least one flow that went through the nat outgoing port test above.
		Expect(numExpectedFlows).ShouldNot(BeZero())
	})
})

var _ = infrastructure.DatastoreDescribe("ipv6 flow log tests", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra  infrastructure.DatastoreInfra
		tc     infrastructure.TopologyContainers
		client client.Interface

		w [2][2]*workload.Workload
	)

	BeforeEach(func() {
		var err error

		iOpts := []infrastructure.CreateOption{
			infrastructure.K8sWithDualStack(),
			infrastructure.K8sWithAPIServerBindAddress("::"),
			infrastructure.K8sWithServiceClusterIPRange("dead:beef::abcd:0:0:0/112,10.101.0.0/16"),
		}

		infra = getInfra(iOpts...)
		opts := infrastructure.DefaultTopologyOptions()
		opts.FlowLogSource = infrastructure.FlowLogSourceFile

		opts.EnableIPv6 = true
		opts.IPIPMode = api.IPIPModeNever
		opts.NATOutgoingEnabled = true
		opts.AutoHEPsEnabled = false
		opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "2"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEENABLED"] = "true"
		opts.ExtraEnvVars["FELIX_IPV6SUPPORT"] = "true"
		opts.ExtraEnvVars["FELIX_DefaultEndpointToHostAction"] = "RETURN"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEAGGREGATIONKINDFORALLOWED"] = strconv.Itoa(int(AggrNone))
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEINCLUDEPOLICIES"] = "true"

		tc, client = infrastructure.StartNNodeTopology(2, opts, infra)

		addWorkload := func(hostname string, ii, wi, port int, labels map[string]string) *workload.Workload {
			if labels == nil {
				labels = make(map[string]string)
			}

			wIP := fmt.Sprintf("10.65.%d.%d", ii, wi+2)
			wIPv6 := fmt.Sprintf("dead:beef::%d:%d", ii, wi+2)
			wName := fmt.Sprintf("w%d%d", ii, wi)

			infrastructure.AssignIP(wName, wIP, hostname, client)
			infrastructure.AssignIP(wName, wIPv6, hostname, client)
			w := workload.New(tc.Felixes[ii], wName, "default",
				wIP, strconv.Itoa(port), "tcp", workload.WithIPv6Address(net.ParseIP(fmt.Sprintf("dead:beef::%d:%d", ii, wi+2)).String()))

			labels["name"] = w.Name
			labels["workload"] = "regular"

			w.WorkloadEndpoint.Labels = labels
			err := w.Start(infra)
			Expect(err).NotTo(HaveOccurred())
			w.ConfigureInInfra(infra)
			return w
		}

		for ii := range tc.Felixes {
			// Two workloads on each host so we can check the same host and other host cases.
			w[ii][0] = addWorkload(tc.Felixes[ii].Hostname, ii, 0, 8055, map[string]string{"port": "8055"})
			w[ii][1] = addWorkload(tc.Felixes[ii].Hostname, ii, 1, 8056, nil)
		}

		err = infra.AddDefaultDeny()
		Expect(err).NotTo(HaveOccurred())

		if BPFMode() {
			ensureAllNodesBPFProgramsAttached(tc.Felixes)
		}

		var gnp1Order float64 = 100
		var gnp2Order float64 = 1

		gnp := api.NewGlobalNetworkPolicy()
		gnp.Name = "gnp-1"
		gnp.Spec.Selector = "all()"

		gnp.Spec.Ingress = []api.Rule{
			{
				Action: api.Allow,
			},
		}
		gnp.Spec.Egress = []api.Rule{
			{
				Action: api.Allow,
			},
		}
		gnp.Spec.Order = &gnp1Order
		_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, gnp, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		np := api.NewGlobalNetworkPolicy()
		np.Name = "gnp-2"
		np.Spec.Selector = "name=='" + w[0][1].Name + "'"
		np.Spec.Ingress = []api.Rule{
			{
				Action: api.Deny,
			},
		}
		np.Spec.Egress = []api.Rule{
			{
				Action: api.Deny,
			},
		}
		np.Spec.Order = &gnp2Order
		_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, np, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		if !BPFMode() {
			rulesProgrammed := func() bool {
				var out string
				var err error
				if NFTMode() {
					out, err = tc.Felixes[0].ExecOutput("nft", "list", "ruleset")
				} else {
					out, err = tc.Felixes[0].ExecOutput("iptables-save", "-t", "filter")
				}
				Expect(err).NotTo(HaveOccurred())
				if strings.Count(out, "gnp-1") == 0 {
					return false
				}
				if strings.Count(out, "gnp-2") == 0 {
					return false
				}
				return true
			}
			Eventually(rulesProgrammed, "10s", "1s").Should(BeTrue(),
				"Expected iptables rules to appear on the correct felix instances")
		} else {
			Eventually(func() bool {
				return bpfCheckIfGlobalNetworkPolicyProgrammed(tc.Felixes[0], w[0][0].InterfaceName, "egress", "gnp-1", "allow", true)
			}, "5s", "200ms").Should(BeTrue())

			Eventually(func() bool {
				return bpfCheckIfGlobalNetworkPolicyProgrammed(tc.Felixes[0], w[0][0].InterfaceName, "ingress", "gnp-1", "allow", true)
			}, "5s", "200ms").Should(BeTrue())

			Eventually(func() bool {
				return bpfCheckIfGlobalNetworkPolicyProgrammed(tc.Felixes[0], w[0][1].InterfaceName, "egress", "gnp-2", "deny", true)
			}, "5s", "200ms").Should(BeTrue())

			Eventually(func() bool {
				return bpfCheckIfGlobalNetworkPolicyProgrammed(tc.Felixes[0], w[0][1].InterfaceName, "ingress", "gnp-2", "deny", true)
			}, "5s", "200ms").Should(BeTrue())
		}

		// Describe the connectivity that we now expect.
		cc := &connectivity.Checker{}
		cc.Protocol = "tcp"
		cc.Expect(connectivity.Some, w[0][0], w[1][0], connectivity.ExpectWithIPVersion(6))
		cc.Expect(connectivity.None, w[0][1], w[1][0], connectivity.ExpectWithIPVersion(6))
		cc.CheckConnectivity()
	})

	It("Should report the ipv6 flow logs", func() {
		var flows []flowlog.FlowLog
		var err error
		Eventually(func() int {
			flows, err = tc.Felixes[0].FlowLogs()
			if err != nil {
				return 0
			}
			return len(flows)
		}, "20s", "1s").Should(Equal(2))

		Expect(flows).ShouldNot(BeEmpty())

		numExpectedFlows := 0
		for _, flow := range flows {
			switch flow.Action {
			case flowlog.ActionAllow:
				if bytes.Equal(flow.Tuple.Src[0:16], []byte(net.ParseIP(w[0][0].IP6))) &&
					bytes.Equal(flow.Tuple.Dst[0:16], []byte(net.ParseIP(w[1][0].IP6))) &&
					flow.SrcMeta.AggregatedName == w[0][0].Name &&
					flow.DstMeta.AggregatedName == w[1][0].Name {
					if flow.PacketsIn > 0 || flow.PacketsOut > 0 || flow.BytesIn > 0 || flow.BytesOut > 0 {
						numExpectedFlows = numExpectedFlows + 1
					}
				}
			case flowlog.ActionDeny:
				if bytes.Equal(flow.Tuple.Src[0:16], []byte(net.ParseIP(w[0][1].IP6))) &&
					bytes.Equal(flow.Tuple.Dst[0:16], []byte(net.ParseIP(w[1][0].IP6))) &&
					flow.SrcMeta.AggregatedName == w[0][1].Name &&
					flow.DstMeta.AggregatedName == w[1][0].Name {
					if flow.PacketsIn > 0 || flow.PacketsOut > 0 || flow.BytesIn > 0 || flow.BytesOut > 0 {
						numExpectedFlows = numExpectedFlows + 1
					}
				}
			}
		}
		Expect(numExpectedFlows).Should(Equal(2))
	})
})

// Tests flow logs for Forward policy.
var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ flow log with Forward policy tests", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	const (
		wepPort = 8055
		svcPort = 8066
	)
	wepPortStr := fmt.Sprintf("%d", wepPort)
	svcPortStr := fmt.Sprintf("%d", svcPort)
	clusterIP := "10.101.0.10"
	interfaceName := "eth0"

	var (
		infra               infrastructure.DatastoreInfra
		opts                infrastructure.TopologyOptions
		tc                  infrastructure.TopologyContainers
		client              client.Interface
		ep1_1, ep2_1, ep2_3 *workload.Workload
		cc                  *connectivity.Checker
	)

	bpfEnabled := os.Getenv("FELIX_FV_ENABLE_BPF") == "true"

	BeforeEach(func() {
		infra = getInfra()
		opts = infrastructure.DefaultTopologyOptions()
		opts.FlowLogSource = infrastructure.FlowLogSourceFile
		opts.IPIPMode = api.IPIPModeNever
		opts.EnableIPv6 = false
		opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "5"
		opts.ExtraEnvVars["FELIX_FLOWLOGSENABLEHOSTENDPOINT"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEINCLUDELABELS"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEINCLUDEPOLICIES"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEAGGREGATIONKINDFORALLOWED"] = strconv.Itoa(int(AggrNone))
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEAGGREGATIONKINDFORDENIED"] = strconv.Itoa(int(AggrNone))
		opts.ExtraEnvVars["FELIX_FLOWLOGSCOLLECTORDEBUGTRACE"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEENABLED"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEINCLUDESERVICE"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSPOLICYSCOPE"] = "AllPolicies"

		// Start 2 felix instances.
		tc, client = infrastructure.StartNNodeTopology(2, opts, infra)

		if bpfEnabled {
			ensureBPFProgramsAttached(tc.Felixes[0])
			ensureBPFProgramsAttached(tc.Felixes[1])
		}

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		// Create workload on host 1.
		infrastructure.AssignIP("ep1-1", "10.65.0.0", tc.Felixes[0].Hostname, client)
		ep1_1 = workload.Run(tc.Felixes[0], "ep1-1", "default", "10.65.0.0", wepPortStr, "tcp")
		ep1_1.ConfigureInInfra(infra)

		infrastructure.AssignIP("ep2-1", "10.65.1.0", tc.Felixes[1].Hostname, client)
		ep2_1 = workload.Run(tc.Felixes[1], "ep2-1", "default", "10.65.1.0", wepPortStr, "tcp")
		ep2_1.ConfigureInInfra(infra)

		infrastructure.AssignIP("ep2-3", "10.65.1.2", tc.Felixes[1].Hostname, client)
		ep2_3 = workload.Run(tc.Felixes[1], "ep2-3", "default", "10.65.1.2", wepPortStr, "tcp")
		ep2_3.ConfigureInInfra(infra)

		// Create a workload on host 2.
		for _, f := range tc.Felixes {
			hep, err := createHEP(f, client, interfaceName)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() error {
				return verifyHostEndpointRules(f, bpfEnabled)
			}, "30s", "1s").Should(BeNil(), "HostEndpoint rules were not correctly configured within timeout period")
			logrus.Infof("Created host endpoint %+v", hep)
		}

		// Create tiers tier1, and tier2.
		tier := api.NewTier()
		tier.Name = "tier1"
		tier.Spec.Order = &float1_0
		_, err := client.Tiers().Create(utils.Ctx, tier, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		tier2 := api.NewTier()
		tier2.Name = "tier2"
		tier2.Spec.Order = &float2_0
		_, err = client.Tiers().Create(utils.Ctx, tier2, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// Create a policy with applyOnForward that passes all traffic to/from the host endpoint.
		gnpfwd := api.NewGlobalNetworkPolicy()
		gnpfwd.Name = "tier1.forward-policy1"
		gnpfwd.Spec.Order = &float1_0
		gnpfwd.Spec.Tier = tier.Name
		gnpfwd.Spec.Selector = "host-endpoint=='true'"
		gnpfwd.Spec.ApplyOnForward = true
		gnpfwd.Spec.Types = []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress}
		gnpfwd.Spec.Egress = []api.Rule{
			{Action: api.Allow},
		}
		gnpfwd.Spec.Ingress = []api.Rule{
			{
				Action: api.Deny,
				Destination: api.EntityRule{
					Nets: []string{"10.65.1.2/32"},
				},
			},
			{Action: api.Allow},
		}
		_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, gnpfwd, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// Allow all traffic to ep2-1
		gnp2_1 := api.NewGlobalNetworkPolicy()
		gnp2_1.Name = "tier2.gnp-ep2-1-allow-ingress"
		gnp2_1.Spec.Order = &float3_0
		gnp2_1.Spec.Tier = tier2.Name
		gnp2_1.Spec.Selector = ep2_1.NameSelector()
		gnp2_1.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
		gnp2_1.Spec.Ingress = []api.Rule{{Action: api.Allow}}
		_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, gnp2_1, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		if !bpfEnabled {
			// Wait for felix to see and program some expected nflog entries, and for the cluster IP to appear.
			Eventually(getRuleFuncTable(tc.Felixes[0], "APE0|gnp/tier1.forward-policy1", "filter"), "10s", "1s").ShouldNot(HaveOccurred())
			Eventually(getRuleFuncTable(tc.Felixes[0], "APE0|gnp/tier2.gnp-ep2-1-allow-ingress", "filter"), "10s", "1s").Should(HaveOccurred())
			Eventually(getRuleFuncTable(tc.Felixes[1], "DPI0|gnp/tier1.forward-policy1", "filter"), "10s", "1s").ShouldNot(HaveOccurred())
			Eventually(getRuleFuncTable(tc.Felixes[1], "API1|gnp/tier1.forward-policy1", "filter"), "10s", "1s").ShouldNot(HaveOccurred())
			Eventually(getRuleFuncTable(tc.Felixes[1], "API0|gnp/tier2.gnp-ep2-1-allow-ingress", "filter"), "10s", "1s").ShouldNot(HaveOccurred())
		} else {
			bpfWaitForPolicyRule(tc.Felixes[0], interfaceName, "egress", "tier1.forward-policy1", `action:"allow"`)
			bpfWaitForPolicyRule(tc.Felixes[1], interfaceName, "ingress", "tier1.forward-policy1", `action:"deny"`)
			bpfWaitForPolicyRule(tc.Felixes[1], interfaceName, "ingress", "tier1.forward-policy1", `action:"allow"`)
			bpfWaitForPolicyRule(tc.Felixes[1], ep2_1.InterfaceName, "ingress", "tier2.gnp-ep2-1-allow-ingress", `action:"allow"`)
		}

		if !bpfEnabled {
			// Mimic the kube-proxy service iptable clusterIP rule.
			for _, f := range tc.Felixes {
				f.Exec("iptables", "-t", "nat", "-A", "PREROUTING",
					"-p", "tcp",
					"-d", clusterIP,
					"-m", "tcp", "--dport", svcPortStr,
					"-j", "DNAT", "--to-destination",
					ep2_1.IP+":"+wepPortStr)
			}
		}
	})

	It("should get expected flow logs for allowed forward policies", func() {
		// Describe the connectivity that we now expect.
		cc = &connectivity.Checker{}
		cc.ExpectSome(ep1_1, ep2_1)

		// Do 3 rounds of connectivity checking.
		cc.CheckConnectivity()
		cc.CheckConnectivity()
		cc.CheckConnectivity()

		flowlogs.WaitForConntrackScan(bpfEnabled)

		// Delete conntrack state so that we don't keep seeing 0-metric copies of the logs.  This will allow the flows
		// to expire quickly.
		for ii := range tc.Felixes {
			tc.Felixes[ii].Exec("conntrack", "-F")
		}

		flowTester := flowlogs.NewFlowTester(flowlogs.FlowTesterOptions{
			ExpectLabels:           true,
			ExpectEnforcedPolicies: true,
			MatchEnforcedPolicies:  true,
			ExpectPendingPolicies:  true,
			MatchPendingPolicies:   true,
			ExpectTransitPolicies:  true,
			MatchTransitPolicies:   true,
			MatchLabels:            false,
			Includes:               []flowlogs.IncludeFilter{flowlogs.IncludeByDestPort(wepPort), flowlogs.IncludeByReporter(flowlog.ReporterSrcFwd), flowlogs.IncludeByReporter(flowlog.ReporterDstFwd)},
			CheckNumFlowsStarted:   true,
		})

		ep1_1_Meta := endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           ep1_1.Name,
			AggregatedName: ep1_1.Name,
		}
		ep2_1_Meta := endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           ep2_1.Name,
			AggregatedName: ep2_1.Name,
		}

		ip1_1, ok := ip.ParseIPAs16Byte("10.65.0.0")
		Expect(ok).To(BeTrue())
		ip2_1, ok := ip.ParseIPAs16Byte("10.65.1.0")
		Expect(ok).To(BeTrue())
		ep1_1_to_ep2_1_Tuple_Agg0 := tuple.Make(ip1_1, ip2_1, 6, flowlogs.SourcePortIsIncluded, wepPort)

		Eventually(func() error {
			// Felix 0.
			if err := flowTester.PopulateFromFlowLogs(tc.Felixes[0]); err != nil {
				return fmt.Errorf("Unable to populate flow tester from flow logs: %v", err)
			}

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      ep1_1_to_ep2_1_Tuple_Agg0,
						SrcMeta:    ep1_1_Meta,
						DstMeta:    ep2_1_Meta,
						DstService: flowlog.EmptyService,
						Action:     "allow",
						Reporter:   "src,fwd",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
					},
					FlowPendingPolicySet: flowlog.FlowPolicySet{
						"0|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
					},
					FlowTransitPolicySet: flowlog.FlowPolicySet{
						"0|tier1|tier1.forward-policy1|allow|0": {},
					},
					FlowProcessReportedStats: flowlog.FlowProcessReportedStats{
						FlowReportedStats: flowlog.FlowReportedStats{
							NumFlowsStarted: 3,
						},
					},
				},
			)

			if err := flowTester.Finish(); err != nil {
				return fmt.Errorf("Flows incorrect on Felix[0]:\n%v", err)
			}

			// Felix 1.
			if err := flowTester.PopulateFromFlowLogs(tc.Felixes[1]); err != nil {
				return fmt.Errorf("Unable to populate flow tester from flow logs: %v", err)
			}

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      ep1_1_to_ep2_1_Tuple_Agg0,
						SrcMeta:    ep1_1_Meta,
						DstMeta:    ep2_1_Meta,
						DstService: flowlog.EmptyService,
						Action:     "allow",
						Reporter:   "dst,fwd",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|tier2|tier2.gnp-ep2-1-allow-ingress|allow|0": {},
					},
					FlowPendingPolicySet: flowlog.FlowPolicySet{
						"0|tier2|tier2.gnp-ep2-1-allow-ingress|allow|0": {},
					},
					FlowTransitPolicySet: flowlog.FlowPolicySet{
						"0|tier1|tier1.forward-policy1|allow|1": {},
					},
					FlowProcessReportedStats: flowlog.FlowProcessReportedStats{
						FlowReportedStats: flowlog.FlowReportedStats{
							NumFlowsStarted: 3,
						},
					},
				},
			)

			if err := flowTester.Finish(); err != nil {
				return fmt.Errorf("Flows incorrect on Felix[1]:\n%v", err)
			}

			return nil
		}, "20s", "1s").ShouldNot(HaveOccurred())
	})

	It("should get expected flow logs for denied forward policies", func() {
		// Describe the connectivity that we now expect.
		cc = &connectivity.Checker{}
		cc.ExpectNone(ep1_1, ep2_3)

		// Do 3 rounds of connectivity checking.
		cc.CheckConnectivity()
		cc.CheckConnectivity()
		cc.CheckConnectivity()

		flowlogs.WaitForConntrackScan(bpfEnabled)

		// Delete conntrack state so that we don't keep seeing 0-metric copies of the logs.  This will allow the flows
		// to expire quickly.
		for ii := range tc.Felixes {
			tc.Felixes[ii].Exec("conntrack", "-F")
		}

		flowTester := flowlogs.NewFlowTester(flowlogs.FlowTesterOptions{
			ExpectLabels:            true,
			ExcludeEnforcedPolicies: true,
			ExcludePendingPolicies:  true,
			ExpectTransitPolicies:   true,
			MatchTransitPolicies:    true,
			MatchLabels:             false,
			Includes:                []flowlogs.IncludeFilter{flowlogs.IncludeByDestPort(wepPort)},
			CheckNumFlowsStarted:    true,
		})

		ep1_1_Meta := endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           ep1_1.Name,
			AggregatedName: ep1_1.Name,
		}
		ep2_3_Meta := endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           ep2_3.Name,
			AggregatedName: ep2_3.Name,
		}

		ip1_1, ok := ip.ParseIPAs16Byte("10.65.0.0")
		Expect(ok).To(BeTrue())
		ip2_3, ok := ip.ParseIPAs16Byte("10.65.1.2")
		Expect(ok).To(BeTrue())
		ep1_1_to_ep2_3_Tuple_Agg0 := tuple.Make(ip1_1, ip2_3, 6, flowlogs.SourcePortIsIncluded, wepPort)

		Eventually(func() error {
			// Felix 0.
			if err := flowTester.PopulateFromFlowLogs(tc.Felixes[0]); err != nil {
				return fmt.Errorf("Unable to populate flow tester from flow logs: %v", err)
			}

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      ep1_1_to_ep2_3_Tuple_Agg0,
						SrcMeta:    ep1_1_Meta,
						DstMeta:    ep2_3_Meta,
						DstService: flowlog.EmptyService,
						Action:     "allow",
						Reporter:   "src,fwd",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
					},
					FlowPendingPolicySet: flowlog.FlowPolicySet{
						"0|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
					},
					FlowTransitPolicySet: flowlog.FlowPolicySet{
						"0|tier1|tier1.forward-policy1|allow|0": {},
					},
					FlowProcessReportedStats: flowlog.FlowProcessReportedStats{
						FlowReportedStats: flowlog.FlowReportedStats{
							NumFlowsStarted: 3,
						},
					},
				},
			)

			if err := flowTester.Finish(); err != nil {
				return fmt.Errorf("Flows incorrect on Felix[0]:\n%v", err)
			}

			// Felix 1.
			if err := flowTester.PopulateFromFlowLogs(tc.Felixes[1]); err != nil {
				return fmt.Errorf("Unable to populate flow tester from flow logs: %v", err)
			}

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      ep1_1_to_ep2_3_Tuple_Agg0,
						SrcMeta:    ep1_1_Meta,
						DstMeta:    ep2_3_Meta,
						DstService: flowlog.EmptyService,
						Action:     "deny",
						Reporter:   "fwd",
					},
					FlowPendingPolicySet: flowlog.FlowPolicySet{
						"0|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
					},
					FlowTransitPolicySet: flowlog.FlowPolicySet{
						"0|tier1|tier1.forward-policy1|deny|0": {},
					},
					FlowProcessReportedStats: flowlog.FlowProcessReportedStats{
						FlowReportedStats: flowlog.FlowReportedStats{
							NumFlowsStarted: 3,
						},
					},
				},
			)

			if err := flowTester.Finish(); err != nil {
				return fmt.Errorf("Flows incorrect on Felix[1]:\n%v", err)
			}

			return nil
		}, "20s", "1s").ShouldNot(HaveOccurred())
	})

	AfterEach(func() {
		for _, felix := range tc.Felixes {
			if bpfEnabled {
				felix.Exec("calico-bpf", "connect-time", "clean")
			}
		}
	})
})

// PreDNAT policy flow log tests.
var _ = infrastructure.DatastoreDescribe(
	"_BPF-SAFE_ flow log with PreDNAT policy tests",
	[]apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes},
	func(getInfra infrastructure.InfraFactory) {
		const (
			nodePort       = 32010
			wepPort        = 8055
			svcPort80      = 80
			svcPort81      = 81
			extIP1, extIP2 = "10.1.2.3", "10.1.2.4"
		)
		wepPortStr := fmt.Sprintf("%d", wepPort)

		var (
			infra          infrastructure.DatastoreInfra
			opts           infrastructure.TopologyOptions
			tc             infrastructure.TopologyContainers
			client         client.Interface
			ep1_1, ep1_2   *workload.Workload
			externalClient *containers.Container
		)

		bpfEnabled := os.Getenv("FELIX_FV_ENABLE_BPF") == "true"

		BeforeEach(func() {
			if NFTMode() {
				Skip("Not supported in NFT mode")
			}

			infra = getInfra()
			opts = infrastructure.DefaultTopologyOptions()
			opts.FlowLogSource = infrastructure.FlowLogSourceFile
			opts.IPIPMode = api.IPIPModeNever
			opts.ExternalIPs = true
			opts.EnableIPv6 = false
			opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "5"
			opts.ExtraEnvVars["FELIX_FLOWLOGSENABLEHOSTENDPOINT"] = "true"
			opts.ExtraEnvVars["FELIX_FLOWLOGSFILEINCLUDELABELS"] = "true"
			opts.ExtraEnvVars["FELIX_FLOWLOGSFILEINCLUDEPOLICIES"] = "true"
			opts.ExtraEnvVars["FELIX_FLOWLOGSFILEAGGREGATIONKINDFORALLOWED"] = strconv.Itoa(int(AggrNone))
			opts.ExtraEnvVars["FELIX_FLOWLOGSFILEAGGREGATIONKINDFORDENIED"] = strconv.Itoa(int(AggrNone))
			opts.ExtraEnvVars["FELIX_FLOWLOGSCOLLECTORDEBUGTRACE"] = "true"
			opts.ExtraEnvVars["FELIX_FLOWLOGSFILEENABLED"] = "true"
			opts.ExtraEnvVars["FELIX_FLOWLOGSFILEINCLUDESERVICE"] = "true"
			opts.ExtraEnvVars["FELIX_BPFConnectTimeLoadBalancing"] = string(api.BPFConnectTimeLBDisabled)
			opts.ExtraEnvVars["FELIX_BPFHostNetworkedNATWithoutCTLB"] = string(api.BPFHostNetworkedNATEnabled)
			opts.ExtraEnvVars["FELIX_FLOWLOGSPOLICYSCOPE"] = "AllPolicies"

			tc, client = infrastructure.StartSingleNodeTopology(opts, infra)

			if bpfEnabled {
				ensureBPFProgramsAttached(tc.Felixes[0])
			}

			infra.AddDefaultAllow()

			ep1_1 = workload.Run(tc.Felixes[0], "ep1-1", "default", "10.65.0.0", wepPortStr, "tcp")
			ep1_1.ConfigureInInfra(infra)

			ep1_2 = workload.Run(tc.Felixes[0], "ep1-2", "default", "10.65.0.1", wepPortStr, "tcp")
			ep1_2.ConfigureInInfra(infra)

			externalClient = infrastructure.RunExtClient(infra, "ext-client")
			externalClient.Exec("ip", "r", "add", "10.65.0.0/24", "via", tc.Felixes[0].IP)
			externalClient.Exec("ip", "r", "add", extIP1+"/32", "via", tc.Felixes[0].IP)
			externalClient.Exec("ip", "r", "add", extIP2+"/32", "via", tc.Felixes[0].IP)
		})

		AfterEach(func() {
			if CurrentGinkgoTestDescription().Failed {
				if bpfEnabled {
					tc.Felixes[0].Exec("calico-bpf", "policy", "dump", ep1_1.InterfaceName, "all", "--asm")
					tc.Felixes[0].Exec("calico-bpf", "policy", "dump", ep1_2.InterfaceName, "all", "--asm")
					tc.Felixes[0].Exec("calico-bpf", "nat", "dump")
				}
			}
			for _, f := range tc.Felixes {
				if bpfEnabled {
					f.Exec("calico-bpf", "connect-time", "clean")
				}
			}
		})

		Context("preDNAT policies applied", func() {
			var (
				tier                           *api.Tier
				privateMeta                    endpoint.Metadata
				ep1_1_Meta                     endpoint.Metadata
				ep1_2_Meta                     endpoint.Metadata
				ext_svc_80_Meta                flowlog.FlowService
				ext_svc_81_Meta                flowlog.FlowService
				external_to_ep1_1_80_Agg0      tuple.Tuple
				external_to_ep1_2_81_Agg0      tuple.Tuple
				external_to_extService_80_Agg0 tuple.Tuple
				external_to_extService_81_Agg0 tuple.Tuple
			)

			tcp := numorstring.ProtocolFromString("TCP")
			interfaceEth0 := "eth0"

			denyPort81Policy := func() {
				preDNATDenyServicePort81 := api.NewGlobalNetworkPolicy()
				preDNATDenyServicePort81.Name = "tier1.prednat-deny-service-port-81-policy"
				preDNATDenyServicePort81.Spec.Order = &float1_0
				preDNATDenyServicePort81.Spec.Tier = tier.Name
				preDNATDenyServicePort81.Spec.Selector = "host-endpoint=='true'"
				preDNATDenyServicePort81.Spec.ApplyOnForward = true
				preDNATDenyServicePort81.Spec.PreDNAT = true
				preDNATDenyServicePort81.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
				preDNATDenyServicePort81.Spec.Ingress = []api.Rule{
					{
						Action:   api.Allow,
						Protocol: &tcp,
						Source: api.EntityRule{
							Nets: []string{externalClient.IP + "/32"},
						},
						Destination: api.EntityRule{
							Ports: []numorstring.Port{numorstring.SinglePort(svcPort80)},
						},
					},
					{
						Action:   api.Deny,
						Protocol: &tcp,
						Source: api.EntityRule{
							Nets: []string{externalClient.IP + "/32"},
						},
						Destination: api.EntityRule{
							Ports: []numorstring.Port{numorstring.SinglePort(svcPort81)},
						},
					},
				}
				_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, preDNATDenyServicePort81, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				if !bpfEnabled {
					Eventually(getRuleFuncTable(tc.Felixes[0], "API0|gnp/tier1.prednat-deny-service-port-81-policy", "mangle"), "10s", "1s").ShouldNot(HaveOccurred())
					Eventually(getRuleFuncTable(tc.Felixes[0], "DPI1|gnp/tier1.prednat-deny-service-port-81-policy", "mangle"), "10s", "1s").ShouldNot(HaveOccurred())
					Eventually(getRuleFuncTable(tc.Felixes[0], "API0|gnp/tier1.default-allow-prednat-policy", "mangle"), "10s", "1s").ShouldNot(HaveOccurred())
				} else {
					bpfWaitForPolicyRule(tc.Felixes[0], interfaceEth0, "ingress", "tier1.prednat-deny-service-port-81-policy", `action:"allow"`)
					bpfWaitForPolicyRule(tc.Felixes[0], interfaceEth0, "ingress", "tier1.prednat-deny-service-port-81-policy", `action:"deny"`)
					bpfWaitForPolicyRule(tc.Felixes[0], interfaceEth0, "ingress", "tier1.default-allow-prednat-policy", `action:"allow"`)
				}
			}

			BeforeEach(func() {
				service1Name := "load-balancer-service-1"
				service2Name := "load-balancer-service-2"

				privateMeta = endpoint.Metadata{
					Type:           "net",
					Namespace:      "-",
					Name:           "-",
					AggregatedName: "pvt",
				}
				ep1_1_Meta = endpoint.Metadata{
					Type:           "wep",
					Namespace:      "default",
					Name:           ep1_1.Name,
					AggregatedName: ep1_1.Name,
				}
				ep1_2_Meta = endpoint.Metadata{
					Type:           "wep",
					Namespace:      "default",
					Name:           ep1_2.Name,
					AggregatedName: ep1_2.Name,
				}
				ext_svc_80_Meta = flowlog.FlowService{
					Namespace: "default",
					Name:      service1Name,
					PortName:  fmt.Sprintf("port-%d", wepPort),
					PortNum:   svcPort80,
				}
				ext_svc_81_Meta = flowlog.FlowService{
					Namespace: "default",
					Name:      service2Name,
					PortName:  fmt.Sprintf("port-%d", wepPort),
					PortNum:   svcPort81,
				}
				externalIP, ok := ip.ParseIPAs16Byte(externalClient.IP)
				Expect(ok).To(BeTrue())
				externalServiceIP1, ok := ip.ParseIPAs16Byte(extIP1)
				Expect(ok).To(BeTrue())
				externalServiceIP2, ok := ip.ParseIPAs16Byte(extIP2)
				Expect(ok).To(BeTrue())
				ep1_1_IP, ok := ip.ParseIPAs16Byte(ep1_1.IP)
				Expect(ok).To(BeTrue())
				ep1_2_IP, ok := ip.ParseIPAs16Byte(ep1_2.IP)
				Expect(ok).To(BeTrue())
				external_to_ep1_1_80_Agg0 = tuple.Make(externalIP, ep1_1_IP, 6, flowlogs.SourcePortIsIncluded, wepPort)
				external_to_ep1_2_81_Agg0 = tuple.Make(externalIP, ep1_2_IP, 6, flowlogs.SourcePortIsIncluded, wepPort)
				external_to_extService_80_Agg0 = tuple.Make(externalIP, externalServiceIP1, 6, flowlogs.SourcePortIsIncluded, svcPort80)
				external_to_extService_81_Agg0 = tuple.Make(externalIP, externalServiceIP2, 6, flowlogs.SourcePortIsIncluded, svcPort81)

				// Create HEPs.
				for _, f := range tc.Felixes {
					hep, err := createHEP(f, client, interfaceEth0)
					Expect(err).NotTo(HaveOccurred())
					Eventually(func() error {
						return verifyHostEndpointRules(f, bpfEnabled)
					}, "30s", "1s").Should(BeNil())
					logrus.Infof("Created host endpoint %+v", hep)
				}

				// Create a tier for the policies.
				tier = api.NewTier()
				tier.Name = "tier1"
				tier.Spec.Order = &float1_0
				_, err := client.Tiers().Create(utils.Ctx, tier, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				// Create a policy with preDNAT that allows all traffic to the host endpoint.
				gnpPreDnatAllow := api.NewGlobalNetworkPolicy()
				gnpPreDnatAllow.Name = "tier1.default-allow-prednat-policy"
				gnpPreDnatAllow.Spec.Order = &float2_0
				gnpPreDnatAllow.Spec.Tier = tier.Name
				gnpPreDnatAllow.Spec.Selector = "host-endpoint=='true'"
				gnpPreDnatAllow.Spec.ApplyOnForward = true
				gnpPreDnatAllow.Spec.PreDNAT = true
				gnpPreDnatAllow.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
				gnpPreDnatAllow.Spec.Ingress = []api.Rule{{Action: api.Allow}}
				_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, gnpPreDnatAllow, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				if !bpfEnabled {
					Eventually(getRuleFuncTable(tc.Felixes[0], "API0|gnp/tier1.default-allow-prednat-policy", "mangle"), "10s", "1s").ShouldNot(HaveOccurred())
				} else {
					bpfWaitForPolicyRule(tc.Felixes[0], interfaceEth0, "ingress", "tier1.default-allow-prednat-policy", `action:"allow"`)
				}

				if !bpfEnabled {
					for _, f := range tc.Felixes {
						f.Exec(
							"iptables", "-t", "nat",
							"-w", "10", "-W", "100000",
							"-A", "PREROUTING",
							"-p", "tcp",
							"-d", extIP1, "--dport", fmt.Sprintf("%d", svcPort80),
							"-j", "DNAT", "--to", ep1_1.IP+":"+wepPortStr,
						)
						f.Exec(
							"iptables", "-t", "nat",
							"-w", "10", "-W", "100000",
							"-A", "PREROUTING",
							"-p", "tcp",
							"-d", extIP2, "--dport", fmt.Sprintf("%d", svcPort81),
							"-j", "DNAT", "--to", ep1_2.IP+":"+wepPortStr,
						)
					}
				}

				serviceExternalIP1 := []string{extIP1}
				tSvc := k8sLBService(service1Name, "10.101.0.10", ep1_1.Name, svcPort80, wepPort, "tcp", serviceExternalIP1, []string{})
				k8sClient := infra.(*infrastructure.K8sDatastoreInfra).K8sClient
				_, err = k8sClient.CoreV1().Services(tSvc.Namespace).Create(context.Background(), tSvc, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(k8sGetEpsForServiceFunc(k8sClient, tSvc), "10s").Should(HaveLen(1), "Expected service endpoint: %s to be created", tSvc.Name)

				serviceExternalIP2 := []string{extIP2}
				tSvc2 := k8sLBService(service2Name, "10.101.0.11", ep1_2.Name, svcPort81, wepPort, "tcp", serviceExternalIP2, []string{})
				_, err = k8sClient.CoreV1().Services(tSvc2.Namespace).Create(context.Background(), tSvc2, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(k8sGetEpsForServiceFunc(k8sClient, tSvc2), "10s").Should(HaveLen(1), "Expected service endpoint: %s to be created", tSvc2.Name)
			})

			It("allows traffic from external client to pod within the cluster", func() {
				cc := &connectivity.Checker{}

				cc.ExpectSome(externalClient, connectivity.TargetIP(extIP1), svcPort80)
				cc.ExpectSome(externalClient, connectivity.TargetIP(extIP2), svcPort81)

				cc.CheckConnectivity()
				cc.CheckConnectivity()
				cc.CheckConnectivity()

				flowlogs.WaitForConntrackScan(bpfEnabled)

				for _, f := range tc.Felixes {
					f.Exec("conntrack", "-F")
				}

				var filters []flowlogs.IncludeFilter
				if !bpfEnabled {
					filters = []flowlogs.IncludeFilter{
						flowlogs.IncludeByDestPort(svcPort80),
						flowlogs.IncludeByDestPort(svcPort81),
					}
				} else {
					filters = []flowlogs.IncludeFilter{
						flowlogs.IncludeByDestPort(wepPort),
					}
				}

				// Create a flow tester and check for the expected flow logs
				flowTester := flowlogs.NewFlowTester(flowlogs.FlowTesterOptions{
					ExpectLabels:            true,
					ExcludeEnforcedPolicies: true,
					ExcludePendingPolicies:  true,
					MatchPendingPolicies:    true,
					ExpectTransitPolicies:   true,
					MatchTransitPolicies:    true,
					MatchLabels:             false,
					Includes:                filters,
					CheckNumFlowsStarted:    true,
				})

				Eventually(func() error {
					if err := flowTester.PopulateFromFlowLogs(tc.Felixes[0]); err != nil {
						return fmt.Errorf("Unable to populate flow tester from flow logs: %v", err)
					}

					if !bpfEnabled {
						flowTester.CheckFlow(flowlog.FlowLog{
							FlowMeta: flowlog.FlowMeta{
								Tuple:      external_to_extService_80_Agg0,
								SrcMeta:    privateMeta,
								DstMeta:    privateMeta,
								DstService: flowlog.EmptyService,
								Action:     "allow",
								Reporter:   "fwd",
							},
							FlowTransitPolicySet: flowlog.FlowPolicySet{
								"0|tier1|tier1.default-allow-prednat-policy|allow|0": {},
							},
							FlowProcessReportedStats: flowlog.FlowProcessReportedStats{
								FlowReportedStats: flowlog.FlowReportedStats{
									NumFlowsStarted: 3,
								},
							},
						})
					} else {
						flowTester.CheckFlow(flowlog.FlowLog{
							FlowMeta: flowlog.FlowMeta{
								Tuple:      external_to_ep1_1_80_Agg0,
								SrcMeta:    privateMeta,
								DstMeta:    ep1_1_Meta,
								DstService: ext_svc_80_Meta,
								Action:     "allow",
								Reporter:   "dst,fwd",
							},
							FlowEnforcedPolicySet: flowlog.FlowPolicySet{
								"0|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
							},
							FlowPendingPolicySet: flowlog.FlowPolicySet{
								"0|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
							},
							FlowTransitPolicySet: flowlog.FlowPolicySet{
								"0|tier1|tier1.default-allow-prednat-policy|allow|0": {},
							},
							FlowProcessReportedStats: flowlog.FlowProcessReportedStats{
								FlowReportedStats: flowlog.FlowReportedStats{
									NumFlowsStarted: 3,
								},
							},
						})
					}

					if !bpfEnabled {
						flowTester.CheckFlow(flowlog.FlowLog{
							FlowMeta: flowlog.FlowMeta{
								Tuple:      external_to_extService_81_Agg0,
								SrcMeta:    privateMeta,
								DstMeta:    privateMeta,
								DstService: flowlog.EmptyService,
								Action:     "allow",
								Reporter:   "fwd",
							},
							FlowTransitPolicySet: flowlog.FlowPolicySet{
								"0|tier1|tier1.default-allow-prednat-policy|allow|0": {},
							},
							FlowProcessReportedStats: flowlog.FlowProcessReportedStats{
								FlowReportedStats: flowlog.FlowReportedStats{
									NumFlowsStarted: 3,
								},
							},
						})
					} else {
						flowTester.CheckFlow(flowlog.FlowLog{
							FlowMeta: flowlog.FlowMeta{
								Tuple:      external_to_ep1_2_81_Agg0,
								SrcMeta:    privateMeta,
								DstMeta:    ep1_2_Meta,
								DstService: ext_svc_81_Meta,
								Action:     "allow",
								Reporter:   "dst,fwd",
							},
							FlowEnforcedPolicySet: flowlog.FlowPolicySet{
								"0|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
							},
							FlowPendingPolicySet: flowlog.FlowPolicySet{
								"0|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
							},
							FlowTransitPolicySet: flowlog.FlowPolicySet{
								"0|tier1|tier1.default-allow-prednat-policy|allow|0": {},
							},
							FlowProcessReportedStats: flowlog.FlowProcessReportedStats{
								FlowReportedStats: flowlog.FlowReportedStats{
									NumFlowsStarted: 3,
								},
							},
						})
					}

					if err := flowTester.Finish(); err != nil {
						return fmt.Errorf("Flows incorrect on Felix[0]:\n%v", err)
					}

					return nil
				}, "20s", "1s").ShouldNot(HaveOccurred())
			})

			It("denies traffic from external client to target with port 81", func() {
				cc := &connectivity.Checker{}

				denyPort81Policy()

				cc.ExpectSome(externalClient, connectivity.TargetIP(extIP1), svcPort80)
				cc.ExpectNone(externalClient, connectivity.TargetIP(extIP2), svcPort81)

				cc.CheckConnectivity()
				cc.CheckConnectivity()
				cc.CheckConnectivity()

				flowlogs.WaitForConntrackScan(bpfEnabled)

				for _, f := range tc.Felixes {
					f.Exec("conntrack", "-F")
				}

				var filters []flowlogs.IncludeFilter
				if !bpfEnabled {
					filters = []flowlogs.IncludeFilter{
						flowlogs.IncludeByDestPort(svcPort80),
						flowlogs.IncludeByDestPort(svcPort81),
					}
				} else {
					filters = []flowlogs.IncludeFilter{
						flowlogs.IncludeByDestPort(wepPort),
					}
				}

				// Create a flow tester and check for the expected flow logs
				flowTester := flowlogs.NewFlowTester(flowlogs.FlowTesterOptions{
					ExpectLabels:            true,
					ExcludeEnforcedPolicies: true,
					ExcludePendingPolicies:  true,
					MatchPendingPolicies:    true,
					ExpectTransitPolicies:   true,
					MatchTransitPolicies:    true,
					MatchLabels:             false,
					Includes:                filters,
					CheckNumFlowsStarted:    true,
				})

				Eventually(func() error {
					if err := flowTester.PopulateFromFlowLogs(tc.Felixes[0]); err != nil {
						return fmt.Errorf("Unable to populate flow tester from flow logs: %v", err)
					}

					if !bpfEnabled {
						flowTester.CheckFlow(flowlog.FlowLog{
							FlowMeta: flowlog.FlowMeta{
								Tuple:      external_to_extService_80_Agg0,
								SrcMeta:    privateMeta,
								DstMeta:    privateMeta,
								DstService: flowlog.EmptyService,
								Action:     "allow",
								Reporter:   "fwd",
							},
							FlowTransitPolicySet: flowlog.FlowPolicySet{
								"0|tier1|tier1.prednat-deny-service-port-81-policy|allow|0": {},
							},
							FlowProcessReportedStats: flowlog.FlowProcessReportedStats{
								FlowReportedStats: flowlog.FlowReportedStats{
									NumFlowsStarted: 3,
								},
							},
						})
					} else {
						flowTester.CheckFlow(flowlog.FlowLog{
							FlowMeta: flowlog.FlowMeta{
								Tuple:      external_to_ep1_1_80_Agg0,
								SrcMeta:    privateMeta,
								DstMeta:    ep1_1_Meta,
								DstService: ext_svc_80_Meta,
								Action:     "allow",
								Reporter:   "dst,fwd",
							},
							FlowEnforcedPolicySet: flowlog.FlowPolicySet{
								"0|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
							},
							FlowPendingPolicySet: flowlog.FlowPolicySet{
								"0|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
							},
							FlowTransitPolicySet: flowlog.FlowPolicySet{
								"0|tier1|tier1.prednat-deny-service-port-81-policy|allow|0": {},
							},
							FlowProcessReportedStats: flowlog.FlowProcessReportedStats{
								FlowReportedStats: flowlog.FlowReportedStats{
									NumFlowsStarted: 3,
								},
							},
						})
					}

					if !bpfEnabled {
						flowTester.CheckFlow(flowlog.FlowLog{
							FlowMeta: flowlog.FlowMeta{
								Tuple:      external_to_extService_81_Agg0,
								SrcMeta:    privateMeta,
								DstMeta:    privateMeta,
								DstService: flowlog.EmptyService,
								Action:     "deny",
								Reporter:   "fwd",
							},
							FlowTransitPolicySet: flowlog.FlowPolicySet{
								"0|tier1|tier1.prednat-deny-service-port-81-policy|deny|1": {},
							},
							FlowProcessReportedStats: flowlog.FlowProcessReportedStats{
								FlowReportedStats: flowlog.FlowReportedStats{
									NumFlowsStarted: 3,
								},
							},
						})
					} else {
						flowTester.CheckFlow(flowlog.FlowLog{
							FlowMeta: flowlog.FlowMeta{
								Tuple:      external_to_ep1_2_81_Agg0,
								SrcMeta:    privateMeta,
								DstMeta:    ep1_2_Meta,
								DstService: ext_svc_81_Meta,
								Action:     "deny",
								Reporter:   "fwd",
							},
							FlowPendingPolicySet: flowlog.FlowPolicySet{
								"0|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
							},
							FlowTransitPolicySet: flowlog.FlowPolicySet{
								"0|tier1|tier1.prednat-deny-service-port-81-policy|deny|1": {},
							},
							FlowProcessReportedStats: flowlog.FlowProcessReportedStats{
								FlowReportedStats: flowlog.FlowReportedStats{
									NumFlowsStarted: 4,
								},
							},
						})
					}

					if err := flowTester.Finish(); err != nil {
						return fmt.Errorf("Flows incorrect on Felix[0]:\n%v", err)
					}

					return nil
				}, "20s", "1s").ShouldNot(HaveOccurred())
			})
		})
	},
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ flow log networkset precedence tests", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra                  infrastructure.DatastoreInfra
		tc                     infrastructure.TopologyContainers
		opts                   infrastructure.TopologyOptions
		client                 client.Interface
		swl1, swl2, swl3, swl4 *workload.Workload
		dwl1, dwl2             *workload.Workload
		cc                     *connectivity.Checker
	)

	BeforeEach(func() {
		if NFTMode() {
			Skip("Not supported in NFT mode")
		}

		infra = getInfra()
		opts = infrastructure.DefaultTopologyOptions()
		opts.FlowLogSource = infrastructure.FlowLogSourceFile
		opts.IPIPMode = api.IPIPModeNever

		opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "2"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEINCLUDELABELS"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEINCLUDEPOLICIES"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSENABLENETWORKSETS"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEAGGREGATIONKINDFORALLOWED"] = strconv.Itoa(int(AggrNone))
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEAGGREGATIONKINDFORDENIED"] = strconv.Itoa(int(AggrNone))
		opts.ExtraEnvVars["FELIX_FLOWLOGSCOLLECTORDEBUGTRACE"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEENABLED"] = "true"
	})

	JustBeforeEach(func() {
		var err error
		numNodes := 2
		tc, client = infrastructure.StartNNodeTopology(numNodes, opts, infra)

		if BPFMode() {
			ensureBPFProgramsAttached(tc.Felixes[0])
			ensureBPFProgramsAttached(tc.Felixes[1])
		}

		infra.AddDefaultAllow()

		// Source workloads on Node 0
		// swl1 in ns1
		swl1 = workload.Run(tc.Felixes[0], "swl1", "ns1", "10.65.0.2", "8055", "tcp")
		swl1.WorkloadEndpoint.GenerateName = "swl1-"
		swl1.WorkloadEndpoint.Namespace = "ns1"
		swl1.ConfigureInInfra(infra)

		// swl2 in ns2
		swl2 = workload.Run(tc.Felixes[0], "swl2", "ns2", "10.65.0.3", "8055", "tcp")
		swl2.WorkloadEndpoint.GenerateName = "swl2-"
		swl2.WorkloadEndpoint.Namespace = "ns2"
		swl2.ConfigureInInfra(infra)

		// swl3 in ns3
		swl3 = workload.Run(tc.Felixes[0], "swl3", "ns3", "10.65.0.4", "8055", "tcp")
		swl3.WorkloadEndpoint.GenerateName = "swl3-"
		swl3.WorkloadEndpoint.Namespace = "ns3"
		swl3.ConfigureInInfra(infra)

		// swl4 in ns3
		swl4 = workload.Run(tc.Felixes[0], "swl4", "ns3", "10.65.0.5", "8055", "tcp")
		swl4.WorkloadEndpoint.GenerateName = "swl4-"
		swl4.WorkloadEndpoint.Namespace = "ns3"
		swl4.ConfigureInInfra(infra)

		// Destination workloads on Node 1 (Host Networked to simulate external/non-WEP IPs)

		// dwl1
		dwl1 = workload.New(tc.Felixes[1], "dwl1", "", "10.65.1.2", "8055", "tcp", workload.WithHostNetworked())
		// Add IP before starting workload so it can bind
		err = tc.Felixes[1].ExecMayFail("ip", "addr", "add", "10.65.1.2/32", "dev", "lo")
		Expect(err).NotTo(HaveOccurred())
		Expect(dwl1.Start(tc.Felixes[1])).NotTo(HaveOccurred())

		// dwl2
		dwl2 = workload.New(tc.Felixes[1], "dwl2", "", "10.65.1.3", "8055", "tcp", workload.WithHostNetworked())
		// Add IP before starting workload so it can bind
		err = tc.Felixes[1].ExecMayFail("ip", "addr", "add", "10.65.1.3/32", "dev", "lo")
		Expect(err).NotTo(HaveOccurred())
		Expect(dwl2.Start(tc.Felixes[1])).NotTo(HaveOccurred())

		// Add a policy to allow all traffic
		policy := api.NewGlobalNetworkPolicy()
		policy.Name = "allow-all"
		order := float64(20)
		policy.Spec.Order = &order
		policy.Spec.Selector = "all()"
		policy.Spec.Ingress = []api.Rule{{Action: api.Allow}}
		policy.Spec.Egress = []api.Rule{{Action: api.Allow}}
		_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		if !BPFMode() {
			Eventually(getRuleFuncTable(tc.Felixes[0], "API0|gnp/allow-all", "filter"), "10s", "1s").ShouldNot(HaveOccurred())
			Eventually(getRuleFuncTable(tc.Felixes[0], "APE0|gnp/allow-all", "filter"), "10s", "1s").ShouldNot(HaveOccurred())
		} else {
			bpfWaitForPolicyRule(tc.Felixes[0], swl1.InterfaceName, "ingress", "allow-all", `action:"allow"`)
			bpfWaitForPolicyRule(tc.Felixes[0], swl1.InterfaceName, "egress", "allow-all", `action:"allow"`)
		}

		// NetworkSets
		// netset-1 in ns1 matches dwl1
		netset1 := api.NewNetworkSet()
		netset1.Name = "netset-1"
		netset1.Namespace = "ns1"
		netset1.Spec.Nets = []string{dwl1.IP + "/32"}
		_, err = client.NetworkSets().Create(utils.Ctx, netset1, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// netset-2 in ns2 matches dwl1
		netset2 := api.NewNetworkSet()
		netset2.Name = "netset-2"
		netset2.Namespace = "ns2"
		netset2.Spec.Nets = []string{dwl1.IP + "/32"}
		_, err = client.NetworkSets().Create(utils.Ctx, netset2, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// gns-1 (global) matches dwl1
		gnetset := api.NewGlobalNetworkSet()
		gnetset.Name = "gns-1"
		gnetset.Spec.Nets = []string{dwl1.IP + "/32"}
		_, err = client.GlobalNetworkSets().Create(utils.Ctx, gnetset, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// netset-4 in ns4 matches dwl2
		netset4 := api.NewNetworkSet()
		netset4.Name = "netset-4"
		netset4.Namespace = "ns4"
		netset4.Spec.Nets = []string{dwl2.IP + "/32"}
		_, err = client.NetworkSets().Create(utils.Ctx, netset4, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		if BPFMode() {
			ensureAllNodesBPFProgramsAttached(tc.Felixes)
		}
	})

	It("should report correct network sets based on namespace precedence", func() {
		// Connectivity check
		cc = &connectivity.Checker{}
		cc.ExpectSome(swl1, dwl1)
		cc.ExpectSome(swl2, dwl1)
		cc.ExpectSome(swl3, dwl1)
		cc.ExpectSome(swl4, dwl2)
		cc.CheckConnectivity()

		bpfMode := BPFMode()
		flowlogs.WaitForConntrackScan(bpfMode)

		for ii := range tc.Felixes {
			tc.Felixes[ii].Exec("conntrack", "-F")
		}

		Eventually(func() error {
			wepPort := 8055
			flowTester := flowlogs.NewFlowTester(flowlogs.FlowTesterOptions{
				ExpectLabels:           true,
				ExpectEnforcedPolicies: true,
				MatchEnforcedPolicies:  true,
				MatchLabels:            false,
				Includes:               []flowlogs.IncludeFilter{flowlogs.IncludeByDestPort(wepPort)},
			})

			err := flowTester.PopulateFromFlowLogs(tc.Felixes[0])
			if err != nil {
				return fmt.Errorf("error populating flow logs from Felix[0]: %s", err)
			}

			type checkArgs struct {
				desc       string
				srcNS      string
				srcName    string
				srcAggName string
				srcIP      string
				dstNS      string
				dstName    string
				dstAggName string
				dstIP      string
			}
			check := func(args checkArgs) {
				var srcIP, dstIP [16]byte
				copy(srcIP[:], net.ParseIP(args.srcIP).To16())
				copy(dstIP[:], net.ParseIP(args.dstIP).To16())
				t := tuple.Make(srcIP, dstIP, 6, flowlogs.SourcePortIsIncluded, wepPort)

				flowTester.CheckFlow(flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      t,
						SrcMeta:    endpoint.Metadata{Type: "wep", Namespace: args.srcNS, Name: args.srcName, AggregatedName: args.srcAggName},
						DstMeta:    endpoint.Metadata{Type: "ns", Namespace: args.dstNS, Name: args.dstName, AggregatedName: args.dstAggName},
						DstService: flowlog.FlowService{Namespace: flowlog.FieldNotIncluded, Name: flowlog.FieldNotIncluded, PortName: flowlog.FieldNotIncluded, PortNum: 0},
						Action:     "allow", Reporter: "src",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{"0|default|allow-all|allow|0": {}},
				})
			}

			check(checkArgs{desc: "ns1 -> netset-1", srcNS: "ns1", srcName: swl1.Name, srcAggName: "swl1-*", srcIP: swl1.IP, dstNS: "ns1", dstName: "netset-1", dstAggName: "netset-1", dstIP: dwl1.IP})
			check(checkArgs{desc: "ns2 -> netset-2", srcNS: "ns2", srcName: swl2.Name, srcAggName: "swl2-*", srcIP: swl2.IP, dstNS: "ns2", dstName: "netset-2", dstAggName: "netset-2", dstIP: dwl1.IP})
			check(checkArgs{desc: "ns3 -> gns-1", srcNS: "ns3", srcName: swl3.Name, srcAggName: "swl3-*", srcIP: swl3.IP, dstNS: flowlog.FieldNotIncluded, dstName: "gns-1", dstAggName: "gns-1", dstIP: dwl1.IP})
			check(checkArgs{desc: "ns3 -> netset-3", srcNS: "ns3", srcName: swl4.Name, srcAggName: "swl4-*", srcIP: swl4.IP, dstNS: "ns4", dstName: "netset-4", dstAggName: "netset-4", dstIP: dwl2.IP})

			if err := flowTester.Finish(); err != nil {
				return fmt.Errorf("Flows incorrect on Felix[0]:\n%v", err)
			}
			return nil
		}, "30s", "3s").ShouldNot(HaveOccurred())
	})
})

var _ = infrastructure.DatastoreDescribe("flow log with deleted service pod test", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	const (
		wepPort = 8055
		svcPort = 8066
	)
	wepPortStr := fmt.Sprintf("%d", wepPort)
	svcPortStr := fmt.Sprintf("%d", svcPort)
	clusterIP := "10.101.0.10"

	var (
		infra        infrastructure.DatastoreInfra
		opts         infrastructure.TopologyOptions
		tc           infrastructure.TopologyContainers
		client       client.Interface
		ep1_1, ep2_1 *workload.Workload
		cc           *connectivity.Checker
	)

	bpfEnabled := os.Getenv("FELIX_FV_ENABLE_BPF") == "true"

	BeforeEach(func() {
		infra = getInfra()
		opts = infrastructure.DefaultTopologyOptions()
		opts.FlowLogSource = infrastructure.FlowLogSourceFile
		opts.IPIPMode = api.IPIPModeNever
		opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "25"
		opts.ExtraEnvVars["FELIX_FLOWLOGSENABLEHOSTENDPOINT"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEINCLUDELABELS"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEINCLUDEPOLICIES"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEAGGREGATIONKINDFORALLOWED"] = strconv.Itoa(int(AggrNone))
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEAGGREGATIONKINDFORDENIED"] = strconv.Itoa(int(AggrNone))
		opts.ExtraEnvVars["FELIX_FLOWLOGSCOLLECTORDEBUGTRACE"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEENABLED"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEINCLUDESERVICE"] = "true"

		// Start felix instances.
		tc, client = infrastructure.StartNNodeTopology(2, opts, infra)

		if bpfEnabled {
			ensureBPFProgramsAttached(tc.Felixes[0])
			ensureBPFProgramsAttached(tc.Felixes[1])
		}

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		// Create workload on host 1.
		ep1_1 = workload.Run(tc.Felixes[0], "ep1-1", "default", "10.65.0.0", wepPortStr, "tcp")
		ep1_1.ConfigureInInfra(infra)

		ep2_1 = workload.Run(tc.Felixes[1], "ep2-1", "default", "10.65.1.0", wepPortStr, "tcp")
		ep2_1.ConfigureInInfra(infra)

		// Create a service that maps to ep2_1. Rather than checking connectivity to the endpoint we'll go via
		// the service to test the destination service name handling.
		svcName := "test-service"
		k8sClient := infra.(*infrastructure.K8sDatastoreInfra).K8sClient
		tSvc := k8sService(svcName, clusterIP, ep2_1, svcPort, wepPort, 0, "tcp")
		tSvcNamespace := tSvc.Namespace
		_, err := k8sClient.CoreV1().Services(tSvcNamespace).Create(context.Background(), tSvc, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Wait for the endpoints to be updated and for the address to be ready.
		Expect(ep2_1.IP).NotTo(Equal(""))
		getEpsFunc := k8sGetEpsForServiceFunc(k8sClient, tSvc)
		epCorrectFn := func() error {
			eps := getEpsFunc()
			if len(eps) != 1 {
				return fmt.Errorf("Wrong number of endpointslices: %#v", eps)
			}
			if len(eps[0].Endpoints) != 1 {
				return fmt.Errorf("Wrong number of endpoints: %#v", eps[0])
			}
			endpoints := eps[0].Endpoints
			addrs := endpoints[0].Addresses
			if len(addrs) != 1 {
				return fmt.Errorf("Wrong number of addresses: %#v", eps[0])
			}
			if addrs[0] != ep2_1.IP {
				return fmt.Errorf("Unexpected IP: %s != %s", addrs[0], ep2_1.IP)
			}
			ports := eps[0].Ports
			if len(ports) != 1 {
				return fmt.Errorf("Wrong number of ports: %#v", eps[0])
			}
			if *ports[0].Port != int32(wepPort) {
				return fmt.Errorf("Wrong port %d != svcPort", *ports[0].Port)
			}
			return nil
		}
		Eventually(epCorrectFn, "10s").ShouldNot(HaveOccurred())

		// Create a policy that allows ep1-1 to communicate with test-service using label matching
		gnpServiceAllow := api.NewGlobalNetworkPolicy()
		gnpServiceAllow.Name = "default.ep1-1-allow-test-service"
		gnpServiceAllow.Spec.Order = &float2_0
		gnpServiceAllow.Spec.Tier = "default"
		gnpServiceAllow.Spec.Selector = ep1_1.NameSelector()
		gnpServiceAllow.Spec.Types = []api.PolicyType{api.PolicyTypeEgress}
		gnpServiceAllow.Spec.Egress = []api.Rule{
			{
				Action: api.Allow,
				Destination: api.EntityRule{
					Services: &api.ServiceMatch{
						Namespace: "default",
						Name:      svcName,
					},
				},
			},
		}
		_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, gnpServiceAllow, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		if !bpfEnabled {
			// Wait for felix to see and program some expected nflog entries, and for the cluster IP to appear.
			Eventually(getRuleFunc(tc.Felixes[0], "APE0|gnp/default.ep1-1-allow-test-service"), "10s", "1s").ShouldNot(HaveOccurred())
		} else {
			checkNat := func() bool {
				for _, f := range tc.Felixes {
					if !f.BPFNATHasBackendForService(clusterIP, svcPort, 6, ep2_1.IP, wepPort) {
						return false
					}
				}
				return true
			}

			Eventually(checkNat, "10s", "1s").Should(BeTrue(), "Expected NAT to be programmed")

			bpfWaitForPolicyRule(tc.Felixes[0], ep1_1.InterfaceName,
				"egress", "default.ep1-1-allow-test-service", `action:"allow"`)
		}

		if !bpfEnabled {
			// Mimic the kube-proxy service iptable clusterIP rule.
			for _, f := range tc.Felixes {
				f.Exec("iptables", "-t", "nat", "-A", "PREROUTING",
					"-p", "tcp",
					"-d", clusterIP,
					"-m", "tcp", "--dport", svcPortStr,
					"-j", "DNAT", "--to-destination",
					ep2_1.IP+":"+wepPortStr)
			}
		}
	})

	It("should get expected flow logs", func() {
		// Describe the connectivity that we now expect.
		// For ep1_1 -> ep2_1 we use the service cluster IP to test service info in the flow log
		cc = &connectivity.Checker{}
		cc.ExpectSome(ep1_1, connectivity.TargetIP(clusterIP), uint16(svcPort)) // allowed by np1-1

		// Do 3 rounds of connectivity checking.
		cc.CheckConnectivity()
		cc.CheckConnectivity()
		cc.CheckConnectivity()

		flowlogs.WaitForConntrackScan(bpfEnabled)

		// Verify we have allowed flow logs before deleting the backing pod
		Eventually(func() error {
			flows, err := tc.Felixes[0].FlowLogs()
			if err != nil {
				return err
			}
			foundAllowed := false
			for _, fl := range flows {
				if fl.Action == "allow" && fl.DstService.PortNum == int(svcPort) {
					foundAllowed = true
					break
				}
			}
			if !foundAllowed {
				return fmt.Errorf("no allowed flow log found for service port %d", svcPort)
			}
			return nil
		}, "20s", "1s").ShouldNot(HaveOccurred())

		// Verify that the workload endpoint for ep2_1 exists
		Eventually(func() error {
			wlList, _ := client.WorkloadEndpoints().List(utils.Ctx, options.ListOptions{})
			for _, wl := range wlList.Items {
				logrus.Infof("Existing workload endpoint: default/%s", wl.Name)
				if strings.Contains(wl.Name, "ep2--1") {
					return nil
				}
			}
			return fmt.Errorf("workload endpoint default/%s still exists", ep2_1.Name)
		}, "10s", "1s").ShouldNot(HaveOccurred())

		// Delete the backing pod (ep2_1) to test flow logs when service has no endpoints
		ep2_1.RemoveFromInfra(infra)

		// Wait a moment for the endpoint deletion to propagate
		Eventually(func() error {
			wlList, _ := client.WorkloadEndpoints().List(utils.Ctx, options.ListOptions{})
			for _, wl := range wlList.Items {
				logrus.Infof("Existing workload endpoint: default/%s", wl.Name)
				if strings.Contains(wl.Name, "ep2--1") {
					return fmt.Errorf("workload endpoint default/%s still exists", ep2_1.Name)
				}
			}
			return nil
		}, "10s", "1s").ShouldNot(HaveOccurred())

		// Now expect connectivity to fail since there's no backing pod
		cc = &connectivity.Checker{}
		cc.ExpectNone(ep1_1, connectivity.TargetIP(clusterIP), uint16(svcPort))

		// Do more rounds of connectivity checking - these should fail
		cc.CheckConnectivity()
		cc.CheckConnectivity()
		cc.CheckConnectivity()

		flowlogs.WaitForConntrackScan(bpfEnabled)

		// Verify we do not get denied flow logs after deleting the backing pod.
		Consistently(func() error {
			var flows []flowlog.FlowLog
			var err error
			if flows, err = tc.Felixes[0].FlowLogs(); err != nil {
				return err
			}
			for _, fl := range flows {
				// After pod deletion, should not see denied flows for the service port
				if fl.DstService.PortNum == int(svcPort) && fl.Action == "deny" {
					return fmt.Errorf("found denied flow log for service port %d", svcPort)
				}
			}
			return nil
		}, "1m", "1s").ShouldNot(HaveOccurred())

		// Delete conntrack state so that we don't keep seeing 0-metric copies of the logs.  This will allow the flows
		// to expire quickly.
		for ii := range tc.Felixes {
			tc.Felixes[ii].Exec("conntrack", "-F")
		}
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			if bpfEnabled {
				tc.Felixes[0].Exec("calico-bpf", "policy", "dump", ep1_1.InterfaceName, "all", "--asm")
			}
		}
	})
})

func createHEP(f *infrastructure.Felix, client client.Interface, ifname string) (hep *api.HostEndpoint, err error) {
	hep = api.NewHostEndpoint()
	hep.Name = ifname + "-" + f.Name
	hep.Labels = map[string]string{
		"name":          hep.Name,
		"host-endpoint": "true",
	}
	hep.Spec.Node = f.Hostname
	hep.Spec.ExpectedIPs = []string{f.IP}
	hep.Spec.InterfaceName = ifname
	_, err = client.HostEndpoints().Create(utils.Ctx, hep, options.SetOptions{})
	if err != nil {
		return nil, err
	}

	return hep, nil
}

// verifyHostEndpointRules checks that the host endpoint rules are properly configured
// based on the active dataplane (BPF, NFT, or iptables)
func verifyHostEndpointRules(f *infrastructure.Felix, bpfEnabled bool) error {
	switch {
	case bpfEnabled:
		numProgs := f.NumTCBPFProgsEth0()
		if numProgs != 2 {
			return fmt.Errorf("expected 2 BPF programs on eth0, found %d", numProgs)
		}

	case NFTMode():
		out, err := f.ExecOutput("nft", "list", "table", "calico")
		if err != nil {
			return fmt.Errorf("failed to list nftables: %w", err)
		}

		if !strings.Contains(out, "cali-thfw-eth0") {
			return fmt.Errorf("nftables missing expected host endpoint chain 'cali-thfw-eth0'")
		}

	default: // iptables mode
		out, err := f.ExecOutput("iptables-save", "-t", "filter")
		if err != nil {
			return fmt.Errorf("failed to list iptables rules: %w", err)
		}

		if !strings.Contains(out, "cali-thfw-eth0") {
			return fmt.Errorf("iptables missing expected host endpoint chain 'cali-thfw-eth0'")
		}
	}

	return nil
}

func getRuleFuncTable(felix *infrastructure.Felix, rule, table string) func() error {
	cmd := []string{"iptables-save", "-t", table}
	if NFTMode() {
		cmd = []string{"nft", "list", "ruleset"}
	}
	return func() error {
		if out, err := felix.ExecOutput(cmd...); err != nil {
			return err
		} else if strings.Count(out, rule) > 0 {
			return nil
		} else {
			return errors.New("Rule not programmed: \nRule: " + rule + "\n" + out)
		}
	}
}
