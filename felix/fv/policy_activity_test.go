// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package fv_test

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/collector/policy"
	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

// findPolicyActivityEntry searches for a policy activity log entry whose Policy.Name
// contains the given substring. Returns nil if not found.
func findPolicyActivityEntry(logs []policy.ActivityLog, nameSubstr string) *policy.ActivityLog {
	for i := range logs {
		if strings.Contains(logs[i].Policy.Name, nameSubstr) {
			return &logs[i]
		}
	}
	return nil
}

// describePolicyActivityLogs returns a human-readable summary of the policy activity log entries.
func describePolicyActivityLogs(logs []policy.ActivityLog) string {
	if len(logs) == 0 {
		return "(empty)"
	}
	var sb strings.Builder
	for i, l := range logs {
		fmt.Fprintf(&sb, "\n  [%d] kind=%s ns=%s name=%s rule=%s lastEvaluated=%v",
			i, l.Policy.Kind, l.Policy.Namespace, l.Policy.Name, l.Rule, l.LastEvaluated)
	}
	return sb.String()
}

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ policy activity refresh tests",
	[]apiconfig.DatastoreType{apiconfig.EtcdV3},
	func(getInfra infrastructure.InfraFactory) {
		var (
			infra        infrastructure.DatastoreInfra
			tc           infrastructure.TopologyContainers
			calicoClient client.Interface
			w            [2]*workload.Workload
		)

		BeforeEach(func() {
			infra = getInfra()
			opts := infrastructure.DefaultTopologyOptions()
			opts.IPIPMode = api.IPIPModeNever
			opts.FlowLogSource = infrastructure.FlowLogSourceFile

			// Enable policy activity logging to file, writing to the same
			// directory as flow logs so the existing volume mount picks it up.
			opts.ExtraEnvVars["FELIX_POLICYACTIVITYLOGSFILEENABLED"] = "true"
			opts.ExtraEnvVars["FELIX_POLICYACTIVITYLOGSFILEDIRECTORY"] = "/var/log/calico/flowlogs"
			opts.ExtraEnvVars["FELIX_POLICYACTIVITYLOGSFLUSHINTERVAL"] = "2"

			// Set a short refresh interval so the test doesn't take too long.
			opts.ExtraEnvVars["FELIX_POLICYACTIVITYREFRESHINTERVAL"] = "5"

			// Disable flow logs — we only care about policy activity here.
			opts.ExtraEnvVars["FELIX_FLOWLOGSFILEENABLED"] = "false"

			tc, calicoClient = infrastructure.StartSingleNodeTopology(opts, infra)

			// Install a default profile that allows all ingress and egress.
			infra.AddDefaultAllow()

			// Create two workloads on the same host.
			for ii := range w {
				wIP := fmt.Sprintf("10.65.0.%d", ii+2)
				wName := fmt.Sprintf("w%d", ii)
				w[ii] = workload.Run(tc.Felixes[0], wName, "default", wIP, "8055", "tcp")
				w[ii].ConfigureInInfra(infra)
			}
		})

		AfterEach(func() {
			for _, wl := range w {
				if wl != nil {
					wl.Stop()
				}
			}
			tc.Stop()
			infra.Stop()
		})

		It("should refresh policy activity timestamps for long-lived connections", func() {
			// Apply a NetworkPolicy that allows traffic to w[1].
			np := api.NewNetworkPolicy()
			np.Name = "default.allow-to-server"
			np.Namespace = "default"
			np.Spec.Tier = "default"
			np.Spec.Selector = fmt.Sprintf("name=='%s'", w[1].Name)
			np.Spec.Ingress = []api.Rule{
				{
					Action: api.Allow,
				},
			}
			np.Spec.Egress = []api.Rule{
				{
					Action: api.Allow,
				},
			}
			_, err := calicoClient.NetworkPolicies().Create(utils.Ctx, np, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			// Start a persistent (long-lived) TCP connection from w[0] to w[1].
			pc, err := w[0].StartPersistentConnectionMayFail(w[1].IP, 8055, workload.PersistentConnectionOpts{
				SourcePort:          12345,
				MonitorConnectivity: true,
			})
			Expect(err).NotTo(HaveOccurred())
			defer pc.Stop()

			// Verify the connection is alive.
			Eventually(pc.PongCount, "10s", "1s").Should(BeNumerically(">", 0))

			// Wait for policy activity logs that contain our policy.
			// Use substring matching for robustness — the name may or may not include tier prefix.
			var initialEntry *policy.ActivityLog
			Eventually(func() error {
				logs, err := tc.Felixes[0].PolicyActivityLogs()
				if err != nil {
					return err
				}
				if len(logs) == 0 {
					return fmt.Errorf("no policy activity logs yet")
				}
				log.Infof("Policy activity logs: %s", describePolicyActivityLogs(logs))
				initialEntry = findPolicyActivityEntry(logs, "allow-to-server")
				if initialEntry == nil {
					return fmt.Errorf("no entry matching 'allow-to-server' in %d logs: %s",
						len(logs), describePolicyActivityLogs(logs))
				}
				return nil
			}, "20s", "1s").ShouldNot(HaveOccurred(), "Expected policy activity logs for 'allow-to-server'")

			initialTime := initialEntry.LastEvaluated

			// Now wait for the refresh interval to fire (5s) plus a flush (2s),
			// then check that the lastEvaluated timestamp has been updated.
			Eventually(func() error {
				logs, err := tc.Felixes[0].PolicyActivityLogs()
				if err != nil {
					return err
				}
				for _, l := range logs {
					if strings.Contains(l.Policy.Name, "allow-to-server") &&
						l.LastEvaluated.After(initialTime) {
						return nil
					}
				}
				return fmt.Errorf("no refreshed policy activity entry found (still at %v), logs: %s",
					initialTime, describePolicyActivityLogs(logs))
			}, "20s", "1s").ShouldNot(HaveOccurred(), "Expected policy activity timestamp to be refreshed")
		})

		It("should create policy activity for a policy added after connection is established", func() {
			// First, establish a long-lived connection with only the default profile in place
			// (no explicit NetworkPolicy yet).
			cc := &connectivity.Checker{Protocol: "tcp"}
			cc.ExpectSome(w[0], w[1])
			cc.CheckConnectivity()

			// Start a persistent connection.
			pc, err := w[0].StartPersistentConnectionMayFail(w[1].IP, 8055, workload.PersistentConnectionOpts{
				SourcePort:          12346,
				MonitorConnectivity: true,
			})
			Expect(err).NotTo(HaveOccurred())
			defer pc.Stop()

			// Verify the connection is alive.
			Eventually(pc.PongCount, "10s", "1s").Should(BeNumerically(">", 0))

			// Now add a NetworkPolicy that matches the server workload.
			// Since the connection is already established, BPF won't re-evaluate it.
			// But the periodic refresh should pick it up.
			np := api.NewNetworkPolicy()
			np.Name = "default.late-policy"
			np.Namespace = "default"
			np.Spec.Tier = "default"
			np.Spec.Selector = fmt.Sprintf("name=='%s'", w[1].Name)
			np.Spec.Ingress = []api.Rule{
				{
					Action: api.Allow,
				},
			}
			np.Spec.Egress = []api.Rule{
				{
					Action: api.Allow,
				},
			}
			_, err = calicoClient.NetworkPolicies().Create(utils.Ctx, np, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			// Wait for the refresh interval to fire and the policy activity to be flushed.
			// The refresh should evaluate the new policy against the existing connection.
			Eventually(func() error {
				logs, err := tc.Felixes[0].PolicyActivityLogs()
				if err != nil {
					return err
				}
				entry := findPolicyActivityEntry(logs, "late-policy")
				if entry != nil {
					return nil
				}
				return fmt.Errorf("no policy activity entry for 'late-policy' in %d logs: %s",
					len(logs), describePolicyActivityLogs(logs))
			}, "30s", "1s").ShouldNot(HaveOccurred(), "Expected policy activity for late-added policy")
		})
	},
)
