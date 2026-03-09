// Copyright (c) 2022-2025 Tigera, Inc. All rights reserved.

package winfv_test

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	log "github.com/sirupsen/logrus"
	"github.com/tigera/windows-networking/pkg/testutils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/felix/collector/flowlog"
	"github.com/projectcalico/calico/felix/collector/types/endpoint"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/collector/utils"
	"github.com/projectcalico/calico/felix/fv/flowlogs"
	. "github.com/projectcalico/calico/felix/fv/winfv"
	"github.com/projectcalico/calico/libcalico-go/lib/winutils"
)

func init() {
	// Stop Gomega from chopping off diffs in logs.
	format.MaxLength = 0
}

// Generate traffic flows to test flow logs on Windows nodes.
// Common features which are not specific on Windows (e.g. cloudwatch)
// are tested with Linux FVs.
//
// Infra setup
//
//             Windows node                         Linx node
//
//              porter                          client (allowed to porter)
//                                              client-b (denied to porter)
//                                              nginx
//

var _ = Describe("Windows flow logs test", func() {
	var (
		porter, client, clientB, nginx string
		fv                             *WinFV
		err                            error
	)

	BeforeEach(func() {
		fv, err = NewWinFV(winutils.GetHostPath("c:\\CalicoWindows"),
			winutils.GetHostPath("c:\\TigeraCalico\\flowlogs"),
			winutils.GetHostPath("c:\\TigeraCalico\\felix-dns-cache.txt"))
		Expect(err).NotTo(HaveOccurred())

		// Get Pod IPs.
		client = testutils.InfraPodIP("client", "demo")
		clientB = testutils.InfraPodIP("client-b", "demo")
		porter = testutils.InfraPodIP("porter", "demo")
		nginx = testutils.InfraPodIP("nginx", "demo")
		log.Infof("Pod IP client %s, client-b %s, porter %s, nginx %s",
			client, clientB, porter, nginx)

		Expect(client).NotTo(BeEmpty())
		Expect(clientB).NotTo(BeEmpty())
		Expect(porter).NotTo(BeEmpty())
		Expect(nginx).NotTo(BeEmpty())
	})

	checkFlowLogs := func(expectedFlows []flowlog.FlowLog) {
		// Within 120s we should see the complete set of expected allow and deny
		// flow logs. Traffic is generated on each iteration because on Windows,
		// ETW events for allowed connections fire only on the first packet; if
		// Felix is still restarting when traffic is first sent, it will miss
		// those events entirely. The long timeout accounts for slow HPC Felix
		// restarts triggered by config changes.
		Eventually(func() error {
			testutils.InfraInitiateTraffic()
			flowTester := flowlogs.NewFlowTester(flowlogs.FlowTesterOptions{
				ExpectLabels:           true,
				ExpectEnforcedPolicies: true,
				MatchEnforcedPolicies:  true,
				Includes:               []flowlogs.IncludeFilter{flowlogs.IncludeByDestPort(80)},
			})
			if err := flowTester.PopulateFromFlowLogs(fv); err != nil {
				return err
			}
			for _, fl := range expectedFlows {
				flowTester.CheckFlow(fl)
			}
			return flowTester.Finish()
		}, "120s", "10s").ShouldNot(HaveOccurred())
	}

	Context("File flow logs only", Ordered, ContinueOnFailure, func() {
		// Dump Felix logs on failure BEFORE AfterAll restarts Felix,
		// so we capture logs from the correct Felix instance.
		AfterEach(func() {
			if CurrentSpecReport().Failed() {
				cmd := `c:\k\kubectl.exe --kubeconfig=c:\k\config -n calico-system logs -l k8s-app=calico-node-windows -c felix --since=5m`
				out, _ := testutils.Powershell(cmd)
				log.Infof("=== Felix logs (last 5m) ===\n%s", out)
			}
		})

		AfterAll(func() {
			err := fv.RestoreConfig()
			Expect(err).NotTo(HaveOccurred())

			// On HPC, RestoreConfig triggers a Felix restart via datastore
			// config change. Wait for it to complete so the next test starts
			// with a settled Felix.
			if IsRunningHPC() {
				log.Info("Waiting for Felix to settle after config restore...")
				time.Sleep(40 * time.Second)
			}
		})

		setupAndRunFelix := func(config map[string]any) {
			err := fv.AddConfigItems(config)
			Expect(err).NotTo(HaveOccurred())

			fv.RestartFelix()

			// Set a cutoff so we only read flow logs generated from now on,
			// ignoring stale entries from previous Felix instances.
			fv.SnapshotFlowLogOffset()
		}

		It("should get expected flow logs with no aggregation", func() {
			zero := 0
			var tenSeconds metav1.Duration
			tenSeconds.Duration = 10 * time.Second
			config := map[string]any{
				"FlowLogsFileAggregationKindForAllowed": &zero,
				"FlowLogsFileAggregationKindForDenied":  &zero,
				"FlowLogsFlushInterval":                 &tenSeconds,
			}
			setupAndRunFelix(config)

			clientIP := utils.IpStrTo16Byte(client)
			clientBIP := utils.IpStrTo16Byte(clientB)
			porterIP := utils.IpStrTo16Byte(porter)
			nginxIP := utils.IpStrTo16Byte(nginx)

			checkFlowLogs([]flowlog.FlowLog{
				// client → porter: allowed by knp allow-client
				{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      tuple.Make(clientIP, porterIP, 6, flowlogs.SourcePortIsIncluded, 80),
						SrcMeta:    endpoint.Metadata{Type: endpoint.Wep, Namespace: "demo", Name: "client", AggregatedName: "client"},
						DstMeta:    endpoint.Metadata{Type: endpoint.Wep, Namespace: "demo", Name: "porter", AggregatedName: "porter"},
						DstService: flowlog.EmptyService,
						Action:     flowlog.ActionAllow,
						Reporter:   flowlog.ReporterDst,
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{"0|default|knp:demo/allow-client|allow|0": {}},
				},
				// porter → nginx: allowed by knp allow-nginx
				{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      tuple.Make(porterIP, nginxIP, 6, flowlogs.SourcePortIsIncluded, 80),
						SrcMeta:    endpoint.Metadata{Type: endpoint.Wep, Namespace: "demo", Name: "porter", AggregatedName: "porter"},
						DstMeta:    endpoint.Metadata{Type: endpoint.Wep, Namespace: "demo", Name: "nginx", AggregatedName: "nginx"},
						DstService: flowlog.FlowService{Namespace: "demo", Name: "nginx", PortName: "-", PortNum: 80},
						Action:     flowlog.ActionAllow,
						Reporter:   flowlog.ReporterSrc,
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{"0|default|knp:demo/allow-nginx|allow|0": {}},
				},
				// client-b → porter: denied (no matching policy)
				{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      tuple.Make(clientBIP, porterIP, 6, flowlogs.SourcePortIsIncluded, 80),
						SrcMeta:    endpoint.Metadata{Type: endpoint.Wep, Namespace: "demo", Name: "client-b", AggregatedName: "client-b"},
						DstMeta:    endpoint.Metadata{Type: endpoint.Wep, Namespace: "demo", Name: "porter", AggregatedName: "porter"},
						DstService: flowlog.EmptyService,
						Action:     flowlog.ActionDeny,
						Reporter:   flowlog.ReporterDst,
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{"0|__PROFILE__|pro:__NO_MATCH__|deny|0": {}},
				},
			})
		})

		It("should get expected flow logs with default aggregation", func() {
			one := 1
			two := 2
			var tenSeconds metav1.Duration
			tenSeconds.Duration = 10 * time.Second
			config := map[string]any{
				"FlowLogsFileAggregationKindForAllowed": &two,
				"FlowLogsFileAggregationKindForDenied":  &one,
				"FlowLogsFlushInterval":                 &tenSeconds,
			}
			setupAndRunFelix(config)

			clientBIP := utils.IpStrTo16Byte(clientB)
			porterIP := utils.IpStrTo16Byte(porter)

			// Aggregation kinds >= 1 (FlowSourcePort, FlowPrefixName) set the
			// source port to -1 internally, which serializes as null in the
			// JSON flow log file. When deserialized, null becomes 0, so the
			// flow tester sees SourcePortIsNotIncluded for all aggregated flows.
			checkFlowLogs([]flowlog.FlowLog{
				// client → porter: allowed, aggregated by pod prefix (no IPs, no names, no source port)
				{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      tuple.Make(flowlog.EmptyIP, flowlog.EmptyIP, 6, flowlogs.SourcePortIsNotIncluded, 80),
						SrcMeta:    endpoint.Metadata{Type: endpoint.Wep, Namespace: "demo", Name: flowlog.FieldNotIncluded, AggregatedName: "client"},
						DstMeta:    endpoint.Metadata{Type: endpoint.Wep, Namespace: "demo", Name: flowlog.FieldNotIncluded, AggregatedName: "porter"},
						DstService: flowlog.EmptyService,
						Action:     flowlog.ActionAllow,
						Reporter:   flowlog.ReporterDst,
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{"0|default|knp:demo/allow-client|allow|0": {}},
				},
				// porter → nginx: allowed, aggregated by pod prefix (no source port)
				{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      tuple.Make(flowlog.EmptyIP, flowlog.EmptyIP, 6, flowlogs.SourcePortIsNotIncluded, 80),
						SrcMeta:    endpoint.Metadata{Type: endpoint.Wep, Namespace: "demo", Name: flowlog.FieldNotIncluded, AggregatedName: "porter"},
						DstMeta:    endpoint.Metadata{Type: endpoint.Wep, Namespace: "demo", Name: flowlog.FieldNotIncluded, AggregatedName: "nginx"},
						DstService: flowlog.FlowService{Namespace: "demo", Name: "nginx", PortName: "-", PortNum: 80},
						Action:     flowlog.ActionAllow,
						Reporter:   flowlog.ReporterSrc,
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{"0|default|knp:demo/allow-nginx|allow|0": {}},
				},
				// client-b → porter: denied, aggregated by source port (no source port)
				{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      tuple.Make(clientBIP, porterIP, 6, flowlogs.SourcePortIsNotIncluded, 80),
						SrcMeta:    endpoint.Metadata{Type: endpoint.Wep, Namespace: "demo", Name: "client-b", AggregatedName: "client-b"},
						DstMeta:    endpoint.Metadata{Type: endpoint.Wep, Namespace: "demo", Name: "porter", AggregatedName: "porter"},
						DstService: flowlog.EmptyService,
						Action:     flowlog.ActionDeny,
						Reporter:   flowlog.ReporterDst,
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{"0|__PROFILE__|pro:__NO_MATCH__|deny|0": {}},
				},
			})
		})
	})
})
