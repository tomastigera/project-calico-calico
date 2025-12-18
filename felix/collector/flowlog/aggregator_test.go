// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.

package flowlog

import (
	"fmt"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types/boundedset"
	"github.com/projectcalico/calico/felix/collector/types/endpoint"
	"github.com/projectcalico/calico/felix/collector/types/metric"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/collector/utils"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type testProcessInfo struct {
	processName     string
	numProcessIDs   int
	processID       string
	numProcessNames int
	processArgs     []string
	numProcessArgs  int
}

type testTcpStats struct {
	SendCongestionWnd TCPWnd
	SmoothRtt         TCPRtt
	MinRtt            TCPRtt
	Mss               TCPMss
	LostOut           int
	TotalRetrans      int
	UnrecoveredRTO    int
	Count             int
}

var (
	srcPort1 = 54123
	srcPort2 = 54124
	srcPort3 = 54125
	srcPort4 = 54125
	srcPort5 = 54126
	srcPort6 = 54127
	dstPort  = 80
)

// Common Tuple definitions
var (
	tuple1 = tuple.Make(localIp1, remoteIp1, proto_tcp, srcPort1, dstPort)
	tuple2 = tuple.Make(localIp1, remoteIp2, proto_tcp, srcPort2, dstPort)
	tuple3 = tuple.Make(localIp2, remoteIp1, proto_tcp, srcPort1, dstPort)
	tuple4 = tuple.Make(localIp2, remoteIp1, proto_tcp, srcPort4, dstPort)
	tuple5 = tuple.Make(localIp2, remoteIp1, proto_tcp, srcPort5, dstPort)
	tuple6 = tuple.Make(localIp2, remoteIp1, proto_tcp, srcPort6, dstPort)
)

var (
	proto_tcp         = 6
	localIp1Str       = "10.0.0.1"
	localIp1          = utils.IpStrTo16Byte(localIp1Str)
	localIp2Str       = "10.0.0.2"
	localIp2          = utils.IpStrTo16Byte(localIp2Str)
	remoteIp1Str      = "20.0.0.1"
	remoteIp1         = utils.IpStrTo16Byte(remoteIp1Str)
	remoteIp2Str      = "20.0.0.2"
	remoteIp2         = utils.IpStrTo16Byte(remoteIp2Str)
	publicIP1Str      = "1.0.0.1"
	publicIP2Str      = "2.0.0.2"
	ingressRule1Allow = calc.NewRuleID(
		v3.KindGlobalNetworkPolicy,
		"default",
		"policy1",
		"",
		0,
		rules.RuleDirIngress,
		rules.RuleActionAllow,
	)
	ingressRule1Deny = calc.NewRuleID(
		v3.KindGlobalNetworkPolicy,
		"default",
		"policy1",
		"",
		0,
		rules.RuleDirIngress,
		rules.RuleActionDeny,
	)
	egressRule1Allow = calc.NewRuleID(
		v3.KindGlobalNetworkPolicy,
		"default",
		"policy2",
		"",
		0,
		rules.RuleDirEgress,
		rules.RuleActionAllow,
	)
	egressRule2Deny = calc.NewRuleID(
		v3.KindGlobalNetworkPolicy,
		"default",
		"policy2",
		"",
		0,
		rules.RuleDirEgress,
		rules.RuleActionDeny,
	)
)

var (
	noProcessInfo  = testProcessInfo{"-", 0, "-", 0, []string{"-"}, 0}
	noTcpStatsInfo = testTcpStats{
		SendCongestionWnd: TCPWnd{Min: 0, Mean: 0},
		SmoothRtt:         TCPRtt{Max: 0, Mean: 0},
		MinRtt:            TCPRtt{Max: 0, Mean: 0},
		Mss:               TCPMss{Min: 0, Mean: 0},
		LostOut:           0,
		TotalRetrans:      0,
		UnrecoveredRTO:    0,
		Count:             0,
	}
)

// Common MetricUpdate definitions
var (
	// Metric update without a connection (ingress stats match those of muConn1Rule1AllowUpdate).
	muNoConn1Rule1AllowUpdate = metric.Update{
		UpdateType:     metric.UpdateTypeReport,
		Tuple:          tuple1,
		RuleIDs:        []*calc.RuleID{ingressRule1Allow},
		PendingRuleIDs: []*calc.RuleID{ingressRule1Deny},
		HasDenyRule:    false,
		IsConnection:   false,
		InMetric: metric.Value{
			DeltaPackets: 1,
			DeltaBytes:   20,
		},
	}

	// Metric update without a connection and with a transit policy (egress stats match those of muConn1Rule1AllowUpdate).
	muNoConn1Rule1TransitAllowUpdate = metric.Update{
		UpdateType:     metric.UpdateTypeReport,
		Tuple:          tuple1,
		RuleIDs:        []*calc.RuleID{ingressRule1Allow},
		PendingRuleIDs: []*calc.RuleID{ingressRule1Deny},
		TransitRuleIDs: []*calc.RuleID{ingressRule1Allow},
		HasDenyRule:    false,
		IsConnection:   false,
		InMetric: metric.Value{
			DeltaPackets: 1,
			DeltaBytes:   20,
		},
		InTransitMetric: metric.Value{
			DeltaPackets: 2,
			DeltaBytes:   40,
		},
	}

	muNoConn1Rule2DenyUpdate = metric.Update{
		UpdateType:     metric.UpdateTypeReport,
		Tuple:          tuple1,
		RuleIDs:        []*calc.RuleID{egressRule2Deny},
		PendingRuleIDs: []*calc.RuleID{ingressRule1Deny},
		HasDenyRule:    true,
		IsConnection:   false,
		InMetric: metric.Value{
			DeltaPackets: 2,
			DeltaBytes:   40,
		},
	}

	// Metric update without a connection (ingress stats match those of muConn1Rule1AllowUpdate).
	muNoConn1Rule1AllowUpdateWithEndpointMeta = metric.Update{
		UpdateType: metric.UpdateTypeReport,
		Tuple:      tuple1,
		SrcEp: &calc.RemoteEndpointData{
			CommonEndpointData: calc.CalculateCommonEndpointData(
				model.WorkloadEndpointKey{
					Hostname:       "node-01",
					OrchestratorID: "k8s",
					WorkloadID:     "kube-system/iperf-4235-5623461",
					EndpointID:     "4352",
				},
				&model.WorkloadEndpoint{GenerateName: "iperf-4235-", Labels: uniquelabels.Make(map[string]string{"test-app": "true"})},
			),
		},
		DstEp: &calc.RemoteEndpointData{
			CommonEndpointData: calc.CalculateCommonEndpointData(
				model.WorkloadEndpointKey{
					Hostname:       "node-02",
					OrchestratorID: "k8s",
					WorkloadID:     "default/nginx-412354-5123451",
					EndpointID:     "4352",
				},
				&model.WorkloadEndpoint{GenerateName: "nginx-412354-", Labels: uniquelabels.Make(map[string]string{"k8s-app": "true"})},
			),
		},
		RuleIDs:      []*calc.RuleID{ingressRule1Allow},
		HasDenyRule:  false,
		IsConnection: false,
		InMetric: metric.Value{
			DeltaPackets: 1,
			DeltaBytes:   20,
		},
		SendCongestionWnd: &sendCongestionWnd,
		SmoothRtt:         &smoothRtt,
		MinRtt:            &minRtt,
		Mss:               &mss,
		TcpMetric: metric.TCPValue{
			DeltaTotalRetrans:   7,
			DeltaLostOut:        6,
			DeltaUnRecoveredRTO: 8,
		},
	}

	// Identical rule/direction connections with differing tuples
	muConn1Rule1AllowUpdate = metric.Update{
		UpdateType:     metric.UpdateTypeReport,
		Tuple:          tuple1,
		RuleIDs:        []*calc.RuleID{ingressRule1Allow},
		PendingRuleIDs: []*calc.RuleID{ingressRule1Deny},
		IsConnection:   true,
		HasDenyRule:    false,
		InMetric: metric.Value{
			DeltaPackets: 2,
			DeltaBytes:   22,
		},
		OutMetric: metric.Value{
			DeltaPackets: 3,
			DeltaBytes:   33,
		},
	}

	muConn1Rule1HTTPReqAllowUpdate = metric.Update{
		UpdateType:     metric.UpdateTypeReport,
		Tuple:          tuple1,
		RuleIDs:        []*calc.RuleID{ingressRule1Allow},
		PendingRuleIDs: []*calc.RuleID{ingressRule1Deny},
		HasDenyRule:    false,
		IsConnection:   true,
		InMetric: metric.Value{
			DeltaPackets:             200,
			DeltaBytes:               22000,
			DeltaAllowedHTTPRequests: 20,
			DeltaDeniedHTTPRequests:  5,
		},
		OutMetric: metric.Value{
			DeltaPackets: 300,
			DeltaBytes:   33000,
		},
	}

	muNoConn1Rule2DenyExpire = metric.Update{
		UpdateType:     metric.UpdateTypeExpire,
		Tuple:          tuple1,
		RuleIDs:        []*calc.RuleID{egressRule2Deny},
		PendingRuleIDs: []*calc.RuleID{ingressRule1Deny},
		HasDenyRule:    true,
		IsConnection:   false,
		InMetric: metric.Value{
			DeltaPackets: 0,
			DeltaBytes:   0,
		},
	}
)

func checkProcessArgs(actual, expected []string, numArgs int) bool {
	count := 0
	actualArgSet := set.New[string]()
	for _, a := range actual {
		actualArgSet.Add(a)
	}
	if actualArgSet.Len() != numArgs {
		return false
	}
	for arg := range actualArgSet.All() {
		for _, e := range expected {
			if arg == e {
				count = count + 1
			}
		}
	}
	return count == numArgs
}

// compareProcessReportedStats compares FlowProcessReportedStats. With process Args
// being aggregated into a list, and the order in which these args are added of the
// arguments is not guaranteed, explicitly iterate over the args list and compare.
func compareProcessReportedStats(actual, expected FlowProcessReportedStats) bool {
	count := 0
	if actual.ProcessName == expected.ProcessName &&
		actual.NumProcessNames == expected.NumProcessNames &&
		actual.ProcessID == expected.ProcessID &&
		actual.NumProcessIDs == expected.NumProcessIDs &&
		actual.NumProcessArgs == expected.NumProcessArgs &&
		actual.FlowReportedStats == expected.FlowReportedStats &&
		actual.FlowReportedTCPStats == expected.FlowReportedTCPStats &&
		len(actual.ProcessArgs) == len(expected.ProcessArgs) {
	} else {
		return false
	}
	for _, a := range actual.ProcessArgs {
		for _, e := range expected.ProcessArgs {
			if a == e {
				count = count + 1
			}
		}
	}
	return count == len(expected.ProcessArgs)
}

var _ = Describe("Flow log aggregator tests", func() {
	// TODO(SS): Pull out the convenience functions for re-use.

	expectFlowLog := func(fl FlowLog, t tuple.Tuple, nf, nfs, nfc int, a Action, fr ReporterType, pi, po, bi, bo, tpi, tpo, tbi, tbo int, sm, dm endpoint.Metadata, dsvc FlowService, sl, dl map[string]string, fap, fep, fpp, fhp FlowPolicySet, fe FlowExtras, fpi testProcessInfo, tcps testTcpStats) {
		expectedFlow := newExpectedFlowLog(t, nf, nfs, nfc, a, fr, pi, po, bi, bo, tpi, tpo, tbi, tbo, sm, dm, dsvc, sl, dl, fap, fep, fpp, fhp, fe, fpi, tcps)

		// We don't include the start and end time in the comparison, so copy to a new log without these
		var flNoTime FlowLog
		flNoTime.FlowMeta = fl.FlowMeta
		flNoTime.FlowLabels = fl.FlowLabels
		flNoTime.FlowEnforcedPolicySet = fl.FlowEnforcedPolicySet
		flNoTime.FlowPendingPolicySet = fl.FlowPendingPolicySet
		flNoTime.FlowTransitPolicySet = fl.FlowTransitPolicySet

		var expFlowNoProc FlowLog
		expFlowNoProc.FlowMeta = expectedFlow.FlowMeta
		expFlowNoProc.FlowLabels = expectedFlow.FlowLabels
		expFlowNoProc.FlowEnforcedPolicySet = expectedFlow.FlowEnforcedPolicySet
		expFlowNoProc.FlowPendingPolicySet = expectedFlow.FlowPendingPolicySet
		expFlowNoProc.FlowTransitPolicySet = expectedFlow.FlowTransitPolicySet

		Expect(flNoTime).WithOffset(1).Should(Equal(expFlowNoProc))
		Expect(compareProcessReportedStats(fl.FlowProcessReportedStats, expectedFlow.FlowProcessReportedStats)).Should(Equal(true))
	}
	expectFlowLogsMatch := func(actualFlows []*FlowLog, expectedFlows []FlowLog) {
		By("Checking all flowlogs match")
		actualFlowsNoTime := []FlowLog{}
		for _, fl := range actualFlows {
			// We don't include the start and end time in the comparison, so copy to a new log without these
			flNoTime := FlowLog{}
			flNoTime.FlowMeta = fl.FlowMeta
			flNoTime.FlowLabels = fl.FlowLabels
			flNoTime.FlowEnforcedPolicySet = fl.FlowEnforcedPolicySet
			flNoTime.FlowPendingPolicySet = fl.FlowPendingPolicySet
			flNoTime.FlowTransitPolicySet = fl.FlowTransitPolicySet
			flNoTime.FlowProcessReportedStats = fl.FlowProcessReportedStats
			actualFlowsNoTime = append(actualFlowsNoTime, flNoTime)
		}
		Expect(actualFlowsNoTime).WithOffset(1).Should(ConsistOf(expectedFlows))
	}
	calculatePacketStats := func(mus ...metric.Update) (epi, epo, ebi, ebo int) {
		for _, mu := range mus {
			epi += mu.InMetric.DeltaPackets
			epo += mu.OutMetric.DeltaPackets
			ebi += mu.InMetric.DeltaBytes
			ebo += mu.OutMetric.DeltaBytes
		}
		return
	}
	calculateTransitPacketStats := func(mus ...metric.Update) (etpi, etpo, etbi, etbo int) {
		for _, mu := range mus {
			etpi += mu.InTransitMetric.DeltaPackets
			etpo += mu.OutTransitMetric.DeltaPackets
			etbi += mu.InTransitMetric.DeltaBytes
			etbo += mu.OutTransitMetric.DeltaBytes
		}
		return
	}
	calculateHTTPRequestStats := func(mus ...metric.Update) (allowed, denied int) {
		for _, mu := range mus {
			allowed += mu.InMetric.DeltaAllowedHTTPRequests
			denied += mu.InMetric.DeltaDeniedHTTPRequests
		}
		return
	}

	extractFlowExtras := func(mus ...metric.Update) FlowExtras {
		var ipBs *boundedset.BoundedSet
		for _, mu := range mus {
			if mu.OrigSourceIPs == nil {
				continue
			}
			if ipBs == nil {
				ipBs = mu.OrigSourceIPs.Copy()
			} else {
				ipBs.Combine(mu.OrigSourceIPs)
			}
		}
		if ipBs != nil {
			return FlowExtras{
				OriginalSourceIPs:    ipBs.ToIPSlice(),
				NumOriginalSourceIPs: ipBs.TotalCount(),
			}
		} else {
			return FlowExtras{}
		}
	}

	extractFlowPolicies := func(mus ...metric.Update) FlowPolicySet {
		fp := make(FlowPolicySet)
		for _, mu := range mus {
			for idx, r := range mu.RuleIDs {
				name := fmt.Sprintf("%d|%s|%s|%s|%s",
					idx,
					r.TierString(),
					r.NameString(),
					r.ActionString(),
					r.IndexStr)
				fp[name] = emptyValue
			}
		}
		return fp
	}

	extractFlowPendingPolicies := func(mus ...metric.Update) FlowPolicySet {
		fp := make(FlowPolicySet)
		for _, mu := range mus {
			for idx, r := range mu.PendingRuleIDs {
				name := fmt.Sprintf("%d|%s|%s|%s|%s",
					idx,
					r.TierString(),
					r.NameString(),
					r.ActionString(),
					r.IndexStr)
				fp[name] = emptyValue
			}
		}
		return fp
	}

	extractFlowTransitPolicies := func(mus ...metric.Update) FlowPolicySet {
		fp := make(FlowPolicySet)
		for _, mu := range mus {
			for idx, r := range mu.TransitRuleIDs {
				name := fmt.Sprintf("%d|%s|%s|%s|%s",
					idx,
					r.TierString(),
					r.NameString(),
					r.ActionString(),
					r.IndexStr,
				)
				fp[name] = emptyValue
			}
		}
		return fp
	}

	extractFlowTCPStats := func(mus ...metric.Update) testTcpStats {
		tcps := testTcpStats{}
		for i, mu := range mus {
			if mu.SendCongestionWnd == nil {
				continue
			}
			if i == 0 {
				tcps.SendCongestionWnd.Min = *mu.SendCongestionWnd
				tcps.SendCongestionWnd.Mean = *mu.SendCongestionWnd

				tcps.SmoothRtt.Max = *mu.SmoothRtt
				tcps.SmoothRtt.Mean = *mu.SmoothRtt

				tcps.MinRtt.Max = *mu.MinRtt
				tcps.MinRtt.Mean = *mu.MinRtt

				tcps.Mss.Min = *mu.Mss
				tcps.Mss.Mean = *mu.Mss
			} else {
				if *mu.SendCongestionWnd < tcps.SendCongestionWnd.Min {
					tcps.SendCongestionWnd.Min = *mu.SendCongestionWnd
				}
				tcps.SendCongestionWnd.Mean = ((tcps.SendCongestionWnd.Mean * tcps.Count) +
					*mu.SendCongestionWnd) / (tcps.Count + 1)
				if *mu.SmoothRtt > tcps.SmoothRtt.Max {
					tcps.SmoothRtt.Max = *mu.SmoothRtt
				}
				tcps.SmoothRtt.Mean = ((tcps.SmoothRtt.Mean * tcps.Count) +
					*mu.SmoothRtt) / (tcps.Count + 1)
				if *mu.MinRtt > tcps.MinRtt.Max {
					tcps.MinRtt.Max = *mu.MinRtt
				}
				tcps.MinRtt.Mean = ((tcps.MinRtt.Mean * tcps.Count) +
					*mu.MinRtt) / (tcps.Count + 1)

				if *mu.Mss < tcps.Mss.Min {
					tcps.Mss.Min = *mu.Mss
				}
				tcps.Mss.Mean = ((tcps.Mss.Mean * tcps.Count) +
					*mu.Mss) / (tcps.Count + 1)
			}
			tcps.LostOut += mu.TcpMetric.DeltaLostOut
			tcps.TotalRetrans += mu.TcpMetric.DeltaTotalRetrans
			tcps.UnrecoveredRTO += mu.TcpMetric.DeltaUnRecoveredRTO
			tcps.Count += 1
		}
		return tcps
	}

	extractFlowProcessInfo := func(mus ...metric.Update) testProcessInfo {
		fpi := testProcessInfo{}
		procNames := set.New[string]()
		procID := set.New[int]()
		procArgs := set.New[string]()
		processName := ""
		processID := ""
		for i, mu := range mus {
			if i == 0 {
				processName = mu.ProcessName
				processID = strconv.Itoa(mu.ProcessID)
			}
			procNames.Add(mu.ProcessName)
			procID.Add(mu.ProcessID)
			if mu.ProcessArgs != "" {
				procArgs.Add(mu.ProcessArgs)
			}
		}

		if procNames.Len() == 1 {
			if processName == "" {
				fpi.processName = "-"
				fpi.numProcessNames = 0
			} else {
				fpi.processName = processName
				fpi.numProcessNames = 1
			}
		} else {
			fpi.processName = "*"
			fpi.numProcessNames = procNames.Len()
		}

		if procID.Len() == 1 {
			if processID == "0" {
				fpi.processID = "-"
				fpi.numProcessIDs = 0
			} else {
				fpi.processID = processID
				fpi.numProcessIDs = 1
			}
		} else {
			fpi.processID = "*"
			fpi.numProcessIDs = procID.Len()
		}
		fpi.numProcessArgs = procArgs.Len()
		if fpi.numProcessArgs == 0 {
			fpi.processArgs = []string{"-"}
		} else {
			argCount := 0
			for item := range procArgs.All() {
				if item != "" {
					fpi.processArgs = append(fpi.processArgs, item)
					argCount = argCount + 1
					if argCount == 5 {
						break
					}
				}
			}
		}
		return fpi
	}

	Context("Flow log aggregator aggregation verification", func() {
		var ca *Aggregator

		BeforeEach(func() {
			ca = NewAggregator()
		})

		It("aggregates the fed metric updates", func() {
			By("default duration")
			ca.IncludePolicies(true)
			Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdate)).NotTo(HaveOccurred())
			messages := ca.GetAndCalibrate(FlowDefault)
			Expect(len(messages)).Should(Equal(1))
			message := *(messages[0])

			expectedNumFlows := 1
			expectedNumFlowsStarted := 1
			expectedNumFlowsCompleted := 0

			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut := calculatePacketStats(muNoConn1Rule1AllowUpdate)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut := calculateTransitPacketStats(muNoConn1Rule1AllowUpdate)
			expectedFP := extractFlowPolicies(muNoConn1Rule1AllowUpdate)
			expectedFPP := extractFlowPendingPolicies(muNoConn1Rule1AllowUpdate)
			expectedTP := extractFlowTransitPolicies(muNoConn1Rule1AllowUpdate)
			expectedFlowExtras := extractFlowExtras(muNoConn1Rule1AllowUpdate)
			expectedTCPS := extractFlowTCPStats(muNoConn1Rule1AllowUpdate)
			expectFlowLog(message, tuple1, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut,
				pvtMeta, pubMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, noProcessInfo, expectedTCPS)

			// Verify a flow log for a metric update with a transit policy.
			Expect(ca.FeedUpdate(&muNoConn1Rule1TransitAllowUpdate)).NotTo(HaveOccurred())
			messages = ca.GetAndCalibrate(FlowDefault)
			Expect(messages).To(HaveLen(2))
			if messages[0].Reporter == ReporterDstFwd {
				message = *(messages[0])
			} else if messages[1].Reporter == ReporterDstFwd {
				message = *(messages[1])
			} else {
				Fail("Expected one of the messages to be from ReporterDstFwd")
			}

			expectedNumFlows = 1
			expectedNumFlowsStarted = 1
			expectedNumFlowsCompleted = 0

			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut = calculatePacketStats(muNoConn1Rule1TransitAllowUpdate)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut = calculateTransitPacketStats(muNoConn1Rule1TransitAllowUpdate)
			expectedFP = extractFlowPolicies(muNoConn1Rule1TransitAllowUpdate)
			expectedFPP = extractFlowPendingPolicies(muNoConn1Rule1TransitAllowUpdate)
			expectedTP = extractFlowTransitPolicies(muNoConn1Rule1TransitAllowUpdate)
			expectedFlowExtras = extractFlowExtras(muNoConn1Rule1TransitAllowUpdate)
			expectedTCPS = extractFlowTCPStats(muNoConn1Rule1TransitAllowUpdate)
			expectFlowLog(message, tuple1, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDstFwd,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, pubMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, noProcessInfo, expectedTCPS)

			By("source port")
			ca = NewAggregator().AggregateOver(FlowSourcePort)
			Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdate)).NotTo(HaveOccurred())
			// Construct a similar update; same tuple but diff src ports.
			muNoConn1Rule1AllowUpdateCopy := muNoConn1Rule1AllowUpdate
			tuple1Copy := tuple1
			tuple1Copy.L4Src = 44123
			muNoConn1Rule1AllowUpdateCopy.Tuple = tuple1Copy
			Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdateCopy)).NotTo(HaveOccurred())
			messages = ca.GetAndCalibrate(FlowSourcePort)
			// Two updates should still result in 1 flow
			Expect(len(messages)).Should(Equal(1))

			By("endpoint prefix names")
			ca = NewAggregator().AggregateOver(FlowPrefixName)
			Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdateWithEndpointMeta)).NotTo(HaveOccurred())
			// Construct a similar update; same tuple but diff src ports.
			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy := muNoConn1Rule1AllowUpdateWithEndpointMeta
			// TODO(SS): Handle and organize these test constants better. Right now they are all over the places
			// like reporter_prometheus_test.go, collector_test.go , etc.
			tuple1Copy = tuple1
			// Everything can change in the 5-tuple except for the dst port.
			tuple1Copy.L4Src = 44123
			tuple1Copy.Src = utils.IpStrTo16Byte("10.0.0.3")
			tuple1Copy.Dst = utils.IpStrTo16Byte("10.0.0.9")
			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy.Tuple = tuple1Copy

			// Updating the Workload IDs for src and dst.
			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy.SrcEp = &calc.RemoteEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(
					model.WorkloadEndpointKey{
						Hostname:       "node-01",
						OrchestratorID: "k8s",
						WorkloadID:     "kube-system/iperf-4235-5434134",
						EndpointID:     "23456",
					},
					&model.WorkloadEndpoint{GenerateName: "iperf-4235-", Labels: uniquelabels.Make(map[string]string{"test-app": "true"})},
				),
			}

			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy.DstEp = &calc.RemoteEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(
					model.WorkloadEndpointKey{
						Hostname:       "node-02",
						OrchestratorID: "k8s",
						WorkloadID:     "default/nginx-412354-6543645",
						EndpointID:     "256267",
					},
					&model.WorkloadEndpoint{GenerateName: "nginx-412354-", Labels: uniquelabels.Make(map[string]string{"k8s-app": "true"})},
				),
			}

			Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdateWithEndpointMetaCopy)).NotTo(HaveOccurred())
			messages = ca.GetAndCalibrate(FlowPrefixName)
			// Two updates should still result in 1 flow
			Expect(len(messages)).Should(Equal(1))
			// Updating the Workload IDs and labels for src and dst.
			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy.SrcEp = &calc.RemoteEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(
					model.WorkloadEndpointKey{
						Hostname:       "node-01",
						OrchestratorID: "k8s",
						WorkloadID:     "kube-system/iperf-4235-5434134",
						EndpointID:     "23456",
					},
					// this new MetricUpdates src endpointMeta has a different label than one currently being tracked.
					&model.WorkloadEndpoint{GenerateName: "iperf-4235-", Labels: uniquelabels.Make(map[string]string{"prod-app": "true"})},
				),
			}

			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy.DstEp = &calc.RemoteEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(
					model.WorkloadEndpointKey{
						Hostname:       "node-02",
						OrchestratorID: "k8s",
						WorkloadID:     "default/nginx-412354-6543645",
						EndpointID:     "256267",
					},
					// different label on the destination workload than one being tracked.
					&model.WorkloadEndpoint{GenerateName: "nginx-412354-", Labels: uniquelabels.Make(map[string]string{"k8s-app": "false"})},
				),
			}

			Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdateWithEndpointMetaCopy)).NotTo(HaveOccurred())
			messages = ca.GetAndCalibrate(FlowPrefixName)
			// Two updates should still result in 1 flow
			Expect(len(messages)).Should(Equal(1))

			By("by endpoint IP classification as the meta name when meta info is missing")
			ca = NewAggregator().AggregateOver(FlowPrefixName)
			endpointMeta := calc.RemoteEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(
					model.WorkloadEndpointKey{
						Hostname:       "node-01",
						OrchestratorID: "k8s",
						WorkloadID:     "kube-system/iperf-4235-5623461",
						EndpointID:     "4352",
					},
					&model.WorkloadEndpoint{GenerateName: "iperf-4235-", Labels: uniquelabels.Make(map[string]string{"test-app": "true"})},
				),
			}

			muWithoutDstEndpointMeta := metric.Update{
				UpdateType:   metric.UpdateTypeReport,
				Tuple:        tuple.Make(utils.IpStrTo16Byte("192.168.0.4"), utils.IpStrTo16Byte("192.168.0.14"), proto_tcp, srcPort1, dstPort),
				SrcEp:        &endpointMeta, // src endpoint meta info available
				DstEp:        nil,           // dst endpoint meta info not available
				RuleIDs:      []*calc.RuleID{ingressRule1Allow},
				HasDenyRule:  false,
				IsConnection: false,
				InMetric: metric.Value{
					DeltaPackets: 1,
					DeltaBytes:   20,
				},
			}
			Expect(ca.FeedUpdate(&muWithoutDstEndpointMeta)).NotTo(HaveOccurred())

			// Another metric update comes in. This time on a different dst private IP
			muWithoutDstEndpointMetaCopy := muWithoutDstEndpointMeta
			muWithoutDstEndpointMetaCopy.Tuple.Dst = utils.IpStrTo16Byte("192.168.0.17")
			Expect(ca.FeedUpdate(&muWithoutDstEndpointMetaCopy)).NotTo(HaveOccurred())
			messages = ca.GetAndCalibrate(FlowPrefixName)
			// One flow expected: srcMeta.GenerateName -> pvt
			// Two updates should still result in 1 flow
			Expect(len(messages)).Should(Equal(1))

			// Initial Update
			Expect(ca.FeedUpdate(&muWithoutDstEndpointMeta)).NotTo(HaveOccurred())
			// + metric update comes in. This time on a non-private dst IP
			muWithoutDstEndpointMetaCopy.Tuple.Dst = utils.IpStrTo16Byte("198.17.8.43")
			Expect(ca.FeedUpdate(&muWithoutDstEndpointMetaCopy)).NotTo(HaveOccurred())
			messages = ca.GetAndCalibrate(FlowPrefixName)
			// 2nd flow expected: srcMeta.GenerateName -> pub
			// Three updates so far should result in 2 flows
			Expect(len(messages)).Should(Equal(2)) // Metric Update comes in with a non private as the dst IP

			// Initial Updates
			Expect(ca.FeedUpdate(&muWithoutDstEndpointMeta)).NotTo(HaveOccurred())
			Expect(ca.FeedUpdate(&muWithoutDstEndpointMetaCopy)).NotTo(HaveOccurred())
			// + metric update comes in. This time with missing src endpointMeta
			muWithoutDstEndpointMetaCopy.SrcEp = nil
			muWithoutDstEndpointMetaCopy.DstEp = &endpointMeta
			Expect(ca.FeedUpdate(&muWithoutDstEndpointMetaCopy)).NotTo(HaveOccurred())
			messages = ca.GetAndCalibrate(FlowPrefixName)

			// 3rd flow expected: pvt -> dst.GenerateName
			// Four updates so far should result in 3 flows
			Expect(len(messages)).Should(Equal(3)) // Metric Update comes in with a non private as the dst IP

			// Confirm the expected flow metas
			fm1 := FlowMeta{
				Tuple: tuple.Tuple{
					Src:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					Dst:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					Proto: 6,
					L4Src: unsetIntField,
					L4Dst: 80,
				},
				SrcMeta: endpoint.Metadata{
					Type:           "wep",
					Namespace:      "kube-system",
					Name:           "-",
					AggregatedName: "iperf-4235-*",
				},
				DstMeta: endpoint.Metadata{
					Type:           "net",
					Namespace:      "-",
					Name:           "-",
					AggregatedName: "pub",
				},
				DstService: noService,
				Action:     "allow",
				Reporter:   "dst",
			}

			fm2 := FlowMeta{
				Tuple: tuple.Tuple{
					Src:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					Dst:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					Proto: 6,
					L4Src: unsetIntField,
					L4Dst: 80,
				},
				SrcMeta: endpoint.Metadata{
					Type:           "net",
					Namespace:      "-",
					Name:           "-",
					AggregatedName: "pvt",
				},
				DstMeta: endpoint.Metadata{
					Type:           "wep",
					Namespace:      "kube-system",
					Name:           "-",
					AggregatedName: "iperf-4235-*",
				},
				DstService: noService,
				Action:     "allow",
				Reporter:   "dst",
			}

			fm3 := FlowMeta{
				Tuple: tuple.Tuple{
					Src:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					Dst:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					Proto: 6,
					L4Src: unsetIntField,
					L4Dst: 80,
				},
				SrcMeta: endpoint.Metadata{
					Type:           "wep",
					Namespace:      "kube-system",
					Name:           "-",
					AggregatedName: "iperf-4235-*",
				},
				DstMeta: endpoint.Metadata{
					Type:           "net",
					Namespace:      "-",
					Name:           "-",
					AggregatedName: "pvt",
				},
				DstService: noService,
				Action:     "allow",
				Reporter:   "dst",
			}

			flowLogMetas := []FlowMeta{}
			for _, fl := range messages {
				flowLogMetas = append(flowLogMetas, fl.FlowMeta)
			}

			Expect(flowLogMetas).Should(ConsistOf(fm1, fm2, fm3))
		})

		It("aggregates labels from metric updates", func() {
			By("intersecting labels in FlowSpec when IncludeLabels configured")
			ca := NewAggregator().IncludeLabels(true)
			Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdateWithEndpointMeta)).NotTo(HaveOccurred())

			// Construct a similar update; but the endpoints have different labels
			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy := muNoConn1Rule1AllowUpdateWithEndpointMeta
			// Updating the Workload IDs for src and dst.
			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy.SrcEp = &calc.RemoteEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(
					model.WorkloadEndpointKey{
						Hostname:       "node-01",
						OrchestratorID: "k8s",
						WorkloadID:     "kube-system/iperf-4235-5623461",
						EndpointID:     "4352",
					},
					&model.WorkloadEndpoint{
						GenerateName: "iperf-4235-",
						Labels:       uniquelabels.Make(map[string]string{"test-app": "true", "new-label": "true"}), // "new-label" appended
					},
				),
			}

			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy.DstEp = &calc.RemoteEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(
					model.WorkloadEndpointKey{
						Hostname:       "node-02",
						OrchestratorID: "k8s",
						WorkloadID:     "default/nginx-412354-5123451",
						EndpointID:     "4352",
					},
					&model.WorkloadEndpoint{
						GenerateName: "nginx-412354-",
						Labels:       uniquelabels.Make(map[string]string{"k8s-app": "false"}), // conflicting labels; originally "k8s-app": "true"
					},
				),
			}
			Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdateWithEndpointMetaCopy)).NotTo(HaveOccurred())
			messages := ca.GetAndCalibrate(FlowDefault)
			// Since the FlowMeta remains the same it should still equal 1.
			Expect(len(messages)).Should(Equal(1))
			message := *(messages[0])

			expectedNumFlows := 1
			expectedNumFlowsStarted := 1
			expectedNumFlowsCompleted := 0
			srcMeta := endpoint.Metadata{
				Type:           "wep",
				Namespace:      "kube-system",
				Name:           "iperf-4235-5623461",
				AggregatedName: "iperf-4235-*",
			}
			dstMeta := endpoint.Metadata{
				Type:           "wep",
				Namespace:      "default",
				Name:           "nginx-412354-5123451",
				AggregatedName: "nginx-412354-*",
			}
			// The labels should have been intersected correctly.
			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut := calculatePacketStats(muNoConn1Rule1AllowUpdateWithEndpointMetaCopy)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut := calculateTransitPacketStats(muNoConn1Rule1AllowUpdateWithEndpointMetaCopy)
			expectedFlowExtras := extractFlowExtras(muNoConn1Rule1AllowUpdateWithEndpointMetaCopy)
			expectedTCPS := extractFlowTCPStats(muNoConn1Rule1AllowUpdateWithEndpointMetaCopy)
			expectedTCPS.Count = expectedTCPS.Count * 2
			expectedTCPS.LostOut = expectedTCPS.LostOut * 2
			expectedTCPS.TotalRetrans = expectedTCPS.TotalRetrans * 2
			expectedTCPS.UnrecoveredRTO = expectedTCPS.UnrecoveredRTO * 2
			expectFlowLog(message, tuple1, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
				expectedPacketsIn*2, expectedPacketsOut, expectedBytesIn*2, expectedBytesOut, expectedTransitPacketsIn*2, expectedTransitPacketsOut, expectedTransitBytesIn*2, expectedTransitBytesOut, srcMeta, dstMeta, noService, map[string]string{"test-app": "true"}, map[string]string{}, nil, nil, nil, nil, expectedFlowExtras, noProcessInfo, expectedTCPS)

			By("not affecting flow logs when IncludeLabels is disabled")
			ca = NewAggregator().IncludeLabels(false)
			Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdateWithEndpointMeta)).NotTo(HaveOccurred())

			// Construct a similar update; but the endpoints have different labels
			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy = muNoConn1Rule1AllowUpdateWithEndpointMeta
			// Updating the Workload IDs for src and dst.
			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy.SrcEp = &calc.RemoteEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(
					model.WorkloadEndpointKey{
						Hostname:       "node-01",
						OrchestratorID: "k8s",
						WorkloadID:     "kube-system/iperf-4235-5623461",
						EndpointID:     "4352",
					},
					&model.WorkloadEndpoint{
						GenerateName: "iperf-4235-",
						Labels:       uniquelabels.Make(map[string]string{"test-app": "true", "new-label": "true"}), // "new-label" appended
					},
				),
			}

			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy.DstEp = &calc.RemoteEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(
					model.WorkloadEndpointKey{
						Hostname:       "node-02",
						OrchestratorID: "k8s",
						WorkloadID:     "default/nginx-412354-5123451",
						EndpointID:     "4352",
					},
					&model.WorkloadEndpoint{
						GenerateName: "nginx-412354-",
						Labels:       uniquelabels.Make(map[string]string{"k8s-app": "false"}), // conflicting labels; originally "k8s-app": "true"
					},
				),
			}
			Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdateWithEndpointMetaCopy)).NotTo(HaveOccurred())
			messages = ca.GetAndCalibrate(FlowDefault)
			// Since the FlowMeta remains the same it should still equal 1.
			Expect(len(messages)).Should(Equal(1))
			message = *(messages[0])

			expectedNumFlows = 1
			expectedNumFlowsStarted = 1
			expectedNumFlowsCompleted = 0
			srcMeta = endpoint.Metadata{
				Type:           "wep",
				Namespace:      "kube-system",
				Name:           "iperf-4235-5623461",
				AggregatedName: "iperf-4235-*",
			}
			dstMeta = endpoint.Metadata{
				Type:           "wep",
				Namespace:      "default",
				Name:           "nginx-412354-5123451",
				AggregatedName: "nginx-412354-*",
			}
			// The labels should have been intersected right.
			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut = calculatePacketStats(muNoConn1Rule1AllowUpdateWithEndpointMetaCopy)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut = calculateTransitPacketStats(muNoConn1Rule1AllowUpdateWithEndpointMetaCopy)
			expectedFlowExtras = extractFlowExtras(muNoConn1Rule1AllowUpdateWithEndpointMetaCopy)
			expectedTCPS = extractFlowTCPStats(muNoConn1Rule1AllowUpdateWithEndpointMetaCopy)
			expectedTCPS.Count = expectedTCPS.Count * 2
			expectedTCPS.LostOut = expectedTCPS.LostOut * 2
			expectedTCPS.TotalRetrans = expectedTCPS.TotalRetrans * 2
			expectedTCPS.UnrecoveredRTO = expectedTCPS.UnrecoveredRTO * 2
			expectFlowLog(message, tuple1, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
				expectedPacketsIn*2, expectedPacketsOut, expectedBytesIn*2, expectedBytesOut, expectedTransitPacketsIn*2, expectedTransitPacketsOut, expectedTransitBytesIn*2, expectedTransitBytesOut, srcMeta, dstMeta, noService, nil, nil, nil, nil, nil, nil, expectedFlowExtras, noProcessInfo, expectedTCPS) // nil & nil for Src and Dst Labels respectively.
		})

		It("GetAndCalibrate does not cause a data race contention on the flowEntry after FeedUpdate adds it to the flowStore", func() {
			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy := muNoConn1Rule1AllowUpdateWithEndpointMeta

			var messages []*FlowLog

			time.AfterFunc(2*time.Second, func() {
				Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdateWithEndpointMetaCopy)).NotTo(HaveOccurred())
			})

			// ok GetAndCalibrate is a little after feedupdate because feedupdate has some preprocesssing
			// before ti accesses flowstore
			time.AfterFunc(2*time.Second+10*time.Millisecond, func() {
				messages = ca.GetAndCalibrate(FlowDefault)
			})

			time.Sleep(3 * time.Second)
			Expect(len(messages)).Should(Equal(1))

			message := messages[0]

			expectedNumFlows := 1
			expectedNumFlowsStarted := 1
			expectedNumFlowsCompleted := 0
			srcMeta := endpoint.Metadata{
				Type:           "wep",
				Namespace:      "kube-system",
				Name:           "iperf-4235-5623461",
				AggregatedName: "iperf-4235-*",
			}
			dstMeta := endpoint.Metadata{
				Type:           "wep",
				Namespace:      "default",
				Name:           "nginx-412354-5123451",
				AggregatedName: "nginx-412354-*",
			}

			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut := calculatePacketStats(muNoConn1Rule1AllowUpdateWithEndpointMeta)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut := calculateTransitPacketStats(muNoConn1Rule1AllowUpdateWithEndpointMeta)
			expectedFlowExtras := extractFlowExtras(muNoConn1Rule1AllowUpdateWithEndpointMeta)
			expectedTCPS := extractFlowTCPStats(muNoConn1Rule1AllowUpdateWithEndpointMeta)
			expectFlowLog(*message, tuple1, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, srcMeta, dstMeta, noService, nil, nil, nil, nil, nil, nil, expectedFlowExtras, noProcessInfo, expectedTCPS)
		})
	})

	Context("Flow log aggregator service aggregation", func() {
		service := FlowService{Namespace: "foo-ns", Name: "foo-svc", PortName: "foo-port", PortNum: 8080}
		serviceNoPortName := FlowService{Namespace: "foo-ns", Name: "foo-svc", PortName: "-", PortNum: 8080}

		It("Does not aggregate endpoints with and without service with Default aggregation", func() {
			By("Creating an aggregator for allow")
			caa := NewAggregator().ForAction(rules.RuleActionAllow).AggregateOver(FlowDefault).IncludeService(true)

			By("Feeding two updates one with service, one without (otherwise identical)")
			_ = caa.FeedUpdate(&muWithEndpointMeta)
			_ = caa.FeedUpdate(&muWithEndpointMetaWithService)

			By("Checking calibration")
			messages := caa.GetAndCalibrate(FlowDefault)
			Expect(len(messages)).Should(Equal(2))
			services := []FlowService{messages[0].DstService, messages[1].DstService}
			Expect(services).To(ConsistOf(noService, service))
		})

		It("Does not aggregate endpoints with and without service with FlowSourcePort aggregation", func() {
			By("Creating an aggregator for allow")
			caa := NewAggregator().ForAction(rules.RuleActionAllow).AggregateOver(FlowSourcePort).IncludeService(true)

			By("Feeding two updates one with service, one without (otherwise identical)")
			_ = caa.FeedUpdate(&muWithEndpointMeta)
			_ = caa.FeedUpdate(&muWithEndpointMetaWithService)

			By("Checking calibration")
			messages := caa.GetAndCalibrate(FlowSourcePort)
			Expect(len(messages)).Should(Equal(2))
			services := []FlowService{messages[0].DstService, messages[1].DstService}
			Expect(services).To(ConsistOf(noService, service))
		})

		It("Does not aggregate endpoints with and without service with FlowPrefixName aggregation", func() {
			By("Creating an aggregator for allow")
			caa := NewAggregator().ForAction(rules.RuleActionAllow).AggregateOver(FlowPrefixName).IncludeService(true)

			By("Feeding two updates one with service, one without (otherwise identical)")
			_ = caa.FeedUpdate(&muWithEndpointMeta)
			_ = caa.FeedUpdate(&muWithEndpointMetaWithService)

			By("Checking calibration")
			messages := caa.GetAndCalibrate(FlowPrefixName)
			Expect(len(messages)).Should(Equal(2))
			services := []FlowService{messages[0].DstService, messages[1].DstService}
			Expect(services).To(ConsistOf(noService, service))
		})

		It("Does not aggregate endpoints with and without service with FlowNoDestPorts aggregation", func() {
			By("Creating an aggregator for allow")
			caa := NewAggregator().ForAction(rules.RuleActionAllow).AggregateOver(FlowNoDestPorts).IncludeService(true)

			By("Feeding two updates one with service, one without (otherwise identical)")
			_ = caa.FeedUpdate(&muWithEndpointMeta)
			_ = caa.FeedUpdate(&muWithEndpointMetaWithService)

			By("Checking calibration")
			messages := caa.GetAndCalibrate(FlowNoDestPorts)
			Expect(len(messages)).Should(Equal(2))
			services := []FlowService{messages[0].DstService, messages[1].DstService}
			Expect(services).To(ConsistOf(noService, serviceNoPortName))
		})
	})

	Context("Flow log aggregator filter verification", func() {
		It("Filters out MetricUpdate based on filter applied", func() {
			By("Creating 2 aggregators - one for denied packets, and one for allowed packets")
			var caa, cad *Aggregator

			By("Checking that the MetricUpdate with deny action is only processed by the aggregator with the deny filter")
			caa = NewAggregator().ForAction(rules.RuleActionAllow)
			cad = NewAggregator().ForAction(rules.RuleActionDeny)

			Expect(caa.FeedUpdate(&muNoConn1Rule2DenyUpdate)).NotTo(HaveOccurred())
			messages := caa.GetAndCalibrate(FlowDefault)
			Expect(len(messages)).Should(Equal(0))
			Expect(cad.FeedUpdate(&muNoConn1Rule2DenyUpdate)).NotTo(HaveOccurred())
			messages = cad.GetAndCalibrate(FlowDefault)
			Expect(len(messages)).Should(Equal(1))

			By("Checking that the MetricUpdate with allow action is only processed by the aggregator with the allow filter")
			caa = NewAggregator().ForAction(rules.RuleActionAllow)
			cad = NewAggregator().ForAction(rules.RuleActionDeny)

			Expect(caa.FeedUpdate(&muConn1Rule1AllowUpdate)).NotTo(HaveOccurred())
			messages = caa.GetAndCalibrate(FlowDefault)
			Expect(len(messages)).Should(Equal(1))
			Expect(cad.FeedUpdate(&muConn1Rule1AllowUpdate)).NotTo(HaveOccurred())
			messages = cad.GetAndCalibrate(FlowDefault)
			Expect(len(messages)).Should(Equal(0))
		})
	})

	Context("Flow log aggregator http request countes", func() {
		It("Aggregates HTTP allowed and denied packets", func() {
			By("Feeding in two updates containing HTTP request counts")
			ca := NewAggregator().ForAction(rules.RuleActionAllow)
			Expect(ca.FeedUpdate(&muConn1Rule1HTTPReqAllowUpdate)).NotTo(HaveOccurred())
			Expect(ca.FeedUpdate(&muConn1Rule1HTTPReqAllowUpdate)).NotTo(HaveOccurred())
			messages := ca.GetAndCalibrate(FlowDefault)
			Expect(len(messages)).Should(Equal(1))
			// StartedFlowRefs count should be 1
			flowLog := messages[0]
			Expect(flowLog.NumFlowsStarted).Should(Equal(1))

			hra, hrd := calculateHTTPRequestStats(muConn1Rule1HTTPReqAllowUpdate, muConn1Rule1HTTPReqAllowUpdate)
			Expect(flowLog.HTTPRequestsAllowedIn).To(Equal(hra))
			Expect(flowLog.HTTPRequestsDeniedIn).To(Equal(hrd))
		})
	})

	Context("Flow log aggregator original source IP", func() {
		It("Aggregates original source IPs", func() {
			By("Feeding in two updates containing HTTP request counts")
			ca := NewAggregator().ForAction(rules.RuleActionAllow)
			Expect(ca.FeedUpdate(&muWithOrigSourceIPs)).NotTo(HaveOccurred())
			Expect(ca.FeedUpdate(&muWithMultipleOrigSourceIPs)).NotTo(HaveOccurred())
			messages := ca.GetAndCalibrate(FlowDefault)
			Expect(len(messages)).Should(Equal(1))
			// StartedFlowRefs count should be 1
			flowLog := messages[0]
			Expect(flowLog.NumFlowsStarted).Should(Equal(1))

			flowExtras := extractFlowExtras(muWithOrigSourceIPs, muWithMultipleOrigSourceIPs)
			Expect(flowLog.FlowExtras.OriginalSourceIPs).To(ConsistOf(flowExtras.OriginalSourceIPs))
			Expect(flowLog.FlowExtras.NumOriginalSourceIPs).To(Equal(flowExtras.NumOriginalSourceIPs))
		})
		It("Aggregates original source IPs with unknown rule ID", func() {
			By("Feeding in update containing HTTP request counts and unknown RuleID")
			ca := NewAggregator().ForAction(rules.RuleActionAllow)
			Expect(ca.FeedUpdate(&muWithOrigSourceIPsUnknownRuleID)).NotTo(HaveOccurred())
			messages := ca.GetAndCalibrate(FlowDefault)
			Expect(len(messages)).Should(Equal(1))
			// StartedFlowRefs count should be 1
			flowLog := messages[0]
			Expect(flowLog.NumFlowsStarted).Should(Equal(1))

			flowExtras := extractFlowExtras(muWithOrigSourceIPsUnknownRuleID)
			Expect(flowLog.FlowExtras.OriginalSourceIPs).To(ConsistOf(flowExtras.OriginalSourceIPs))
			Expect(flowLog.FlowExtras.NumOriginalSourceIPs).To(Equal(flowExtras.NumOriginalSourceIPs))
		})
	})

	Context("Flow log aggregator flowstore lifecycle", func() {
		It("Purges only the completed non-aggregated flowMetas", func() {
			By("Accounting for only the completed 5-tuple refs when making a purging decision")
			ca := NewAggregator().ForAction(rules.RuleActionDeny)
			Expect(ca.FeedUpdate(&muNoConn1Rule2DenyUpdate)).NotTo(HaveOccurred())
			messages := ca.GetAndCalibrate(FlowDefault)
			Expect(len(messages)).Should(Equal(1))
			// StartedFlowRefs count should be 1
			flowLog := messages[0]
			Expect(flowLog.NumFlowsStarted).Should(Equal(1))

			// flowStore is not purged of the entry since the flowRef hasn't been expired
			Expect(len(ca.flowStore)).Should(Equal(1))

			// Feeding an update again. But StartedFlowRefs count should be 0
			Expect(ca.FeedUpdate(&muNoConn1Rule2DenyUpdate)).NotTo(HaveOccurred())
			messages = ca.GetAndCalibrate(FlowDefault)
			Expect(len(messages)).Should(Equal(1))
			flowLog = messages[0]
			Expect(flowLog.NumFlowsStarted).Should(Equal(0))

			// Feeding an expiration of the conn.
			Expect(ca.FeedUpdate(&muNoConn1Rule2DenyExpire)).NotTo(HaveOccurred())
			messages = ca.GetAndCalibrate(FlowDefault)
			Expect(len(messages)).Should(Equal(1))
			flowLog = messages[0]
			Expect(flowLog.NumFlowsCompleted).Should(Equal(1))
			Expect(flowLog.NumFlowsStarted).Should(Equal(0))
			Expect(flowLog.NumFlows).Should(Equal(1))

			// flowStore is now purged of the entry since the flowRef has been expired
			Expect(len(ca.flowStore)).Should(Equal(0))
		})

		It("Purges only the completed aggregated flowMetas", func() {
			By("Accounting for only the completed 5-tuple refs when making a purging decision")
			ca := NewAggregator().AggregateOver(FlowPrefixName)
			Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdateWithEndpointMeta)).NotTo(HaveOccurred())
			// Construct a similar update; same tuple but diff src ports.
			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy := muNoConn1Rule1AllowUpdateWithEndpointMeta
			tuple1Copy := tuple1
			// Everything can change in the 5-tuple except for the dst port.
			tuple1Copy.L4Src = 44123
			tuple1Copy.Src = utils.IpStrTo16Byte("10.0.0.3")
			tuple1Copy.Dst = utils.IpStrTo16Byte("10.0.0.9")
			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy.Tuple = tuple1Copy

			// Updating the Workload IDs for src and dst.
			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy.SrcEp = &calc.RemoteEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(
					model.WorkloadEndpointKey{
						Hostname:       "node-01",
						OrchestratorID: "k8s",
						WorkloadID:     "kube-system/iperf-4235-5434134",
						EndpointID:     "23456",
					},
					&model.WorkloadEndpoint{GenerateName: "iperf-4235-", Labels: uniquelabels.Make(map[string]string{"test-app": "true"})},
				),
			}

			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy.DstEp = &calc.RemoteEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(
					model.WorkloadEndpointKey{
						Hostname:       "node-02",
						OrchestratorID: "k8s",
						WorkloadID:     "default/nginx-412354-6543645",
						EndpointID:     "256267",
					},
					&model.WorkloadEndpoint{GenerateName: "nginx-412354-", Labels: uniquelabels.Make(map[string]string{"k8s-app": "true"})},
				),
			}

			Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdateWithEndpointMetaCopy)).NotTo(HaveOccurred())
			messages := ca.GetAndCalibrate(FlowPrefixName)
			// Two updates should still result in 1 flowMeta
			Expect(len(messages)).Should(Equal(1))
			// flowStore is not purged of the entry since the flowRefs havn't been expired
			Expect(len(ca.flowStore)).Should(Equal(1))
			// And the no. of Started Flows should be 2
			flowLog := messages[0]
			Expect(flowLog.NumFlowsStarted).Should(Equal(2))

			// Update one of the two flows and expire the other.
			Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdateWithEndpointMeta)).NotTo(HaveOccurred())
			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy.UpdateType = metric.UpdateTypeExpire
			Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdateWithEndpointMetaCopy)).NotTo(HaveOccurred())
			messages = ca.GetAndCalibrate(FlowPrefixName)
			Expect(len(messages)).Should(Equal(1))
			// flowStore still carries that 1 flowMeta
			Expect(len(ca.flowStore)).Should(Equal(1))
			flowLog = messages[0]
			Expect(flowLog.NumFlowsStarted).Should(Equal(0))
			Expect(flowLog.NumFlowsCompleted).Should(Equal(1))
			Expect(flowLog.NumFlows).Should(Equal(2))

			// Expire the sole flowRef
			muNoConn1Rule1AllowUpdateWithEndpointMeta.UpdateType = metric.UpdateTypeExpire
			Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdateWithEndpointMeta)).NotTo(HaveOccurred())
			// Pre-purge/Dispatch the meta still lingers
			Expect(len(ca.flowStore)).Should(Equal(1))
			// On a dispatch the flowMeta is eventually purged
			messages = ca.GetAndCalibrate(FlowDefault)
			Expect(len(ca.flowStore)).Should(Equal(0))
			flowLog = messages[0]
			Expect(flowLog.NumFlowsStarted).Should(Equal(0))
			Expect(flowLog.NumFlowsCompleted).Should(Equal(1))
			Expect(flowLog.NumFlows).Should(Equal(1))
		})

		It("Updates the stats associated with the flows", func() {
			By("Accounting for only the packet/byte counts as seen during the interval")
			ca := NewAggregator().ForAction(rules.RuleActionAllow)
			Expect(ca.FeedUpdate(&muConn1Rule1AllowUpdate)).NotTo(HaveOccurred())
			messages := ca.GetAndCalibrate(FlowDefault)
			Expect(len(messages)).Should(Equal(1))
			// After the initial update the counts as expected.
			flowLog := messages[0]
			Expect(flowLog.PacketsIn).Should(Equal(2))
			Expect(flowLog.BytesIn).Should(Equal(22))
			Expect(flowLog.PacketsOut).Should(Equal(3))
			Expect(flowLog.BytesOut).Should(Equal(33))

			// The flow doesn't expire. But the Get should reset the stats.
			// A new update on top, then, should result in the same counts
			Expect(ca.FeedUpdate(&muConn1Rule1AllowUpdate)).NotTo(HaveOccurred())
			messages = ca.GetAndCalibrate(FlowDefault)
			Expect(len(messages)).Should(Equal(1))
			// After the initial update the counts as expected.
			flowLog = messages[0]
			Expect(flowLog.PacketsIn).Should(Equal(2))
			Expect(flowLog.BytesIn).Should(Equal(22))
			Expect(flowLog.PacketsOut).Should(Equal(3))
			Expect(flowLog.BytesOut).Should(Equal(33))
		})
	})

	Context("Flow log Aggregator changes aggregation levels", func() {
		It("Adjusts aggregation levels", func() {
			aggregator := NewAggregator()
			aggregator.AggregateOver(FlowNoDestPorts)

			By("Changing the level to ")
			aggregator.AdjustLevel(FlowPrefixName)

			Expect(aggregator.AggregationLevelChanged()).Should(Equal(true))
			Expect(aggregator.CurrentAggregationLevel()).Should(Equal(FlowPrefixName))
			Expect(aggregator.DefaultAggregationLevel()).Should(Equal(FlowNoDestPorts))
		})
	})

	Context("Flow log aggregator process args", func() {
		muWithProcessNameArg1 := muWithProcessName
		muWithProcessNameArg2 := muWithProcessName
		muWithProcessNameArg2.ProcessArgs = "arg2"
		muWithProcessNameArg2.ProcessID = 1324
		muWithProcessNameArg3 := muWithProcessName
		muWithProcessNameArg3.ProcessArgs = "arg3"
		muWithProcessNameArg3.ProcessID = 1432
		muWithProcessNameArg4 := muWithProcessName
		muWithProcessNameArg4.ProcessArgs = "arg4"
		muWithProcessNameArg4.ProcessID = 4321
		muWithProcessNameArg5 := muWithProcessName
		muWithProcessNameArg5.ProcessArgs = "arg5"
		muWithProcessNameArg5.ProcessID = 3214
		muWithProcessNameArg6 := muWithProcessName
		muWithProcessNameArg6.ProcessArgs = "arg6"
		muWithProcessNameArg5.ProcessID = 2143
		It("Aggregates process args", func() {
			By("Creating an aggregator with perflow process args limit set to default")
			caa := NewAggregator().ForAction(rules.RuleActionAllow).AggregateOver(FlowDefault).IncludePolicies(true).IncludeProcess(true).PerFlowProcessLimit(2).PerFlowProcessArgsLimit(5)
			_ = caa.FeedUpdate(&muWithProcessNameArg1)
			_ = caa.FeedUpdate(&muWithProcessNameArg2)
			_ = caa.FeedUpdate(&muWithProcessNameArg3)
			_ = caa.FeedUpdate(&muWithProcessNameArg4)
			_ = caa.FeedUpdate(&muWithProcessNameArg5)
			_ = caa.FeedUpdate(&muWithProcessNameArg6)
			messages := caa.GetAndCalibrate(FlowDefault)
			Expect(len(messages)).Should(Equal(1))
			flowLog := messages[0]
			Expect(flowLog.FlowProcessReportedStats.NumProcessArgs).Should(Equal(6))
			expectedArgList := []string{"arg1", "arg2", "arg3", "arg4", "arg5", "arg6"}
			Expect(checkProcessArgs(flowLog.FlowProcessReportedStats.ProcessArgs, expectedArgList, 5)).Should(Equal(true))
		})
		It("Process arg test with increased process args limit", func() {
			By("Creating an aggregator with perflow process args limit set to 6")
			caa := NewAggregator().ForAction(rules.RuleActionAllow).AggregateOver(FlowDefault).IncludePolicies(true).IncludeProcess(true).PerFlowProcessLimit(2).PerFlowProcessArgsLimit(6)
			_ = caa.FeedUpdate(&muWithProcessNameArg1)
			_ = caa.FeedUpdate(&muWithProcessNameArg2)
			_ = caa.FeedUpdate(&muWithProcessNameArg3)
			_ = caa.FeedUpdate(&muWithProcessNameArg4)
			_ = caa.FeedUpdate(&muWithProcessNameArg5)
			_ = caa.FeedUpdate(&muWithProcessNameArg6)
			messages := caa.GetAndCalibrate(FlowDefault)
			Expect(len(messages)).Should(Equal(1))
			flowLog := messages[0]
			Expect(flowLog.FlowProcessReportedStats.NumProcessArgs).Should(Equal(6))
			expectedArgList := []string{"arg1", "arg2", "arg3", "arg4", "arg5", "arg6"}
			Expect(checkProcessArgs(flowLog.FlowProcessReportedStats.ProcessArgs, expectedArgList, 6)).Should(Equal(true))
		})
		It("Process aggregation, same process ID, different arguments", func() {
			By("Creating an aggregator, aggregating same ID with different args")
			caa := NewAggregator().ForAction(rules.RuleActionAllow).AggregateOver(FlowDefault).IncludePolicies(true).IncludeProcess(true).PerFlowProcessLimit(2).PerFlowProcessArgsLimit(5)
			muWithProcessNameArg1SamePid := muWithProcessNameArg1
			muWithProcessNameArg1SamePid.ProcessArgs = "arg123"
			_ = caa.FeedUpdate(&muWithProcessNameArg1)
			_ = caa.FeedUpdate(&muWithProcessNameArg1SamePid)
			messages := caa.GetAndCalibrate(FlowDefault)
			Expect(len(messages)).Should(Equal(1))
			flowLog := messages[0]
			Expect(flowLog.FlowProcessReportedStats.NumProcessArgs).Should(Equal(1))
			expectedArgList := []string{"arg123"}
			Expect(checkProcessArgs(flowLog.FlowProcessReportedStats.ProcessArgs, expectedArgList, 1)).Should(Equal(true))
		})
	})
	Context("Flow log aggregator process information", func() {
		It("Includes process information with default aggregation", func() {
			By("Creating an aggregator for allow")
			caa := NewAggregator().ForAction(rules.RuleActionAllow).AggregateOver(FlowDefault).IncludePolicies(true).IncludeProcess(true).PerFlowProcessLimit(2)

			By("Feeding update with process information")
			_ = caa.FeedUpdate(&muWithProcessName)

			By("Checking calibration")
			messages := caa.GetAndCalibrate(FlowDefault)
			Expect(len(messages)).Should(Equal(1))
			flowLog := messages[0]

			dstMeta := endpoint.Metadata{
				Type:           "wep",
				Namespace:      "default",
				Name:           "nginx-412354-5123451",
				AggregatedName: "nginx-412354-*",
			}

			expectedNumFlows := 1
			expectedNumFlowsStarted := 1
			expectedNumFlowsCompleted := 0

			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut := calculatePacketStats(muWithProcessName)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut := calculateTransitPacketStats(muWithProcessName)
			expectedFP := extractFlowPolicies(muWithProcessName)
			expectedFPP := extractFlowPendingPolicies(muWithProcessName)
			expectedTP := extractFlowTransitPolicies(muWithProcessName)
			expectedFlowExtras := extractFlowExtras(muWithProcessName)
			expectedFlowProcessInfo := extractFlowProcessInfo(muWithProcessName)
			expectedTCPS := extractFlowTCPStats(muWithProcessName)
			expectFlowLog(*flowLog, tuple1, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDstFwd,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, dstMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, expectedFlowProcessInfo, expectedTCPS)
		})

		It("Includes process information with default aggregation with different processIDs", func() {
			By("Creating an aggregator for allow")
			caa := NewAggregator().ForAction(rules.RuleActionAllow).AggregateOver(FlowDefault).IncludePolicies(true).IncludeProcess(true).PerFlowProcessLimit(2)

			By("Feeding update with process information")
			_ = caa.FeedUpdate(&muWithProcessName)
			_ = caa.FeedUpdate(&muWithProcessNameDifferentIDSameTuple)

			By("Checking calibration")
			messages := caa.GetAndCalibrate(FlowDefault)
			Expect(len(messages)).Should(Equal(1))
			flowLog := messages[0]

			dstMeta := endpoint.Metadata{
				Type:           "wep",
				Namespace:      "default",
				Name:           "nginx-412354-5123451",
				AggregatedName: "nginx-412354-*",
			}

			expectedNumFlows := 1
			expectedNumFlowsStarted := 1
			expectedNumFlowsCompleted := 0

			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut := calculatePacketStats(muWithProcessName, muWithSameProcessNameDifferentID)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut := calculateTransitPacketStats(muWithProcessName, muWithSameProcessNameDifferentID)
			expectedFP := extractFlowPolicies(muWithProcessName, muWithSameProcessNameDifferentID)
			expectedFPP := extractFlowPendingPolicies(muWithProcessName, muWithSameProcessNameDifferentID)
			expectedTP := extractFlowTransitPolicies(muWithProcessName, muWithSameProcessNameDifferentID)
			expectedFlowExtras := extractFlowExtras(muWithProcessName, muWithSameProcessNameDifferentID)
			expectedFlowProcessInfo := extractFlowProcessInfo(muWithProcessName, muWithSameProcessNameDifferentID)
			expectedTCPS := extractFlowTCPStats(muWithProcessName, muWithSameProcessNameDifferentID)
			expectFlowLog(*flowLog, tuple1, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDstFwd,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, dstMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, expectedFlowProcessInfo, expectedTCPS)
		})

		It("Includes process information with default aggregation with different processIDs and expiration", func() {
			By("Creating an aggregator for allow")
			caa := NewAggregator().ForAction(rules.RuleActionAllow).AggregateOver(FlowDefault).IncludePolicies(true).IncludeProcess(true).PerFlowProcessLimit(2)

			By("Feeding update with process information")
			_ = caa.FeedUpdate(&muWithProcessName)
			_ = caa.FeedUpdate(&muWithProcessNameDifferentIDSameTuple)
			_ = caa.FeedUpdate(&muWithProcessNameExpire)

			By("Checking calibration")
			messages := caa.GetAndCalibrate(FlowDefault)
			Expect(len(messages)).Should(Equal(1))
			flowLog := messages[0]

			dstMeta := endpoint.Metadata{
				Type:           "wep",
				Namespace:      "default",
				Name:           "nginx-412354-5123451",
				AggregatedName: "nginx-412354-*",
			}

			expectedNumFlows := 1
			expectedNumFlowsStarted := 1
			expectedNumFlowsCompleted := 1

			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut := calculatePacketStats(muWithProcessName, muWithSameProcessNameDifferentID, muWithProcessNameExpire)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut := calculateTransitPacketStats(muWithProcessName, muWithSameProcessNameDifferentID, muWithProcessNameExpire)
			expectedFP := extractFlowPolicies(muWithProcessName, muWithSameProcessNameDifferentID, muWithProcessNameExpire)
			expectedFPP := extractFlowPendingPolicies(muWithProcessName, muWithSameProcessNameDifferentID, muWithProcessNameExpire)
			expectedTP := extractFlowTransitPolicies(muWithProcessName, muWithSameProcessNameDifferentID, muWithProcessNameExpire)
			expectedFlowExtras := extractFlowExtras(muWithProcessName, muWithSameProcessNameDifferentID, muWithProcessNameExpire)
			expectedFlowProcessInfo := extractFlowProcessInfo(muWithProcessName, muWithSameProcessNameDifferentID, muWithProcessNameExpire)
			expectedTCPS := extractFlowTCPStats(muWithProcessName, muWithSameProcessNameDifferentID, muWithProcessNameExpire)
			expectFlowLog(*flowLog, tuple1, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDstFwd,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, dstMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, expectedFlowProcessInfo, expectedTCPS)

			messages = caa.GetAndCalibrate(FlowDefault)
			Expect(len(messages)).Should(Equal(0))
		})

		It("Includes process information with default aggregation with different process names", func() {
			By("Creating an aggregator for allow")
			caa := NewAggregator().ForAction(rules.RuleActionAllow).AggregateOver(FlowDefault).IncludePolicies(true).IncludeProcess(true).PerFlowProcessLimit(2)

			By("Feeding update with process information")
			_ = caa.FeedUpdate(&muWithProcessName)
			_ = caa.FeedUpdate(&muWithDifferentProcessNameDifferentID)
			_ = caa.FeedUpdate(&muWithDifferentProcessNameDifferentIDExpire)

			By("Checking calibration")
			actualFlowLogs := caa.GetAndCalibrate(FlowDefault)
			Expect(len(actualFlowLogs)).Should(Equal(2))

			dstMeta := endpoint.Metadata{
				Type:           "wep",
				Namespace:      "default",
				Name:           "nginx-412354-5123451",
				AggregatedName: "nginx-412354-*",
			}

			expectedFlowLogs := []FlowLog{}

			expectedNumFlows := 1
			expectedNumFlowsStarted := 1
			expectedNumFlowsCompleted := 0

			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut := calculatePacketStats(muWithProcessName)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut := calculateTransitPacketStats(muWithProcessName)
			expectedFP := extractFlowPolicies(muWithProcessName)
			expectedFPP := extractFlowPendingPolicies(muWithProcessName)
			expectedTP := extractFlowTransitPolicies(muWithProcessName)
			expectedFlowExtras := extractFlowExtras(muWithProcessName)
			expectedFlowProcessInfo := extractFlowProcessInfo(muWithProcessName)
			expectedTCPS := extractFlowTCPStats(muWithProcessName)
			expectedFlowLog := newExpectedFlowLog(tuple1, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDstFwd,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, dstMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, expectedFlowProcessInfo, expectedTCPS)
			expectedFlowLogs = append(expectedFlowLogs, expectedFlowLog)

			expectedNumFlows = 1
			expectedNumFlowsStarted = 1
			expectedNumFlowsCompleted = 1

			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut = calculatePacketStats(muWithDifferentProcessNameDifferentID, muWithDifferentProcessNameDifferentIDExpire)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut = calculateTransitPacketStats(muWithDifferentProcessNameDifferentID, muWithDifferentProcessNameDifferentIDExpire)
			expectedFP = extractFlowPolicies(muWithDifferentProcessNameDifferentID, muWithDifferentProcessNameDifferentIDExpire)
			expectedFPP = extractFlowPendingPolicies(muWithDifferentProcessNameDifferentID, muWithDifferentProcessNameDifferentIDExpire)
			expectedTP = extractFlowTransitPolicies(muWithDifferentProcessNameDifferentID, muWithDifferentProcessNameDifferentIDExpire)
			expectedFlowExtras = extractFlowExtras(muWithDifferentProcessNameDifferentID, muWithDifferentProcessNameDifferentIDExpire)
			expectedFlowProcessInfo = extractFlowProcessInfo(muWithDifferentProcessNameDifferentID, muWithDifferentProcessNameDifferentIDExpire)
			expectedTCPS = extractFlowTCPStats(muWithDifferentProcessNameDifferentID, muWithDifferentProcessNameDifferentIDExpire)
			expectedFlowLog = newExpectedFlowLog(tuple3, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, dstMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, expectedFlowProcessInfo, expectedTCPS)
			expectedFlowLogs = append(expectedFlowLogs, expectedFlowLog)

			expectFlowLogsMatch(actualFlowLogs, expectedFlowLogs)

			By("Checking calibration and expired flows is removed")
			actualFlowLogs = caa.GetAndCalibrate(FlowDefault)
			Expect(len(actualFlowLogs)).Should(Equal(1))
		})

		It("Aggregates process information with pod prefix aggregation", func() {
			By("Creating an aggregator for allow")
			caa := NewAggregator().ForAction(rules.RuleActionAllow).AggregateOver(FlowPrefixName).IncludePolicies(true).IncludeProcess(true).PerFlowProcessLimit(2)

			By("Feeding update with process information")
			_ = caa.FeedUpdate(&muWithProcessName2)
			_ = caa.FeedUpdate(&muWithProcessName3)
			_ = caa.FeedUpdate(&muWithProcessName4)
			_ = caa.FeedUpdate(&muWithProcessName5)

			By("Checking calibration")
			actualFlowLogs := caa.GetAndCalibrate(FlowPrefixName)
			Expect(len(actualFlowLogs)).Should(Equal(3))

			dstMeta := endpoint.Metadata{
				Type:           "wep",
				Namespace:      "default",
				Name:           "-",
				AggregatedName: "nginx-412354-*",
			}

			expectedFlowLogs := []FlowLog{}

			By("Constructing the first of three flowlogs")
			expectedNumFlows := 1
			expectedNumFlowsStarted := 1
			expectedNumFlowsCompleted := 0

			tuple3Aggregated := tuple3
			tuple3Aggregated.L4Src = -1
			tuple3Aggregated.Src = [16]byte{}
			tuple3Aggregated.Dst = [16]byte{}

			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut := calculatePacketStats(muWithProcessName2)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut := calculateTransitPacketStats(muWithProcessName2)
			expectedFP := extractFlowPolicies(muWithProcessName2)
			expectedFPP := extractFlowPendingPolicies(muWithProcessName2)
			expectedTP := extractFlowTransitPolicies(muWithProcessName2)
			expectedFlowExtras := extractFlowExtras(muWithProcessName2)
			expectedFlowProcessInfo := extractFlowProcessInfo(muWithProcessName2)
			expectedTCPS := extractFlowTCPStats(muWithProcessName2)
			expectedFlowLog := newExpectedFlowLog(tuple3Aggregated, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, dstMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, expectedFlowProcessInfo, expectedTCPS)
			expectedFlowLogs = append(expectedFlowLogs, expectedFlowLog)

			By("Constructing the second of three flowlogs")
			expectedNumFlows = 1
			expectedNumFlowsStarted = 1
			expectedNumFlowsCompleted = 0

			tuple4Aggregated := tuple4
			tuple4Aggregated.L4Src = -1
			tuple4Aggregated.Src = [16]byte{}
			tuple4Aggregated.Dst = [16]byte{}

			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut = calculatePacketStats(muWithProcessName3)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut = calculateTransitPacketStats(muWithProcessName3)
			expectedFP = extractFlowPolicies(muWithProcessName3)
			expectedFPP = extractFlowPendingPolicies(muWithProcessName3)
			expectedTP = extractFlowTransitPolicies(muWithProcessName3)
			expectedFlowExtras = extractFlowExtras(muWithProcessName3)
			expectedFlowProcessInfo = extractFlowProcessInfo(muWithProcessName3)
			expectedTCPS = extractFlowTCPStats(muWithProcessName3)
			expectedFlowLog = newExpectedFlowLog(tuple4Aggregated, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, dstMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, expectedFlowProcessInfo, expectedTCPS)
			expectedFlowLogs = append(expectedFlowLogs, expectedFlowLog)

			By("Constructing the third of three flowlogs")
			expectedNumFlows = 2
			expectedNumFlowsStarted = 2
			expectedNumFlowsCompleted = 0

			tuple5Aggregated := tuple5
			tuple5Aggregated.L4Src = -1
			tuple5Aggregated.Src = [16]byte{}
			tuple5Aggregated.Dst = [16]byte{}

			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut = calculatePacketStats(muWithProcessName4, muWithProcessName5)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut = calculateTransitPacketStats(muWithProcessName4, muWithProcessName5)
			expectedFP = extractFlowPolicies(muWithProcessName4, muWithProcessName5)
			expectedFPP = extractFlowPendingPolicies(muWithProcessName4, muWithProcessName5)
			expectedTP = extractFlowTransitPolicies(muWithProcessName4, muWithProcessName5)
			expectedFlowExtras = extractFlowExtras(muWithProcessName4, muWithProcessName5)
			expectedFlowProcessInfo = extractFlowProcessInfo(muWithProcessName4, muWithProcessName5)
			expectedTCPS = extractFlowTCPStats(muWithProcessName4, muWithProcessName5)
			expectedFlowLog = newExpectedFlowLog(tuple5Aggregated, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, dstMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, expectedFlowProcessInfo, expectedTCPS)
			expectedFlowLogs = append(expectedFlowLogs, expectedFlowLog)

			expectFlowLogsMatch(actualFlowLogs, expectedFlowLogs)
		})

		It("Doesn't aggregate process information with default aggregation", func() {
			By("Creating an aggregator for allow")
			caa := NewAggregator().ForAction(rules.RuleActionAllow).AggregateOver(FlowDefault).IncludePolicies(true).IncludeProcess(true).PerFlowProcessLimit(2)

			By("Feeding update with process information")
			_ = caa.FeedUpdate(&muWithProcessName2)
			_ = caa.FeedUpdate(&muWithProcessName3)
			_ = caa.FeedUpdate(&muWithProcessName4)
			_ = caa.FeedUpdate(&muWithProcessName5)

			By("Checking calibration")
			actualFlowLogs := caa.GetAndCalibrate(FlowDefault)
			Expect(len(actualFlowLogs)).Should(Equal(4))

			dstMeta := endpoint.Metadata{
				Type:           "wep",
				Namespace:      "default",
				Name:           "nginx-412354-5123451",
				AggregatedName: "nginx-412354-*",
			}

			expectedFlowLogs := []FlowLog{}

			By("Constructing the first of four flowlogs")
			expectedNumFlows := 1
			expectedNumFlowsStarted := 1
			expectedNumFlowsCompleted := 0

			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut := calculatePacketStats(muWithProcessName2)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut := calculateTransitPacketStats(muWithProcessName2)
			expectedFP := extractFlowPolicies(muWithProcessName2)
			expectedFPP := extractFlowPendingPolicies(muWithProcessName2)
			expectedTP := extractFlowTransitPolicies(muWithProcessName2)
			expectedFlowExtras := extractFlowExtras(muWithProcessName2)
			expectedFlowProcessInfo := extractFlowProcessInfo(muWithProcessName2)
			expectedTCPS := extractFlowTCPStats(muWithProcessName2)
			expectedFlowLog := newExpectedFlowLog(tuple3, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, dstMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, expectedFlowProcessInfo, expectedTCPS)
			expectedFlowLogs = append(expectedFlowLogs, expectedFlowLog)

			By("Constructing the second of four flowlogs")

			expectedNumFlows = 1
			expectedNumFlowsStarted = 1
			expectedNumFlowsCompleted = 0

			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut = calculatePacketStats(muWithProcessName3)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut = calculateTransitPacketStats(muWithProcessName3)
			expectedFP = extractFlowPolicies(muWithProcessName3)
			expectedFPP = extractFlowPendingPolicies(muWithProcessName3)
			expectedTP = extractFlowTransitPolicies(muWithProcessName3)
			expectedFlowExtras = extractFlowExtras(muWithProcessName3)
			expectedFlowProcessInfo = extractFlowProcessInfo(muWithProcessName3)
			expectedTCPS = extractFlowTCPStats(muWithProcessName3)
			expectedFlowLog = newExpectedFlowLog(tuple4, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, dstMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, expectedFlowProcessInfo, expectedTCPS)
			expectedFlowLogs = append(expectedFlowLogs, expectedFlowLog)

			By("Constructing the third of four flowlogs")

			expectedNumFlows = 1
			expectedNumFlowsStarted = 1
			expectedNumFlowsCompleted = 0

			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut = calculatePacketStats(muWithProcessName4)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut = calculateTransitPacketStats(muWithProcessName4)
			expectedFP = extractFlowPolicies(muWithProcessName4)
			expectedFPP = extractFlowPendingPolicies(muWithProcessName4)
			expectedTP = extractFlowTransitPolicies(muWithProcessName4)
			expectedFlowExtras = extractFlowExtras(muWithProcessName4)
			expectedFlowProcessInfo = extractFlowProcessInfo(muWithProcessName4)
			expectedTCPS = extractFlowTCPStats(muWithProcessName4)
			expectedFlowLog = newExpectedFlowLog(tuple5, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, dstMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, expectedFlowProcessInfo, expectedTCPS)
			expectedFlowLogs = append(expectedFlowLogs, expectedFlowLog)

			By("Constructing the fourth of four flowlogs")
			expectedNumFlows = 1
			expectedNumFlowsStarted = 1
			expectedNumFlowsCompleted = 0

			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut = calculatePacketStats(muWithProcessName5)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut = calculateTransitPacketStats(muWithProcessName5)
			expectedFP = extractFlowPolicies(muWithProcessName5)
			expectedFPP = extractFlowPendingPolicies(muWithProcessName5)
			expectedTP = extractFlowTransitPolicies(muWithProcessName5)
			expectedFlowExtras = extractFlowExtras(muWithProcessName5)
			expectedFlowProcessInfo = extractFlowProcessInfo(muWithProcessName5)
			expectedTCPS = extractFlowTCPStats(muWithProcessName5)
			expectedFlowLog = newExpectedFlowLog(tuple6, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, dstMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, expectedFlowProcessInfo, expectedTCPS)
			expectedFlowLogs = append(expectedFlowLogs, expectedFlowLog)

			expectFlowLogsMatch(actualFlowLogs, expectedFlowLogs)
		})

		It("Aggregates process information with source port aggregation", func() {
			By("Creating an aggregator for allow")
			caa := NewAggregator().ForAction(rules.RuleActionAllow).AggregateOver(FlowSourcePort).IncludePolicies(true).IncludeProcess(true).PerFlowProcessLimit(2)

			By("Feeding update with process information")
			_ = caa.FeedUpdate(&muWithProcessName2)
			_ = caa.FeedUpdate(&muWithProcessName3)
			_ = caa.FeedUpdate(&muWithProcessName4)
			_ = caa.FeedUpdate(&muWithProcessName5)

			By("Checking calibration")
			actualFlowLogs := caa.GetAndCalibrate(FlowPrefixName)
			Expect(len(actualFlowLogs)).Should(Equal(3))

			dstMeta := endpoint.Metadata{
				Type:           "wep",
				Namespace:      "default",
				Name:           "nginx-412354-5123451",
				AggregatedName: "nginx-412354-*",
			}

			expectedFlowLogs := []FlowLog{}

			expectedNumFlows := 1
			expectedNumFlowsStarted := 1
			expectedNumFlowsCompleted := 0

			tuple3Aggregated := tuple3
			tuple3Aggregated.L4Src = -1

			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut := calculatePacketStats(muWithProcessName2)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut := calculateTransitPacketStats(muWithProcessName2)
			expectedFP := extractFlowPolicies(muWithProcessName2)
			expectedFPP := extractFlowPendingPolicies(muWithProcessName2)
			expectedTP := extractFlowTransitPolicies(muWithProcessName2)
			expectedFlowExtras := extractFlowExtras(muWithProcessName2)
			expectedFlowProcessInfo := extractFlowProcessInfo(muWithProcessName2)
			expectedTCPS := extractFlowTCPStats(muWithProcessName2)
			expectedFlowLog := newExpectedFlowLog(tuple3Aggregated, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, dstMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, expectedFlowProcessInfo, expectedTCPS)
			expectedFlowLogs = append(expectedFlowLogs, expectedFlowLog)

			expectedNumFlows = 1
			expectedNumFlowsStarted = 1
			expectedNumFlowsCompleted = 0

			tuple4Aggregated := tuple4
			tuple4Aggregated.L4Src = -1

			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut = calculatePacketStats(muWithProcessName3)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut = calculateTransitPacketStats(muWithProcessName3)
			expectedFP = extractFlowPolicies(muWithProcessName3)
			expectedFPP = extractFlowPendingPolicies(muWithProcessName3)
			expectedTP = extractFlowTransitPolicies(muWithProcessName3)
			expectedFlowExtras = extractFlowExtras(muWithProcessName3)
			expectedFlowProcessInfo = extractFlowProcessInfo(muWithProcessName3)
			expectedTCPS = extractFlowTCPStats(muWithProcessName3)
			expectedFlowLog = newExpectedFlowLog(tuple4Aggregated, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, dstMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, expectedFlowProcessInfo, expectedTCPS)
			expectedFlowLogs = append(expectedFlowLogs, expectedFlowLog)

			expectedNumFlows = 2
			expectedNumFlowsStarted = 2
			expectedNumFlowsCompleted = 0

			tuple5Aggregated := tuple5
			tuple5Aggregated.L4Src = -1

			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut = calculatePacketStats(muWithProcessName4, muWithProcessName5)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut = calculateTransitPacketStats(muWithProcessName4, muWithProcessName5)
			expectedFP = extractFlowPolicies(muWithProcessName4, muWithProcessName5)
			expectedFPP = extractFlowPendingPolicies(muWithProcessName4, muWithProcessName5)
			expectedTP = extractFlowTransitPolicies(muWithProcessName4, muWithProcessName5)
			expectedFlowExtras = extractFlowExtras(muWithProcessName4, muWithProcessName5)
			expectedFlowProcessInfo = extractFlowProcessInfo(muWithProcessName4, muWithProcessName5)
			expectedTCPS = extractFlowTCPStats(muWithProcessName4, muWithProcessName5)
			expectedFlowLog = newExpectedFlowLog(tuple5Aggregated, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, dstMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, expectedFlowProcessInfo, expectedTCPS)
			expectedFlowLogs = append(expectedFlowLogs, expectedFlowLog)

			expectFlowLogsMatch(actualFlowLogs, expectedFlowLogs)
		})

		It("Includes correct process information with default aggregation across multiple flush intervals", func() {
			By("Creating an aggregator for allow")
			caa := NewAggregator().ForAction(rules.RuleActionAllow).AggregateOver(FlowDefault).IncludePolicies(true).IncludeProcess(true).PerFlowProcessLimit(2)

			By("Feeding update with process information")
			_ = caa.FeedUpdate(&muWithProcessName)

			By("Checking calibration")
			messages := caa.GetAndCalibrate(FlowDefault)
			Expect(len(messages)).Should(Equal(1))
			flowLog := messages[0]

			dstMeta := endpoint.Metadata{
				Type:           "wep",
				Namespace:      "default",
				Name:           "nginx-412354-5123451",
				AggregatedName: "nginx-412354-*",
			}

			expectedNumFlows := 1
			expectedNumFlowsStarted := 1
			expectedNumFlowsCompleted := 0

			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut := calculatePacketStats(muWithProcessName)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut := calculateTransitPacketStats(muWithProcessName)
			expectedFP := extractFlowPolicies(muWithProcessName)
			expectedFPP := extractFlowPendingPolicies(muWithProcessName)
			expectedTP := extractFlowTransitPolicies(muWithProcessName)
			expectedFlowExtras := extractFlowExtras(muWithProcessName)
			expectedFlowProcessInfo := extractFlowProcessInfo(muWithProcessName)
			expectedTCPS := extractFlowTCPStats(muWithProcessName)
			expectFlowLog(*flowLog, tuple1, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDstFwd,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, dstMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, expectedFlowProcessInfo, expectedTCPS)

			By("Checking calibration without any additional metric update")
			messages = caa.GetAndCalibrate(FlowDefault)
			Expect(len(messages)).Should(Equal(1))
			flowLog = messages[0]

			// MetricUpdate object only used for  calculating expectations and not really sent to aggregator
			muWithProcessNameButNoStats := muWithProcessName
			muWithProcessNameButNoStats.TcpMetric = metric.TCPValue{}
			muWithProcessNameButNoStats.InMetric = metric.Value{}
			muWithProcessNameButNoStats.SendCongestionWnd = nil
			muWithProcessNameButNoStats.SmoothRtt = nil
			muWithProcessNameButNoStats.MinRtt = nil
			muWithProcessNameButNoStats.Mss = nil

			By("Expected flow logs contain the process ID")
			expectedNumFlows = 1
			expectedNumFlowsStarted = 0
			expectedNumFlowsCompleted = 0

			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut = calculatePacketStats(muWithProcessNameButNoStats)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut = calculateTransitPacketStats(muWithProcessNameButNoStats)
			expectedFP = extractFlowPolicies(muWithProcessNameButNoStats)
			expectedFPP = extractFlowPendingPolicies(muWithProcessNameButNoStats)
			expectedTP = extractFlowTransitPolicies(muWithProcessNameButNoStats)
			expectedFlowExtras = extractFlowExtras(muWithProcessNameButNoStats)
			expectedFlowProcessInfo = extractFlowProcessInfo(muWithProcessNameButNoStats)
			expectedTCPS = extractFlowTCPStats(muWithProcessNameButNoStats)
			expectFlowLog(*flowLog, tuple1, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDstFwd,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, dstMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, expectedFlowProcessInfo, expectedTCPS)

			By("Feeding update with same process name but different ID")
			_ = caa.FeedUpdate(&muWithProcessNameDifferentIDSameTuple)

			By("Checking calibration")
			messages = caa.GetAndCalibrate(FlowDefault)
			Expect(len(messages)).Should(Equal(1))
			flowLog = messages[0]

			By("Expected flow logs contain the new process ID from the metric update")
			expectedNumFlows = 1
			expectedNumFlowsStarted = 0
			expectedNumFlowsCompleted = 0

			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut = calculatePacketStats(muWithProcessNameDifferentIDSameTuple)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut = calculateTransitPacketStats(muWithProcessNameDifferentIDSameTuple)
			expectedFP = extractFlowPolicies(muWithProcessNameDifferentIDSameTuple)
			expectedFPP = extractFlowPendingPolicies(muWithProcessNameDifferentIDSameTuple)
			expectedTP = extractFlowTransitPolicies(muWithProcessNameDifferentIDSameTuple)
			expectedFlowExtras = extractFlowExtras(muWithProcessNameDifferentIDSameTuple)
			expectedFlowProcessInfo = extractFlowProcessInfo(muWithProcessNameDifferentIDSameTuple)
			expectedTCPS = extractFlowTCPStats(muWithProcessNameDifferentIDSameTuple)
			expectFlowLog(*flowLog, tuple1, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDstFwd,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, dstMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, expectedFlowProcessInfo, expectedTCPS)
		})

		It("Handles missing process information with default aggregation", func() {
			By("Creating an aggregator for allow")
			caa := NewAggregator().ForAction(rules.RuleActionAllow).AggregateOver(FlowDefault).IncludePolicies(true).IncludeProcess(true).PerFlowProcessLimit(2)

			muWithoutProcessName := muWithProcessName
			muWithoutProcessName.ProcessName = ""
			muWithoutProcessName.ProcessID = 0
			muWithoutProcessName.ProcessArgs = ""

			// copy original intended value as muWithoutProcessName will be modified
			originalMuWithoutProcessName := muWithoutProcessName

			By("Feeding update with process information")
			_ = caa.FeedUpdate(&muWithoutProcessName)

			By("Checking calibration")
			messages := caa.GetAndCalibrate(FlowDefault)
			Expect(len(messages)).Should(Equal(1))
			flowLog := messages[0]

			dstMeta := endpoint.Metadata{
				Type:           "wep",
				Namespace:      "default",
				Name:           "nginx-412354-5123451",
				AggregatedName: "nginx-412354-*",
			}

			expectedNumFlows := 1
			expectedNumFlowsStarted := 1
			expectedNumFlowsCompleted := 0

			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut := calculatePacketStats(muWithoutProcessName)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut := calculateTransitPacketStats(muWithoutProcessName)
			expectedFP := extractFlowPolicies(muWithoutProcessName)
			expectedFPP := extractFlowPendingPolicies(muWithoutProcessName)
			expectedTP := extractFlowTransitPolicies(muWithoutProcessName)
			expectedFlowExtras := extractFlowExtras(muWithoutProcessName)

			expectedFlowProcessInfo := extractFlowProcessInfo(originalMuWithoutProcessName)

			expectedTCPS := extractFlowTCPStats(muWithoutProcessName)
			expectFlowLog(*flowLog, tuple1, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDstFwd,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, dstMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, expectedFlowProcessInfo, expectedTCPS)
		})
	})

	Context("Flow log Aggregator post SNAT ports", func() {
		It("doesn't overwrite the nat outgoing port with an empty value", func() {
			muWithSNATPort1 := muWithSNATPort
			muWithSNATPort2 := muWithSNATPort
			muWithSNATPort2.NatOutgoingPort = 0

			aggregator := NewAggregator().
				ForAction(rules.RuleActionAllow).
				AggregateOver(FlowSourcePort).
				IncludePolicies(true).
				IncludeProcess(true).
				PerFlowProcessLimit(2).
				PerFlowProcessArgsLimit(6)

			Expect(aggregator.FeedUpdate(&muWithSNATPort1)).ShouldNot(HaveOccurred())
			Expect(aggregator.FeedUpdate(&muWithSNATPort2)).ShouldNot(HaveOccurred())

			flows := aggregator.GetAndCalibrate(FlowSourcePort)
			Expect(len(flows)).ShouldNot(BeZero())
			Expect(flows[0].NatOutgoingPorts).To(ConsistOf(muWithSNATPort1.NatOutgoingPort))
		})

		It("overwrites an empty nat outgoing port with a non empty value", func() {
			muWithSNATPort1 := muWithSNATPort
			muWithSNATPort1.NatOutgoingPort = 0
			muWithSNATPort2 := muWithSNATPort

			aggregator := NewAggregator().
				ForAction(rules.RuleActionAllow).
				AggregateOver(FlowSourcePort).
				IncludePolicies(true).
				IncludeProcess(true).
				PerFlowProcessLimit(2).
				PerFlowProcessArgsLimit(6)

			Expect(aggregator.FeedUpdate(&muWithSNATPort1)).ShouldNot(HaveOccurred())
			Expect(aggregator.FeedUpdate(&muWithSNATPort2)).ShouldNot(HaveOccurred())

			flows := aggregator.GetAndCalibrate(FlowSourcePort)
			Expect(len(flows)).ShouldNot(BeZero())
			Expect(flows[0].NatOutgoingPorts).To(ConsistOf(muWithSNATPort2.NatOutgoingPort))
		})

		It("chooses SNAT'd ports for active connections over expired ones when the post SNAT port limit is too low", func() {
			muWithSNATPort1 := muWithSNATPort
			muWithSNATPort1.UpdateType = metric.UpdateTypeExpire
			muWithSNATPort2 := muWithSNATPort
			muWithSNATPort2.Tuple.L4Src = 54124
			muWithSNATPort2.NatOutgoingPort = 6788
			muWithSNATPort3 := muWithSNATPort
			muWithSNATPort3.Tuple.L4Src = 54125
			muWithSNATPort3.NatOutgoingPort = 6787
			muWithSNATPort4 := muWithSNATPort
			muWithSNATPort4.Tuple.L4Src = 54126
			muWithSNATPort4.NatOutgoingPort = 6786

			aggregator := NewAggregator().
				ForAction(rules.RuleActionAllow).
				AggregateOver(FlowSourcePort).
				IncludePolicies(true).
				IncludeProcess(true).
				PerFlowProcessLimit(2).
				PerFlowProcessArgsLimit(6)

			Expect(aggregator.FeedUpdate(&muWithSNATPort1)).ShouldNot(HaveOccurred())
			Expect(aggregator.FeedUpdate(&muWithSNATPort2)).ShouldNot(HaveOccurred())
			Expect(aggregator.FeedUpdate(&muWithSNATPort3)).ShouldNot(HaveOccurred())
			Expect(aggregator.FeedUpdate(&muWithSNATPort4)).ShouldNot(HaveOccurred())

			flows := aggregator.GetAndCalibrate(FlowSourcePort)
			Expect(len(flows)).ShouldNot(BeZero())
			Expect(flows[0].NatOutgoingPorts).To(ConsistOf(6788, 6787, 6786))
		})

		It("includes expired connections if the post SNAT port limit is high enough", func() {
			muWithSNATPort1 := muWithSNATPort
			muWithSNATPort1.UpdateType = metric.UpdateTypeExpire
			muWithSNATPort2 := muWithSNATPort
			muWithSNATPort2.Tuple.L4Src = 54124
			muWithSNATPort2.NatOutgoingPort = 6788
			muWithSNATPort3 := muWithSNATPort
			muWithSNATPort3.Tuple.L4Src = 54125
			muWithSNATPort3.NatOutgoingPort = 6787
			muWithSNATPort4 := muWithSNATPort
			muWithSNATPort4.Tuple.L4Src = 54126
			muWithSNATPort4.NatOutgoingPort = 6786

			aggregator := NewAggregator().
				ForAction(rules.RuleActionAllow).
				AggregateOver(FlowSourcePort).
				IncludePolicies(true).
				IncludeProcess(true).
				PerFlowProcessLimit(2).
				PerFlowProcessArgsLimit(6).
				NatOutgoingPortLimit(4)

			Expect(aggregator.FeedUpdate(&muWithSNATPort1)).ShouldNot(HaveOccurred())
			Expect(aggregator.FeedUpdate(&muWithSNATPort2)).ShouldNot(HaveOccurred())
			Expect(aggregator.FeedUpdate(&muWithSNATPort3)).ShouldNot(HaveOccurred())
			Expect(aggregator.FeedUpdate(&muWithSNATPort4)).ShouldNot(HaveOccurred())

			flows := aggregator.GetAndCalibrate(FlowSourcePort)
			Expect(len(flows)).ShouldNot(BeZero())
			Expect(flows[0].NatOutgoingPorts).To(ConsistOf(6789, 6788, 6787, 6786))
		})
	})
})
