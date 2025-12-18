// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.

package flowlog

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"

	"github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/collector/types/boundedset"
	"github.com/projectcalico/calico/felix/collector/types/endpoint"
	"github.com/projectcalico/calico/felix/collector/types/metric"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
)

var (
	logGroupName  = "test-group"
	logStreamName = "test-stream"
	flushInterval = 500 * time.Millisecond
	includeLabels = false
	noService     = FlowService{Namespace: "-", Name: "-", PortName: "-", PortNum: 0}
)

var (
	pvtMeta = endpoint.Metadata{Type: endpoint.Net, Namespace: "-", Name: "-", AggregatedName: "pvt"}
	pubMeta = endpoint.Metadata{Type: endpoint.Net, Namespace: "-", Name: "-", AggregatedName: "pub"}
)

type testFlowLogReporter struct {
	mutex    sync.Mutex
	logs     []*FlowLog
	failInit bool
}

// Mock time helper.
type mockTime struct {
	val int64
}

func (mt *mockTime) getMockTime() time.Duration {
	val := atomic.LoadInt64(&mt.val)
	return time.Duration(val)
}
func (mt *mockTime) incMockTime(inc time.Duration) {
	atomic.AddInt64(&mt.val, int64(inc))
}

func (d *testFlowLogReporter) Start() error {
	if d.failInit {
		return errors.New("failed to initialize testFlowLogReporter")
	}
	return nil
}

func (d *testFlowLogReporter) Report(logSlice interface{}) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	log.Info("In dispatch")
	fl := logSlice.([]*FlowLog)
	d.logs = append(d.logs, fl...)
	return nil
}

func (d *testFlowLogReporter) getLogs() []*FlowLog {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	return d.logs
}

var _ = Describe("FlowLog Reporter verification", func() {
	var (
		cr         *FlowLogReporter
		ca         *Aggregator
		dispatcher *testFlowLogReporter
	)

	mt := &mockTime{}
	expectFlowLogsInEventStream := func(fls ...FlowLog) {
		flogs := dispatcher.getLogs()
		count := 0
		for _, fl := range fls {
			for _, flog := range flogs {
				if reflect.DeepEqual(flog.FlowMeta, fl.FlowMeta) &&
					reflect.DeepEqual(flog.FlowEnforcedPolicySet, fl.FlowEnforcedPolicySet) &&
					reflect.DeepEqual(flog.FlowExtras, fl.FlowExtras) &&
					reflect.DeepEqual(flog.FlowLabels, fl.FlowLabels) &&
					reflect.DeepEqual(flog.FlowProcessReportedStats, fl.FlowProcessReportedStats) {
					count++
					if count == len(fls) {
						break
					}
				}
			}
		}
		Expect(count).Should(Equal(len(fls)))
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
			return FlowExtras{OriginalSourceIPs: []net.IP{}, NumOriginalSourceIPs: 0}
		}
	}
	extractFlowPolicies := func(mus ...metric.Update) FlowPolicySet {
		fp := make(FlowPolicySet)
		for _, mu := range mus {
			for idx, r := range mu.RuleIDs {
				name := fmt.Sprintf("%d|%s|%s.%s|%s|%s", idx,
					r.TierString(),
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
				name := fmt.Sprintf("%d|%s|%s.%s|%s|%s", idx,
					r.TierString(),
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
				name := fmt.Sprintf("%d|%s|%s.%s|%s|%s", idx,
					r.TierString(),
					r.TierString(),
					r.NameString(),
					r.ActionString(),
					r.IndexStr)
				fp[name] = emptyValue
			}
		}
		return fp
	}
	Context("No Aggregation kind specified", func() {
		BeforeEach(func() {
			dispatcherMap := map[string]types.Reporter{}
			dispatcher = &testFlowLogReporter{}
			dispatcherMap["testFlowLog"] = dispatcher
			ca = NewAggregator()
			ca.IncludePolicies(true)
			cr = NewReporter(dispatcherMap, flushInterval, nil, false, true, &NoOpLogOffset{})
			cr.AddAggregator(ca, []string{"testFlowLog"})
			cr.timeNowFn = mt.getMockTime
			Expect(cr.Start()).NotTo(HaveOccurred())
		})

		It("reports the given metric update in form of a flowLog", func() {
			By("reporting the first metric Update")
			Expect(cr.Report(muNoConn1Rule1AllowUpdate)).NotTo(HaveOccurred())
			// Wait for aggregation and export to happen.
			time.Sleep(1 * time.Second)
			expectedNumFlows := 1
			expectedNumFlowsStarted := 1
			expectedNumFlowsCompleted := 0
			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut := calculatePacketStats(muNoConn1Rule1AllowUpdate)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut := calculateTransitPacketStats(muNoConn1Rule1AllowUpdate)
			expectedFP := extractFlowPolicies(muNoConn1Rule1AllowUpdate)
			expectedFPP := extractFlowPendingPolicies(muNoConn1Rule1AllowUpdate)
			expectedTP := extractFlowTransitPolicies(muNoConn1Rule1AllowUpdate)
			expectedFlowExtras := extractFlowExtras(muNoConn1Rule1AllowUpdate)
			expectFlowLogsInEventStream(newExpectedFlowLog(tuple1, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, pubMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, noProcessInfo, noTcpStatsInfo))

			By("reporting the same metric Update with metrics in both directions")
			Expect(cr.Report(muConn1Rule1AllowUpdate)).NotTo(HaveOccurred())
			// Wait for aggregation and export to happen.
			time.Sleep(1 * time.Second)
			expectedNumFlowsStarted = 0
			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut = calculatePacketStats(muConn1Rule1AllowUpdate)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut = calculateTransitPacketStats(muConn1Rule1AllowUpdate)
			expectedFP = extractFlowPolicies(muConn1Rule1AllowUpdate)
			expectedFPP = extractFlowPendingPolicies(muConn1Rule1AllowUpdate)
			expectedTP = extractFlowTransitPolicies(muConn1Rule1AllowUpdate)
			expectFlowLogsInEventStream(newExpectedFlowLog(tuple1, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, pubMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, noProcessInfo, noTcpStatsInfo))

			By("reporting a expired metric Update for the same tuple")
			Expect(cr.Report(muConn1Rule1AllowExpire)).NotTo(HaveOccurred())
			// Wait for aggregation and export to happen.
			time.Sleep(1 * time.Second)
			expectedNumFlowsStarted = 0
			expectedNumFlowsCompleted = 1
			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut = calculatePacketStats(muConn1Rule1AllowExpire)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut = calculateTransitPacketStats(muConn1Rule1AllowExpire)
			expectedFP = extractFlowPolicies(muConn1Rule1AllowExpire)
			expectedFPP = extractFlowPendingPolicies(muConn1Rule1AllowExpire)
			expectedTP = extractFlowTransitPolicies(muConn1Rule1AllowExpire)
			expectFlowLogsInEventStream(newExpectedFlowLog(tuple1, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, pubMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, noProcessInfo, noTcpStatsInfo))

			By("reporting a metric Update for denied packets")
			Expect(cr.Report(muNoConn3Rule2DenyUpdate)).NotTo(HaveOccurred())
			// Wait for aggregation and export to happen.
			time.Sleep(1 * time.Second)
			expectedNumFlows = 1
			expectedNumFlowsStarted = 1
			expectedNumFlowsCompleted = 0
			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut = calculatePacketStats(muNoConn1Rule2DenyUpdate)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut = calculateTransitPacketStats(muNoConn1Rule2DenyUpdate)
			expectedFP = extractFlowPolicies(muNoConn1Rule2DenyUpdate)
			expectedFPP = extractFlowPendingPolicies(muNoConn1Rule2DenyUpdate)
			expectedTP = extractFlowTransitPolicies(muNoConn1Rule2DenyUpdate)
			expectFlowLogsInEventStream(newExpectedFlowLog(tuple3, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionDeny, ReporterSrc,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, pubMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, noProcessInfo, noTcpStatsInfo))

			By("reporting a expired denied packet metric Update for the same tuple")
			Expect(cr.Report(muNoConn3Rule2DenyExpire)).NotTo(HaveOccurred())
			// Wait for aggregation and export to happen.
			time.Sleep(1 * time.Second)
			expectedNumFlowsStarted = 0
			expectedNumFlowsCompleted = 1
			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut = calculatePacketStats(muNoConn1Rule2DenyExpire)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut = calculateTransitPacketStats(muNoConn1Rule2DenyExpire)
			expectedFP = extractFlowPolicies(muNoConn1Rule2DenyExpire)
			expectedFPP = extractFlowPendingPolicies(muNoConn1Rule2DenyExpire)
			expectedTP = extractFlowTransitPolicies(muNoConn1Rule2DenyExpire)
			expectFlowLogsInEventStream(newExpectedFlowLog(tuple3, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionDeny, ReporterSrc,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, pubMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, noProcessInfo, noTcpStatsInfo))
		})
		It("aggregates metric updates for the duration of aggregation when reporting to flow logs", func() {
			By("reporting the same metric Update twice and expiring it immediately")
			Expect(cr.Report(muConn1Rule1AllowUpdate)).NotTo(HaveOccurred())
			Expect(cr.Report(muConn1Rule1AllowUpdate)).NotTo(HaveOccurred())
			Expect(cr.Report(muConn1Rule1AllowExpire)).NotTo(HaveOccurred())
			// Wait for aggregation and export to happen.
			time.Sleep(1 * time.Second)
			expectedNumFlows := 1
			expectedNumFlowsStarted := 1
			expectedNumFlowsCompleted := 1
			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut := calculatePacketStats(muConn1Rule1AllowUpdate, muConn1Rule1AllowUpdate, muConn1Rule1AllowExpire)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut := calculateTransitPacketStats(muConn1Rule1AllowUpdate, muConn1Rule1AllowUpdate, muConn1Rule1AllowExpire)
			expectedFP := extractFlowPolicies(muConn1Rule1AllowUpdate, muConn1Rule1AllowUpdate, muConn1Rule1AllowExpire)
			expectedFPP := extractFlowPendingPolicies(muConn1Rule1AllowUpdate, muConn1Rule1AllowUpdate, muConn1Rule1AllowExpire)
			expectedTP := extractFlowTransitPolicies(muConn1Rule1AllowUpdate, muConn1Rule1AllowUpdate, muConn1Rule1AllowExpire)
			expectedFlowExtras := extractFlowExtras(muConn1Rule1AllowUpdate, muConn1Rule1AllowUpdate, muConn1Rule1AllowExpire)
			expectFlowLogsInEventStream(newExpectedFlowLog(tuple1, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, pubMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, noProcessInfo, noTcpStatsInfo))

			By("reporting the same tuple different policies should be reported as separate flow logs")
			Expect(cr.Report(muConn1Rule1AllowUpdate)).NotTo(HaveOccurred())
			Expect(cr.Report(muNoConn1Rule2DenyUpdate)).NotTo(HaveOccurred())
			// Wait for aggregation and export to happen.
			time.Sleep(1 * time.Second)

			expectedNumFlows = 1
			expectedNumFlowsStarted = 1
			expectedNumFlowsCompleted = 0
			expectedPacketsIn1, expectedPacketsOut1, expectedBytesIn1, expectedBytesOut1 := calculatePacketStats(muConn1Rule1AllowUpdate)
			expectedPacketsIn2, expectedPacketsOut2, expectedBytesIn2, expectedBytesOut2 := calculatePacketStats(muNoConn1Rule2DenyUpdate)
			expectedTransitPacketsIn1, expectedTransitPacketsOut1, expectedTransitBytesIn1, expectedTransitBytesOut1 := calculateTransitPacketStats(muConn1Rule1AllowUpdate)
			expectedTransitPacketsIn2, expectedTransitPacketsOut2, expectedTransitBytesIn2, expectedTransitBytesOut2 := calculateTransitPacketStats(muNoConn1Rule2DenyUpdate)
			expectedFP1 := extractFlowPolicies(muConn1Rule1AllowUpdate)
			expectedFPP1 := extractFlowPendingPolicies(muConn1Rule1AllowUpdate)
			expectedTP1 := extractFlowTransitPolicies(muConn1Rule1AllowUpdate)
			expectedFP2 := extractFlowPolicies(muNoConn1Rule2DenyUpdate)
			expectedFPP2 := extractFlowPendingPolicies(muNoConn1Rule2DenyUpdate)
			expectedTP2 := extractFlowTransitPolicies(muNoConn1Rule2DenyUpdate)
			expectedFlowExtras1 := extractFlowExtras(muConn1Rule1AllowUpdate)
			expectedFlowExtras2 := extractFlowExtras(muNoConn1Rule2DenyUpdate)
			// We only care about the flow log entry to exist and don't care about the actual order.
			expectFlowLogsInEventStream(
				newExpectedFlowLog(tuple1, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
					expectedPacketsIn1, expectedPacketsOut1, expectedBytesIn1, expectedBytesOut1, expectedTransitPacketsIn1, expectedTransitPacketsOut1, expectedTransitBytesIn1, expectedTransitBytesOut1, pvtMeta, pubMeta, noService, nil, nil, expectedFP1, expectedFP1, expectedFPP1, expectedTP1, expectedFlowExtras1, noProcessInfo, noTcpStatsInfo),
				newExpectedFlowLog(tuple1, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionDeny, ReporterSrc,
					expectedPacketsIn2, expectedPacketsOut2, expectedBytesIn2, expectedBytesOut2, expectedTransitPacketsIn2, expectedTransitPacketsOut2, expectedTransitBytesIn2, expectedTransitBytesOut2, pvtMeta, pubMeta, noService, nil, nil, expectedFP2, expectedFP2, expectedFPP2, expectedTP2, expectedFlowExtras2, noProcessInfo, noTcpStatsInfo))
		})

		It("aggregates metric updates from multiple tuples", func() {
			By("report different connections")
			Expect(cr.Report(muConn1Rule1AllowUpdate)).NotTo(HaveOccurred())
			Expect(cr.Report(muConn2Rule1AllowUpdate)).NotTo(HaveOccurred())
			// Wait for aggregation and export to happen.
			time.Sleep(1 * time.Second)

			expectedNumFlows := 1
			expectedNumFlowsStarted := 1
			expectedNumFlowsCompleted := 0
			expectedPacketsIn1, expectedPacketsOut1, expectedBytesIn1, expectedBytesOut1 := calculatePacketStats(muConn1Rule1AllowUpdate)
			expectedPacketsIn2, expectedPacketsOut2, expectedBytesIn2, expectedBytesOut2 := calculatePacketStats(muConn2Rule1AllowUpdate)
			expectedTransitPacketsIn1, expectedTransitPacketsOut1, expectedTransitBytesIn1, expectedTransitBytesOut1 := calculateTransitPacketStats(muConn1Rule1AllowUpdate)
			expectedTransitPacketsIn2, expectedTransitPacketsOut2, expectedTransitBytesIn2, expectedTransitBytesOut2 := calculateTransitPacketStats(muConn2Rule1AllowUpdate)
			expectedFP1 := extractFlowPolicies(muConn1Rule1AllowUpdate)
			expectedFPP1 := extractFlowPendingPolicies(muConn1Rule1AllowUpdate)
			expectedTP1 := extractFlowTransitPolicies(muConn1Rule1AllowUpdate)
			expectedFP2 := extractFlowPolicies(muConn2Rule1AllowUpdate)
			expectedFPP2 := extractFlowPendingPolicies(muConn2Rule1AllowUpdate)
			expectedTP2 := extractFlowTransitPolicies(muConn2Rule1AllowUpdate)
			expectedFlowExtras1 := extractFlowExtras(muConn1Rule1AllowUpdate)
			expectedFlowExtras2 := extractFlowExtras(muConn2Rule1AllowUpdate)
			// We only care about the flow log entry to exist and don't care about the actual order.
			expectFlowLogsInEventStream(
				newExpectedFlowLog(tuple1, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
					expectedPacketsIn1, expectedPacketsOut1, expectedBytesIn1, expectedBytesOut1, expectedTransitPacketsIn1, expectedTransitPacketsOut1, expectedTransitBytesIn1, expectedTransitBytesOut1, pvtMeta, pubMeta, noService, nil, nil, expectedFP1, expectedFP1, expectedFPP1, expectedTP1, expectedFlowExtras1, noProcessInfo, noTcpStatsInfo),
				newExpectedFlowLog(tuple2, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
					expectedPacketsIn2, expectedPacketsOut2, expectedBytesIn2, expectedBytesOut2, expectedTransitPacketsIn2, expectedTransitPacketsOut2, expectedTransitBytesIn2, expectedTransitBytesOut2, pvtMeta, pubMeta, noService, nil, nil, expectedFP2, expectedFP2, expectedFPP2, expectedTP2, expectedFlowExtras2, noProcessInfo, noTcpStatsInfo))

			By("report expirations of the same connections")
			Expect(cr.Report(muConn1Rule1AllowExpire)).NotTo(HaveOccurred())
			Expect(cr.Report(muConn2Rule1AllowExpire)).NotTo(HaveOccurred())
			// Wait for aggregation and export to happen.
			time.Sleep(1 * time.Second)

			expectedNumFlows = 1
			expectedNumFlowsStarted = 0
			expectedNumFlowsCompleted = 1
			expectedPacketsIn1, expectedPacketsOut1, expectedBytesIn1, expectedBytesOut1 = calculatePacketStats(muConn1Rule1AllowExpire)
			expectedPacketsIn2, expectedPacketsOut2, expectedBytesIn2, expectedBytesOut2 = calculatePacketStats(muConn2Rule1AllowExpire)
			expectedTransitPacketsIn1, expectedTransitPacketsOut1, expectedTransitBytesIn1, expectedTransitBytesOut1 = calculateTransitPacketStats(muConn1Rule1AllowExpire)
			expectedTransitPacketsIn2, expectedTransitPacketsOut2, expectedTransitBytesIn2, expectedTransitBytesOut2 = calculateTransitPacketStats(muConn2Rule1AllowExpire)
			expectedFP1 = extractFlowPolicies(muConn1Rule1AllowExpire)
			expectedFPP1 = extractFlowPendingPolicies(muConn1Rule1AllowExpire)
			expectedTP1 = extractFlowTransitPolicies(muConn1Rule1AllowExpire)
			expectedFP2 = extractFlowPolicies(muConn2Rule1AllowExpire)
			expectedFPP2 = extractFlowPendingPolicies(muConn2Rule1AllowExpire)
			expectedTP2 = extractFlowTransitPolicies(muConn2Rule1AllowExpire)
			expectedFlowExtras1 = extractFlowExtras(muConn1Rule1AllowExpire)
			expectedFlowExtras2 = extractFlowExtras(muConn2Rule1AllowExpire)
			// We only care about the flow log entry to exist and don't care about the actual order.
			expectFlowLogsInEventStream(
				newExpectedFlowLog(tuple1, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
					expectedPacketsIn1, expectedPacketsOut1, expectedBytesIn1, expectedBytesOut1, expectedTransitPacketsIn1, expectedTransitPacketsOut1, expectedTransitBytesIn1, expectedTransitBytesOut1, pvtMeta, pubMeta, noService, nil, nil, expectedFP1, expectedFP1, expectedFPP1, expectedTP1, expectedFlowExtras1, noProcessInfo, noTcpStatsInfo),
				newExpectedFlowLog(tuple2, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
					expectedPacketsIn2, expectedPacketsOut2, expectedBytesIn2, expectedBytesOut2, expectedTransitPacketsIn2, expectedTransitPacketsOut2, expectedTransitBytesIn2, expectedTransitBytesOut2, pvtMeta, pubMeta, noService, nil, nil, expectedFP2, expectedFP2, expectedFPP2, expectedTP2, expectedFlowExtras2, noProcessInfo, noTcpStatsInfo))
		})
		It("Doesn't process flows from Hostendoint to Hostendpoint", func() {
			By("Reporting a update with host endpoint to host endpoint")
			muConn1Rule1AllowUpdateCopy := muConn1Rule1AllowUpdate
			muConn1Rule1AllowUpdateCopy.SrcEp = localHostEd1
			muConn1Rule1AllowUpdateCopy.DstEp = remoteHostEd1
			Expect(cr.Report(muConn1Rule1AllowUpdateCopy)).NotTo(HaveOccurred())
			time.Sleep(1 * time.Second)

			By("Verifying that flow logs are logged with pvt and pub metadata")
			time.Sleep(1 * time.Second)
			expectedNumFlows := 1
			expectedNumFlowsStarted := 1
			expectedNumFlowsCompleted := 0
			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut := calculatePacketStats(muConn1Rule1AllowUpdateCopy)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut := calculateTransitPacketStats(muConn1Rule1AllowUpdateCopy)
			expectedFP := extractFlowPolicies(muConn1Rule1AllowUpdateCopy)
			expectedFPP := extractFlowPendingPolicies(muConn1Rule1AllowUpdateCopy)
			expectedTP := extractFlowTransitPolicies(muConn1Rule1AllowUpdateCopy)
			expectedFlowExtras := extractFlowExtras(muConn1Rule1AllowUpdateCopy)
			expectFlowLogsInEventStream(newExpectedFlowLog(tuple1, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, pubMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, noProcessInfo, noTcpStatsInfo))
		})
		It("reports the given metric update with original source IPs in a flow log", func() {
			By("reporting the first metric Update")
			Expect(cr.Report(muWithOrigSourceIPs)).NotTo(HaveOccurred())
			// Wait for aggregation and export to happen.
			time.Sleep(1 * time.Second)
			expectedNumFlows := 1
			expectedNumFlowsStarted := 1
			expectedNumFlowsCompleted := 0
			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut := calculatePacketStats(muWithOrigSourceIPs)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut := calculateTransitPacketStats(muWithOrigSourceIPs)
			expectedFP := extractFlowPolicies(muWithOrigSourceIPs)
			expectedFPP := extractFlowPendingPolicies(muWithOrigSourceIPs)
			expectedTP := extractFlowTransitPolicies(muWithOrigSourceIPs)
			expectedFlowExtras := extractFlowExtras(muWithOrigSourceIPs)
			meta := endpoint.Metadata{Type: endpoint.Wep, Namespace: "default", Name: "nginx-412354-5123451", AggregatedName: "nginx-412354-*"}
			expectFlowLogsInEventStream(newExpectedFlowLog(tuple1, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, pvtMeta, meta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, noProcessInfo, noTcpStatsInfo))
		})
	})
	Context("Enable Flowlogs for HEPs", func() {
		BeforeEach(func() {
			dispatcherMap := map[string]types.Reporter{}
			dispatcher = &testFlowLogReporter{}
			dispatcherMap["testFlowLog"] = dispatcher
			ca = NewAggregator()
			ca.IncludePolicies(true)
			cr = NewReporter(dispatcherMap, flushInterval, nil, true, true, &NoOpLogOffset{})
			cr.AddAggregator(ca, []string{"testFlowLog"})
			cr.timeNowFn = mt.getMockTime
			Expect(cr.Start()).NotTo(HaveOccurred())
		})
		It("processes flows from Hostendoint to Hostendpoint", func() {
			By("Reporting a update with host endpoint to host endpoint")
			muConn1Rule1AllowUpdateCopy := muConn1Rule1AllowUpdate
			muConn1Rule1AllowUpdateCopy.SrcEp = localHostEd1
			muConn1Rule1AllowUpdateCopy.DstEp = remoteHostEd1
			Expect(cr.Report(muConn1Rule1AllowUpdateCopy)).NotTo(HaveOccurred())

			By("Verifying that flow logs are logged with HEP metadata")
			time.Sleep(1 * time.Second)
			expectedNumFlows := 1
			expectedNumFlowsStarted := 1
			expectedNumFlowsCompleted := 0
			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut := calculatePacketStats(muConn1Rule1AllowUpdateCopy)
			expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut := calculateTransitPacketStats(muConn1Rule1AllowUpdateCopy)
			expectedSrcMeta := endpoint.Metadata{Type: endpoint.Hep, Namespace: "-", Name: "eth1", AggregatedName: "localhost"}
			expectedDstMeta := endpoint.Metadata{Type: endpoint.Hep, Namespace: "-", Name: "eth1", AggregatedName: "remotehost"}
			expectedFP := extractFlowPolicies(muConn1Rule1AllowUpdateCopy)
			expectedFPP := extractFlowPendingPolicies(muConn1Rule1AllowUpdateCopy)
			expectedTP := extractFlowTransitPolicies(muConn1Rule1AllowUpdateCopy)
			expectedFlowExtras := extractFlowExtras(muConn1Rule1AllowUpdateCopy)
			expectFlowLogsInEventStream(newExpectedFlowLog(tuple1, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, expectedTransitPacketsIn, expectedTransitPacketsOut, expectedTransitBytesIn, expectedTransitBytesOut, expectedSrcMeta, expectedDstMeta, noService, nil, nil, expectedFP, expectedFP, expectedFPP, expectedTP, expectedFlowExtras, noProcessInfo, noTcpStatsInfo))
		})
	})
})

var _ = Describe("Flowlog Reporter health verification", func() {
	var (
		cr         *FlowLogReporter
		hr         *health.HealthAggregator
		dispatcher *testFlowLogReporter
	)

	mt := &mockTime{}
	Context("Test with no errors", func() {
		BeforeEach(func() {
			dispatcherMap := map[string]types.Reporter{}
			dispatcher = &testFlowLogReporter{}
			dispatcherMap["testFlowLog"] = dispatcher
			hr = health.NewHealthAggregator()
			cr = NewReporter(dispatcherMap, flushInterval, hr, false, true, &NoOpLogOffset{})
			cr.timeNowFn = mt.getMockTime
			Expect(cr.Start()).NotTo(HaveOccurred())
		})
		It("verify health reporting.", func() {
			By("checking the Readiness flag in health aggregator")
			expectedReport := health.HealthReport{Live: true, Ready: true}
			Eventually(func() bool { return hr.Summary().Live }, 15, 1).Should(Equal(expectedReport.Live))
			Eventually(func() bool { return hr.Summary().Ready }, 15, 1).Should(Equal(expectedReport.Ready))
		})
	})
	Context("Test with dispatcher that fails to initialize", func() {
		BeforeEach(func() {
			dispatcherMap := map[string]types.Reporter{}
			dispatcher = &testFlowLogReporter{failInit: true}
			dispatcherMap["testFlowLog"] = dispatcher
			hr = health.NewHealthAggregator()
			cr = NewReporter(dispatcherMap, flushInterval, hr, false, true, &NoOpLogOffset{})
			cr.timeNowFn = mt.getMockTime
			Expect(cr.Start()).NotTo(HaveOccurred())
		})
		It("verify health reporting.", func() {
			By("checking the Readiness flag in health aggregator")
			expectedReport := health.HealthReport{Live: true, Ready: false}
			Eventually(func() bool { return hr.Summary().Live }, 15, 1).Should(Equal(expectedReport.Live))
			Eventually(func() bool { return hr.Summary().Ready }, 15, 1).Should(Equal(expectedReport.Ready))
		})
	})
})

var _ = Describe("FlowLog per minute verification", func() {
	var (
		cr         *FlowLogReporter
		ca         *Aggregator
		dispatcher *testFlowLogReporter
	)

	mt := &mockTime{}

	Context("Flow logs per minute verification", func() {
		It("Usage report is triggered before flushIntervalDuration", func() {
			By("Triggering report right away before flushIntervalDuration")
			ca = NewAggregator()
			dispatcherMap := map[string]types.Reporter{}
			dispatcher = &testFlowLogReporter{}
			dispatcherMap["testFlowLog"] = dispatcher
			mockFlushInterval := 600 * time.Second
			cr = NewReporter(dispatcherMap, mockFlushInterval, nil, false, true, &NoOpLogOffset{})
			cr.AddAggregator(ca, []string{"testFlowLog"})
			cr.timeNowFn = mt.getMockTime
			Expect(cr.Start()).NotTo(HaveOccurred())

			Expect(cr.GetAndResetFlowLogsAvgPerMinute()).Should(Equal(0.0))
		})
		It("Usage report is triggered post flushIntervalDuration", func() {
			By("Triggering report post flushIntervalDuration by mocking flushInterval")
			ca = NewAggregator()
			ca.IncludePolicies(true)
			dispatcherMap := map[string]types.Reporter{}
			dispatcher = &testFlowLogReporter{}
			dispatcherMap["testFlowLog"] = dispatcher
			cr = NewReporter(dispatcherMap, flushInterval, nil, false, true, &NoOpLogOffset{})
			cr.AddAggregator(ca, []string{"testFlowLog"})
			cr.timeNowFn = mt.getMockTime
			Expect(cr.Start()).NotTo(HaveOccurred())

			Expect(cr.Report(muNoConn1Rule1AllowUpdate)).NotTo(HaveOccurred())
			time.Sleep(1 * time.Second)

			Expect(cr.GetAndResetFlowLogsAvgPerMinute()).Should(BeNumerically(">", 0))
		})
	})
})

var _ = Describe("FlowLogAvg reporting for a Reporter", func() {
	var (
		cr         *FlowLogReporter
		ca         *Aggregator
		dispatcher *testFlowLogReporter
	)

	BeforeEach(func() {
		ca = NewAggregator()
		ca.IncludePolicies(true)
		dispatcherMap := map[string]types.Reporter{}
		dispatcher = &testFlowLogReporter{}
		dispatcherMap["testFlowLog"] = dispatcher

		cr = NewReporter(dispatcherMap, flushInterval, nil, false, true, &NoOpLogOffset{})
	})

	It("updateFlowLogsAvg does not cause a data race contention  with resetFlowLogsAvg", func() {
		previousTotal := 10
		newTotal := previousTotal + 5

		cr.updateFlowLogsAvg(previousTotal)

		var timeResetStart time.Time
		var timeResetEnd time.Time

		time.AfterFunc(2*time.Second, func() {
			timeResetStart = time.Now()
			cr.resetFlowLogsAvg()
			timeResetEnd = time.Now()
		})

		// Update is a little after resetFlowLogsAvg because feedupdate has some preprocesssing
		// before it accesses flowAvg
		time.AfterFunc(2*time.Second+10*time.Millisecond, func() {
			cr.updateFlowLogsAvg(newTotal)
		})

		Eventually(func() int { return cr.flowLogAvg.totalFlows }, "6s", "2s").Should(Equal(newTotal))
		Expect(cr.flowLogAvg.lastReportTime.Before(timeResetEnd)).To(BeTrue())
		Expect(cr.flowLogAvg.lastReportTime.After(timeResetStart)).To(BeTrue())
	})
})

type logOffsetMock struct {
	mock.Mock
}

func (m *logOffsetMock) Read() Offsets {
	args := m.Called()
	v, _ := args.Get(0).(Offsets)
	return v
}

func (m *logOffsetMock) IsBehind(offsets Offsets) bool {
	args := m.Called()
	v, _ := args.Get(0).(bool)
	return v
}

func (m *logOffsetMock) GetIncreaseFactor(offsets Offsets) int {
	args := m.Called()
	v, _ := args.Get(0).(int)
	return v
}

type mockDispatcher struct {
	mock.Mock
	iteration    int
	maxIteration int
	collector    chan []*FlowLog
	started      atomic.Bool
}

func newMockDispatcher(maxIterations int) *mockDispatcher {
	return &mockDispatcher{
		collector:    make(chan []*FlowLog),
		maxIteration: maxIterations,
	}
}

func (m *mockDispatcher) Start() error {
	m.started.Store(true)
	return nil
}

func (m *mockDispatcher) Report(logSlice interface{}) error {
	m.iteration++
	log.Infof("Mocked dispatcher was called %d times ", m.iteration)
	logs := logSlice.([]*FlowLog)
	log.Infof("Reporting num=%d of logs", len(logs))
	if m.iteration <= m.maxIteration {
		m.collector <- logs
	}
	return nil
}

func (m *mockDispatcher) Started() bool {
	return m.started.Load()
}

func (m *mockDispatcher) Close() {
	close(m.collector)
}

type mockTicker struct {
	mock.Mock
	tick chan time.Time
	stop chan bool
}

func newMockTicker() *mockTicker {
	return &mockTicker{
		tick: make(chan time.Time),
		stop: make(chan bool),
	}
}

func (m *mockTicker) invokeTick(x time.Time) {
	m.tick <- x
}

func (m *mockTicker) Channel() <-chan time.Time {
	return m.tick
}

func (m *mockTicker) Stop() {
	close(m.tick)
	close(m.stop)
}

func (m *mockTicker) Done() chan bool {
	return m.stop
}

var _ = Describe("FlowLogsReporter should adjust aggregation levels", func() {
	Context("Simulate flow logs being stalled in the pipeline", func() {
		It("increments with 1 level 2 times and decrements to the initial level", func() {
			// mock log offset to mark that the log pipeline is stalled for two iterations and then rectifies
			mockLogOffset := &logOffsetMock{}
			mockLogOffset.On("Read").Return(Offsets{})
			mockLogOffset.On("IsBehind").Return(true).Times(2)
			mockLogOffset.On("IsBehind").Return(false)
			mockLogOffset.On("GetIncreaseFactor").Return(1)

			// mock ticker
			ticker := newMockTicker()
			defer ticker.Stop()

			// mock log dispatcher
			dispatcher := newMockDispatcher(4)
			defer dispatcher.Close()
			dispatchers := map[string]types.Reporter{"mock": dispatcher}

			// add a flow log aggregator  to a reporter with a mocked log offset
			reporter := newReporterTest(dispatchers, nil, false, ticker, mockLogOffset)
			agg := NewAggregator()
			reporter.AddAggregator(agg, []string{"mock"})

			By("Starting the log reporter")
			Expect(reporter.Start()).NotTo(HaveOccurred())
			Eventually(dispatcher.Started).Should(BeTrue(), "dispatcher should have been started")

			expectedLevel := 0
			// Feed reporter with log with two iterations
			for i := 0; i < 2; i++ {
				By(fmt.Sprintf("Feeding metric updates to the reporter as batch %d", i+1))
				err := reporter.Report(muNoConn1Rule1AllowUpdate)
				Expect(err).NotTo(HaveOccurred())
				By("Sending a tick...")
				ticker.invokeTick(time.Now())
				By("Waiting for the collector...")
				var logs []*FlowLog
				Eventually(dispatcher.collector).Should(Receive(&logs))
				Expect(len(logs)).To(Equal(1))
				Expect(int(agg.CurrentAggregationLevel())).To(Equal(expectedLevel + 1))
				expectedLevel++
			}

			// Feed reporter with another log with two iterations
			for i := 2; i < 4; i++ {
				By(fmt.Sprintf("Feeding metric updates to the reporter as batch %d", i+1))
				Expect(reporter.Report(muNoConn1Rule1AllowUpdate)).NotTo(HaveOccurred())
				By("Sending a tick...")
				ticker.invokeTick(time.Now())
				By("Waiting for the collector...")
				var logs []*FlowLog
				Eventually(dispatcher.collector).Should(Receive(&logs))
				Expect(len(logs)).To(Equal(1))
				Expect(agg.CurrentAggregationLevel()).To(Equal(FlowDefault))
			}
		})

		It("keeps the same aggregation level if the pipeline is not stalled", func() {
			mockLogOffset := &logOffsetMock{}
			mockLogOffset.On("Read").Return(Offsets{})
			mockLogOffset.On("IsBehind").Return(false)
			mockLogOffset.On("GetIncreaseFactor").Return(1)

			// mock ticker
			ticker := newMockTicker()
			defer ticker.Stop()

			// mock log dispatcher
			dispatcher := newMockDispatcher(4)
			defer dispatcher.Close()
			dispatchers := map[string]types.Reporter{"mock": dispatcher}

			// add a flow log aggregator  to a reporter with a mocked log offset
			reporter := newReporterTest(dispatchers, nil, false, ticker, mockLogOffset)
			agg := NewAggregator()
			agg.AggregateOver(FlowPrefixName)
			reporter.AddAggregator(agg, []string{"mock"})

			By("Starting the log reporter")
			Expect(reporter.Start()).NotTo(HaveOccurred())
			Eventually(dispatcher.Started).Should(BeTrue(), "dispatcher should have been started")

			expectedLevel := 0
			// Feed reporter with log with four iterations

			for i := 0; i < 4; i++ {
				By(fmt.Sprintf("Feeding metric updates to the reporter as batch %d", i+1))
				Expect(reporter.Report(muNoConn1Rule1AllowUpdate)).NotTo(HaveOccurred())
				ticker.invokeTick(time.Now())
				var logs []*FlowLog
				Eventually(dispatcher.collector).Should(Receive(&logs))
				Expect(len(logs)).To(Equal(1))
				Expect(agg.CurrentAggregationLevel()).To(Equal(FlowPrefixName))
				expectedLevel++
			}
		})

		/* Temporary disable test- https://tigera.atlassian.net/browse/SAAS-647

		It("increases the same aggregation level across multiple dispatchers", func() {
			// mock log offset to mark that the log pipeline is stalled
			var mockLogOffset = &logOffsetMock{}
			mockLogOffset.On("Read").Return(Offsets{})
			mockLogOffset.On("IsBehind").Return(true)
			mockLogOffset.On("GetIncreaseFactor").Return(1)

			// mock ticker
			var ticker = &mockTicker{}
			ticker.tick = make(chan time.Time)
			ticker.stop = make(chan bool)
			defer ticker.Stop()

			// mock log dispatcher
			var cd = newMockDispatcher(1)
			defer cd.Close()
			var ds = map[string]LogReporter{"mock": cd}

			// add two flow log aggregators to a reporter with a mocked log offset
			var cr = newReporterTest(ds, nil, false, ticker, mockLogOffset)
			// first aggregator will have level FlowPrefixName
			var oneAggregator = NewAggregator()
			oneAggregator.AggregateOver(FlowPrefixName)

			// second aggregator will have level FlowDefault
			var anotherAggregator = NewAggregator()
			anotherAggregator.AggregateOver(FlowDefault)
			cr.AddAggregator(oneAggregator, []string{"mock"})
			cr.AddAggregator(anotherAggregator, []string{"mock"})

			By("Starting the log reporter")
			cr.Start()

			// Feed reporter with log with one iterations
			for i := 0; i < 1; i++ {
				By(fmt.Sprintf("Feeding metric updates to the reporter as batch %d", i+1))
				cr.Report(muNoConn1Rule1AllowUpdate)
				ticker.invokeTick(time.Now())
				var logs = <-cd.collector
				Expect(len(logs)).To(Equal(1))
			}

			Expect(oneAggregator.GetCurrentAggregationLevel()).To(Equal(FlowNoDestPorts))
			Expect(anotherAggregator.GetCurrentAggregationLevel()).To(Equal(FlowSourcePort))

		})*/

		It("increases only to the max level", func() {
			mockLogOffset := &logOffsetMock{}
			mockLogOffset.On("Read").Return(Offsets{})
			mockLogOffset.On("IsBehind").Return(true)
			mockLogOffset.On("GetIncreaseFactor").Return(1)

			// mock ticker
			ticker := newMockTicker()
			defer ticker.Stop()

			// mock log dispatcher
			dispatcher := newMockDispatcher(5)
			defer dispatcher.Close()
			dispatchers := map[string]types.Reporter{"mock": dispatcher}

			// add a flow log aggregator  to a reporter with a mocked log offset
			reporter := newReporterTest(dispatchers, nil, false, ticker, mockLogOffset)
			agg := NewAggregator()
			agg.AggregateOver(FlowPrefixName)
			reporter.AddAggregator(agg, []string{"mock"})

			By("Starting the log reporter")
			Expect(reporter.Start()).NotTo(HaveOccurred())
			Eventually(dispatcher.Started).Should(BeTrue(), "dispatcher should have been started")

			// Feed reporter with log with five iterations

			for i := 0; i < 5; i++ {
				By(fmt.Sprintf("Feeding metric updates to the reporter as batch %d", i+1))
				Expect(reporter.Report(muNoConn1Rule1AllowUpdate)).NotTo(HaveOccurred())
				ticker.invokeTick(time.Now())
				var logs []*FlowLog
				Eventually(dispatcher.collector).Should(Receive(&logs))
				Expect(len(logs)).To(Equal(1))
			}

			Expect(agg.CurrentAggregationLevel()).To(Equal(MaxAggregationLevel))
		})
	})
})

func newExpectedFlowLog(t tuple.Tuple, nf, nfs, nfc int, a Action, fr ReporterType, pi, po, bi, bo, tpi, tpo, tbi, tbo int, srcMeta, dstMeta endpoint.Metadata, dstService FlowService, srcLabels, dstLabels map[string]string, fap, fep, fpp, fhp FlowPolicySet, fe FlowExtras, fpi testProcessInfo, tcps testTcpStats) FlowLog {
	return FlowLog{
		FlowMeta: FlowMeta{
			Tuple:      t,
			Action:     a,
			Reporter:   fr,
			SrcMeta:    srcMeta,
			DstMeta:    dstMeta,
			DstService: dstService,
		},
		FlowLabels: FlowLabels{
			SrcLabels: uniquelabels.Make(srcLabels),
			DstLabels: uniquelabels.Make(dstLabels),
		},
		FlowEnforcedPolicySet: fep,
		FlowPendingPolicySet:  fpp,
		FlowTransitPolicySet:  fhp,
		FlowExtras:            fe,
		FlowProcessReportedStats: FlowProcessReportedStats{
			ProcessName:     fpi.processName,
			NumProcessNames: fpi.numProcessNames,
			ProcessID:       fpi.processID,
			NumProcessIDs:   fpi.numProcessIDs,
			ProcessArgs:     fpi.processArgs,
			NumProcessArgs:  fpi.numProcessArgs,
			FlowReportedStats: FlowReportedStats{
				NumFlows:          nf,
				NumFlowsStarted:   nfs,
				NumFlowsCompleted: nfc,
				PacketsIn:         pi,
				PacketsOut:        po,
				BytesIn:           bi,
				BytesOut:          bo,
				TransitPacketsIn:  tpi,
				TransitPacketsOut: tpo,
				TransitBytesIn:    tbi,
				TransitBytesOut:   tbo,
			},
			FlowReportedTCPStats: FlowReportedTCPStats{
				SendCongestionWnd: TCPWnd{
					Mean: tcps.SendCongestionWnd.Mean,
					Min:  tcps.SendCongestionWnd.Min,
				},
				SmoothRtt: TCPRtt{
					Mean: tcps.SmoothRtt.Mean,
					Max:  tcps.SmoothRtt.Max,
				},
				MinRtt: TCPRtt{
					Mean: tcps.MinRtt.Mean,
					Max:  tcps.MinRtt.Max,
				},
				Mss: TCPMss{
					Mean: tcps.Mss.Mean,
					Min:  tcps.Mss.Min,
				},
				LostOut:        tcps.LostOut,
				TotalRetrans:   tcps.TotalRetrans,
				UnrecoveredRTO: tcps.UnrecoveredRTO,
				Count:          tcps.Count,
			},
		},
	}
}
