// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package prometheus

import (
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/collector/types/metric"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/collector/utils"
	"github.com/projectcalico/calico/felix/rules"
)

var (
	srcPort1 = 54123
	srcPort2 = 54124
	srcPort3 = 54125
	srcPort4 = 54125
	srcPort5 = 54126
	srcPort6 = 54127
)

var (
	proto_tcp    = 6
	dstPort      = 80
	localIp1Str  = "10.0.0.1"
	localIp1     = utils.IpStrTo16Byte(localIp1Str)
	localIp2Str  = "10.0.0.2"
	localIp2     = utils.IpStrTo16Byte(localIp2Str)
	remoteIp1Str = "20.0.0.1"
	remoteIp1    = utils.IpStrTo16Byte(remoteIp1Str)
	remoteIp2Str = "20.0.0.2"
	remoteIp2    = utils.IpStrTo16Byte(remoteIp2Str)
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

// Common RuleID definitions
var (
	ingressRule1Allow = calc.NewRuleID(
		v3.KindGlobalNetworkPolicy,
		"default",
		"policy1",
		"",
		0,
		rules.RuleDirIngress,
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

	ingressRule3Pass = calc.NewRuleID(
		v3.KindGlobalNetworkPolicy,
		"bar",
		"policy3",
		"",
		0,
		rules.RuleDirIngress,
		rules.RuleActionPass,
	)

	egressRule3Pass = calc.NewRuleID(
		v3.KindGlobalNetworkPolicy,
		"bar",
		"policy3",
		"",
		0,
		rules.RuleDirEgress,
		rules.RuleActionPass,
	)
)

// Common Update definitions
var (
	// Metric update without a connection (ingress stats match those of muConn1Rule1AllowUpdate).
	muNoConn1Rule1AllowUpdate = metric.Update{
		UpdateType:     metric.UpdateTypeReport,
		Tuple:          tuple1,
		RuleIDs:        []*calc.RuleID{ingressRule1Allow},
		PendingRuleIDs: []*calc.RuleID{ingressRule1Allow},
		HasDenyRule:    false,
		IsConnection:   false,
		InMetric: metric.Value{
			DeltaPackets: 1,
			DeltaBytes:   20,
		},
	}

	// Identical rule/direction connections with differing tuples
	muConn1Rule1AllowUpdate = metric.Update{
		UpdateType:     metric.UpdateTypeReport,
		Tuple:          tuple1,
		RuleIDs:        []*calc.RuleID{ingressRule1Allow},
		PendingRuleIDs: []*calc.RuleID{ingressRule1Allow},
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

	muConn1Rule1AllowExpire = metric.Update{
		UpdateType:     metric.UpdateTypeExpire,
		Tuple:          tuple1,
		RuleIDs:        []*calc.RuleID{ingressRule1Allow},
		PendingRuleIDs: []*calc.RuleID{ingressRule1Allow},
		HasDenyRule:    false,
		IsConnection:   true,
		InMetric: metric.Value{
			DeltaPackets: 4,
			DeltaBytes:   44,
		},
		OutMetric: metric.Value{
			DeltaPackets: 3,
			DeltaBytes:   24,
		},
	}

	muNoConn1Rule2DenyUpdate = metric.Update{
		UpdateType:     metric.UpdateTypeReport,
		Tuple:          tuple1,
		RuleIDs:        []*calc.RuleID{egressRule2Deny},
		PendingRuleIDs: []*calc.RuleID{egressRule2Deny},
		HasDenyRule:    true,
		IsConnection:   false,
		InMetric: metric.Value{
			DeltaPackets: 2,
			DeltaBytes:   40,
		},
	}

	muConn2Rule1AllowUpdate = metric.Update{
		UpdateType:     metric.UpdateTypeReport,
		Tuple:          tuple2,
		RuleIDs:        []*calc.RuleID{ingressRule1Allow},
		PendingRuleIDs: []*calc.RuleID{ingressRule1Allow},
		HasDenyRule:    false,
		IsConnection:   true,
		InMetric: metric.Value{
			DeltaPackets: 7,
			DeltaBytes:   77,
		},
	}

	muConn2Rule1AllowExpire = metric.Update{
		UpdateType:     metric.UpdateTypeExpire,
		Tuple:          tuple2,
		RuleIDs:        []*calc.RuleID{ingressRule1Allow},
		PendingRuleIDs: []*calc.RuleID{ingressRule1Allow},
		HasDenyRule:    false,
		IsConnection:   true,
		InMetric: metric.Value{
			DeltaPackets: 8,
			DeltaBytes:   88,
		},
	}

	muNoConn3Rule2DenyUpdate = metric.Update{
		UpdateType:     metric.UpdateTypeReport,
		Tuple:          tuple3,
		RuleIDs:        []*calc.RuleID{egressRule2Deny},
		PendingRuleIDs: []*calc.RuleID{egressRule2Deny},
		HasDenyRule:    true,
		IsConnection:   false,
		InMetric: metric.Value{
			DeltaPackets: 2,
			DeltaBytes:   40,
		},
	}

	muNoConn3Rule2DenyExpire = metric.Update{
		UpdateType:     metric.UpdateTypeExpire,
		Tuple:          tuple3,
		RuleIDs:        []*calc.RuleID{egressRule2Deny},
		PendingRuleIDs: []*calc.RuleID{egressRule2Deny},
		HasDenyRule:    true,
		IsConnection:   false,
		InMetric: metric.Value{
			DeltaPackets: 0,
			DeltaBytes:   0,
		},
	}

	muConn1Rule3AllowUpdate = metric.Update{
		UpdateType:     metric.UpdateTypeReport,
		Tuple:          tuple1,
		RuleIDs:        []*calc.RuleID{ingressRule3Pass, ingressRule1Allow},
		PendingRuleIDs: []*calc.RuleID{ingressRule3Pass, ingressRule1Allow},
		HasDenyRule:    false,
		IsConnection:   true,
		InMetric: metric.Value{
			DeltaPackets: 2,
			DeltaBytes:   22,
		},
		OutMetric: metric.Value{
			DeltaPackets: 3,
			DeltaBytes:   33,
		},
	}

	muConn1Rule3AllowExpire = metric.Update{
		UpdateType:     metric.UpdateTypeExpire,
		Tuple:          tuple1,
		RuleIDs:        []*calc.RuleID{ingressRule3Pass, ingressRule1Allow},
		PendingRuleIDs: []*calc.RuleID{ingressRule3Pass, ingressRule1Allow},
		HasDenyRule:    false,
		IsConnection:   true,
		InMetric: metric.Value{
			DeltaPackets: 4,
			DeltaBytes:   44,
		},
		OutMetric: metric.Value{
			DeltaPackets: 3,
			DeltaBytes:   24,
		},
	}

	muNoConn1Rule4DenyUpdate = metric.Update{
		UpdateType:     metric.UpdateTypeReport,
		Tuple:          tuple1,
		RuleIDs:        []*calc.RuleID{egressRule3Pass, egressRule2Deny},
		PendingRuleIDs: []*calc.RuleID{egressRule3Pass, egressRule2Deny},
		HasDenyRule:    true,
		IsConnection:   false,
		InMetric: metric.Value{
			DeltaPackets: 2,
			DeltaBytes:   40,
		},
	}

	muNoConn1Rule4DenyExpire = metric.Update{
		UpdateType:     metric.UpdateTypeExpire,
		Tuple:          tuple1,
		RuleIDs:        []*calc.RuleID{egressRule3Pass, egressRule2Deny},
		PendingRuleIDs: []*calc.RuleID{egressRule3Pass, egressRule2Deny},
		HasDenyRule:    true,
		IsConnection:   false,
		InMetric: metric.Value{
			DeltaPackets: 0,
			DeltaBytes:   0,
		},
	}

	muConn1Rule1HTTPReqAllowUpdate = metric.Update{
		UpdateType:     metric.UpdateTypeReport,
		Tuple:          tuple1,
		RuleIDs:        []*calc.RuleID{ingressRule1Allow},
		PendingRuleIDs: []*calc.RuleID{ingressRule1Allow},
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
)

// Common RuleAggregateKey definitions
var (
	keyRule1Allow = RuleAggregateKey{
		ruleID: *ingressRule1Allow,
	}

	keyRule2Deny = RuleAggregateKey{
		ruleID: *egressRule2Deny,
	}

	keyRule3Pass = RuleAggregateKey{
		ruleID: *ingressRule3Pass,
	}

	keyEgressRule3Pass = RuleAggregateKey{
		ruleID: *egressRule3Pass,
	}
)

var (
	retentionTime = 500 * time.Millisecond
	expectTimeout = 4 * retentionTime
)

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

func getMetricCount(m prometheus.Counter) int {
	// The get the actual number stored inside a prometheus metric we need to convert
	// into protobuf format which then has publicly available accessors.
	if m == nil {
		return -1
	}
	dtoMetric := &dto.Metric{}
	if err := m.Write(dtoMetric); err != nil {
		panic(err)
	}
	return int(*dtoMetric.Counter.Value)
}

func getDirectionalPackets(dir types.TrafficDirection, v *RuleAggregateValue) (ret prometheus.Counter) {
	switch dir {
	case types.TrafficDirInbound:
		ret = v.inPackets
	case types.TrafficDirOutbound:
		ret = v.outPackets
	}
	return
}

func getDirectionalBytes(dir types.TrafficDirection, v *RuleAggregateValue) (ret prometheus.Counter) {
	switch dir {
	case types.TrafficDirInbound:
		ret = v.inBytes
	case types.TrafficDirOutbound:
		ret = v.outBytes
	}
	return
}

func eventuallyExpectRuleAggregateKeys(pa *PolicyRulesAggregator, keys []RuleAggregateKey) {
	Eventually(pa.ruleAggStats, expectTimeout).Should(HaveLen(len(keys)))
	Consistently(pa.ruleAggStats, expectTimeout).Should(HaveLen(len(keys)))
	for _, key := range keys {
		Expect(pa.ruleAggStats).To(HaveKey(key))
	}
}

func eventuallyExpectRuleAggregates(
	pa *PolicyRulesAggregator, dir types.TrafficDirection, k RuleAggregateKey,
	expectedPackets int, expectedBytes int, expectedConnections int,
) {
	Eventually(func() int {
		value, ok := pa.ruleAggStats[k]
		if !ok {
			return -1
		}
		return getMetricCount(getDirectionalPackets(dir, value))
	}, expectTimeout).Should(Equal(expectedPackets))
	Consistently(func() int {
		value, ok := pa.ruleAggStats[k]
		if !ok {
			return -1
		}
		return getMetricCount(getDirectionalPackets(dir, value))
	}, expectTimeout).Should(Equal(expectedPackets))

	Eventually(func() int {
		value, ok := pa.ruleAggStats[k]
		if !ok {
			return -1
		}
		return getMetricCount(getDirectionalBytes(dir, value))
	}, expectTimeout).Should(Equal(expectedBytes))
	Consistently(func() int {
		value, ok := pa.ruleAggStats[k]
		if !ok {
			return -1
		}
		return getMetricCount(getDirectionalBytes(dir, value))
	}, expectTimeout).Should(Equal(expectedBytes))

	if types.RuleDirToTrafficDir(k.ruleID.Direction) != dir {
		// Don't check connections if rules doesn't match direction.
		return
	}
	Eventually(func() int {
		value, ok := pa.ruleAggStats[k]
		if !ok {
			return -1
		}
		return getMetricCount(value.numConnections)
	}, expectTimeout).Should(Equal(expectedConnections))
	Consistently(func() int {
		value, ok := pa.ruleAggStats[k]
		if !ok {
			return -1
		}
		return getMetricCount(value.numConnections)
	}, expectTimeout).Should(Equal(expectedConnections))
}

var _ = Describe("Prometheus Reporter verification", func() {
	var (
		pr *PrometheusReporter
		pa *PolicyRulesAggregator
	)
	mt := &mockTime{}
	BeforeEach(func() {
		// Create a PrometheusReporter and start the reporter without starting the HTTP service.
		pr = NewReporter(prometheus.NewRegistry(), 0, retentionTime, "", "", "")
		pa = NewPolicyRulesAggregator(retentionTime, "testHost")
		pr.timeNowFn = mt.getMockTime
		pa.timeNowFn = mt.getMockTime
		pr.AddAggregator(pa)
		go pr.startReporter()
	})
	AfterEach(func() {
		counterRulePackets.Reset()
		counterRuleBytes.Reset()
		counterRuleConns.Reset()
	})
	// First set of test handle adding the same rules with two different connections and
	// traffic directions.  Connections should not impact the number of Prometheus metrics,
	// but traffic direction does.
	It("handles the same rule but with two different connections and traffic directions", func() {
		var expectedPacketsInbound, expectedBytesInbound, expectedConnsInbound int
		var expectedPacketsOutbound, expectedBytesOutbound, expectedConnsOutbound int

		By("reporting two separate metrics for same rule and traffic direction, but different connections")
		Expect(pr.Report(muConn1Rule1AllowUpdate)).NotTo(HaveOccurred())
		expectedPacketsInbound += muConn1Rule1AllowUpdate.InMetric.DeltaPackets
		expectedBytesInbound += muConn1Rule1AllowUpdate.InMetric.DeltaBytes
		expectedPacketsOutbound += muConn1Rule1AllowUpdate.OutMetric.DeltaPackets
		expectedBytesOutbound += muConn1Rule1AllowUpdate.OutMetric.DeltaBytes
		expectedConnsInbound += 1
		Expect(pr.Report(muConn2Rule1AllowUpdate)).NotTo(HaveOccurred())
		expectedPacketsInbound += muConn2Rule1AllowUpdate.InMetric.DeltaPackets
		expectedBytesInbound += muConn2Rule1AllowUpdate.InMetric.DeltaBytes
		expectedConnsInbound += 1

		By("checking for the correct number of aggregated statistics")
		eventuallyExpectRuleAggregateKeys(pa, []RuleAggregateKey{keyRule1Allow})

		By("checking for the correct packet and byte counts")
		eventuallyExpectRuleAggregates(pa, types.TrafficDirInbound, keyRule1Allow, expectedPacketsInbound, expectedBytesInbound, expectedConnsInbound)
		eventuallyExpectRuleAggregates(pa, types.TrafficDirOutbound, keyRule1Allow, expectedPacketsOutbound, expectedBytesOutbound, expectedConnsOutbound)

		By("reporting one of the same metrics")
		Expect(pr.Report(muConn1Rule1AllowUpdate)).NotTo(HaveOccurred())
		expectedPacketsInbound += muConn1Rule1AllowUpdate.InMetric.DeltaPackets
		expectedBytesInbound += muConn1Rule1AllowUpdate.InMetric.DeltaBytes
		expectedPacketsOutbound += muConn1Rule1AllowUpdate.OutMetric.DeltaPackets
		expectedBytesOutbound += muConn1Rule1AllowUpdate.OutMetric.DeltaBytes
		expectedConnsInbound += 0 // connection already registered

		By("checking for the correct number of aggregated statistics")
		eventuallyExpectRuleAggregateKeys(pa, []RuleAggregateKey{keyRule1Allow})

		By("checking for the correct packet and byte counts")
		eventuallyExpectRuleAggregates(pa, types.TrafficDirInbound, keyRule1Allow, expectedPacketsInbound, expectedBytesInbound, expectedConnsInbound)
		eventuallyExpectRuleAggregates(pa, types.TrafficDirOutbound, keyRule1Allow, expectedPacketsOutbound, expectedBytesOutbound, expectedConnsOutbound)

		By("expiring one of the metric updates for Rule1 Inbound and one for Outbound")
		Expect(pr.Report(muConn1Rule1AllowExpire)).NotTo(HaveOccurred())
		expectedPacketsInbound += muConn1Rule1AllowExpire.InMetric.DeltaPackets
		expectedBytesInbound += muConn1Rule1AllowExpire.InMetric.DeltaBytes
		expectedPacketsOutbound += muConn1Rule1AllowExpire.OutMetric.DeltaPackets
		expectedBytesOutbound += muConn1Rule1AllowExpire.OutMetric.DeltaBytes
		// Adjust the clock, but not past the retention period, the outbound rule aggregate should
		// not yet be expunged.
		mt.incMockTime(retentionTime / 2)

		By("checking for the correct number of aggregated statistics: outbound rule should be present for retention time")
		eventuallyExpectRuleAggregateKeys(pa, []RuleAggregateKey{keyRule1Allow})

		By("checking for the correct packet and byte counts")
		eventuallyExpectRuleAggregates(pa, types.TrafficDirInbound, keyRule1Allow, expectedPacketsInbound, expectedBytesInbound, expectedConnsInbound)
		eventuallyExpectRuleAggregates(pa, types.TrafficDirOutbound, keyRule1Allow, expectedPacketsOutbound, expectedBytesOutbound, expectedConnsOutbound)

		By("incrementing time by the retention time - outbound rule should be expunged")
		mt.incMockTime(retentionTime)
		eventuallyExpectRuleAggregateKeys(pa, []RuleAggregateKey{keyRule1Allow})

		By("expiring the remaining Rule1 Inbound metric")
		Expect(pr.Report(muConn2Rule1AllowExpire)).NotTo(HaveOccurred())
		expectedPacketsInbound += muConn2Rule1AllowExpire.InMetric.DeltaPackets
		expectedBytesInbound += muConn2Rule1AllowExpire.InMetric.DeltaBytes
		// Adjust the clock, but not past the retention period, the inbound rule aggregate should
		// not yet be expunged.
		mt.incMockTime(retentionTime / 2)

		By("checking for the correct number of aggregated statistics: inbound rule should be present for retention time")
		eventuallyExpectRuleAggregateKeys(pa, []RuleAggregateKey{keyRule1Allow})

		By("checking for the correct packet and byte counts")
		eventuallyExpectRuleAggregates(pa, types.TrafficDirInbound, keyRule1Allow, expectedPacketsInbound, expectedBytesInbound, expectedConnsInbound)

		By("incrementing time by the retention time - inbound rule should be expunged")
		mt.incMockTime(retentionTime)
		eventuallyExpectRuleAggregateKeys(pa, []RuleAggregateKey{})
	})
	It("handles multiple rules within the metric update and in both directions", func() {
		var expectedPacketsInbound, expectedBytesInbound, expectedConnsInbound, expectedPassConns int
		var expectedPacketsOutbound, expectedBytesOutbound, expectedConnsOutbound int

		By("reporting ingress direction metrics with multiple rules")
		Expect(pr.Report(muConn1Rule3AllowUpdate)).NotTo(HaveOccurred())
		expectedPacketsInbound += muConn1Rule3AllowUpdate.InMetric.DeltaPackets
		expectedBytesInbound += muConn1Rule3AllowUpdate.InMetric.DeltaBytes
		expectedPacketsOutbound += muConn1Rule3AllowUpdate.OutMetric.DeltaPackets
		expectedBytesOutbound += muConn1Rule3AllowUpdate.OutMetric.DeltaBytes
		expectedConnsInbound += 1
		By("checking for the correct number of aggregated statistics")
		eventuallyExpectRuleAggregateKeys(pa, []RuleAggregateKey{keyRule3Pass, keyRule1Allow})

		By("checking for the correct packet and byte counts")
		eventuallyExpectRuleAggregates(pa, types.TrafficDirInbound, keyRule3Pass, expectedPacketsInbound, expectedBytesInbound, expectedPassConns)
		eventuallyExpectRuleAggregates(pa, types.TrafficDirOutbound, keyRule3Pass, expectedPacketsOutbound, expectedBytesOutbound, expectedPassConns)
		eventuallyExpectRuleAggregates(pa, types.TrafficDirInbound, keyRule1Allow, expectedPacketsInbound, expectedBytesInbound, expectedConnsInbound)
		eventuallyExpectRuleAggregates(pa, types.TrafficDirOutbound, keyRule1Allow, expectedPacketsOutbound, expectedBytesOutbound, expectedConnsOutbound)

		By("expiring one of the metric updates for Rule1 Inbound and one for Outbound")
		Expect(pr.Report(muConn1Rule3AllowExpire)).NotTo(HaveOccurred())
		expectedPacketsInbound += muConn1Rule3AllowExpire.InMetric.DeltaPackets
		expectedBytesInbound += muConn1Rule3AllowExpire.InMetric.DeltaBytes
		expectedPacketsOutbound += muConn1Rule3AllowExpire.OutMetric.DeltaPackets
		expectedBytesOutbound += muConn1Rule3AllowExpire.OutMetric.DeltaBytes
		// Adjust the clock, but not past the retention period, the outbound rule aggregate should
		// not yet be expunged.
		mt.incMockTime(retentionTime / 2)

		By("checking for the correct number of aggregated statistics: outbound rule should be present for retention time")
		eventuallyExpectRuleAggregateKeys(pa, []RuleAggregateKey{keyRule3Pass, keyRule1Allow})

		By("checking for the correct packet and byte counts")
		eventuallyExpectRuleAggregates(pa, types.TrafficDirInbound, keyRule3Pass, expectedPacketsInbound, expectedBytesInbound, expectedPassConns)
		eventuallyExpectRuleAggregates(pa, types.TrafficDirOutbound, keyRule3Pass, expectedPacketsOutbound, expectedBytesOutbound, expectedPassConns)
		eventuallyExpectRuleAggregates(pa, types.TrafficDirInbound, keyRule1Allow, expectedPacketsInbound, expectedBytesInbound, expectedConnsInbound)
		eventuallyExpectRuleAggregates(pa, types.TrafficDirOutbound, keyRule1Allow, expectedPacketsOutbound, expectedBytesOutbound, expectedConnsOutbound)
	})
	It("handles multiple rules within the metric update which is a deny", func() {
		var expectedPacketsInbound, expectedBytesInbound, expectedPassConns int
		var expectedPacketsOutbound, expectedBytesOutbound int

		By("reporting ingress direction metrics with multiple rules")
		Expect(pr.Report(muNoConn1Rule4DenyUpdate)).NotTo(HaveOccurred())
		expectedPacketsInbound += muNoConn1Rule4DenyUpdate.InMetric.DeltaPackets
		expectedBytesInbound += muNoConn1Rule4DenyUpdate.InMetric.DeltaBytes
		expectedPacketsOutbound += muNoConn1Rule4DenyUpdate.OutMetric.DeltaPackets
		expectedBytesOutbound += muNoConn1Rule4DenyUpdate.OutMetric.DeltaBytes

		By("checking for the correct number of aggregated statistics")
		eventuallyExpectRuleAggregateKeys(pa, []RuleAggregateKey{keyEgressRule3Pass, keyRule2Deny})

		By("checking for the correct packet and byte counts")
		eventuallyExpectRuleAggregates(pa, types.TrafficDirInbound, keyEgressRule3Pass, expectedPacketsInbound, expectedBytesInbound, expectedPassConns)
		eventuallyExpectRuleAggregates(pa, types.TrafficDirOutbound, keyEgressRule3Pass, expectedPacketsOutbound, expectedBytesOutbound, expectedPassConns)
		eventuallyExpectRuleAggregates(pa, types.TrafficDirInbound, keyEgressRule3Pass, expectedPacketsInbound, expectedBytesInbound, expectedPassConns)
		eventuallyExpectRuleAggregates(pa, types.TrafficDirOutbound, keyEgressRule3Pass, expectedPacketsOutbound, expectedBytesOutbound, expectedPassConns)

		By("expiring the deny metric")
		Expect(pr.Report(muNoConn1Rule4DenyExpire)).NotTo(HaveOccurred())
		// no counters should change.
		mt.incMockTime(retentionTime / 2)
		By("checking for the correct number of aggregated statistics: ")
		eventuallyExpectRuleAggregateKeys(pa, []RuleAggregateKey{keyEgressRule3Pass, keyRule2Deny})
	})
})
