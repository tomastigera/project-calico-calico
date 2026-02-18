// Copyright (c) 2017-2023 Tigera, Inc. All rights reserved.

package prometheus

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/collector/types/metric"
	"github.com/projectcalico/calico/felix/rules"
)

func TestRuleAggregator(t *testing.T) {
	RegisterTestingT(t)

	// Create a PolicyRulesAggregator
	pa := NewPolicyRulesAggregator(retentionTime, "testHost")

	enforcedIngressRule1 := calc.NewRuleID(v3.KindNetworkPolicy, "tier1", "tier.policy1", "ns1", 0, rules.RuleDirIngress, rules.RuleActionPass)
	enforcedIngressRule3 := calc.NewRuleID(v3.KindNetworkPolicy, "tier4", "tier.policy3", "ns4", 0, rules.RuleDirIngress, rules.RuleActionAllow)
	stagedIngressRule1 := calc.NewRuleID(v3.KindStagedNetworkPolicy, "tier2", "tier.policy1", "ns3", 0, rules.RuleDirIngress, rules.RuleActionPass)
	stagedIngressRule2 := calc.NewRuleID(v3.KindStagedNetworkPolicy, "tier3", "tier.policy2", "ns5", 0, rules.RuleDirIngress, rules.RuleActionAllow)

	mu := metric.Update{
		UpdateType:     metric.UpdateTypeReport,
		Tuple:          tuple1,
		RuleIDs:        []*calc.RuleID{enforcedIngressRule1, stagedIngressRule1, stagedIngressRule2, enforcedIngressRule3},
		PendingRuleIDs: []*calc.RuleID{enforcedIngressRule1, stagedIngressRule1, stagedIngressRule2},
		HasDenyRule:    false,
		IsConnection:   false,
		InMetric: metric.Value{
			DeltaPackets: 1,
			DeltaBytes:   20,
		},
	}

	By("Updating the aggregator with a set of enforced and staged rules")
	pa.OnUpdate(mu)

	Expect(pa.retainedRuleAggMetrics).To(HaveLen(4))
	Expect(pa.retainedRuleAggMetrics).To(HaveKey(RuleAggregateKey{ruleID: *enforcedIngressRule1}))
	Expect(pa.retainedRuleAggMetrics).To(HaveKey(RuleAggregateKey{ruleID: *enforcedIngressRule3}))
	Expect(pa.retainedRuleAggMetrics).To(HaveKey(RuleAggregateKey{ruleID: *stagedIngressRule1}))
	Expect(pa.retainedRuleAggMetrics).To(HaveKey(RuleAggregateKey{ruleID: *stagedIngressRule2}))
}

var _ = Describe("Prometheus Policy Rules PromAggregator verification", func() {
	var pa *PolicyRulesAggregator
	mt := &mockTime{}
	BeforeEach(func() {
		// Create a PolicyRulesAggregator
		pa = NewPolicyRulesAggregator(retentionTime, "testHost")
		registry := prometheus.NewRegistry()
		pa.RegisterMetrics(registry)
		pa.timeNowFn = mt.getMockTime
	})
	AfterEach(func() {
		counterRulePackets.Reset()
		counterRuleBytes.Reset()
	})

	// First set of test handle adding the same rules with two different connections and
	// traffic directions.  Connections should not impact the number of Prometheus metrics,
	// but traffic direction does.
	It("handles the same rule but with two different connections and traffic directions", func() {
		var expectedPacketsInbound, expectedBytesInbound, expectedConnsInbound int
		var expectedPacketsOutbound, expectedBytesOutbound, expectedConnsOutbound int

		By("reporting an initial set of metrics for a rule and traffic dir, but conntrack not yet established")
		pa.OnUpdate(muNoConn1Rule1AllowUpdate)
		expectedPacketsInbound += muNoConn1Rule1AllowUpdate.InMetric.DeltaPackets
		expectedBytesInbound += muNoConn1Rule1AllowUpdate.InMetric.DeltaBytes

		expectRuleAggregateKeys(pa, []RuleAggregateKey{keyRule1Allow})
		expectRuleAggregates(pa, types.TrafficDirInbound, keyRule1Allow, expectedPacketsInbound, expectedBytesInbound, expectedConnsInbound)
		expectRuleAggregates(pa, types.TrafficDirOutbound, keyRule1Allow, expectedPacketsOutbound, expectedBytesOutbound, expectedConnsOutbound)

		By("reporting metrics for the same rule and traffic direction, but conntrack has kicked in")
		pa.OnUpdate(muConn1Rule1AllowUpdate)
		// All counts should have been reset to avoid double counting the stats.
		expectedPacketsInbound += muConn1Rule1AllowUpdate.InMetric.DeltaPackets
		expectedBytesInbound += muConn1Rule1AllowUpdate.InMetric.DeltaBytes
		expectedPacketsOutbound += muConn1Rule1AllowUpdate.OutMetric.DeltaPackets
		expectedBytesOutbound += muConn1Rule1AllowUpdate.OutMetric.DeltaBytes
		expectedConnsInbound += 1

		expectRuleAggregateKeys(pa, []RuleAggregateKey{keyRule1Allow})
		expectRuleAggregates(pa, types.TrafficDirInbound, keyRule1Allow, expectedPacketsInbound, expectedBytesInbound, expectedConnsInbound)
		expectRuleAggregates(pa, types.TrafficDirOutbound, keyRule1Allow, expectedPacketsOutbound, expectedBytesOutbound, expectedConnsOutbound)

		By("reporting metrics for same rule and traffic direction, but a different connection")
		pa.OnUpdate(muConn2Rule1AllowUpdate)
		expectedPacketsInbound += muConn2Rule1AllowUpdate.InMetric.DeltaPackets
		expectedBytesInbound += muConn2Rule1AllowUpdate.InMetric.DeltaBytes
		expectedConnsInbound += 1

		expectRuleAggregateKeys(pa, []RuleAggregateKey{keyRule1Allow})
		expectRuleAggregates(pa, types.TrafficDirInbound, keyRule1Allow, expectedPacketsInbound, expectedBytesInbound, expectedConnsInbound)
		expectRuleAggregates(pa, types.TrafficDirOutbound, keyRule1Allow, expectedPacketsOutbound, expectedBytesOutbound, expectedConnsOutbound)

		By("reporting one of the same metrics")
		pa.OnUpdate(muConn1Rule1AllowUpdate)
		expectedPacketsInbound += muConn1Rule1AllowUpdate.InMetric.DeltaPackets
		expectedBytesInbound += muConn1Rule1AllowUpdate.InMetric.DeltaBytes
		expectedPacketsOutbound += muConn1Rule1AllowUpdate.OutMetric.DeltaPackets
		expectedBytesOutbound += muConn1Rule1AllowUpdate.OutMetric.DeltaBytes
		expectedConnsInbound += 0 // connection is not new.

		expectRuleAggregateKeys(pa, []RuleAggregateKey{keyRule1Allow})
		expectRuleAggregates(pa, types.TrafficDirInbound, keyRule1Allow, expectedPacketsInbound, expectedBytesInbound, expectedConnsInbound)
		expectRuleAggregates(pa, types.TrafficDirOutbound, keyRule1Allow, expectedPacketsOutbound, expectedBytesOutbound, expectedConnsOutbound)

		By("expiring one of the metric updates for Rule1 Inbound and one for Outbound")
		pa.OnUpdate(muConn1Rule1AllowExpire)
		expectedPacketsInbound += muConn1Rule1AllowExpire.InMetric.DeltaPackets
		expectedBytesInbound += muConn1Rule1AllowExpire.InMetric.DeltaBytes
		expectedPacketsOutbound += muConn1Rule1AllowExpire.OutMetric.DeltaPackets
		expectedBytesOutbound += muConn1Rule1AllowExpire.OutMetric.DeltaBytes
		// Adjust the clock, but not past the retention period, the outbound rule aggregate should
		// not yet be expunged.
		mt.incMockTime(retentionTime / 2)
		pa.CheckRetainedMetrics(mt.getMockTime())

		expectRuleAggregateKeys(pa, []RuleAggregateKey{keyRule1Allow})
		expectRuleAggregates(pa, types.TrafficDirInbound, keyRule1Allow, expectedPacketsInbound, expectedBytesInbound, expectedConnsInbound)
		expectRuleAggregates(pa, types.TrafficDirOutbound, keyRule1Allow, expectedPacketsOutbound, expectedBytesOutbound, expectedConnsOutbound)

		By("incrementing time by the retention time - outbound rule should be expunged")
		mt.incMockTime(retentionTime)
		pa.CheckRetainedMetrics(mt.getMockTime())
		expectRuleAggregateKeys(pa, []RuleAggregateKey{keyRule1Allow})

		By("expiring the remaining Rule1 Inbound metric")
		pa.OnUpdate(muConn2Rule1AllowExpire)
		expectedPacketsInbound += muConn2Rule1AllowExpire.InMetric.DeltaPackets
		expectedBytesInbound += muConn2Rule1AllowExpire.InMetric.DeltaBytes
		// Adjust the clock, but not past the retention period, the inbound rule aggregate should
		// not yet be expunged.
		mt.incMockTime(retentionTime / 2)
		pa.CheckRetainedMetrics(mt.getMockTime())

		expectRuleAggregateKeys(pa, []RuleAggregateKey{keyRule1Allow})
		expectRuleAggregates(pa, types.TrafficDirInbound, keyRule1Allow, expectedPacketsInbound, expectedBytesInbound, expectedConnsInbound)

		By("incrementing time by the retention time - inbound rule should be expunged")
		mt.incMockTime(retentionTime)
		pa.CheckRetainedMetrics(mt.getMockTime())

		expectRuleAggregateKeys(pa, []RuleAggregateKey{})
	})
})

func expectRuleAggregateKeys(pa *PolicyRulesAggregator, keys []RuleAggregateKey) {
	By("checking for the correct number of aggregated statistics")
	Expect(pa.ruleAggStats).To(HaveLen(len(keys)))
	for _, key := range keys {
		Expect(pa.ruleAggStats).To(HaveKey(key))
	}
}

func expectRuleAggregates(
	pa *PolicyRulesAggregator, dir types.TrafficDirection, k RuleAggregateKey,
	expectedPackets int, expectedBytes int, expectedConnections int,
) {
	By("checking for the correct " + dir.String() + " packet count")
	Expect(func() int {
		value, ok := pa.ruleAggStats[k]
		if !ok {
			return -1
		}
		return getMetricCount(getDirectionalPackets(dir, value))
	}()).To(Equal(expectedPackets))

	By("checking for the correct " + dir.String() + " byte count")
	Expect(func() int {
		value, ok := pa.ruleAggStats[k]
		if !ok {
			return -1
		}
		return getMetricCount(getDirectionalBytes(dir, value))
	}()).To(Equal(expectedBytes))

	if types.RuleDirToTrafficDir(k.ruleID.Direction) != dir {
		// Don't check connections if rules doesn't match direction.
		return
	}

	By("checking for the correct number of connections")
	Expect(func() int {
		value, ok := pa.ruleAggStats[k]
		if !ok {
			return -1
		}
		return getMetricCount(value.numConnections)
	}()).To(Equal(expectedConnections))
}
