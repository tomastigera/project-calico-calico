// Copyright (c) 2018-2023 Tigera, Inc. All rights reserved.

package prometheus

import (
	"time"

	"github.com/gavv/monotime"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/collector/types/metric"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// Calico Enterprise Metrics
var (
	LABEL_TIER        = "tier"
	LABEL_NAMESPACE   = "namespace"
	LABEL_POLICY      = "policy"
	LABEL_KIND        = "kind"
	LABEL_RULE_IDX    = "rule_index"
	LABEL_ACTION      = "action"
	LABEL_TRAFFIC_DIR = "traffic_direction"
	LABEL_RULE_DIR    = "rule_direction"
	LABEL_INSTANCE    = "instance"

	counterRulePackets = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cnx_policy_rule_packets",
			Help: "Total number of packets handled by Calico Enterprise policy rules.",
		},
		[]string{LABEL_ACTION, LABEL_TIER, LABEL_NAMESPACE, LABEL_POLICY, LABEL_KIND, LABEL_RULE_DIR, LABEL_RULE_IDX, LABEL_TRAFFIC_DIR, LABEL_INSTANCE},
	)
	counterRuleBytes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cnx_policy_rule_bytes",
			Help: "Total number of bytes handled by Calico Enterprise policy rules.",
		},
		[]string{LABEL_ACTION, LABEL_TIER, LABEL_NAMESPACE, LABEL_POLICY, LABEL_KIND, LABEL_RULE_DIR, LABEL_RULE_IDX, LABEL_TRAFFIC_DIR, LABEL_INSTANCE},
	)
	counterRuleConns = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cnx_policy_rule_connections",
			Help: "Total number of connections handled by Calico Enterprise policy rules.",
		},
		[]string{LABEL_TIER, LABEL_NAMESPACE, LABEL_POLICY, LABEL_KIND, LABEL_RULE_DIR, LABEL_RULE_IDX, LABEL_TRAFFIC_DIR, LABEL_INSTANCE},
	)
)

// RuleAggregateKey is a hashable key identifying a rule aggregation key.
type RuleAggregateKey struct {
	ruleID calc.RuleID
}

// PacketByteLabels returns the Prometheus packet/byte counter labels associated
// with a specific rule and traffic direction.
func (k *RuleAggregateKey) PacketByteLabels(trafficDir types.TrafficDirection, felixHostname string) prometheus.Labels {
	return prometheus.Labels{
		LABEL_ACTION:      k.ruleID.ActionString(),
		LABEL_TIER:        k.ruleID.TierString(),
		LABEL_NAMESPACE:   k.ruleID.NamespaceString(),
		LABEL_POLICY:      k.ruleID.NameString(),
		LABEL_KIND:        k.ruleID.Kind,
		LABEL_RULE_DIR:    k.ruleID.DirectionString(),
		LABEL_RULE_IDX:    k.ruleID.IndexStr,
		LABEL_TRAFFIC_DIR: trafficDir.String(),
		LABEL_INSTANCE:    felixHostname,
	}
}

// ConnectionLabels returns the Prometheus connection gauge labels associated
// with a specific rule and traffic direction.
func (k *RuleAggregateKey) ConnectionLabels(felixHostname string) prometheus.Labels {
	return prometheus.Labels{
		LABEL_TIER:        k.ruleID.TierString(),
		LABEL_NAMESPACE:   k.ruleID.NamespaceString(),
		LABEL_POLICY:      k.ruleID.NameString(),
		LABEL_KIND:        k.ruleID.Kind,
		LABEL_RULE_DIR:    k.ruleID.DirectionString(),
		LABEL_RULE_IDX:    k.ruleID.IndexStr,
		LABEL_TRAFFIC_DIR: types.RuleDirToTrafficDir(k.ruleID.Direction).String(),
		LABEL_INSTANCE:    felixHostname,
	}
}

type RuleAggregateValue struct {
	inPackets      prometheus.Counter
	inBytes        prometheus.Counter
	outPackets     prometheus.Counter
	outBytes       prometheus.Counter
	numConnections prometheus.Counter
	tuples         tuple.Set
}

func newRuleAggregateValue(key RuleAggregateKey, felixHostname string) *RuleAggregateValue {
	// Initialize all the counters. Although we may not strictly need reverse counters if the rule has
	// not resulted in any connections, we create the counters anyways - the rule stats are expected to
	// be semi-long lived.
	cLabels := key.ConnectionLabels(felixHostname)
	pbInLabels := key.PacketByteLabels(types.TrafficDirInbound, felixHostname)
	pbOutLabels := key.PacketByteLabels(types.TrafficDirOutbound, felixHostname)
	return &RuleAggregateValue{
		tuples:         tuple.NewSet(),
		inPackets:      counterRulePackets.With(pbInLabels),
		inBytes:        counterRuleBytes.With(pbInLabels),
		outPackets:     counterRulePackets.With(pbOutLabels),
		outBytes:       counterRuleBytes.With(pbOutLabels),
		numConnections: counterRuleConns.With(cLabels),
	}
}

// PolicyRulesAggregator aggregates directional packets, bytes, and connections statistics in prometheus metrics.
type PolicyRulesAggregator struct {
	retentionTime time.Duration
	felixHostname string

	// Allow the time function to be mocked for test purposes.
	timeNowFn func() time.Duration

	// Stats are aggregated by rule.
	ruleAggStats           map[RuleAggregateKey]*RuleAggregateValue
	retainedRuleAggMetrics map[RuleAggregateKey]time.Duration
}

func NewPolicyRulesAggregator(rTime time.Duration, felixHostname string) *PolicyRulesAggregator {
	return &PolicyRulesAggregator{
		ruleAggStats:           make(map[RuleAggregateKey]*RuleAggregateValue),
		retainedRuleAggMetrics: make(map[RuleAggregateKey]time.Duration),
		timeNowFn:              monotime.Now,
		retentionTime:          rTime,
		felixHostname:          felixHostname,
	}
}

func (pa *PolicyRulesAggregator) RegisterMetrics(registry *prometheus.Registry) {
	registry.MustRegister(counterRuleBytes)
	registry.MustRegister(counterRulePackets)
	registry.MustRegister(counterRuleConns)
}

// OnUpdate handles reporting and expiration of Rule-aggregated metrics.
// When updateType is set to UpdateTypeReport handleRuleMetric, increments our counters
// from the metric update and ensures the metric will expire if there are no associated
// connections and no activity within the retention period.
// When updateType is set to UpdateTypeExpire, it is actually similar to UpdateTypeReport,
// it increments our counters from the metric update, removes any connection associated
// with the metric and ensures the metric will expire if there are no associated connections
// and no activity within the retention period. Unlike reportMetric, if there is no cached
// entry for this metric one is not created and therefore the metric will not be reported.
//
// The rule metrics associated to enforced policies are updates incoming from the dataplane
// and the rule metrics associated to staged policies are updates incoming from the policy
// evaluator.
func (pa *PolicyRulesAggregator) OnUpdate(mu metric.Update) {
	enforcedRuleIDs := getEnforcedPolicyRuleIDs(mu)
	for _, rID := range enforcedRuleIDs {
		pa.updateRuleKey(RuleAggregateKey{ruleID: rID}, mu)
	}
	stagedRuleIDs := getStagedPolicyRuleIDs(mu)
	for _, rID := range stagedRuleIDs {
		pa.updateRuleKey(RuleAggregateKey{ruleID: rID}, mu)
	}
}

func (pa *PolicyRulesAggregator) updateRuleKey(key RuleAggregateKey, mu metric.Update) {
	value, ok := pa.ruleAggStats[key]
	if !ok {
		value = newRuleAggregateValue(key, pa.felixHostname)
		pa.ruleAggStats[key] = value
	}

	// Increment the packet counters if non-zero.
	if mu.InMetric.DeltaPackets != 0 && mu.InMetric.DeltaBytes != 0 {
		value.inPackets.Add(float64(mu.InMetric.DeltaPackets))
		value.inBytes.Add(float64(mu.InMetric.DeltaBytes))
	}
	if mu.OutMetric.DeltaPackets != 0 && mu.OutMetric.DeltaBytes != 0 {
		value.outPackets.Add(float64(mu.OutMetric.DeltaPackets))
		value.outBytes.Add(float64(mu.OutMetric.DeltaBytes))
	}

	// If this is an new connection (and we aren't expiring the stats), add to our
	// connections tuple and update our connections counter, otherwise make sure
	// it is removed.
	if mu.IsConnection && mu.UpdateType == metric.UpdateTypeReport {
		if !value.tuples.Contains(mu.Tuple) {
			value.tuples.Add(mu.Tuple)
			// Update the numConnections only if the action is not a `pass`.
			if key.ruleID.Action != rules.RuleActionPass {
				value.numConnections.Inc()
			}
		}
	} else {
		value.tuples.Discard(mu.Tuple)
	}

	// If there are some connections for this rule then keep it active, otherwise (re)set the timeout
	// for this metric to ensure we tidy up after a period of inactivity.
	if value.tuples.Len() > 0 {
		pa.unmarkRuleAggregateForDeletion(key)
	} else {
		pa.markRuleAggregateForDeletion(key)
	}
}

func (pa *PolicyRulesAggregator) CheckRetainedMetrics(now time.Duration) {
	for key, expirationTime := range pa.retainedRuleAggMetrics {
		log.WithField("key", key).Debugf("Checking if key is expired now: %v expirationTime: %v", now, expirationTime)
		if now >= expirationTime {
			log.WithField("key", key).Debug("Key expired")
			pa.deleteRuleAggregateMetric(key)
			delete(pa.retainedRuleAggMetrics, key)
		}
	}
}

// unmarkRuleAggregateForDeletion removes a rule aggregate metric from the expiration
// list.
func (pa *PolicyRulesAggregator) unmarkRuleAggregateForDeletion(key RuleAggregateKey) {
	delete(pa.retainedRuleAggMetrics, key)
}

// markRuleAggregateForDeletion marks a rule aggregate metric for expiration.
func (pa *PolicyRulesAggregator) markRuleAggregateForDeletion(key RuleAggregateKey) {
	pa.retainedRuleAggMetrics[key] = pa.timeNowFn() + pa.retentionTime
}

// deleteRuleAggregateMetric deletes the prometheus metrics associated with the
// supplied key.
func (pa *PolicyRulesAggregator) deleteRuleAggregateMetric(key RuleAggregateKey) {
	log.WithField("key", key).Debug("Cleaning up rule aggregate metric previously marked to be deleted.")

	_, ok := pa.ruleAggStats[key]
	if !ok {
		// Nothing to do here.
		return
	}
	pbInLabels := key.PacketByteLabels(types.TrafficDirInbound, pa.felixHostname)
	pbOutLabels := key.PacketByteLabels(types.TrafficDirOutbound, pa.felixHostname)
	cLabels := key.ConnectionLabels(pa.felixHostname)
	switch key.ruleID.Direction {
	case rules.RuleDirIngress:
		counterRulePackets.Delete(pbInLabels)
		counterRuleBytes.Delete(pbInLabels)
		counterRulePackets.Delete(pbOutLabels)
		counterRuleBytes.Delete(pbOutLabels)
		counterRuleConns.Delete(cLabels)
	case rules.RuleDirEgress:
		counterRulePackets.Delete(pbOutLabels)
		counterRuleBytes.Delete(pbOutLabels)
		counterRulePackets.Delete(pbInLabels)
		counterRuleBytes.Delete(pbInLabels)
		counterRuleConns.Delete(cLabels)
	}

	delete(pa.ruleAggStats, key)
}

// getEnforcedPolicyRuleIDs returns the rule IDs that are enforced in the metric update.
func getEnforcedPolicyRuleIDs(mu metric.Update) []calc.RuleID {
	if mu.RuleIDs == nil {
		return nil
	}
	enforcedRuleIDs := []calc.RuleID{}
	for _, rID := range mu.RuleIDs {
		if rID == nil || model.KindIsStaged(rID.Kind) {
			continue
		}
		enforcedRuleIDs = append(enforcedRuleIDs, *rID)
	}
	return enforcedRuleIDs
}

// getStagedPolicyRuleIDs returns the rule IDs that are staged, from the pending rule IDs, in the
// metric update.
func getStagedPolicyRuleIDs(mu metric.Update) []calc.RuleID {
	if mu.PendingRuleIDs == nil {
		return nil
	}
	pendingRuleIDs := []calc.RuleID{}
	for _, rID := range mu.PendingRuleIDs {
		if rID == nil || !model.KindIsStaged(rID.Kind) {
			continue
		}
		pendingRuleIDs = append(pendingRuleIDs, *rID)
	}
	return pendingRuleIDs
}
