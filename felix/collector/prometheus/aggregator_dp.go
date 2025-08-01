// Copyright (c) 2018-2023 Tigera, Inc. All rights reserved.

package prometheus

import (
	"fmt"
	"net"
	"time"

	"github.com/gavv/monotime"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types/metric"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/rules"
)

// Calico Metrics
var (
	gaugeDeniedPackets = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "calico_denied_packets",
		Help: "Total number of packets denied by calico policies.",
	},
		[]string{"srcIP", "policy", LABEL_INSTANCE},
	)
	gaugeDeniedBytes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "calico_denied_bytes",
		Help: "Total number of bytes denied by calico policies.",
	},
		[]string{"srcIP", "policy", LABEL_INSTANCE},
	)
)

type DeniedPacketsAggregateKey struct {
	policy string
	srcIP  [16]byte
}

func getDeniedPacketsAggregateKey(mu metric.Update) (DeniedPacketsAggregateKey, error) {
	lastRuleID := lastRuleID(mu)
	if lastRuleID == nil {
		log.WithField("metric update", mu).Error("no rule id present")
		return DeniedPacketsAggregateKey{}, fmt.Errorf("invalid metric update")
	}
	return DeniedPacketsAggregateKey{
		policy: lastRuleID.GetDeniedPacketRuleName(),
		srcIP:  mu.Tuple.Src,
	}, nil
}

type DeniedPacketsAggregateValue struct {
	labels  prometheus.Labels
	packets prometheus.Gauge
	bytes   prometheus.Gauge
	refs    tuple.Set
}

// DeniedPacketsAggregator aggregates denied packets and bytes statistics in prometheus metrics.
type DeniedPacketsAggregator struct {
	retentionTime time.Duration
	timeNowFn     func() time.Duration
	// Stats are aggregated by policy (mangled tiered policy rule) and source IP.
	aggStats        map[DeniedPacketsAggregateKey]DeniedPacketsAggregateValue
	retainedMetrics map[DeniedPacketsAggregateKey]time.Duration
	felixHostname   string
}

func NewDeniedPacketsAggregator(rTime time.Duration, felixHostname string) *DeniedPacketsAggregator {
	return &DeniedPacketsAggregator{
		aggStats:        make(map[DeniedPacketsAggregateKey]DeniedPacketsAggregateValue),
		retainedMetrics: make(map[DeniedPacketsAggregateKey]time.Duration),
		retentionTime:   rTime,
		timeNowFn:       monotime.Now,
		felixHostname:   felixHostname,
	}
}

func (dp *DeniedPacketsAggregator) RegisterMetrics(registry *prometheus.Registry) {
	registry.MustRegister(gaugeDeniedPackets)
	registry.MustRegister(gaugeDeniedBytes)
}

func (dp *DeniedPacketsAggregator) OnUpdate(mu metric.Update) {
	lastRuleID := lastRuleID(mu)
	if lastRuleID == nil {
		log.WithField("metric update", mu).Error("no rule id present")
		return
	}
	if lastRuleID.Action != rules.RuleActionDeny {
		// We only want denied packets. Skip the rest of them.
		return
	}
	switch mu.UpdateType {
	case metric.UpdateTypeReport:
		dp.reportMetric(mu)
	case metric.UpdateTypeExpire:
		dp.expireMetric(mu)
	}
}

func (dp *DeniedPacketsAggregator) CheckRetainedMetrics(now time.Duration) {
	for key, expirationTime := range dp.retainedMetrics {
		if now >= expirationTime {
			dp.deleteMetric(key)
			delete(dp.retainedMetrics, key)
		}
	}
}

func (dp *DeniedPacketsAggregator) reportMetric(mu metric.Update) {
	key, e := getDeniedPacketsAggregateKey(mu)
	if e != nil {
		return
	}
	value, ok := dp.aggStats[key]
	if ok {
		_, exists := dp.retainedMetrics[key]
		if exists {
			delete(dp.retainedMetrics, key)
		}
		value.refs.Add(mu.Tuple)
	} else {
		l := prometheus.Labels{
			"srcIP":        net.IP(key.srcIP[:16]).String(),
			"policy":       key.policy,
			LABEL_INSTANCE: dp.felixHostname,
		}
		value = DeniedPacketsAggregateValue{
			labels:  l,
			packets: gaugeDeniedPackets.With(l),
			bytes:   gaugeDeniedBytes.With(l),
			refs:    tuple.NewSet(),
		}
		value.refs.Add(mu.Tuple)
	}
	inMetric := mu.InMetric
	outMetric := mu.OutMetric
	lastRuleID := mu.GetLastRuleID()
	if lastRuleID == nil {
		inMetric = mu.InTransitMetric
		outMetric = mu.OutTransitMetric
		lastRuleID = mu.GetLastTransitRuleID()
	}
	if lastRuleID == nil {
		log.WithField("metric update", mu).Error("no rule id present")
		return
	}
	switch lastRuleID.Direction {
	case rules.RuleDirIngress:
		value.packets.Add(float64(inMetric.DeltaPackets))
		value.bytes.Add(float64(inMetric.DeltaBytes))
	case rules.RuleDirEgress:
		value.packets.Add(float64(outMetric.DeltaPackets))
		value.bytes.Add(float64(outMetric.DeltaBytes))
	default:
		return
	}

	dp.aggStats[key] = value
}

func (dp *DeniedPacketsAggregator) expireMetric(mu metric.Update) {
	key, e := getDeniedPacketsAggregateKey(mu)
	if e != nil {
		return
	}
	value, ok := dp.aggStats[key]
	if !ok || !value.refs.Contains(mu.Tuple) {
		return
	}
	lastRuleID := lastRuleID(mu)
	if lastRuleID == nil {
		log.WithField("metric update", mu).Error("no rule id present")
		return
	}
	// If the metric update has updated counters this is the time to update our counters.
	// We retain deleted metric for a little bit so that prometheus can get a chance
	// to scrape the metric.
	var deltaPackets, deltaBytes int
	switch lastRuleID.Direction {
	case rules.RuleDirIngress:
		deltaPackets = mu.InMetric.DeltaPackets
		deltaBytes = mu.InMetric.DeltaBytes
	case rules.RuleDirEgress:
		deltaPackets = mu.OutMetric.DeltaPackets
		deltaBytes = mu.OutMetric.DeltaBytes
	default:
		return
	}
	if deltaPackets != 0 && deltaBytes != 0 {
		value.packets.Add(float64(deltaPackets))
		value.bytes.Add(float64(deltaBytes))
		dp.aggStats[key] = value
	}
	value.refs.Discard(mu.Tuple)
	dp.aggStats[key] = value
	if value.refs.Len() == 0 {
		dp.markForDeletion(key)
	}
}

func (dp *DeniedPacketsAggregator) markForDeletion(key DeniedPacketsAggregateKey) {
	log.WithField("key", key).Debug("Marking metric for deletion.")
	dp.retainedMetrics[key] = dp.timeNowFn() + dp.retentionTime
}

func (dp *DeniedPacketsAggregator) deleteMetric(key DeniedPacketsAggregateKey) {
	log.WithField("key", key).Debug("Cleaning up candidate marked to be deleted.")
	value, ok := dp.aggStats[key]
	if ok {
		gaugeDeniedPackets.Delete(value.labels)
		gaugeDeniedBytes.Delete(value.labels)
		delete(dp.aggStats, key)
	}
}

func lastRuleID(mu metric.Update) *calc.RuleID {
	lastRuleID := mu.GetLastRuleID()
	if lastRuleID == nil {
		lastRuleID = mu.GetLastTransitRuleID()
	}
	return lastRuleID
}
