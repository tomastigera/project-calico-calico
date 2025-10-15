// Copyright (c) 2020 Tigera, Inc. All rights reserved.

package metrics

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/node/pkg/bgp"
)

// Calico Enterprise BGP Metrics
var (
	// Peer count by a given status can both increase and decrease
	gaugePeerCountByStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "bgp_peers",
			Help: "Total number of peers of a given status for a given node.",
		},
		// Track total number of peers by instance (node), BGP peer status and IP version
		[]string{labelPeerStatus, labelInstance, labelIPVersion},
	)
)

// peerCountAggregator is responsible for computing counts of BGP peers by status
// value for the given intance with instanceName
type peerCountAggregator struct {
	instanceName string
	statsType    bgp.StatsType
}

// newPeerCountAggregator sets up a new aggregator instance for BGP status and returns it
func newPeerCountAggregator(hostname string, statsType bgp.StatsType) *peerCountAggregator {
	return &peerCountAggregator{
		instanceName: hostname,
		statsType:    statsType,
	}
}

func (aggr *peerCountAggregator) registerMetrics(registry *prometheus.Registry) {
	registry.MustRegister(gaugePeerCountByStatus)
}

// computeMetrics calculates peer count metrics by status value using the given
// bgp.Stats.
func (aggr *peerCountAggregator) computeMetrics(stats *bgp.Stats) error {
	peers, ok := stats.Data.([]bgp.Peer)
	if !ok {
		log.Errorf("Failed to extract peers: %+v", stats.Data)
		return fmt.Errorf("failed to extract peers: %+v", stats.Data)
	}
	fields := log.Fields{
		"peers": peers,
	}
	log.WithFields(fields).Debugln("Compute peer count metrics using peers")

	// Create a table of BGP peer counts by status value
	statusPeerCounts := map[string]float64{}
	for _, status := range bgp.PeerStatuses {
		statusPeerCounts[status] = 0.0
	}

	// Tally up peer count by BGP status value
	for _, p := range peers {
		if _, ok := statusPeerCounts[p.BGPState]; ok {
			statusPeerCounts[p.BGPState]++
		} else {
			// This should not happen, it means there's a mismatch between
			// BGP state values in BIRD and the status values in bgp.PeerStatuses
			log.Errorf("Skipping peer count, unrecognized BGP state value: %+v", p.BGPState)
		}
	}

	// Update the Prometheus metrics for peer count for this node
	for _, status := range bgp.PeerStatuses {
		l := prometheus.Labels{
			labelInstance:   aggr.instanceName,
			labelPeerStatus: status,
			labelIPVersion:  stats.IPVer.String(),
		}
		gaugePeerCountByStatus.With(l).Set(statusPeerCounts[status])
	}
	return nil
}

// string() retruns a string representation of this aggregator (for logging purposes)
func (aggr *peerCountAggregator) string() string {
	return fmt.Sprintf(
		"BGP Peer Count Aggregator: instance '%s' stats type '%s'",
		aggr.instanceName,
		aggr.statsType.String(),
	)
}
