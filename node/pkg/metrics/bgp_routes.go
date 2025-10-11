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
	// Number of routes successfully imported to the routing table; this is a gauge
	// because it can both increase and decrease (may decrease when recalculating / comparing
	// routes, it may drop a route)
	gaugeRoutesImported = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "bgp_routes_imported",
			Help: "Current number of routes successfully imported into a given node's routing table.",
		},
		// Track total routes imported by instance (node) and IP version
		[]string{labelInstance, labelIPVersion},
	)
	// Number of route updates received, which includes the following:
	//   - Number of route updates rejected as invalid
	//   - Number of route updates rejected by filters
	//   - Number of route updates rejected as already in route table
	//   - Number of route updates accepted and imported
	//
	// NOTE: This is technically a counter, because it can only increase.
	// However, we use a gauge instead because we want to set an absolute
	// value everytime instead of keeping track of how much to increment.
	// We do not maintain our own internal state. Instead we rely on the
	// value directly from the source (BIRD). Thus, we need the ability to
	// set the absolute value, which a Prometheus gauge provides, but a
	// Prometheus counter does not.
	gaugeRoutesReceived = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "bgp_route_updates_received",
			Help: "Total number of route updates received by a given node over time (since startup).",
		},
		// Track total number of routes received by instance (node) and IP version
		[]string{labelInstance, labelIPVersion},
	)
)

// routeCountAggregator is responsible for computing counts of routes received
// for the given intance with instanceName
type routeCountAggregator struct {
	instanceName string
	statsType    bgp.StatsType
}

// newRouteCountAggregator sets up a new aggregator instance for BGP status and returns it
func newRouteCountAggregator(hostname string, statsType bgp.StatsType) *routeCountAggregator {
	return &routeCountAggregator{
		instanceName: hostname,
		statsType:    statsType,
	}
}

func (aggr *routeCountAggregator) registerMetrics(registry *prometheus.Registry) {
	registry.MustRegister(gaugeRoutesImported)
	registry.MustRegister(gaugeRoutesReceived)
}

// computeMetrics calculates peer count metrics by status value using the given
// bgp.Stats.
func (aggr *routeCountAggregator) computeMetrics(stats *bgp.Stats) error {
	peers, ok := stats.Data.([]bgp.Peer)
	if !ok {
		log.Errorf("Failed to extract peers: %+v", stats.Data)
		return fmt.Errorf("failed to extract peers: %+v", stats.Data)
	}
	fields := log.Fields{
		"peers": peers,
	}
	log.WithFields(fields).Debugf("Compute route count metrics using peers")

	// Tally up route counts for this node
	routesImported := float64(0)
	routesReceived := float64(0)
	for _, p := range peers {
		routesImported += float64(p.Details.RouteCounts.NumImported)
		routesReceived += float64(p.Details.ImportUpdateCounts.NumReceived)
	}

	// Update the Prometheus metrics for routes received for this node
	l := prometheus.Labels{
		labelInstance:  aggr.instanceName,
		labelIPVersion: stats.IPVer.String(),
	}
	gaugeRoutesImported.With(l).Set(routesImported)
	gaugeRoutesReceived.With(l).Set(routesReceived)
	return nil
}

// string() retruns a string representation of this aggregator (for logging purposes)
func (aggr *routeCountAggregator) string() string {
	return fmt.Sprintf(
		"BGP Route Count Aggregator: instance '%s' stats type '%s'",
		aggr.instanceName,
		aggr.statsType.String(),
	)
}
