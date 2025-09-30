// Copyright (c) 2020 Tigera, Inc. All rights reserved.

package metrics

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/metricsserver"
	"github.com/projectcalico/calico/node/pkg/bgp"
)

const (
	// labelInstance is a Prometheus metrics label for a node instance
	labelInstance = "instance"
	// labelPeerStatus is a Prometheus metrics label for a BGP connection status for a peer
	labelPeerStatus = "status"
	// labelIPVersion is a Prometheus metrics label for IP version of BIRD (v4 or v6)
	labelIPVersion = "ip_version"

	// defaultReportingInterval is the default time interval to check BGP stats from daemon
	// and recompute BGP metrics
	defaultReportingInterval = 5 * time.Second
)

// reportingInterval specifies how often (in sec) to check BGP stats and recompute metrics
// based on those stats
var reportingInterval time.Duration

func init() {
	getReportingInterval()
}

// getReportingInterval sets the reporting interval based on envrionment variable or default
// value.
func getReportingInterval() {
	reportingInterval = defaultReportingInterval

	intervalStr := os.Getenv("BGP_REPORTINGINTERVALSECS")
	if intervalStr != "" {
		if intervalInt, err := strconv.Atoi(intervalStr); err != nil {
			log.Panicf("Failed to parse value for reporting interval %s", intervalStr)
		} else {
			reportingInterval = time.Duration(intervalInt) * time.Second
		}
	}
}

// prometheusMetricAggregator ties a given Prometheus metric with the underlying stats and how
// it is computed
type prometheusMetricAggregator interface {
	// Register metrics that should be reported with a Prometheus registry
	registerMetrics(registry *prometheus.Registry)
	// Compute metrics that should be reported to Prometheus
	computeMetrics(stats *bgp.Stats) error
	// Return string representation of aggregator
	string() string
}

// prometheusBGPReporter compiles BGP statistics into Prometheus metrics.
type prometheusBGPReporter struct {
	port         int
	certFile     string
	keyFile      string
	caFile       string
	registry     *prometheus.Registry
	aggregators  []prometheusMetricAggregator
	statsGetters []func() (*bgp.Stats, error)
}

// newPrometheusBGPReporter sets up a new Prometheus reporter instance and returns it
func newPrometheusBGPReporter(port int, certFile, keyFile, caFile string) *prometheusBGPReporter {
	registry := prometheus.NewRegistry()
	return &prometheusBGPReporter{
		port:     port,
		certFile: certFile,
		keyFile:  keyFile,
		caFile:   caFile,
		registry: registry,
	}
}

// addMetricAggregator appends the given metrics aggregator to the reporter's list
// and registers the aggregator's metrics to the reporter's Prometheus registry.
func (pr *prometheusBGPReporter) addMetricAggregator(a prometheusMetricAggregator) {
	a.registerMetrics(pr.registry)
	pr.aggregators = append(pr.aggregators, a)
}

// addStatsGetter records the given function parameter to the reporter's list of
// stats getters. These are invoked from within the recordMetrics function.
func (pr *prometheusBGPReporter) addStatsGetter(s func() (*bgp.Stats, error)) {
	pr.statsGetters = append(pr.statsGetters, s)
}

// start kicks off the required elements for the reporter to run. Waits on both
// call to serve Prometheus metrics and to record metrics. An empty channel can be
// passed into the function to trigger the reporter to halt operation.
func (pr *prometheusBGPReporter) start(stop <-chan struct{}) {
	log.Info("Starting BGP Prometheus Reporter")
	go pr.servePrometheusMetrics(stop)
	go pr.recordMetrics(stop)
	<-stop
}

// servePrometheusMetrics starts a lightweight web server to server prometheus metrics.
func (pr *prometheusBGPReporter) servePrometheusMetrics(stop <-chan struct{}) {
	log.Info("Serve BGP Prometheus Metrics")
	for {
		select {
		case <-stop:
			return
		default:
			log.Infof("listening for requests at %s", fmt.Sprintf("[%v]:%v", "localhost", pr.port))
			err := metricsserver.ServePrometheusMetricsHTTPS(
				pr.registry,
				"",
				pr.port,
				pr.certFile,
				pr.keyFile,
				string(v3.RequireAndVerifyClientCert),
				pr.caFile,
			)
			log.WithError(err).Error("BGP Prometheus metrics endpoint failed, trying to restart it...")
			time.Sleep(1 * time.Second)
		}
	}
}

// recordMetrics starts computing the registered metrics every getMetricsInterval time period.
func (pr *prometheusBGPReporter) recordMetrics(stop <-chan struct{}) {
	log.Info("Begin recording BGP Prometheus Metrics")
	for {
		select {
		case <-stop:
			return
		default:
			for _, getter := range pr.statsGetters {
				s, err := getter()
				if err != nil {
					log.Errorf("Error retrieving BGP peers to compute BGP metrics %v", err)
				} else {
					// For each type of BGP metric recompute
					for _, a := range pr.aggregators {
						fields := log.Fields{
							"aggregator": a.string(),
							"statsType":  s.Type,
							"ipVer":      s.IPVer,
						}
						err = a.computeMetrics(s)
						if err != nil {
							log.WithFields(fields).Errorf("Failed to compute metrics: %v", err)
						} else {
							log.WithFields(fields).Debugln("Trigger compute metrics")
						}
					}
				}
			}
			time.Sleep(reportingInterval)
		}
	}
}
