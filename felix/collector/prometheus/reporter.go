// Copyright (c) 2017-2023 Tigera, Inc. All rights reserved.

package prometheus

import (
	"fmt"
	"time"

	"github.com/gavv/monotime"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/collector/types/metric"
	"github.com/projectcalico/calico/felix/jitter"
	"github.com/projectcalico/calico/libcalico-go/lib/metricsserver"
)

const checkInterval = 5 * time.Second

type PromAggregator interface {
	// Register Metrics that should be reported with a prometheus registry
	RegisterMetrics(registry *prometheus.Registry)
	// OnUpdate is called every time a new metric Update is received by the
	// PrometheusReporter.
	OnUpdate(mu metric.Update)
	// CheckRetainedMetrics is called everytime the aggregator should check if a retained
	// metric has expired.
	CheckRetainedMetrics(now time.Duration)
}

// PrometheusReporter records denied packets and bytes statistics in prometheus metrics.
type PrometheusReporter struct {
	port            int
	certFile        string
	keyFile         string
	caFile          string
	registry        *prometheus.Registry
	reportChan      chan metric.Update
	retentionTime   time.Duration
	retentionTicker jitter.TickerInterface
	aggregators     []PromAggregator

	// Allow the time function to be mocked for test purposes.
	timeNowFn func() time.Duration
}

func NewReporter(registry *prometheus.Registry, port int, retentionTime time.Duration, certFile, keyFile, caFile string) *PrometheusReporter {
	// Set the ticker interval appropriately, we should be checking at least half of the retention time,
	// or the hard-coded check interval (whichever is smaller).
	tickerInterval := min(checkInterval, retentionTime/2)

	return &PrometheusReporter{
		port:            port,
		certFile:        certFile,
		keyFile:         keyFile,
		caFile:          caFile,
		registry:        registry,
		reportChan:      make(chan metric.Update),
		retentionTicker: jitter.NewTicker(tickerInterval, tickerInterval/10),
		retentionTime:   retentionTime,
		timeNowFn:       monotime.Now,
	}
}

func (pr *PrometheusReporter) AddAggregator(agg PromAggregator) {
	agg.RegisterMetrics(pr.registry)
	pr.aggregators = append(pr.aggregators, agg)
}

func (pr *PrometheusReporter) Start() error {
	log.Info("Starting PrometheusReporter")
	go pr.servePrometheusMetrics()
	go pr.startReporter()
	return nil
}

func (pr *PrometheusReporter) Report(u any) error {
	mu, ok := u.(metric.Update)
	if !ok {
		return fmt.Errorf("invalid metric update")
	}
	pr.reportChan <- mu
	return nil
}

// servePrometheusMetrics starts a lightweight web server to server prometheus metrics.
func (pr *PrometheusReporter) servePrometheusMetrics() {
	var err error
	for {
		if pr.certFile != "" && pr.keyFile != "" {
			// Configured for TLS, serve securely.
			err = metricsserver.ServePrometheusMetricsHTTPS(
				pr.registry,
				"",
				pr.port,
				pr.certFile,
				pr.keyFile,
				string(v3.RequireAndVerifyClientCert),
				pr.caFile,
			)
		} else {
			// Not configured for TLS, serve insecurely.
			metricsserver.ServePrometheusMetricsHTTP(pr.registry, "", pr.port)
		}
		log.WithError(err).Error("Prometheus reporter metrics endpoint failed, trying to restart it...")
		time.Sleep(1 * time.Second)
	}
}

// startReporter starts listening for and processing reports and expired metrics.
func (pr *PrometheusReporter) startReporter() {
	// Loop continuously processing metric reports and expirations. A single
	// loop ensures access to the aggregated datastructures is single-threaded.
	for {
		select {
		case mu := <-pr.reportChan:
			for _, agg := range pr.aggregators {
				agg.OnUpdate(mu)
			}
		case <-pr.retentionTicker.Channel():
			// TODO: RLB: Maybe improve this processing using a linked-list (ordered by time)
			now := pr.timeNowFn()
			for _, agg := range pr.aggregators {
				agg.CheckRetainedMetrics(now)
			}
		}
	}
}
