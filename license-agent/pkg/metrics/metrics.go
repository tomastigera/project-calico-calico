// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package metrics

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/metricsserver"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	licenseClient "github.com/projectcalico/calico/licensing/client"
)

type LicenseStatus int

const (
	InValid LicenseStatus = iota
	Valid
)

// Declare Prometheus metrics variables
var (
	gaugeNumDays = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "license_number_of_days",
		Help: "Total number of days license in valid state.",
	})
	gaugeNumNodes = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "calico_nodes_used",
		Help: "Total number of nodes currently in use.",
	})
	gaugeMaxNodes = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "calico_maximum_licensed_nodes",
		Help: "Total number of Licensed nodes.",
	})
	gaugeValidLicense = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "calico_license_valid",
		Help: "Is valid calico Enterprise License.",
	})

	wg sync.WaitGroup
)

// License Reporter contains data which is required to start webserver,
// and serve prometheus requests
type LicenseReporter struct {
	// Prometheus requests are served on this port
	port int
	host string
	// CA, certifciate and Key file location for secured connections
	caFile   string
	keyFile  string
	certFile string
	// Sampling Interval to scrape data
	pollInterval time.Duration
	client       clientv3.Interface
}

func NewLicenseReporter(host, certFile, keyFile, caFile string, pollInterval time.Duration, port int) *LicenseReporter {
	return &LicenseReporter{
		port:         port,
		host:         host,
		caFile:       caFile,
		keyFile:      keyFile,
		certFile:     certFile,
		pollInterval: pollInterval,
	}
}

// Start Prometheus server and data collecteion
func (lr *LicenseReporter) Start() {
	var err error
	lr.client, err = clientv3.NewFromEnv()
	if err != nil {
		log.Fatal("Unable to get client v3 handle")
		return
	}
	wg.Add(2)
	go lr.servePrometheusMetrics()
	go lr.startReporter()
	wg.Wait()
}

// Register Prometheus Metrics variable
func init() {
	prometheus.MustRegister(gaugeNumDays)
	prometheus.MustRegister(gaugeNumNodes)
	prometheus.MustRegister(gaugeMaxNodes)
	prometheus.MustRegister(gaugeValidLicense)
	// Discard GolangMetrics
	prometheus.Unregister(collectors.NewGoCollector())
	// Discard process metrics
	prometheus.Unregister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
}

// servePrometheusMetrics starts a lightweight web server to serve prometheus metrics.
func (lr *LicenseReporter) servePrometheusMetrics() {
	err := metricsserver.ServePrometheusMetricsHTTPS(
		prometheus.DefaultGatherer,
		lr.host,
		lr.port,
		lr.certFile,
		lr.keyFile,
		string(v3.RequireAndVerifyClientCert),
		lr.caFile,
	)
	if err != nil {
		log.WithError(err).Error("Error from libcalico library")
	}
	wg.Done()
}

// Continuously scrape License Validity, Number of days license valid
// Maximum number of nodes licensed and Number of nodes in Use
func (lr *LicenseReporter) startReporter() {
	for {
		// Get Licensekey from datastore, only if license exists scrape data
		lic, err := lr.client.LicenseKey().Get(context.Background(), "default", options.GetOptions{})
		if err != nil {
			switch err.(type) {
			case cerrors.ErrorResourceDoesNotExist:
				log.Infof("No valid License found in your Cluster")
			default:
				log.Infof("Error getting LicenseKey :%v", err)
			}
			time.Sleep(lr.pollInterval)
			continue
		}

		nodeList, err := lr.client.Nodes().List(context.Background(), options.ListOptions{})
		if err != nil {
			log.WithError(err).Error("Unable to get Node count from libcalico library")
			time.Sleep(lr.pollInterval)
			continue
		}
		isValid, daysToExpire, maxNodes := lr.LicenseHandler(*lic)
		gaugeNumNodes.Set(float64(len(nodeList.Items)))
		gaugeNumDays.Set(float64(daysToExpire))
		gaugeMaxNodes.Set(float64(maxNodes))
		if isValid {
			gaugeValidLicense.Set(float64(Valid))
		} else {
			gaugeValidLicense.Set(float64(InValid))
		}
		time.Sleep(lr.pollInterval)
	}
}

// Decode License, get expiry date, maximum allowed nodes
func (lr *LicenseReporter) LicenseHandler(lic apiv3.LicenseKey) (isValid bool, daysToExpire, maxNodes int) {
	// Decode the LicenseKey
	claims, err := licenseClient.Decode(lic)
	if err != nil {
		log.Warnf("License is corrupted. Please Contact Tigera support")
		return false, 0, 0
	}

	// Check if License is Valid
	if licStatus := claims.Validate(); licStatus != licenseClient.Valid {
		log.Warnf("License has expired. Please Contact Tigera support")
		return false, 0, 0
	}

	// Find number of days license valid, Maximum nodes
	durationInHours := int(time.Until(claims.Claims.Expiry.Time()).Hours())
	maxNodes = *claims.Nodes
	return true, durationInHours / 24, maxNodes
}
