// Copyright (c) 2019-2022 Tigera, Inc. All rights reserved.
package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
	"k8s.io/klog/v2"

	capi "github.com/projectcalico/calico/compliance/pkg/api"
	"github.com/projectcalico/calico/compliance/pkg/config"
	"github.com/projectcalico/calico/compliance/pkg/report"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

const (
	// The health name for the reporter component.
	healthReporterName = "ComplianceReporter"
)

var ver bool

func init() {
	// Tell klog to log into STDERR.
	var sflags flag.FlagSet
	klog.InitFlags(&sflags)
	err := sflags.Set("logtostderr", "true")
	if err != nil {
		log.WithError(err).Fatal("Failed to set logging configuration")
	}

	// Add a flag to check the version.
	flag.BoolVar(&ver, "version", false, "Print version information")
}

func main() {
	flag.Parse()

	if ver {
		buildinfo.PrintVersion()
		return
	}

	// Load the config.
	cfg := config.MustLoadConfig()
	cfg.InitializeLogging()

	// Create a health check aggregator and start the health check service.
	h := health.NewHealthAggregator()
	h.ServeHTTP(cfg.HealthEnabled, cfg.HealthHost, cfg.HealthPort)
	h.RegisterReporter(healthReporterName, &health.HealthReport{Live: true}, cfg.HealthTimeoutReporter)

	// Define a function that can be used to report health.
	healthy := func() {
		h.Report(healthReporterName, &health.HealthReport{Live: true})
	}

	// Create a linseed client.
	config := rest.Config{
		URL:            cfg.LinseedURL,
		CACertPath:     cfg.LinseedCA,
		ClientKeyPath:  cfg.LinseedClientKey,
		ClientCertPath: cfg.LinseedClientCert,
	}
	linseed, err := client.NewClient(cfg.TenantID, config, rest.WithTokenPath(cfg.LinseedToken))
	if err != nil {
		log.WithError(err).Fatal("failed to create linseed client")
	}
	store := capi.NewComplianceStore(linseed, "")

	// Setup signals.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	cxt, cancel := context.WithCancel(context.Background())

	go func() {
		<-sigs
		cancel()
	}()

	// Indicate healthy.
	healthy()

	// Run the reporter.
	if err := report.Run(cxt, cfg, healthy, store); err != nil {
		log.Panicf("Hit terminating error in reporter: %v", err)
	}
}
