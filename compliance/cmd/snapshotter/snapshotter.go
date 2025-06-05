// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
	"k8s.io/klog/v2"

	"github.com/projectcalico/calico/compliance/pkg/api"
	"github.com/projectcalico/calico/compliance/pkg/config"
	"github.com/projectcalico/calico/compliance/pkg/datastore"
	"github.com/projectcalico/calico/compliance/pkg/snapshot"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

const (
	// The health name for the snapshotter component.
	healthReporterName = "ComplianceSnapshotter"
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

	// Load config.
	cfg := config.MustLoadConfig()
	cfg.InitializeLogging()
	log.WithField("config", cfg).Info("Loaded configuration")

	// Create a health check aggregator and start the health check service.
	h := health.NewHealthAggregator()
	h.ServeHTTP(cfg.HealthEnabled, cfg.HealthHost, cfg.HealthPort)
	h.RegisterReporter(healthReporterName, &health.HealthReport{Live: true}, cfg.HealthTimeout)

	// Define a function that can be used to report health.
	healthy := func(healthy bool) {
		h.Report(healthReporterName, &health.HealthReport{Live: healthy})
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
	store := api.NewComplianceStore(linseed, "")

	// Create clientset.
	datastoreClient := datastore.MustGetClientSet()

	// Indicate healthy.
	healthy(true)

	// Setup signals.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	cxt, cancel := context.WithCancel(context.Background())

	go func() {
		signal := <-sigs
		log.WithField("signal", signal).Warn("Received signal, canceling context")
		cancel()
	}()

	// Run snapshotter.
	if err := snapshot.Run(cxt, cfg, datastoreClient, store, healthy); err != nil {
		log.WithError(err).Error("Hit terminating error")
	}
}
