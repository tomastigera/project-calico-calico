package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/compliance/pkg/api"
	"github.com/projectcalico/calico/compliance/pkg/benchmark"
	"github.com/projectcalico/calico/compliance/pkg/cis"
	"github.com/projectcalico/calico/compliance/pkg/config"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

const (
	healthReporterName = "ComplianceBenchmarker"
)

func main() {
	var ver bool
	flag.BoolVar(&ver, "version", false, "Print version information")
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
	h.RegisterReporter(healthReporterName, &health.HealthReport{Live: true}, cfg.HealthTimeoutBenchMarker)

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

	// Indicate healthy
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

	// Run benchmarker.
	if err := benchmark.Run(cxt, cfg, cis.NewBenchmarker(), store, store, healthy); err != nil {
		log.WithError(err).Error("Hit terminating error")
	}
}
