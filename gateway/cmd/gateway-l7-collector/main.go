// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package main

import (
	"context"
	"flag"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	gatewayclientset "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"

	gatewaycollector "github.com/projectcalico/calico/gateway/pkg/collector"
	"github.com/projectcalico/calico/gateway/pkg/indexer"
	"github.com/projectcalico/calico/gateway/pkg/license"
	l7collector "github.com/projectcalico/calico/l7-collector/pkg/collector"
	"github.com/projectcalico/calico/l7-collector/pkg/config"
	l7felixclient "github.com/projectcalico/calico/l7-collector/pkg/felixclient"
	"github.com/projectcalico/calico/libcalico-go/lib/uds"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

const (
	// Environment variable names for owning gateway info.
	// These are set by the operator via Kubernetes downward API from pod labels
	// that EnvoyProxy sets on gateway pods.
	envOwningGatewayName      = "OWNING_GATEWAY_NAME"
	envOwningGatewayNamespace = "OWNING_GATEWAY_NAMESPACE"
)

func main() {
	var ver bool
	flag.BoolVar(&ver, "version", false, "Print version information")
	flag.Parse()

	if ver {
		buildinfo.PrintVersion()
		return
	}
	log.Infof("Starting l7-collector version %s", buildinfo.Version)
	// Create/read config
	// Load environment config.
	cfg := config.MustLoadConfig()
	cfg.InitializeLogging()

	log.Infof("Configuration: %+v", cfg)

	// Initialize Kubernetes clients for Gateway API enrichment
	k8sConfig, err := rest.InClusterConfig()
	if err != nil {
		log.WithError(err).Warn("Failed to create K8s config, enrichment will be disabled")
	}

	var enricher *gatewaycollector.Enricher

	if k8sConfig != nil {
		k8sClient, err := kubernetes.NewForConfig(k8sConfig)
		if err != nil {
			log.WithError(err).Warn("Failed to create K8s client, enrichment will be disabled")
		}

		gatewayClient, err := gatewayclientset.NewForConfig(k8sConfig)
		if err != nil {
			log.WithError(err).Warn("Failed to create Gateway API client, enrichment will be disabled")
		}

		if k8sClient != nil && gatewayClient != nil {
			// Create zap logger for indexer
			zapLogger, err := zap.NewProduction()
			if err != nil {
				log.WithError(err).Warn("Failed to create zap logger, using default logger")
				zapLogger = zap.NewNop()
			}

			// Initialize StatusIndexer
			log.Info("Initializing Gateway API status indexer...")
			statusIndexer, err := indexer.NewStatusIndexer(zapLogger, k8sClient, gatewayClient)
			if err != nil {
				log.WithError(err).Warn("Failed to create status indexer, enrichment will be disabled")
			} else {
				// Start watching Gateway API resources
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				go func() {
					if err := statusIndexer.Start(ctx); err != nil {
						log.WithError(err).Error("Status indexer failed")
					}
				}()

				// Wait for initial cache sync
				log.Info("Waiting for Gateway API resource cache to sync...")
				time.Sleep(2 * time.Second)

				// Read owning gateway info from environment variables (set via downward API)
				owningGatewayName := os.Getenv(envOwningGatewayName)
				owningGatewayNamespace := os.Getenv(envOwningGatewayNamespace)

				// Create enricher with options
				var enricherOpts []gatewaycollector.EnricherOption
				if owningGatewayName != "" && owningGatewayNamespace != "" {
					log.WithFields(log.Fields{
						"gatewayName":      owningGatewayName,
						"gatewayNamespace": owningGatewayNamespace,
					}).Info("Owning gateway info available from environment")
					enricherOpts = append(enricherOpts,
						gatewaycollector.WithDefaultGateway(owningGatewayNamespace, owningGatewayName))
				} else {
					log.Info("Owning gateway environment variables not set, will use indexer-based lookup")
				}

				enricher = gatewaycollector.NewEnricher(statusIndexer, enricherOpts...)
				log.Info("Gateway API enrichment enabled")
			}
		}
	}

	// Initialize license monitoring before starting l7-collector
	gatewayLicense := license.NewIngressGatewayLicenseMonitor()
	gatewayLicense.InitializeLicenseMonitor()

	// Instantiate the log collector
	reportCh := make(chan l7collector.EnvoyInfo)
	c := l7collector.NewEnvoyCollector(cfg, reportCh)

	// Set enricher if available
	if enricher != nil {
		c.SetEnricher(enricher)
	}

	log.Info("creating l7-collector...")

	// Instantiate the felix client
	opts := uds.GetDialOptions()
	felixClient := l7felixclient.NewFelixClient(cfg.DialTarget, opts)

	log.Infof("setting up Felixclient at %s", cfg.DialTarget)

	// Start the log collector
	CollectAndSend(context.Background(), felixClient, c, gatewayLicense)
}

func CollectAndSend(ctx context.Context, client l7felixclient.FelixClient, collector l7collector.EnvoyCollector, gatewayLicense license.GatewayLicense) {
	ctx, cancel := context.WithCancel(ctx)
	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		log.Info("Starting log collection...")
		collector.ReadAccessLogs(ctx, gatewayLicense)
		cancel()
		wg.Done()
	}()

	// Start the DataplaneStats reporting go routine.
	wg.Add(1)
	go func() {
		client.SendStats(ctx, collector)
		cancel()
		wg.Done()
	}()

	// Wait for the go routine to complete before exiting
	wg.Wait()
	log.Info("All go routines completed, exiting l7-collector.")
}
