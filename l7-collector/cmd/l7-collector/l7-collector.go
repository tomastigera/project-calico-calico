// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

package main

import (
	"context"
	"flag"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/l7-collector/pkg/collector"
	"github.com/projectcalico/calico/l7-collector/pkg/config"
	"github.com/projectcalico/calico/l7-collector/pkg/felixclient"
	"github.com/projectcalico/calico/libcalico-go/lib/uds"
	"github.com/projectcalico/calico/pkg/buildinfo"
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

	// Instantiate the log collector
	reportCh := make(chan collector.EnvoyInfo)
	c := collector.NewEnvoyCollector(cfg, reportCh)

	log.Info("creating l7-collector...")

	// Instantiate the felix client
	opts := uds.GetDialOptions()
	felixClient := felixclient.NewFelixClient(cfg.DialTarget, opts)

	log.Infof("setting up Felixclient at %s", cfg.DialTarget)

	// Start the log collector
	CollectAndSend(context.Background(), felixClient, c)
}

func CollectAndSend(ctx context.Context, client felixclient.FelixClient, collector collector.EnvoyCollector) {
	ctx, cancel := context.WithCancel(ctx)
	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		collector.ReadAccessLogs(ctx)
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
