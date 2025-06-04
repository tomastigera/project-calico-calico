// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

package main

import (
	"context"
	"flag"
	"net"
	"os"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

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

	// Create/read config
	// Load environment config.
	cfg := config.MustLoadConfig()
	cfg.InitializeLogging()

	// Instantiate the log collector
	reportCh := make(chan collector.EnvoyInfo)
	c := collector.NewEnvoyCollector(cfg, reportCh)

	// Instantiate the felix client
	opts := uds.GetDialOptions()
	felixClient := felixclient.NewFelixClient(cfg.DialTarget, opts)

	// Start gRPC log collector
	gRPCServerStart(cfg, reportCh)

	// Start the log collector
	CollectAndSend(context.Background(), felixClient, c)
}

func gRPCServerStart(cfg *config.Config, reportCh chan collector.EnvoyInfo) {
	log.Info("Starting gRCP server...")
	ctx := context.Background()
	gs := grpc.NewServer()
	grpcCollector := collector.NewEnvoyCollector(cfg, reportCh)
	logServer := collector.NewLoggingServer(grpcCollector.ReceiveLogs)
	logServer.RegisterAccessLogServiceServer(gs)
	go grpcCollector.Start(ctx)

	// Run gRPC server on separate goroutine so we catch any signals and clean up.
	if cfg.ListenNetwork == "unix" {
		_ = syscall.Unlink(cfg.ListenAddress)
	}
	lis, err := net.Listen(cfg.ListenNetwork, cfg.ListenAddress)
	if err != nil {
		log.Fatal("could not start listener: ", err)
	}
	if cfg.ListenNetwork == "unix" {
		// anyone on system can connect.
		if err := os.Chmod(cfg.ListenAddress, 0o777); err != nil {
			log.Fatal("unable to set write permission on socket: ", err)
		}
	}
	go func() {
		if err := gs.Serve(lis); err != nil {
			log.Errorf("failed to serve: %v", err)
		}
		defer lis.Close()
	}()
}

func CollectAndSend(ctx context.Context, client felixclient.FelixClient, collector collector.EnvoyCollector) {
	ctx, cancel := context.WithCancel(ctx)
	wg := sync.WaitGroup{}

	// Start the log ingestion go routine.
	wg.Add(1)
	go func() {
		collector.ReadLogs(ctx)
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
}
