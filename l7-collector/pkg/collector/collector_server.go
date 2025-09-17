// Copyright (c) 2025 Tigera, Inc. All rights reserv

package collector

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/l7-collector/pkg/api"
	"github.com/projectcalico/calico/l7-collector/pkg/felixclient"
)

func CollectAndSend(ctx context.Context, client felixclient.FelixClient, collector api.EnvoyCollector, readFiles bool) {
	ctx, cancel := context.WithCancel(ctx)
	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		log.Info("Starting log collection...")
		if readFiles {
			collector.ReadAccessLogs(ctx)
		} else {
			collector.ReadLogs(ctx)
		}
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
