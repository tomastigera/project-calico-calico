// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/third_party/dex/wrapper/pkg/watcher"
	"github.com/projectcalico/calico/third_party/dex/wrapper/pkg/wrapper"
	log "github.com/sirupsen/logrus"
)

func main() {
	setupLogging()
	log.Info("starting dex entrypoint wrapper...")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	dw := wrapper.New()
	defer dw.Cleanup()

	if dw.NeedsWatching() {
		dexRestartCh := make(chan struct{})
		dw.SetRestartCh(dexRestartCh)

		stopDebounceCh := make(chan struct{})
		dw.SetStopDebounceCh(stopDebounceCh)

		w, err := watcher.New(dw.GetWatchDir(), dexRestartCh, stopDebounceCh)
		if err != nil {
			log.WithError(err).Fatal("failed to create watcher")
		}
		defer func() {
			err := w.Close()
			if err != nil {
				log.WithError(err).Warn("failed to close watcher")
			}
		}()

		go func() {
			err := w.Start(ctx)
			if err != nil {
				log.WithError(err).Fatal("unrecoverable error occurred when running watcher")
			}
		}()
	}

	if err := dw.Run(ctx); err != nil {
		log.WithError(err).Fatal("unrecoverable error occurred when running dex wrapper")
	}
}

func setupLogging() {
	logutils.ConfigureFormatter("dex-wrapper")
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
}
