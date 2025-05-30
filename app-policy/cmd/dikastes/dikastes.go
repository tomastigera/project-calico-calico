// Copyright (c) 2018-2024 Tigera, Inc. All rights reserved.

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/app-policy/flags"
	"github.com/projectcalico/calico/app-policy/server"
)

var VERSION string = "dev"

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config := flags.New()
	if err := config.Parse(os.Args); err != nil {
		log.Fatal(err)
		return
	}

	log.Infof("Dikastes (%s) launching", VERSION)
	switch config.Command {
	case "init-sidecar":
		// At least one of them should be enabled
		if !(config.SidecarALPEnabled || config.SidecarWAFEnabled || config.SidecarLogsEnabled) {
			log.Fatal("At least one of the main features ALP, WAF and Logs should be enabled")
		}

		runInit(config)
	case "server":
		if config.DialAddress == "" {
			log.Fatal("Dial Address for PolicySync connection is mandatory")
		}

		runServer(ctx, config)
	}
}

func runServer(ctx context.Context, config *flags.Config, readyCh ...chan struct{}) {
	// setup log level
	setLevel, err := log.ParseLevel(config.LogLevel)
	if err != nil {
		log.WithError(err).Warn("invalid log-level value. falling back to default value 'info'")
		setLevel = log.InfoLevel
	}
	log.SetLevel(setLevel)

	// Lifecycle: use a buffered channel so we don't miss any signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	log.WithFields(config.Fields()).Info("runtime arguments")

	// Dikastes main: Setup and serve
	dikastesServer := server.NewDikastesServer(
		server.WithListenArguments(config.ListenNetwork, config.ListenAddress),
		server.WithDialAddress(config.DialNetwork, config.DialAddress),
		server.WithSubscriptionType(config.SubscriptionType),
		server.WithALPConfig(config.PerHostALPEnabled),
		server.WithWAFConfig(
			config.PerHostWAFEnabled,
			config.WAFRulesetRootDir,
			config.WAFRulesetFiles.Value(),
			config.WAFDirectives.Value(),
		),
		server.WithGeoIPConfig(config.GeoDBPath, config.GeoDBType),
	)
	go dikastesServer.Serve(ctx, readyCh...)

	// Istio: termination handler (i.e., quitquitquit handler)
	thChan := make(chan struct{}, 1)
	if config.HTTPServerPort != "" {
		th := httpTerminationHandler{thChan}
		log.Info("http server port is", config.HTTPServerPort)
		if httpServer, httpServerWg, err := th.RunHTTPServer(config.HTTPServerAddr, config.HTTPServerPort); err == nil {
			defer httpServerWg.Wait()
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err = httpServer.Shutdown(ctx); err != nil {
					log.Fatalf("error while shutting down HTTP server: %v", err)
				}
			}()
		} else {
			log.Fatal(err)
		}
	}

	// Lifecycle: block until a signal is received.
	select {
	case <-ctx.Done():
		log.Info("Context cancelled")
	case sig := <-sigChan:
		log.Infof("Got signal: %v", sig)
	case <-thChan:
		log.Info("Received HTTP termination request")
	}
}
