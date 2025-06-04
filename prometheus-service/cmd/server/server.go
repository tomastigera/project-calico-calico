// Copyright (c) 2021 Tigera. All rights reserved.
package main

import (
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	server "github.com/projectcalico/calico/prometheus-service/pkg/server"
)

const (
	LOG_LEVEL_ENV_VAR = "LOG_LEVEL"
)

func main() {
	setLogger()

	config, err := server.NewConfigFromEnv()
	if err != nil {
		log.WithError(err).Fatal("Configuration Error.")
	}

	server.Start(config)
	server.Wait()
}

func setLogger() {
	logLevel := log.InfoLevel
	logLevelStr := os.Getenv(LOG_LEVEL_ENV_VAR)
	logutils.ConfigureFormatter("promsvc")
	parsedLogLevel, err := log.ParseLevel(logLevelStr)

	if err == nil {
		logLevel = parsedLogLevel
	} else {
		log.Warnf("Could not parse log level %v, setting log level to %v", logLevelStr, logLevel)
	}
	log.SetLevel(logLevel)
}
