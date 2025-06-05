// Copyright (c) 2020 Tigera, Inc. All rights reserved.

package main

import (
	"flag"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/license-agent/pkg/config"
	"github.com/projectcalico/calico/license-agent/pkg/metrics"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

// Below variables are filled out during the build process (using git describe output)
var (
	version bool
)

func init() {
	// Add a flag to check the version.
	flag.BoolVar(&version, "version", false, "Display version")
}

func main() {
	flag.Parse()
	if version {
		buildinfo.PrintVersion()
		os.Exit(0)
	}

	logLevel := log.InfoLevel
	logLevelStr := os.Getenv("LOG_LEVEL")
	logutils.ConfigureFormatter("license")
	parsedLogLevel, err := log.ParseLevel(logLevelStr)
	if err == nil {
		logLevel = parsedLogLevel
	} else {
		log.Warnf("Could not parse log level %v, setting log level to %v", logLevelStr, logLevel)
	}
	log.SetLevel(logLevel)

	// Load env config
	cfg := config.MustLoadConfig()

	// Find file path
	cert := checkFileExists(cfg.MetricsCertFile)
	ca := checkFileExists(cfg.MetricsCaFile)
	key := checkFileExists(cfg.MetricsKeyFile)

	// Create New Instance of License reporter
	lr := metrics.NewLicenseReporter(cfg.MetricsHost, cert, key, ca, cfg.MetricPollInterval, cfg.MetricsPort)
	// Start License metric server and scraper
	lr.Start()
}

// checkFileExist checks valid file exist, if so returns
// File Path else return empty string
func checkFileExists(name string) string {
	if _, err := os.Stat(name); os.IsNotExist(err) {
		return ""
	}

	return name
}
