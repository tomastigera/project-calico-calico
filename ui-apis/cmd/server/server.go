// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	log "github.com/sirupsen/logrus"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/pkg/buildinfo"
	"github.com/projectcalico/calico/ui-apis/pkg/server"
)

// This is filled out during the build process (using git describe output)
var version bool

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

	// Install a hook that adds file/line number information.
	logutils.ConfigureFormatter("ui-apis")
	logLevel := log.InfoLevel
	logLevelStr := os.Getenv("LOG_LEVEL")
	parsedLogLevel, err := log.ParseLevel(logLevelStr)
	if err == nil {
		logLevel = parsedLogLevel
	} else {
		log.Warnf("Could not parse log level %v, setting log level to %v", logLevelStr, logLevel)
	}
	log.SetLevel(logLevel)

	config, err := server.NewConfigFromEnv()
	if err != nil {
		log.WithError(err).Fatal("Configuration Error.")
	}

	// If configuration for certificates isn't provided, then generate one ourselves and
	// set the correct paths.
	if config.CertFile == "" || config.KeyFile == "" {
		log.Warnf("Generating self-signed cert: (%s, %s)", config.DefaultCertFile, config.DefaultKeyFile)
		config.CertFile = config.DefaultCertFile
		config.KeyFile = config.DefaultKeyFile
		err := MaybeDefaultWithSelfSignedCerts("localhost", nil, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, config.DefaultCertFile, config.DefaultKeyFile)
		if err != nil {
			log.WithError(err).Fatal("Error creating self-signed certificates", err)
		}
	}

	_ = server.Start(config)

	server.Wait()
}

// Copied from "k8s.io/apiserver/pkg/server/options" for self signed certificate generation.
// Original source is licensed under the Apache License, Version 2.0.
func MaybeDefaultWithSelfSignedCerts(publicAddress string, alternateDNS []string, alternateIPs []net.IP, defaultCertFilePath string, defaultKeyFilePath string) error {
	canReadCertAndKey, err := certutil.CanReadCertAndKey(defaultCertFilePath, defaultKeyFilePath)
	if err != nil {
		return err
	}
	if !canReadCertAndKey {
		// add localhost to the valid alternates
		alternateDNS = append(alternateDNS, "localhost")

		if cert, key, err := certutil.GenerateSelfSignedCertKey(publicAddress, alternateIPs, alternateDNS); err != nil {
			return fmt.Errorf("unable to generate self signed cert: %v", err)
		} else {
			if err := certutil.WriteCert(defaultCertFilePath, cert); err != nil {
				return err
			}

			if err := keyutil.WriteKey(defaultKeyFilePath, key); err != nil {
				return err
			}
			log.Infof("Generated self-signed cert (%s, %s)", defaultCertFilePath, defaultKeyFilePath)
		}
	}

	return nil
}
