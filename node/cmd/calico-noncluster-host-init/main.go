// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/pkg/nonclusterhost"
)

const (
	defaultFelixConfig      = "/etc/calico/calico-node/calico-node.conf"
	nodeEnvironmentFilePath = "/etc/calico/calico-node/calico-node.env"
)

var flagSet = flag.NewFlagSet("CalicoNonClusterHostInit", flag.ContinueOnError)

var felixConfig = flagSet.String("felix-config", defaultFelixConfig, "Path to the Felix config file")
var renewalThreshold = flagSet.Duration("renewal-threshold", 90*24*time.Hour, "Threshold for certificate renewal")
var timeout = flagSet.Duration("timeout", 3*time.Minute, "Timeout for the certificate request")

func main() {
	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fileConfig, err := config.LoadConfigFile(*felixConfig)
	if err != nil {
		logrus.WithError(err).WithField("configFile", *felixConfig).Fatal("Failed to load configuration file")
	}

	caFile, ok := fileConfig["TyphaCAFile"]
	if !ok {
		logrus.Fatal("TyphaCAFile not found in configuration file")
	}
	pkFile, ok := fileConfig["TyphaKeyFile"]
	if !ok {
		logrus.Fatal("TyphaKeyFile not found in configuration file")
	}
	certFile, ok := fileConfig["TyphaCertFile"]
	if !ok {
		logrus.Fatal("TyphaCertFile not found in configuration file")
	}

	if err := renewCertificates(caFile, pkFile, certFile); err != nil {
		os.Exit(1)
	}

	if err := updateLabels(); err != nil {
		os.Exit(1)
	}

	os.Exit(0)
}

func renewCertificates(caFile, pkFile, certFile string) error {
	ctx, cancel := context.WithTimeout(context.TODO(), *timeout)
	defer cancel()

	certManager, err := nonclusterhost.NewCertificateManager(ctx, caFile, pkFile, certFile, nodeEnvironmentFilePath)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create certificate manager")
		return err
	}

	if err := certManager.MaybeRenewCertificate(*renewalThreshold); err != nil {
		logrus.WithError(err).Fatal("Failed to renew certificates")
		return err
	}
	return nil
}

func updateLabels() error {
	ctx, cancel := context.WithTimeout(context.TODO(), 3*time.Minute)
	defer cancel()

	labelUpdater, err := nonclusterhost.NewLabelUpdater(ctx)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create label updater")
		return err
	}

	if err := labelUpdater.UpdateLabels(); err != nil {
		logrus.WithError(err).Fatal("Failed to update labels")
		return err
	}
	return nil
}
