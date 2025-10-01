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

	if err := maybeRenewCertificate(caFile, pkFile, certFile); err != nil {
		os.Exit(1)
	}

	if err := updateLabels(); err != nil {
		os.Exit(1)
	}

	os.Exit(0)
}

func maybeRenewCertificate(caFile, pkFile, certFile string) error {
	ctx, cancel := context.WithTimeout(context.TODO(), *timeout)
	defer cancel()

	certManager, err := nonclusterhost.NewCertificateManager(ctx, caFile, pkFile, certFile, nodeEnvironmentFilePath)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create certificate manager")
		return err
	}

	valid, err := certManager.IsCertificateValid(*renewalThreshold)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to validate certificate")
		return err
	}

	if !valid {
		logrus.Info("Certificate is not valid or is nearing expiry, attempting to renew")

		isBYO, err := certManager.IsBYO()
		if err != nil {
			logrus.WithError(err).Warn("Failed to determine if using BYO certificate, assuming Tigera Operator managed")
		}

		if !isBYO {
			// Send a CSR to the Tigera Operator signer to request a new certificate.
			logrus.Info("Requesting new certificate from Tigera Operator")

			resCh := make(chan error, 1)
			defer close(resCh)

			go func() {
				// Rotate private key and request a new certificate when the current certificate is expired.
				if err := certManager.RequestAndWriteCertificate(); err != nil {
					resCh <- err
				}
				resCh <- nil
			}()

			select {
			case err := <-resCh:
				if err != nil {
					logrus.WithError(err).Fatal("Failed to obtain certificate")
					return err
				}
			case <-ctx.Done():
				if err := ctx.Err(); err != nil {
					logrus.WithError(err).Fatal("Context canceled while obtaining certificate")
					return err
				}
			}
		} else {
			// Use BYO certificate.
			logrus.Info("Using BYO certificate")

			if err := certManager.WriteBYOCertificate(); err != nil {
				logrus.WithError(err).Fatal("Failed to write BYO certificates")
				return err
			}
		}
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
