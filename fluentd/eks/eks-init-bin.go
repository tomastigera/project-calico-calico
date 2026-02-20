// Copyright (c) 2019-2026 Tigera Inc. All rights reserved.
package main

import (
	"context"
	"flag"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/pkg/buildinfo"
)

func main() {
	version := flag.Bool("version", false, "prints version information")
	flag.Parse()

	if *version {
		buildinfo.PrintVersion()
		return
	}

	config, err := LoadConfig()
	if err != nil {
		log.WithError(err).Fatal("Error loading configuration.")
	}

	linseed, err := GetLinseedClient(config)
	if err != nil {
		log.WithError(err).Fatal("Error setting linseed client.")
	}

	ctx := context.Background()

	logs, err := AwsSetupLogSession(ctx)
	if err != nil {
		log.WithError(err).Fatal("Error setting up AWS session.")
	}

	// Get start-time from ES via linseed and get the token based on that
	startTime, err := GetStartTime(config, linseed)
	if err != nil {
		log.WithError(err).Fatal("Error getting start-time from elastic via linseed.")
	}

	stateFileTokenMap, err := AwsGetStateFileWithToken(ctx, logs, config.EKSCloudwatchLogGroup, config.EKSCloudwatchLogStreamPrefix, startTime)
	if err != nil {
		log.WithError(err).Fatal("Error getting token for given start-time.")
	}

	if err = generateStateFile(config.EKSStateFileDir, stateFileTokenMap); err != nil {
		log.WithError(err).Fatal("Error generating state-file for log-stream.")
	}
}

func generateStateFile(path string, stateTokens map[string]string) error {
	for s, t := range stateTokens {
		f, err := os.OpenFile(path+s, os.O_RDWR|os.O_CREATE, 0755)
		if err != nil {
			return err
		}
		defer f.Close()

		if _, err = f.WriteString(t); err != nil {
			return err
		}
	}

	return nil
}
