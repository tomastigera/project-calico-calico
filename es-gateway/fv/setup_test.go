// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package fv_test

import (
	"context"
	"testing"
	"time"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/linseed/pkg/config"
)

var (
	ctx        context.Context
	kibana     *containers.Container
	challenger *containers.Container
)

// setupAndTeardown provides common setup and teardown logic for all FV tests to use.
func setupAndTeardown(t *testing.T, args *RunChallengerArgs, kibanaArgs *RunKibanaArgs) func() {
	// Hook logrus into testing.T
	config.ConfigureLogging("DEBUG")
	logCancel := logutils.RedirectLogrusToTestingT(t)

	// Start a Kibana proxy instance.
	if args != nil {
		challenger = RunChallenger(t, args)
	}

	// Configure Kibana instance
	if kibanaArgs != nil {
		kibana = RunKibana(t, kibanaArgs)
	}

	// Set up context with a timeout.
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), 60*time.Second)

	return func() {
		if challenger != nil {
			challenger.Stop()
		}
		if kibana != nil {
			kibana.Stop()
		}
		logCancel()
		cancel()
	}
}
