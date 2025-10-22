// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package fv_test

import (
	"fmt"
	"testing"

	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

type RunChallengerArgs struct {
	Port                  int
	HealthPort            int
	ElasticEndpoint       string
	ElasticClientCertPath string
	ElasticCAPath         string
	TenantID              string
}

func DefaultChallengerArgs() *RunChallengerArgs {
	return &RunChallengerArgs{
		Port:            5555,
		ElasticEndpoint: "http://localhost:9200",
		TenantID:        "A",
	}
}

func RunChallenger(t *testing.T, args *RunChallengerArgs) *containers.Container {
	// The container library uses gomega, so we need to connect our testing.T to it.
	gomega.RegisterTestingT(t)

	dockerArgs := []string{
		"--net=host",
		"-e", "ES_GATEWAY_LOG_LEVEL=TRACE",
		"-e", "ES_GATEWAY_KIBANA_CATCH_ALL_ROUTE=/",
		"-e", fmt.Sprintf("ES_GATEWAY_CHALLENGER_PORT=%d", args.Port),
		"-e", fmt.Sprintf("ES_GATEWAY_ELASTIC_ENDPOINT=%s", args.ElasticEndpoint),
		"-e", fmt.Sprintf("TENANT_ID=%s", args.TenantID),
		"tigera/es-gateway:latest",
		"-run-as-challenger",
	}

	name := "tigera-challenger-fv"

	c := containers.Run(name, containers.RunOpts{AutoRemove: true, OutputWriter: logutils.TestingTWriter{T: t}}, dockerArgs...)
	c.StopLogs()
	return c
}

type RunKibanaArgs struct {
	Image        string
	ElasticHosts string
}

func RunKibana(t *testing.T, args *RunKibanaArgs) *containers.Container {
	// The container library uses gomega, so we need to connect our testing.T to it.
	gomega.RegisterTestingT(t)

	dockerArgs := []string{
		"--net=host",
		"-e", fmt.Sprintf("ELASTICSEARCH_HOSTS=%s", args.ElasticHosts),
		args.Image,
	}

	name := "tigera-kibana"

	c := containers.Run(name, containers.RunOpts{AutoRemove: true, OutputWriter: logutils.TestingTWriter{T: t}}, dockerArgs...)
	c.StopLogs()
	return c
}
