// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package handlers_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestGateway(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/gateway_suite.xml"
	ginkgo.RunSpecs(t, "Gateway Suite", suiteConfig, reporterConfig)
}
