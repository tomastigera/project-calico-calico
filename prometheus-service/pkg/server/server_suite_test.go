// Copyright (c) 2021 Tigera. All rights reserved.
package server_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestServer(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/server_suite.xml"
	ginkgo.RunSpecs(t, "Server Suite", suiteConfig, reporterConfig)
}
