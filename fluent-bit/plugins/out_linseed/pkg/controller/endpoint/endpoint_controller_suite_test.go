// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package endpoint

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestLinseedOutPluginEndpoint(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../../../report/endpoint_controller_suite.xml"
	ginkgo.RunSpecs(t, "Linseed output plugin endpoint test suite", suiteConfig, reporterConfig)
}
