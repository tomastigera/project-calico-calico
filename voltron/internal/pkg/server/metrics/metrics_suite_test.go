// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package metrics

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestServer(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../../report/metrics_suite.xml"
	ginkgo.RunSpecs(t, "Access Log Suite", suiteConfig, reporterConfig)
}
