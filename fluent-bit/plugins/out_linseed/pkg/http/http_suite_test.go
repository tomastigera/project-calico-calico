// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package http_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestLinseedOutPluginHTTP(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../../report/http_suite.xml"
	ginkgo.RunSpecs(t, "Linseed output plugin http test suite", suiteConfig, reporterConfig)
}
