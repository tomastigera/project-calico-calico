// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package ruleset

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestWAFMiddleware(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../../report/waf_ruleset_suite.xml"
	ginkgo.RunSpecs(t, "WAF Middleware test suite.", suiteConfig, reporterConfig)
}
