// Copyright (c) 2022 Tigera. All rights reserved.
package query

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestAuth(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../report/query_suite.xml"
	ginkgo.RunSpecs(t, "QueryServer Query Test Suite", suiteConfig, reporterConfig)
}
