// Copyright (c) 2024 Tigera. All rights reserved.
package auth

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestAuth(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/auth_suite.xml"
	ginkgo.RunSpecs(t, "QueryServer Auth Suite", suiteConfig, reporterConfig)
}
