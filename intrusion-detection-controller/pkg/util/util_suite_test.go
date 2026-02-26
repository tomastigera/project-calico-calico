// Copyright (c) 2022 Tigera, Inc. All rights reserved.
package util

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestUtil(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/util_suite.xml"
	ginkgo.RunSpecs(t, "Util Suite", suiteConfig, reporterConfig)
}
