//  Copyright (c) 2016,2018 Tigera, Inc. All rights reserved.

package utils_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestUtils(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../report/utils_suite.xml"
	ginkgo.RunSpecs(t, "Utils Suite", suiteConfig, reporterConfig)
}
