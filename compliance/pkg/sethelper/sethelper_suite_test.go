// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package sethelper

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestSetHelper(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/sethelper_suite.xml"
	ginkgo.RunSpecs(t, "Set helper Suite", suiteConfig, reporterConfig)
}
