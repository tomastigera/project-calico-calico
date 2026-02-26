// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package keyselector

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestLabelSelector(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/keyselector_suite.xml"
	ginkgo.RunSpecs(t, "Key Selector Suite", suiteConfig, reporterConfig)
}
