// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package docindex

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestLabelSelector(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/docindex_suite.xml"
	ginkgo.RunSpecs(t, "Document index Suite", suiteConfig, reporterConfig)
}
