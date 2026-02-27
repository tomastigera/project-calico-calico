// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package list

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestResourceListing(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/list_suite.xml"
	ginkgo.RunSpecs(t, "List Suite", suiteConfig, reporterConfig)
}
