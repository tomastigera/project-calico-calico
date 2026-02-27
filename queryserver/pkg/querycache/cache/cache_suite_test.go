// Copyright (c) 2023 Tigera, Inc. All rights reserved.
package cache

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestCommands(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../report/cache_suite.xml"
	ginkgo.RunSpecs(t, "Querycache Cache Suite", suiteConfig, reporterConfig)
}
