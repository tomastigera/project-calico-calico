// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.

package managedcluster

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestConfig(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../report/managedcluster_suite.xml"
	ginkgo.RunSpecs(t, "Managed cluster controller Suite", suiteConfig, reporterConfig)
}
