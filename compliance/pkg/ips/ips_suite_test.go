// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package ips

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestLabelSelector(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/ips_suite.xml"
	ginkgo.RunSpecs(t, "IPs Suite", suiteConfig, reporterConfig)
}
