// Copyright (c) 2021 Tigera. All rights reserved.
package handler_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestProxy(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../report/proxy_suite.xml"
	ginkgo.RunSpecs(t, "Proxy Suite", suiteConfig, reporterConfig)
}
