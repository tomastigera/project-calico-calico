// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package proxy_test

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
