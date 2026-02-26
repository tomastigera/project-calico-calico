// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package config_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestServer(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../report/config_suite.xml"
	ginkgo.RunSpecs(t, "Config Suite", suiteConfig, reporterConfig)
}
