// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package config

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestLinseedOutPluginConfig(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../../report/config_suite.xml"
	ginkgo.RunSpecs(t, "Linseed output plugin config test suite", suiteConfig, reporterConfig)
}
