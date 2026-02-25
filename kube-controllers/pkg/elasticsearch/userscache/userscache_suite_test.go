// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package userscache

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestConfig(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "./report/userscache.xml"
	ginkgo.RunSpecs(t, "OIDCUserCache Suite", suiteConfig, reporterConfig)
}
