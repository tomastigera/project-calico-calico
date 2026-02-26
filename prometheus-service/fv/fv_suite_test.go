// Copyright (c) 2021 Tigera. All rights reserved.
package fv_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestFv(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../report/fv_suite.xml"
	ginkgo.RunSpecs(t, "Recommendation Fv Suite", suiteConfig, reporterConfig)
}
