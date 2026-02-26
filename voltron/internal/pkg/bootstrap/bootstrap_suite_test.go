// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package bootstrap

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestClient(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../report/bootstrap_suite.xml"
	ginkgo.RunSpecs(t, "Bootstrap Suite", suiteConfig, reporterConfig)
}
