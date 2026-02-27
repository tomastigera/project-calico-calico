// Copyright 2022 Tigera Inc. All rights reserved.
package sync

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestClientUtils(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../report/client_suite.xml"
	ginkgo.RunSpecs(t, "Client suite", suiteConfig, reporterConfig)
}
