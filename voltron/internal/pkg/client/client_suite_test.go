// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package client_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestClient(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../report/client_suite.xml"
	ginkgo.RunSpecs(t, "Client Suite", suiteConfig, reporterConfig)
}
