// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package flow_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestFlow(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/flow_suite.xml"
	ginkgo.RunSpecs(t, "Flow Suite", suiteConfig, reporterConfig)
}
