// Copyright (c) 2020 Tigera, Inc. All rights reserved.

package capture

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func TestCollector(t *testing.T) {
	testutils.HookLogrusForGinkgo()
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../report/capture_suite.xml"
	ginkgo.RunSpecs(t, "UT: felix/capture", suiteConfig, reporterConfig)
}
