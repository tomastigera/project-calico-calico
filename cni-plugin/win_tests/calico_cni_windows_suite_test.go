//  Copyright (c) 2016,2018 Tigera, Inc. All rights reserved.

package main_windows_test

import (
	"os"
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func init() {
	testutils.HookLogrusForGinkgo()
}

func TestCalicoCni(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reportPath := os.Getenv("REPORT")
	if reportPath == "" {
		// Default the report path if not specified.
		reportPath = "../report/windows_suite.xml"
	}
	reporterConfig.JUnitReport = reportPath
	ginkgo.RunSpecs(t, "CNI suite (Windows)", suiteConfig, reporterConfig)
}
