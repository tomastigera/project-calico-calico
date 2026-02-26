// Copyright (c) 2020 Tigera, Inc. All rights reserved.
package fortimanager_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func TestHandler(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	testutils.HookLogrusForGinkgo()
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/fortigate_suite.xml"
	ginkgo.RunSpecs(t, "FortiGate Test Suite", suiteConfig, reporterConfig)
}
