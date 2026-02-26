// Copyright 2021 Tigera Inc. All rights reserved.

package query

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func TestGlobalAlert(t *testing.T) {
	testutils.HookLogrusForGinkgo()
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../report/service_suite.xml"
	ginkgo.RunSpecs(t, "GlobalAlert Test Suite", suiteConfig, reporterConfig)
}
