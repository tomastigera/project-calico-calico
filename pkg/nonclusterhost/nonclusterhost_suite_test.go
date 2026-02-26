// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package nonclusterhost_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func TestClient(t *testing.T) {
	testutils.HookLogrusForGinkgo()
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../report/nonclusterhost_suite.xml"
	ginkgo.RunSpecs(t, "NonClusterHost Test Suite", suiteConfig, reporterConfig)
}
