// Copyright (c) 2018 Tigera, Inc. All rights reserved.

package federationsyncer

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
	reporterConfig.JUnitReport = "../../../../report/federationsyncer_suite.xml"
	ginkgo.RunSpecs(t, "federationsyncer test suite", suiteConfig, reporterConfig)
}
