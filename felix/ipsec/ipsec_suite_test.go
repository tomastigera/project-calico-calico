// Copyright (c) 2018 Tigera, Inc. All rights reserved.

package ipsec_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func init() {
	testutils.HookLogrusForGinkgo()
}

func TestConfig(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../report/ipsec_suite.xml"
	ginkgo.RunSpecs(t, "UT: felix/ipsec", suiteConfig, reporterConfig)
}
