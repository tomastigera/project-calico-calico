// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package wafevents

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func init() {
	testutils.HookLogrusForGinkgo()
	logutils.ConfigureFormatter("test")
	logrus.SetLevel(logrus.DebugLevel)
}

func TestWafevents(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/wafevents_suite.xml"
	ginkgo.RunSpecs(t, "UT: felix/collector/wafevents", suiteConfig, reporterConfig)
}
