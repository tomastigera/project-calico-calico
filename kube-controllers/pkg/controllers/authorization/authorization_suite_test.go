// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.

package authorization

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func init() {
	testutils.HookLogrusForGinkgo()
	logrus.SetLevel(logrus.DebugLevel)
}

func TestConfig(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "report/authorization.xml"
	ginkgo.RunSpecs(t, "Authorization controller Suite", suiteConfig, reporterConfig)
}
