// Copyright (c) 2024 Tigera Inc. All rights reserved.
package watcher_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func TestControllers(t *testing.T) {
	testutils.HookLogrusForGinkgo()
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../report/watcher_suite.xml"
	ginkgo.RunSpecs(t, "Recommendation Watcher Suite", suiteConfig, reporterConfig)
}
