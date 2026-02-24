// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package dispatcher_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func TestDispatcher(t *testing.T) {
	testutils.HookLogrusForGinkgo()
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/dispatcher_suite.xml"
	ginkgo.RunSpecs(t, "Dispatcher Suite", suiteConfig, reporterConfig)
}
