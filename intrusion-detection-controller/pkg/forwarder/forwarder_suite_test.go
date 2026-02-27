// Copyright 2021 Tigera Inc. All rights reserved.

package forwarder

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func TestEventForwarder(t *testing.T) {
	testutils.HookLogrusForGinkgo()
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/forwarder_suite.xml"
	ginkgo.RunSpecs(t, "Event Forwarder", suiteConfig, reporterConfig)
}
