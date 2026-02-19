// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package nfqueue_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func init() {
	testutils.HookLogrusForGinkgo()
}

func TestPolicysync(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../report/nfqueue.xml"
	ginkgo.RunSpecs(t, "UT: felix/nfqueue", suiteConfig, reporterConfig)
}
