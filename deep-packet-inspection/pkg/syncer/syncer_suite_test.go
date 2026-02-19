// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package syncer_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func TestSyncer(t *testing.T) {
	testutils.HookLogrusForGinkgo()
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/syncer_suite.xml"
	ginkgo.RunSpecs(t, "Syncer Suite", suiteConfig, reporterConfig)
}
