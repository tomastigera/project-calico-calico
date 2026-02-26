// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package recommendation_controller_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func TestRecommendationController(t *testing.T) {
	testutils.HookLogrusForGinkgo()
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../report/recommendation_suite.xml"
	ginkgo.RunSpecs(t, "Recommendation Controllers Suite", suiteConfig, reporterConfig)
}
