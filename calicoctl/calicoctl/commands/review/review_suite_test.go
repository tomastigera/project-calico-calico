// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package review

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestReview(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../report/review_suite.xml"
	ginkgo.RunSpecs(t, "Review Suite", suiteConfig, reporterConfig)
}
