// Copyright (c) 2026 Tigera, Inc. All rights reserved.
package recordprocessor

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestRecordProcessor(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../../report/record_processor_suite.xml"
	ginkgo.RunSpecs(t, "Linseed output plugin record processor test suite", suiteConfig, reporterConfig)
}
