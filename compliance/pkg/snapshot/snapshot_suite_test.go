// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package snapshot

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestSnapshot(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/snapshot_suite.xml"
	ginkgo.RunSpecs(t, "Snapshot Suite", suiteConfig, reporterConfig)
}
