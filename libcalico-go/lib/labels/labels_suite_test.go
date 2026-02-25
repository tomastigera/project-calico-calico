// Copyright (c) 2023 Tigera, Inc. All rights reserved.
package labels

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestClient(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/labels_suite.xml"
	ginkgo.RunSpecs(t, "labels suite", suiteConfig, reporterConfig)
}
