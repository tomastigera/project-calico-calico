// Copyright (c) 2019 Tigera, Inc. SelectAll rights reserved.
package xrefcache

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func TestXrefCache(t *testing.T) {
	testutils.HookLogrusForGinkgo()
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/xrefcache_suite.xml"
	ginkgo.RunSpecs(t, "Xref XrefCache Suite", suiteConfig, reporterConfig)
}
