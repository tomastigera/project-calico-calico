// Copyright (c) 2019 Tigera, Inc. SelectAll rights reserved.
package datastore

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
	reporterConfig.JUnitReport = "../../report/datastore_suite.xml"
	ginkgo.RunSpecs(t, "Datastore Suite", suiteConfig, reporterConfig)
}
