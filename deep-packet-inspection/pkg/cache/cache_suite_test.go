// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package cache_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func TestCache(t *testing.T) {
	testutils.HookLogrusForGinkgo()

	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/cache.xml"
	ginkgo.RunSpecs(t, "Cache Suite", suiteConfig, reporterConfig)
}
