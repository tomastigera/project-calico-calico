// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package k8sutils

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func init() {
	testutils.HookLogrusForGinkgo()
}

func TestK8sUtilsGinkgo(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../report/k8sutils_suite.xml"
	ginkgo.RunSpecs(t, "UT: felix/k8sutils", suiteConfig, reporterConfig)
}
