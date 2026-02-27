// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package policyrec_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func TestPolicyRec(t *testing.T) {
	testutils.HookLogrusForGinkgo()
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/policyrec_suite.xml"
	ginkgo.RunSpecs(t, "Policy Recommendation Suite", suiteConfig, reporterConfig)
}
