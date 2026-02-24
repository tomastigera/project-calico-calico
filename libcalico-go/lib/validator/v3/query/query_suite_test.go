// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package query

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func TestQueryValidator(t *testing.T) {
	testutils.HookLogrusForGinkgo()
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../../report/v3_query_validator_suite.xml"
	ginkgo.RunSpecs(t, "v3 Query Validator Suite", suiteConfig, reporterConfig)
}
