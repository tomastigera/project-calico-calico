// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package middlewares_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestMiddlewares(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/middlewares_suite.xml"
	ginkgo.RunSpecs(t, "Middlewares Suite", suiteConfig, reporterConfig)
}
