package waf_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestWafAlertGeneration(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../../report/waf_suite.xml"
	ginkgo.RunSpecs(t, "WAF controllers Suite", suiteConfig, reporterConfig)
}
