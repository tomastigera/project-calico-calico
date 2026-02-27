package health

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestIDCHealthSuite(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/health_suite.xml"
	ginkgo.RunSpecs(t, "IDC Health Suite Tests", suiteConfig, reporterConfig)
}
