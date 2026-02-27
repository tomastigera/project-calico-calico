package geodb

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestGeoDB(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../report/geodb_suite.xml"
	ginkgo.RunSpecs(t, "GeoDB Suite", suiteConfig, reporterConfig)
}
