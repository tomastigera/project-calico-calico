package worker

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestWorkerAbstractStruct(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../report/worker_suite.xml"
	ginkgo.RunSpecs(t, "Abstract Worker Test Suite", suiteConfig, reporterConfig)
}
