package benchmark_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestBenchmark(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/benchmark_suite.xml"
	ginkgo.RunSpecs(t, "Benchmark Suite", suiteConfig, reporterConfig)
}
