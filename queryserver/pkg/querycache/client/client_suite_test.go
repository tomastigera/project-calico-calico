package client

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestCommands(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../report/querycache_client_suite.xml"
	ginkgo.RunSpecs(t, "Querycache Client Suite", suiteConfig, reporterConfig)
}
