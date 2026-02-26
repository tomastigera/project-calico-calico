package tunnel_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestTunnel(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/tunnel_suite.xml"
	ginkgo.RunSpecs(t, "Tunnel Suite", suiteConfig, reporterConfig)
}
