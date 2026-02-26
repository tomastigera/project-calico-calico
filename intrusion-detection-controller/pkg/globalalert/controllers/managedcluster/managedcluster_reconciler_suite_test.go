package managedcluster_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestManagedClusterReconciler(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../../report/managedcluster_reconciler_suite.xml"
	ginkgo.RunSpecs(t, "Mananged Cluster Reconciler Test Suite", suiteConfig, reporterConfig)
}
