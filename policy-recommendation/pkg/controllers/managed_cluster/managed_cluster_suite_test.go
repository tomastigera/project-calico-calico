// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package managed_cluster_controller_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func TestManagedClusterController(t *testing.T) {
	testutils.HookLogrusForGinkgo()
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../report/managed_cluster_suite.xml"
	ginkgo.RunSpecs(t, "ManagedCluster Controller Suite", suiteConfig, reporterConfig)
}
