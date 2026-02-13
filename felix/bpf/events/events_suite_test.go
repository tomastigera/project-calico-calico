// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package events

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func TestEvents(t *testing.T) {
	testutils.HookLogrusForGinkgo()
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/felix_bpf_events_suite.xml"
	ginkgo.RunSpecs(t, "UT: felix/bpf/events", suiteConfig, reporterConfig)
}
