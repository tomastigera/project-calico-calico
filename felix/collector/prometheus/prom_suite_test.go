// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package prometheus

import (
	"testing"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func init() {
	testutils.HookLogrusForGinkgo()
	logutils.ConfigureFormatter("test")
	logrus.SetLevel(logrus.DebugLevel)
}

func TestPrometheus(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../report/prom_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "UT: felix/collector/prometheus", []Reporter{junitReporter})
}
