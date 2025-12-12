// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package capture_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func init() {
	testutils.HookLogrusForGinkgo()
	logutils.ConfigureFormatter("test")
}

func TestCalculationCapture(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../report/capture_calc_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "UT: felix/calc/capture", []Reporter{junitReporter})
}
