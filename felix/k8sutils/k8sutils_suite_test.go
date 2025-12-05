// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package k8sutils

import (
	"testing"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func init() {
	testutils.HookLogrusForGinkgo()
}

func TestK8sUtilsGinkgo(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../report/k8sutils_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "UT: felix/k8sutils", []Reporter{junitReporter})
}
