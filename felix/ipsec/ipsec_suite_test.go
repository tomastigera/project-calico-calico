// Copyright (c) 2018 Tigera, Inc. All rights reserved.

package ipsec_test

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

func TestConfig(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../report/ipsec_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "UT: felix/ipsec", []Reporter{junitReporter})
}
