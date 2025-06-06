// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package nonclusterhost_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func TestClient(t *testing.T) {
	testutils.HookLogrusForGinkgo()
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../report/nonclusterhost_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "NonClusterHost Test Suite", []Reporter{junitReporter})
}
