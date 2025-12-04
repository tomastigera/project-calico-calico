// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package dnsdeniedpacket_test

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

func TestPolicysync(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../report/dnsdeniedpacket.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "UT: felix/nfqueue/dnsdeniedpacket", []Reporter{junitReporter})
}
