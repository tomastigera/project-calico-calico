// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package fv_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func TestFv(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	testutils.HookLogrusForGinkgo()
	ginkgo.RunSpecs(t, "[FV] Voltron-Guardian e2e Suite")
}
