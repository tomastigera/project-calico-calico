// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package sethelper

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestSetHelper(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Set helper Suite")
}
