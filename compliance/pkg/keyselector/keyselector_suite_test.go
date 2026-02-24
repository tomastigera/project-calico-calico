// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package keyselector

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestLabelSelector(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Key Selector Suite")
}
