// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package list

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestResourceListing(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "List Suite")
}
