// Copyright (c) 2024 Tigera. All rights reserved.
package client

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestAuth(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "QueryServerClient Test Suite")
}
