// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package parser

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestWAFMiddleware(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "WAF Middleware test suite.")
}
