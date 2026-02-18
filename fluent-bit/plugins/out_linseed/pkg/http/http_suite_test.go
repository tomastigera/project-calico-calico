// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package http_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestLinseedOutPluginHTTP(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Linseed output plugin http test suite")
}
