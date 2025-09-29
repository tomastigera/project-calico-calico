// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package http_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestLinseedOutPluginHTTP(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Linseed output plugin http test suite")
}
