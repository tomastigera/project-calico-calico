// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package endpoint

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestLinseedOutPluginEndpoint(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Linseed output plugin endpoint test suite")
}
