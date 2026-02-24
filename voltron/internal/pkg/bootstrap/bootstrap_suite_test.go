// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package bootstrap

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestClient(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Bootstrap Suite")
}
