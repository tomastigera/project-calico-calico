// Copyright (c) 2023 Tigera, Inc. All rights reserved.
package cache

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestCommands(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Querycache Cache Suite")
}
