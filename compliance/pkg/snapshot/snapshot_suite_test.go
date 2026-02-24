// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package snapshot

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestSnapshot(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Snapshot Suite")
}
