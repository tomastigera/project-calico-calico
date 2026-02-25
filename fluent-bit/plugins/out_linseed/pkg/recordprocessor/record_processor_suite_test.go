// Copyright (c) 2026 Tigera, Inc. All rights reserved.
package recordprocessor

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestRecordProcessor(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Linseed output plugin record processor test suite")
}
