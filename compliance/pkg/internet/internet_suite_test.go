// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package internet

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestInternetHelpers(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Internet Suite")
}
