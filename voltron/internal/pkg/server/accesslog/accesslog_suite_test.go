// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package accesslog_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestServer(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Access Log Suite")
}
