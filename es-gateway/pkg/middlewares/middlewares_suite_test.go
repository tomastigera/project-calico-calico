// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package middlewares_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestMiddlewares(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Middlewares Suite")
}
