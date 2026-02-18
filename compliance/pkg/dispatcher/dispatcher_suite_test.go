// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package dispatcher

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestDispatcher(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Dispatcher Suite")
}
