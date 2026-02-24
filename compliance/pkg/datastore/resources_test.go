// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package datastore

import (
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/resources"
)

// TODO(rlb): Compliance should have it's own view of supported types - not blindly use the full list from libcalico.
var _ = ginkgo.Describe("all typemetas are accounted for with corresponding list functions", func() {
	ginkgo.It("should find a list function for each supported type meta", func() {
		for _, r := range resources.GetAllResourceHelpers() {
			gomega.Expect(resourceHelpersMap).To(gomega.HaveKey(r.TypeMeta()))
		}
	})
})
