// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package hashutils_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/projectcalico/calico/compliance/pkg/hashutils"
)

var _ = Describe("Id", func() {
	It("should return the suffix if short enough", func() {
		Expect(GetLengthLimitedName("felix", 10)).To(Equal("felix"))
	})
	It("should return a shortened hashed name when too long", func() {
		name := GetLengthLimitedName("1234567891123456789112345678910001234567891012345678911234567891123456789100012345678910", 50)
		Expect(name).To(HaveLen(50))
		Expect(name).To(Equal("123456789112345678911234567891000123456789-q6fu3r9"))
	})
})
