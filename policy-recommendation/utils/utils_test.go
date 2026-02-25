// Copyright (c) 2024 Tigera, Inc. All rights reserved
package utils

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("getRFC1123PolicyName", func() {
	DescribeTable("should return the policy name with suffix if it is valid",
		func(tier, name, suffix, expected string, wantErr bool) {
			result, err := getRFC1123PolicyName(tier, name, suffix)
			if wantErr {
				Expect(err).To(HaveOccurred())
			} else {
				Expect(result).To(Equal(expected))
			}
		},
		Entry("valid name", "tier", "a", "x1ed6", "tier.a-x1ed6", false),
		Entry("valid name with long name", "tier", "a123456789012345678901234567890123456789015432540", "x1ed6", "tier.a123456789012345678901234567890123456789015432540-x1ed6", false),
		Entry("valid name with long name cut down", "tier", "a123456789012345678901234567890123456789015432540243243439385802860348504393405", "x1ed6", "tier.a123456789012345678901234567890123456789015432540243-x1ed6", false),
		Entry("invalid name", "tier", "", "x1ed6", "", true),
		Entry("invalid name", "", "my-name", "x1ed6", "", true),
		Entry("invalid name with long tier name", "tiera12345678901234567000000000000000000000000000000000000000000000000", "a12345678901234567890123456789012345678901543254024324343", "x1ed6", "", true),
	)
})
