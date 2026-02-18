// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package ips_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/compliance/pkg/ips"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var _ = Describe("Normalized IP address tests", func() {
	It("normalize valid addresses", func() {
		By("Removing leading zeros for IPv6")
		ip, err := ips.NormalizeIP("0:0::1234")
		Expect(err).NotTo(HaveOccurred())
		Expect(ip).To(Equal("::1234"))

		By("Using consistent case")
		upper, err := ips.NormalizeIP("::123A")
		Expect(err).ToNot(HaveOccurred())
		lower, err := ips.NormalizeIP("::123a")
		Expect(err).ToNot(HaveOccurred())
		Expect(upper).To(Equal(lower))

		By("Converting IPv4 in IPv6 back to IPv4")
		ip, err = ips.NormalizeIP("::ffff:0102:0304")
		Expect(err).ToNot(HaveOccurred())
		Expect(ip).To(Equal("1.2.3.4"))

		By("Converting a set of IP strings")
		s, err := ips.NormalizedIPSet("::ffff:0102:0304", "0:0::1234", "1.200.43.16")
		Expect(err).ToNot(HaveOccurred())
		Expect(s.Equals(set.From("1.200.43.16", "::1234", "1.2.3.4"))).To(BeTrue())
	})

	It("errors for invalid address formats", func() {
		// Starting from go 1.17, IPv4 with leading zeros are invalid
		// See: https://github.com/golang/go/issues/30999 and https://go-review.googlesource.com/c/go/+/361534/
		By("Reject leading zeros for IPv4")
		_, err := ips.NormalizeIP("001.200.043.016")
		Expect(err).To(HaveOccurred())

		By("Normalizing an invalid IP")
		_, err = ips.NormalizeIP("a.123.2.3")
		Expect(err).To(HaveOccurred())

		By("Converting a set of IP strings with one invalid")
		s, err := ips.NormalizedIPSet("::ffff:0102:0304", "0:0::1234", "1.200.43.16", "a.1.2.3")
		Expect(err).To(HaveOccurred())
		Expect(s.Equals(set.From("1.200.43.16", "::1234", "1.2.3.4"))).To(BeTrue())
	})
})
