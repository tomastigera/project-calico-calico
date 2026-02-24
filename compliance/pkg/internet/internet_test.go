// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package internet_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/compliance/pkg/internet"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

var (
	public1 = net.MustParseCIDR("16.0.0.0/8")
	//public2  = net.MustParseCIDR("128.0.2.0/24")
	private1 = net.MustParseCIDR("10.5.0.0/16")
	private2 = net.MustParseCIDR("172.16.0.1/32")
	private3 = net.MustParseCIDR("192.168.24.0/24")
)

var _ = Describe("internet address checks", func() {
	It("should determine if a net is within a private range or not", func() {
		By("checking CIDR 16.0.0.0/8 is public")
		Expect(internet.NetContainsInternetAddr(public1)).To(BeTrue())

		By("checking CIDR 10.5.0.0/16 is private")
		Expect(internet.NetContainsInternetAddr(private1)).To(BeFalse())

		By("checking CIDR 172.16.0.1/32 is private")
		Expect(internet.NetContainsInternetAddr(private2)).To(BeFalse())

		By("checking CIDR 192.168.24.0/24 is private")
		Expect(internet.NetContainsInternetAddr(private3)).To(BeFalse())
	})

	It("should determine if a slice of nets is within a private range or not", func() {
		By("checking two private addresses are private")
		Expect(internet.NetsContainInternetAddr(
			[]net.IPNet{private1, private2},
		)).To(BeFalse())

		By("checking a public and private net is public")
		Expect(internet.NetsContainInternetAddr(
			[]net.IPNet{public1, private1},
		)).To(BeTrue())

		By("checking no nets is private")
		Expect(internet.NetsContainInternetAddr([]net.IPNet{})).To(BeFalse())
	})

	It("should determine if a slice of net pointers is within a private range or not", func() {
		By("checking two private addresses are private")
		Expect(internet.NetPointersContainInternetAddr(
			[]*net.IPNet{&private1, &private2},
		)).To(BeFalse())

		By("checking a public and private net is public")
		Expect(internet.NetPointersContainInternetAddr(
			[]*net.IPNet{&public1, &private1},
		)).To(BeTrue())

		By("checking no nets is private")
		Expect(internet.NetPointersContainInternetAddr([]*net.IPNet{})).To(BeFalse())
	})
})
