// Copyright (c) 2018-2019 Tigera, Inc. All rights reserved.
package client

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Test compareIPv4StringSlice", func() {
	It("Properly compares IP string slices of the same length", func() {
		By("Checking that slices of length 1 are properly compared")
		ipSet1 := []string{"192.10.1.1"}
		ipSet2 := []string{"192.8.1.2"}
		Expect(compareIPv4StringSlice(ipSet1, ipSet2)).To(BeNumerically(">", 0))
		Expect(compareIPv4StringSlice(ipSet2, ipSet1)).To(BeNumerically("<", 0))

		By("Checking that slices of longer lengths are properly compared")
		ipSet1 = []string{"192.10.1.2", "10.10.1.2", "192.8.1.4"}
		ipSet2 = []string{"192.10.1.2", "10.10.1.2", "192.8.1.3"}
		Expect(compareIPv4StringSlice(ipSet1, ipSet2)).To(BeNumerically(">", 0))
		Expect(compareIPv4StringSlice(ipSet2, ipSet1)).To(BeNumerically("<", 0))

		By("Checking that equality holds true")
		ipSet1 = []string{"192.10.1.2"}
		ipSet2 = []string{"192.10.1.2"}
		Expect(compareIPv4StringSlice(ipSet1, ipSet2)).To(Equal(0))
	})

	It("Properly compares IP string slices of differing lengths", func() {
		By("Checking that slices are compared only depending on the contents not the length")
		ipSet1 := []string{"192.10.1.2"}
		ipSet2 := []string{"10.10.1.1", "10.10.1.2", "10.10.1.3"}
		Expect(compareIPv4StringSlice(ipSet1, ipSet2)).To(BeNumerically(">", 0))
		Expect(compareIPv4StringSlice(ipSet2, ipSet1)).To(BeNumerically("<", 0))

		By("Checking that slices are compared in order so IPs at the end may not be compared")
		ipSet1 = []string{"192.10.1.2"}
		ipSet2 = []string{"10.10.1.1", "10.10.1.2", "192.168.1.3"}
		Expect(compareIPv4StringSlice(ipSet1, ipSet2)).To(BeNumerically(">", 0))
		Expect(compareIPv4StringSlice(ipSet2, ipSet1)).To(BeNumerically("<", 0))

		ipSet1 = []string{"192.10.1.2", "10.10.1.2", "192.168.1.3"}
		ipSet2 = []string{"10.10.1.1"}
		Expect(compareIPv4StringSlice(ipSet1, ipSet2)).To(BeNumerically(">", 0))
		Expect(compareIPv4StringSlice(ipSet2, ipSet1)).To(BeNumerically("<", 0))
	})

	It("Properly compares empty string slices", func() {
		ipSet1 := []string{}
		ipSet2 := []string{}
		Expect(compareIPv4StringSlice(ipSet1, ipSet2)).To(Equal(0))
	})

	It("Properly handles IP strings that represent a subnet", func() {
		By("Checking that subnets are compared only when the IPs are equal")
		ipSet1 := []string{"192.10.0.0/24"}
		ipSet2 := []string{"192.10.0.0/16"}
		Expect(compareIPv4StringSlice(ipSet1, ipSet2)).To(BeNumerically(">", 0))
		Expect(compareIPv4StringSlice(ipSet2, ipSet1)).To(BeNumerically("<", 0))

		ipSet1 = []string{"192.10.1.1/8"}
		ipSet2 = []string{"192.8.1.2/16"}
		Expect(compareIPv4StringSlice(ipSet1, ipSet2)).To(BeNumerically(">", 0))
		Expect(compareIPv4StringSlice(ipSet2, ipSet1)).To(BeNumerically("<", 0))

		By("Checking that no subnet specified is counted as a value of 0")
		ipSet1 = []string{"192.10.0.0/8"}
		ipSet2 = []string{"192.10.0.0"}
		Expect(compareIPv4StringSlice(ipSet1, ipSet2)).To(BeNumerically(">", 0))
		Expect(compareIPv4StringSlice(ipSet2, ipSet1)).To(BeNumerically("<", 0))

		By("Checking that equality works with subnets")
		ipSet1 = []string{"192.10.0.0/16"}
		ipSet2 = []string{"192.10.0.0/16"}
		Expect(compareIPv4StringSlice(ipSet1, ipSet2)).To(Equal(0))

		By("Checking that subnets are properly separated from IP addresses")
		// If the logic just added the subnet mask to the IP, then some IPs would be commpared as equal when they would not be.
		ipSet1 = []string{"192.10.0.16"}
		ipSet2 = []string{"192.10.0.0/16"}
		Expect(compareIPv4StringSlice(ipSet1, ipSet2)).To(BeNumerically(">", 0))
		Expect(compareIPv4StringSlice(ipSet2, ipSet1)).To(BeNumerically("<", 0))
	})
})
