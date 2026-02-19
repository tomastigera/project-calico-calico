// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package nfqueue

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("packetDataList handling", func() {
	var list *packetDataList
	var slice [5]*packetData

	BeforeEach(func() {
		list = &packetDataList{}
		for i := uint32(0); i < 5; i++ {
			pd := &packetData{
				packetID: i,
			}
			list.add(pd)
			slice[i] = pd
		}
		Expect(list.length).To(Equal(5))
	})

	When("packetData is added to the list", func() {
		It("adds in the correct order going forward", func() {
			d := list.first
			for i := uint32(0); i < 5; i++ {
				Expect(d).NotTo(BeNil())
				Expect(d.packetID).To(Equal(i))
				d = d.next
			}
			Expect(d).To(BeNil())
		})

		It("adds in the correct order going backwards", func() {
			d := list.last
			for i := uint32(0); i < 5; i++ {
				Expect(d).NotTo(BeNil())
				Expect(d.packetID).To(Equal(4 - i))
				d = d.prev
			}
			Expect(d).To(BeNil())
		})

		It("panics if the item is already in a list", func() {
			otherList := &packetDataList{}
			otherItem := &packetData{}
			otherList.add(otherItem)
			Expect(func() { list.add(otherItem) }).To(Panic())
		})
	})

	When("packetData is removed the list", func() {
		It("maintains the correct order going forward", func() {
			// Remove the middle entry.
			list.remove(slice[2])

			// Should be updated to not be in the list.
			Expect(slice[2].prev).To(BeNil())
			Expect(slice[2].next).To(BeNil())
			Expect(list.length).To(Equal(4))

			// Check the list is complete apart from the middle entry.
			d := list.first
			for i := uint32(0); i < 5; i++ {
				if i == 2 {
					continue
				}
				Expect(d).NotTo(BeNil())
				Expect(d.packetID).To(Equal(i))
				d = d.next
			}
			Expect(d).To(BeNil())
		})

		It("maintains the correct order going backwards", func() {
			// Remove the middle entry.
			list.remove(slice[2])

			// Should be updated to not be in the list.
			Expect(slice[2].prev).To(BeNil())
			Expect(slice[2].next).To(BeNil())
			Expect(list.length).To(Equal(4))

			// Check the list is complete apart from the middle entry.
			d := list.last
			for i := uint32(0); i < 5; i++ {
				if i == 2 {
					continue
				}
				Expect(d).NotTo(BeNil())
				Expect(d.packetID).To(Equal(4 - i))
				d = d.prev
			}
			Expect(d).To(BeNil())
		})

		It("panics if the item is not in a list", func() {
			otherItem := &packetData{}
			Expect(func() { list.remove(otherItem) }).To(Panic())
		})

		It("panics if the item is in a different list", func() {
			otherList := &packetDataList{}
			otherItem := &packetData{}
			otherList.add(otherItem)
			Expect(func() { list.remove(otherItem) }).To(Panic())
		})
	})

	When("all packetData is removed from the list from first to last", func() {
		It("correctly updates the entries and the list", func() {
			for i := 0; i < 5; i++ {
				Expect(list.length).To(Equal(5 - i))
				Expect(list.first).To(Equal(slice[i]))
				Expect(list.last).To(Equal(slice[4]))
				list.remove(slice[i])
				Expect(slice[i].prev).To(BeNil())
				Expect(slice[i].next).To(BeNil())
			}
			Expect(list.length).To(Equal(0))
			Expect(list.first).To(BeNil())
			Expect(list.last).To(BeNil())
		})
	})

	When("all packetData is removed from the list from last to first", func() {
		It("correctly updates the entries and the list", func() {
			for i := 0; i < 5; i++ {
				Expect(list.length).To(Equal(5 - i))
				Expect(list.first).To(Equal(slice[0]))
				Expect(list.last).To(Equal(slice[4-i]))
				list.remove(slice[4-i])
				Expect(slice[4-i].prev).To(BeNil())
				Expect(slice[4-i].next).To(BeNil())
			}
			Expect(list.length).To(Equal(0))
			Expect(list.first).To(BeNil())
			Expect(list.last).To(BeNil())
		})
	})
})
