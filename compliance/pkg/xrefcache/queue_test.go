// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package xrefcache_test

import (
	"container/heap"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/compliance/pkg/xrefcache"
)

var (
	tr1 = &xrefcache.CacheEntryServiceEndpoints{}
	tr2 = &xrefcache.CacheEntryNetworkPolicy{}
	tr3 = &xrefcache.CacheEntryNamespace{}
	tr4 = &xrefcache.CacheEntryTier{}
)

var _ = Describe("Resource priority queue", func() {
	It("should empty the queue in the correct order", func() {
		By("Creating a queue and populating with different priority resources")
		q := &xrefcache.PriorityQueue{}
		heap.Init(q)

		heap.Push(q, &xrefcache.QueueItem{
			Entry:    tr1,
			Priority: 2,
		})
		heap.Push(q, &xrefcache.QueueItem{
			Entry:    tr2,
			Priority: 1,
		})
		heap.Push(q, &xrefcache.QueueItem{
			Entry:    tr3,
			Priority: 3,
		})
		heap.Push(q, &xrefcache.QueueItem{
			Entry:    tr4,
			Priority: 2,
		})

		By("Checking the items are popped in the correct order")
		qi, ok := heap.Pop(q).(*xrefcache.QueueItem)
		Expect(ok).To(BeTrue())
		Expect(qi.Entry).To(Equal(tr3))
		qi, ok = heap.Pop(q).(*xrefcache.QueueItem)
		Expect(ok).To(BeTrue())
		ra := qi.Entry
		qi, ok = heap.Pop(q).(*xrefcache.QueueItem)
		Expect(ok).To(BeTrue())
		rb := qi.Entry
		Expect(ra == tr1 || ra == tr4).To(BeTrue())
		Expect(rb == tr1 || rb == tr4).To(BeTrue())
		Expect(ra).ToNot(Equal(rb))
		qi, ok = heap.Pop(q).(*xrefcache.QueueItem)
		Expect(ok).To(BeTrue())
		Expect(qi.Entry).To(Equal(tr2))
	})
})
