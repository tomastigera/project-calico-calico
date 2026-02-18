// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package docindex_test

import (
	"math/rand"
	"sort"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/compliance/pkg/docindex"
)

var _ = Describe("Document index tests", func() {
	It("should order indexes correctly", func() {

		By("Creating a bunch of ids")
		id1 := docindex.New("1")
		id2 := docindex.New("1.1")
		id3 := docindex.New("1.1.1")
		id4 := docindex.New("1.1.abc")
		id5 := docindex.New("1.1.abcd")
		id6 := docindex.New("1.1.bcd")
		id7 := docindex.New("1.2.3")
		id8 := docindex.New("1.8")
		id9 := docindex.New("1.abc")
		id10 := docindex.New("1.abc.1")
		id11 := docindex.New("2")
		id12 := docindex.New("2.1.1.1.1")
		id13 := docindex.New("20.1")
		id14 := docindex.New("abcd")

		correctOrder := docindex.SortableDocIndexes{
			id1, id2, id3, id4, id5, id6, id7, id8, id9, id10, id11, id12, id13, id14,
		}

		for i := 0; i < 10; i++ {
			By("creating a shuffled list and shuffling some more")
			randomOrder := docindex.SortableDocIndexes{
				id8, id14, id1, id4, id9, id7, id6, id3, id5, id12, id11, id10, id13, id2,
			}
			swap := func(i, j int) {
				randomOrder[i], randomOrder[j] = randomOrder[j], randomOrder[i]
			}
			rand.Shuffle(len(randomOrder), swap)

			By("sorting and checking expected order")
			sort.Sort(randomOrder)

			Expect(randomOrder).To(Equal(correctOrder))
		}
	})

	It("should handle one index containing another", func() {
		By("Creating a bunch of ids")
		id1 := docindex.New("1")
		id2 := docindex.New("1.1")
		id3 := docindex.New("1.1.1")
		id4 := docindex.New("2")
		id5 := docindex.New("1.abc")
		id6 := docindex.New("1.abc.1")
		id7 := docindex.New("2.1.1.1.1")

		By("Validating 1 contains 1.1")
		Expect(id1.Contains(id2)).To(BeTrue())
		Expect(id2.Contains(id1)).To(BeFalse())

		By("Validating 1 contains 1.1.1")
		Expect(id1.Contains(id3)).To(BeTrue())
		Expect(id3.Contains(id1)).To(BeFalse())

		By("Validating 1.1 contains 1.1")
		Expect(id2.Contains(id2)).To(BeTrue())

		By("Validating 2 does not contain 1.1")
		Expect(id4.Contains(id2)).To(BeFalse())
		Expect(id2.Contains(id4)).To(BeFalse())

		By("Validating 1.abc contains 1.abc.1")
		Expect(id5.Contains(id6)).To(BeTrue())
		Expect(id6.Contains(id5)).To(BeFalse())

		By("Validating 2 contains 2.1.1.1.1")
		Expect(id4.Contains(id7)).To(BeTrue())
		Expect(id7.Contains(id4)).To(BeFalse())
	})
})
