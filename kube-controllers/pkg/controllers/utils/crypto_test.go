// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package utils

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Test password generation", func() {
	It("should generate the correct password lengths", func() {
		for l := range 100 {
			p := GeneratePassword(l)
			Expect(p).To(HaveLen(l), "GeneratePassword returned result with incorrect length")
		}
	})

	It("should not generate duplicates", func() {
		seenPasswords := map[string]bool{}
		seenChars := map[rune]bool{}
		for range 1000 {
			p := GeneratePassword(22) // 132 bits of entropy, vanishingly unlikely to see dupes by chance
			Expect(seenPasswords).NotTo(HaveKey(p), "GeneratePassword generated duplicate passwords")
			seenPasswords[p] = true
			for _, r := range p {
				seenChars[r] = true
			}
		}
		Expect(seenChars).To(HaveLen(len(chars)), "GeneratePassword didn't use every character after many trials")
	})
})

var _ = Describe("Test hash generation", func() {
	It("should generate a hash with the correct length", func() {
		const object = "test"
		Expect(GenerateTruncatedHash(object, -500)).To(HaveLen(64))
		Expect(GenerateTruncatedHash(object, -1)).To(HaveLen(64))
		Expect(GenerateTruncatedHash(object, 0)).To(HaveLen(0))
		Expect(GenerateTruncatedHash(object, 1)).To(HaveLen(1))
		Expect(GenerateTruncatedHash(object, 30)).To(HaveLen(30))
		Expect(GenerateTruncatedHash(object, 64)).To(HaveLen(64))
		Expect(GenerateTruncatedHash(object, 500)).To(HaveLen(64))
	})
})
