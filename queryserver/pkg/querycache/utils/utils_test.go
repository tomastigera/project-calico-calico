package utils

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("", func() {
	Context("test BuildSubstringRegexMatcher", func() {
		It("should fail if list is empty", func() {
			_, err := BuildSubstringRegexMatcher([]string{})
			Expect(err).Should(HaveOccurred())
		})

		It("should match all strings that have a substring in the list", func() {
			list := []string{"foo", "bar"}
			regex, err := BuildSubstringRegexMatcher(list)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(regex.MatchString("foo")).To(BeTrue())
			Expect(regex.MatchString("a foo fee")).To(BeTrue())
			Expect(regex.MatchString("(foo)")).To(BeTrue())

			Expect(regex.MatchString("foo bar")).To(BeTrue())
			Expect(regex.MatchString("{{bar}}")).To(BeTrue())
			Expect(regex.MatchString("bbarr")).To(BeTrue())

			Expect(regex.MatchString("")).To(BeFalse())
			Expect(regex.MatchString("bbaarr")).To(BeFalse())
			Expect(regex.MatchString("oof")).To(BeFalse())
		})

		It("should match everything when list has empty string", func() {
			list := []string{""}
			regex, err := BuildSubstringRegexMatcher(list)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(regex.MatchString("a")).To(BeTrue())
			Expect(regex.MatchString("")).To(BeTrue())
			Expect(regex.MatchString(" ")).To(BeTrue())
			Expect(regex.MatchString("1234*")).To(BeTrue())
		})
	})
})
