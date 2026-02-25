package maputil

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("maputil", func() {
	Context("Copy - create a deep copy", func() {
		It("should not reflect the changes made on copied map in source map", func() {
			srcValue := "src_value"
			cpValue := "cp_value"

			src := map[string]any{
				"a": map[string]any{"b": srcValue},
				"c": srcValue,
				"d": map[string]any{"e": map[string]any{"f": srcValue}},
			}
			Expect(src["a"].(map[string]any)["b"]).Should(Equal(srcValue))
			Expect(src["c"]).Should(Equal(srcValue))
			Expect(src["d"].(map[string]any)["e"].(map[string]any)["f"]).Should(Equal(srcValue))

			cp, err := Copy(src)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(src).Should(BeEquivalentTo(cp))

			cp["a"].(map[string]any)["b"] = cpValue
			cp["c"] = cpValue
			cp["d"].(map[string]any)["e"].(map[string]any)["f"] = cpValue
			Expect(src).ShouldNot(BeEquivalentTo(cp))

			Expect(src["a"].(map[string]any)["b"]).Should(Equal(srcValue))
			Expect(src["c"]).Should(Equal(srcValue))
			Expect(src["d"].(map[string]any)["e"].(map[string]any)["f"]).Should(Equal(srcValue))
			Expect(cp["a"].(map[string]any)["b"]).Should(Equal(cpValue))
			Expect(cp["c"]).Should(Equal(cpValue))
			Expect(cp["d"].(map[string]any)["e"].(map[string]any)["f"]).Should(Equal(cpValue))
		})
	})

	Context("CreateLabelValuePairStr", func() {
		It("should create empty string givne empty map", func() {
			result := CreateLabelValuePairStr(make(map[string]string))

			Expect(result).To(Equal(""))
		})

		It("should key value pair string given non empty map", func() {
			result := CreateLabelValuePairStr(map[string]string{
				"key0": "val0",
				"key1": "val1",
			})

			Expect(strings.Contains(result, "key0=val0")).To(BeTrue())
			Expect(strings.Contains(result, "key1=val1")).To(BeTrue())
		})
	})
})
