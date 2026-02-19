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

			src := map[string]interface{}{
				"a": map[string]interface{}{"b": srcValue},
				"c": srcValue,
				"d": map[string]interface{}{"e": map[string]interface{}{"f": srcValue}},
			}
			Expect(src["a"].(map[string]interface{})["b"]).Should(Equal(srcValue))
			Expect(src["c"]).Should(Equal(srcValue))
			Expect(src["d"].(map[string]interface{})["e"].(map[string]interface{})["f"]).Should(Equal(srcValue))

			cp, err := Copy(src)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(src).Should(BeEquivalentTo(cp))

			cp["a"].(map[string]interface{})["b"] = cpValue
			cp["c"] = cpValue
			cp["d"].(map[string]interface{})["e"].(map[string]interface{})["f"] = cpValue
			Expect(src).ShouldNot(BeEquivalentTo(cp))

			Expect(src["a"].(map[string]interface{})["b"]).Should(Equal(srcValue))
			Expect(src["c"]).Should(Equal(srcValue))
			Expect(src["d"].(map[string]interface{})["e"].(map[string]interface{})["f"]).Should(Equal(srcValue))
			Expect(cp["a"].(map[string]interface{})["b"]).Should(Equal(cpValue))
			Expect(cp["c"]).Should(Equal(cpValue))
			Expect(cp["d"].(map[string]interface{})["e"].(map[string]interface{})["f"]).Should(Equal(cpValue))
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
