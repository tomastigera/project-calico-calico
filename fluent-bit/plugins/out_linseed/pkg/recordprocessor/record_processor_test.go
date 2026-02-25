// Copyright (c) 2026 Tigera, Inc. All rights reserved.
package recordprocessor

import (
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Record processor tests", func() {
	Context("toStringMap", func() {
		It("should convert basic types correctly", func() {
			record := Record{
				"string_key": "string_value",
				"int_key":    42,
				"float_key":  3.14,
				"bool_key":   true,
				"nil_key":    nil,
				"bytes_key":  []byte("bytes_value"),
			}

			result := toStringMap(record)

			Expect(result).To(HaveKeyWithValue("string_key", "string_value"))
			Expect(result).To(HaveKeyWithValue("int_key", 42))
			Expect(result).To(HaveKeyWithValue("float_key", 3.14))
			Expect(result).To(HaveKeyWithValue("bool_key", true))
			Expect(result).To(HaveKey("nil_key"))
			Expect(result["nil_key"]).To(BeNil())
			// []byte should be converted to string
			Expect(result).To(HaveKeyWithValue("bytes_key", "bytes_value"))
		})

		It("should convert nested maps recursively", func() {
			record := Record{
				"outer": map[any]any{
					"inner_string": "value",
					"inner_bytes":  []byte("nested_bytes"),
				},
			}

			result := toStringMap(record)

			Expect(result).To(HaveKey("outer"))
			nested, ok := result["outer"].(map[string]any)
			Expect(ok).To(BeTrue())
			Expect(nested).To(HaveKeyWithValue("inner_string", "value"))
			Expect(nested).To(HaveKeyWithValue("inner_bytes", "nested_bytes"))
		})

		It("should convert nested slices recursively", func() {
			record := Record{
				"list": []any{
					"string_elem",
					[]byte("bytes_elem"),
					map[any]any{"key": "val"},
					[]any{[]byte("nested_bytes")},
				},
			}

			result := toStringMap(record)

			Expect(result).To(HaveKey("list"))
			list, ok := result["list"].([]any)
			Expect(ok).To(BeTrue())
			Expect(list).To(HaveLen(4))
			Expect(list[0]).To(Equal("string_elem"))
			Expect(list[1]).To(Equal("bytes_elem"))

			nestedMap, ok := list[2].(map[string]any)
			Expect(ok).To(BeTrue())
			Expect(nestedMap).To(HaveKeyWithValue("key", "val"))

			nestedSlice, ok := list[3].([]any)
			Expect(ok).To(BeTrue())
			Expect(nestedSlice[0]).To(Equal("nested_bytes"))
		})

		It("should drop non-string keys", func() {
			record := Record{
				"valid_key": "value",
				42:          "should_be_dropped",
				true:        "also_dropped",
			}

			result := toStringMap(record)

			Expect(result).To(HaveLen(1))
			Expect(result).To(HaveKeyWithValue("valid_key", "value"))
		})

		It("should handle empty records", func() {
			result := toStringMap(Record{})
			Expect(result).To(BeEmpty())
		})

		It("should produce JSON without base64-encoded byte values", func() {
			record := Record{
				"message": []byte("hello world"),
				"nested": map[any]any{
					"data": []byte("nested data"),
				},
			}

			result := toStringMap(record)
			jsonData, err := json.Marshal(result)
			Expect(err).NotTo(HaveOccurred())

			jsonStr := string(jsonData)
			Expect(jsonStr).To(ContainSubstring(`"hello world"`))
			Expect(jsonStr).To(ContainSubstring(`"nested data"`))
		})
	})
})
