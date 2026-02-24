// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package v1_test

import (
	"encoding/json"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/projectcalico/calico/lma/pkg/apis/v1"
)

var _ = Describe("Unmarshaling works correctly", func() {
	It("Errors with no from field", func() {
		var tr TimeRange
		d := "{\"to\":\"now\"}"

		err := json.Unmarshal([]byte(d), &tr)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal("Request body contains an invalid time range: values must either both be explicit times or both be relative to now"))
	})

	It("No errors with no from field", func() {
		var tr TimeRange
		d := "{\"to\":\"2021-05-30T21:23:10Z\"}"

		err := json.Unmarshal([]byte(d), &tr)
		Expect(err).NotTo(HaveOccurred())
	})

	It("Errors with no to field", func() {
		var tr TimeRange
		d := "{\"from\":\"now\"}"

		err := json.Unmarshal([]byte(d), &tr)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal("Request body contains an invalid time range: values must either both be explicit times or both be relative to now"))
	})

	It("No errors with no to field", func() {
		var tr TimeRange
		d := "{\"from\":\"2021-05-30T21:23:10Z\"}"

		err := json.Unmarshal([]byte(d), &tr)
		Expect(err).NotTo(HaveOccurred())
	})

	It("Parses relative times", func() {
		var tr TimeRange
		d := "{\"from\":\"now-15m\",\"to\":\"now\"}"

		err := json.Unmarshal([]byte(d), &tr)
		Expect(err).NotTo(HaveOccurred())
		Expect(tr.Now).NotTo(BeNil())
		Expect(tr.To).To(Equal(*tr.Now))
		Expect(tr.Duration()).To(Equal(15 * time.Minute))
	})

	It("Parses actual times", func() {
		var tr TimeRange
		d := "{\"from\":\"2021-05-30T21:23:10Z\", \"to\":\"2021-05-30T21:24:10Z\"}"

		err := json.Unmarshal([]byte(d), &tr)
		Expect(err).NotTo(HaveOccurred())
		Expect(tr.Now).To(BeNil())
		Expect(tr.Duration()).To(Equal(time.Minute))
	})

	It("Errors with mixed formats", func() {
		var tr TimeRange
		d := "{\"from\":\"2021-05-30T21:23:10Z\", \"to\":\"now\"}"

		err := json.Unmarshal([]byte(d), &tr)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal("Request body contains an invalid time range: values must either both be explicit times or both be relative to now"))
	})

	It("Errors with reversed relative times", func() {
		var tr TimeRange
		d := "{\"from\":\"now\", \"to\":\"now-15m\"}"

		err := json.Unmarshal([]byte(d), &tr)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal("Request body contains an invalid time range: from (now) is after to (now-15m)"))
	})

	It("Errors with reversed actual times", func() {
		var tr TimeRange
		d := "{\"from\":\"2021-05-30T21:23:10Z\", \"to\":\"2021-05-30T21:22:10Z\"}"

		err := json.Unmarshal([]byte(d), &tr)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal("Request body contains an invalid time range: from (2021-05-30T21:23:10Z) is after to (2021-05-30T21:22:10Z)"))
	})

	It("Errors with bad time in from", func() {
		var tr TimeRange
		d := "{\"from\":\"now-X\", \"to\":\"now-15m\"}"

		err := json.Unmarshal([]byte(d), &tr)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal("Request body contains an invalid value for the time range 'from' field: now-X"))
	})

	It("Errors with bad time in to", func() {
		var tr TimeRange
		d := "{\"from\":\"now-15m\", \"to\":\"now-X\"}"

		err := json.Unmarshal([]byte(d), &tr)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal("Request body contains an invalid value for the time range 'to' field: now-X"))
	})

	DescribeTable("Test Field field", func(fieldValue string, d string) {
		var tr TimeRange

		err := json.Unmarshal([]byte(d), &tr)
		Expect(err).NotTo(HaveOccurred())
		Expect(tr.Now).To(BeNil())
		Expect(tr.Duration()).To(Equal(time.Minute))
		Expect(string(tr.Field)).To(Equal(fieldValue))
	},
		Entry("Handles start_time value", "start_time", "{\"field\":\"start_time\", \"from\":\"2021-05-30T21:23:10Z\", \"to\":\"2021-05-30T21:24:10Z\"}"),
		Entry("Handles generated_time value", "generated_time", "{\"field\":\"generated_time\", \"from\":\"2021-05-30T21:23:10Z\", \"to\":\"2021-05-30T21:24:10Z\"}"),
	)

	It("Rejects an unsupported Field field", func() {
		var tr TimeRange
		d := "{\"field\":\"unsupported_time_field\", \"from\":\"2021-05-30T21:23:10Z\", \"to\":\"2021-05-30T21:24:10Z\"}"

		err := json.Unmarshal([]byte(d), &tr)
		Expect(err).To(HaveOccurred())
	})
})
