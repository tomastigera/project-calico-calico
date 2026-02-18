// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package capture_test

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/felix/calc/capture"
)

var _ = Describe("Time for PacketCapture", func() {
	var startTime = metav1.NewTime(time.Unix(0, 0))
	var endTime = metav1.NewTime(time.Unix(100, 0))

	DescribeTable("RenderStartTime",
		func(input *metav1.Time, expected time.Time) {
			var result = capture.RenderStartTime(input)
			Expect(result).To(Equal(expected))
		},
		Entry("No time defined", nil, capture.MinTime),
		Entry("Any time defined", &startTime, time.Unix(0, 0)),
	)

	DescribeTable("RenderEndTime",
		func(input *metav1.Time, expected time.Time) {
			var result = capture.RenderEndTime(input)
			Expect(result).To(Equal(expected))
		},
		Entry("No time defined", nil, capture.MaxTime),
		Entry("Any time defined", &endTime, time.Unix(100, 0)),
	)
})
