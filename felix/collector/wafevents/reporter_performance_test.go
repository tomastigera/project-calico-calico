//go:build !race

// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package wafevents

import (
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/proto"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

// Performance test that's excluded when running with race detector
// since the race detector adds 5-10x overhead making the timing
// requirements impossible to meet.
var _ = ginkgo.Describe("WAFEvent Log Reporter Performance", func() {
	var (
		dispatcher   *testWAFEventReporter
		r            *WAFEventReporter
		flushTrigger chan time.Time
		r0, r1       *Report
	)

	ginkgo.BeforeEach(func() {
		dispatcher = &testWAFEventReporter{logs: make(chan []*v1.WAFLog, 1)}
		flushTrigger = make(chan time.Time, 1)
		r = NewReporterWithShims([]types.Reporter{dispatcher}, flushTrigger, nil)
		gomega.Expect(r.Start()).NotTo(gomega.HaveOccurred())

		r0 = &Report{
			Src: &v1.WAFEndpoint{
				IP:           "10.0.0.1",
				PortNum:      65500,
				PodName:      "pod-client-0",
				PodNameSpace: "default-ns",
			},
			Dst: &v1.WAFEndpoint{
				IP:           "10.0.0.100",
				PortNum:      8080,
				PodName:      "pod-server-0",
				PodNameSpace: "server-ns",
			},
			WAFEvent: &proto.WAFEvent{
				TxId:    "id000",
				Host:    "server-svc.server-ns",
				SrcIp:   "10.0.0.1",
				SrcPort: 65500,
				DstIp:   "10.0.0.100",
				DstPort: 8080,
				Request: &proto.HTTPRequest{
					Method:  "GET",
					Path:    "/",
					Version: "1.1",
				},
				Timestamp: &timestamppb.Timestamp{Seconds: 58800},
			},
		}
		r1 = &Report{
			Src: &v1.WAFEndpoint{
				IP:           "10.0.1.1",
				PortNum:      65501,
				PodName:      "pod-client-1",
				PodNameSpace: "default-ns",
			},
			Dst: &v1.WAFEndpoint{
				IP:           "10.0.0.100",
				PortNum:      8080,
				PodName:      "pod-server-0",
				PodNameSpace: "server-ns",
			},
			WAFEvent: &proto.WAFEvent{
				TxId:    "id001",
				Host:    "server-svc.server-ns",
				SrcIp:   "10.0.1.1",
				SrcPort: 65501,
				DstIp:   "10.0.0.100",
				DstPort: 8080,
				Request: &proto.HTTPRequest{
					Method:  "POST",
					Path:    "/login",
					Version: "1.1",
				},
				Timestamp: &timestamppb.Timestamp{Seconds: 58801},
			},
		}
	})

	ginkgo.It("should perform on huge loads", func() {
		// get start time
		start := time.Now()

		// report the 100k events
		for range 25000 {
			err := r.Report(r0)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		}
		for range 75000 {
			err := r.Report(r1)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		}

		// flush and verify logs
		flushTrigger <- time.Now()
		logs := <-dispatcher.logs
		gomega.Expect(logs).To(gomega.HaveLen(2))

		// test if it takes less than 10 secs
		gomega.Expect(time.Since(start)).To(gomega.BeNumerically("<", 10*time.Second))
	})
})
