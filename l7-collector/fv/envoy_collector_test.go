// Copyright (c) 2020 Tigera, Inc. All rights reserved.

package fv_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/proto"
)

var handler *CollectorTestHandler

var _ = Describe("Envoy Collector FV Test", func() {
	BeforeEach(func() {
		handler = NewCollectorTestHandler()
		// Run the PolicySync server for receiving updates
		go func() {
			handler.StartPolicySyncServer()
		}()
	})

	AfterEach(func() {
		handler.Shutdown()
	})
	Context("With one basic log", func() {
		It("Should parse and receive the basic log", func() {
			// Write the logs
			WriteAndCollect([]string{httpLog})

			// Validate the result
			var result *proto.DataplaneStats
			Eventually(handler.StatsChan(), handler.Timeout(), handler.Interval()).Should(Receive(&result))
			Expect(len(result.HttpData)).To(Equal(1))
			Expect(result).To(Equal(httpStat))
		})
	})
	Context("With one basic log", func() {
		It("Should parse and receive the basic log, bypass any log other than reporter=destination log", func() {
			// Write the logs
			WriteAndCollect([]string{sourceLog, httpLog, sourceLog})

			// Validate the result
			var result *proto.DataplaneStats
			Eventually(handler.StatsChan(), handler.Timeout(), handler.Interval()).Should(Receive(&result))
			Expect(len(result.HttpData)).To(Equal(1))
			Expect(result).To(Equal(httpStat))
		})
	})
	Context("With logs with same EnvoyLogKey data but with different bytes received, bytes sent, duration below the batch limit", func() {
		It("Should receive single log, with one http data object. bytes_sent, bytes_received, duration, count should be summed up", func() {
			// Write the logs
			WriteAndCollect([]string{httpLog, httpLog, httpLog})

			// Validate the result
			var result *proto.DataplaneStats
			Eventually(handler.StatsChan(), handler.Timeout(), handler.Interval()).Should(Receive(&result))
			Expect(len(result.HttpData)).To(Equal(1))
			Expect(result.Stats[0].Value).To(Equal(int64(3)))
			Expect(result.HttpData[0].Count).To(Equal(int32(3)))
			Expect(result.HttpData[0].BytesSent).To(Equal(int32(99)))
			Expect(result.HttpData[0].BytesReceived).To(Equal(int32(3)))
			Expect(result.HttpData[0].Duration).To(Equal(int32(9)))
			Expect(result.HttpData[0].DurationMax).To(Equal(int32(3)))
			Expect(result).To(Equal(httpStatSummation))
		})
	})

	Context("With logs with same 5-tuple data but with different EnvoyLogKey data below the batch limit", func() {
		It("Should receive single log, with as many http data object as the logs sent", func() {
			// Write the logs
			WriteAndCollect([]string{httpLog, httpPostLog, httpDeleteLog})

			// Validate the result
			var result *proto.DataplaneStats
			Eventually(handler.StatsChan(), handler.Timeout(), handler.Interval()).Should(Receive(&result))

			Expect(result.SrcIp).To(Equal(httpBatchStat3.SrcIp))
			Expect(result.DstIp).To(Equal(httpBatchStat3.DstIp))
			Expect(result.SrcPort).To(Equal(httpBatchStat3.SrcPort))
			Expect(result.DstPort).To(Equal(httpBatchStat3.DstPort))
			Expect(result.Protocol).To(Equal(httpBatchStat3.Protocol))
			Expect(len(result.HttpData)).To(Equal(3))
			Expect(result.HttpData).To(ConsistOf(httpBatchStat3.HttpData))
			Expect(result.Stats[0].Value).To(Equal(int64(3)))
		})
	})

	Context("With logs with same EnvoyLogKey data exceeding 5 batch limit", func() {
		It("Should receive the log, http data objects should be 1, stats count equal to the logs passed", func() {
			// Write the logs
			WriteAndCollect([]string{httpLog, httpLog2, httpLog3, httpLog4, httpLog5, httpLog6, httpLog7})

			// Validate the result
			var result *proto.DataplaneStats
			Eventually(handler.StatsChan(), handler.Timeout(), handler.Interval()).Should(Receive(&result))
			expected := DeepCopyDpsWithoutHttpData(httpStat)
			found := DeepCopyDpsWithoutHttpData(result)
			Expect(found).To(Equal(expected))
			// http data length will be limited by the batch size, stats count will be the total number of logs
			Expect(len(result.HttpData)).To(Equal(1))
			Expect(result.Stats[0].Value).To(Equal(int64(7)))
		})
	})

	Context("With tcp logs with same EnvoyLogKey data exceeding 5 batch limit", func() {
		It("Should receive a single log, with single http data object, bytes sent, bytes received, duration should be summed up for all logs", func() {
			// Write the logs
			WriteAndCollect([]string{tcpLog, tcpLog, tcpLog, tcpLog, tcpLog, tcpLog})

			// Validate the result
			var result *proto.DataplaneStats
			Eventually(handler.StatsChan(), handler.Timeout(), handler.Interval()).Should(Receive(&result))
			Expect(len(result.HttpData)).To(Equal(1))
			Expect(result.HttpData[0].BytesSent).To(Equal(int32(42)))     // each tcp log has 7 as bytes sent
			Expect(result.HttpData[0].BytesReceived).To(Equal(int32(84))) // each tcp log has 14 as bytes sent
			Expect(result.HttpData[0].Duration).To(Equal(int32(12)))      // each tcp log has 2 as duration
			Expect(result.HttpData[0].Count).To(Equal(int32(6)))
			Expect(result.Stats[0].Value).To(Equal(int64(6)))
		})
	})

	Context("With tcp logs with same EnvoyLogKey multiple durations", func() {
		It("Should receive a single log, with single http data object, bytes sent, bytes received, duration should be summed up, max duration should be set", func() {
			// Write the logs
			WriteAndCollect([]string{tcpLog, tcpLog2, tcpLog3})

			// Validate the result
			var result *proto.DataplaneStats
			Eventually(handler.StatsChan(), handler.Timeout(), handler.Interval()).Should(Receive(&result))
			Expect(len(result.HttpData)).To(Equal(1))
			Expect(result.HttpData[0].BytesSent).To(Equal(int32(20)))     // sum of 7 + 3 + 10 per log
			Expect(result.HttpData[0].BytesReceived).To(Equal(int32(22))) // sum of 14 + 4 + 4 per log
			Expect(result.HttpData[0].Duration).To(Equal(int32(14)))      // sum of 2 + 4 + 8 per log
			Expect(result.HttpData[0].DurationMax).To(Equal(int32(8)))    // max of (2,4,8)
			Expect(result.HttpData[0].Count).To(Equal(int32(3)))
			Expect(result.Stats[0].Value).To(Equal(int64(3)))
		})
	})

})

func WriteAndCollect(logs []string) {
	// Write the logs to the log file
	for _, log := range logs {
		handler.WriteToLog(log)
	}

	// Run the main collector
	go handler.CollectAndSend()
}
