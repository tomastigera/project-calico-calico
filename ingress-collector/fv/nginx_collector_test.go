// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package fv_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	googleproto "google.golang.org/protobuf/proto"

	"github.com/projectcalico/calico/felix/proto"
)

var handler *CollectorTestHandler

var _ = Describe("Ingress Collector FV Test", func() {
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
			WriteAndCollect([]string{basicLog})

			// Validate the result
			var result *proto.DataplaneStats
			Eventually(handler.StatsChan(), handler.Timeout(), handler.Interval()).Should(Receive(&result))
			Expect(googleproto.Equal(result, basicLogDps)).To(BeTrue())
		})
	})

	Context("With multiple of the same log", func() {
		It("Should return as if only one log line was written", func() {
			// Write the logs
			WriteAndCollect([]string{basicLog, basicLog, basicLog})

			// Validate the result
			var result *proto.DataplaneStats
			Eventually(handler.StatsChan(), handler.Timeout(), handler.Interval()).Should(Receive(&result))
			Expect(googleproto.Equal(result, basicLogDps)).To(BeTrue())
		})
	})

	Context("With  multiple logs with unique IPs less than the request limit", func() {
		It("Should return all the unique IPs for each log", func() {
			// Write the logs
			WriteAndCollect([]string{basicLog, basicLog2, basicLog3})

			// Validate the result
			var result *proto.DataplaneStats
			Eventually(handler.StatsChan(), handler.Timeout(), handler.Interval()).Should(Receive(&result))
			expected := DeepCopyDpsWithoutHttpData(basicLogDpsMultiple)
			found := DeepCopyDpsWithoutHttpData(result)
			Expect(found).To(Equal(expected))
			Expect(result.HttpData).To(HaveLen(len(basicLogDpsMultiple.HttpData)))
			Expect(result.HttpData).Should(ConsistOf(basicLogDpsMultiple.HttpData))
		})
	})

	Context("With multiple logs with some repeat IPs less than the request limit", func() {
		It("Should return all the unique IPs", func() {
			// Write the logs
			WriteAndCollect([]string{basicLog, basicLog2, basicLog3, basicLogRepeat})

			// Validate the result
			var result *proto.DataplaneStats
			Eventually(handler.StatsChan(), handler.Timeout(), handler.Interval()).Should(Receive(&result))
			expected := DeepCopyDpsWithoutHttpData(basicLogDpsMultiple)
			found := DeepCopyDpsWithoutHttpData(result)
			Expect(found).To(Equal(expected))
			Expect(result.HttpData).To(HaveLen(len(basicLogDpsMultiple.HttpData)))
			Expect(result.HttpData).Should(ConsistOf(basicLogDpsMultiple.HttpData))
		})
	})

	Context("With multiple logs with some repeat IPs on different connections less than the request limit", func() {
		It("Should return all the IPs per connection", func() {
			// Write the logs
			WriteAndCollect([]string{basicLog, basicLog2, basicLog3, basicLogConn, basicLogRepeat})

			// Validate the result
			var result *proto.DataplaneStats
			var resultConn *proto.DataplaneStats
			Eventually(handler.StatsChan(), handler.Timeout(), handler.Interval()).Should(Receive(&result))
			// Cannot guarantee the order that the logs will be output for an interval.
			// This will allow the right logs to be checked properly.
			if len(result.HttpData) == len(basicLogDpsMultiple.HttpData) {
				Eventually(handler.StatsChan(), handler.Timeout(), handler.Interval()).Should(Receive(&resultConn))
			} else {
				resultConn = result
				Eventually(handler.StatsChan(), handler.Timeout(), handler.Interval()).Should(Receive(&result))
			}

			expected := DeepCopyDpsWithoutHttpData(basicLogDpsMultiple)
			found := DeepCopyDpsWithoutHttpData(result)
			Expect(found).To(Equal(expected))
			Expect(result.HttpData).To(HaveLen(len(basicLogDpsMultiple.HttpData)))
			Expect(result.HttpData).Should(ConsistOf(basicLogDpsMultiple.HttpData))

			expectedConn := DeepCopyDpsWithoutHttpData(basicLogDpsConn)
			foundConn := DeepCopyDpsWithoutHttpData(resultConn)
			Expect(foundConn).To(Equal(expectedConn))
			Expect(resultConn.HttpData).To(HaveLen(len(basicLogDpsConn.HttpData)))
			Expect(resultConn.HttpData).Should(ConsistOf(basicLogDpsConn.HttpData))
		})
	})

	Context("With multiple logs that exceed the request limit", func() {
		It("Should return the first unique IPs up until the request limit is hit", func() {
			// Write the logs
			WriteAndCollect([]string{basicLog, basicLog2, basicLog3, basicLogRepeat, basicLog4, basicLog5, basicLog6})

			// Validate the result
			var result *proto.DataplaneStats
			Eventually(handler.StatsChan(), handler.Timeout(), handler.Interval()).Should(Receive(&result))
			expected := DeepCopyDpsWithoutHttpData(basicLogDpsLimit)
			found := DeepCopyDpsWithoutHttpData(result)
			Expect(found).To(Equal(expected))
			Expect(result.HttpData).To(HaveLen(len(basicLogDpsLimit.HttpData)))
			Expect(result.HttpData).Should(ConsistOf(basicLogDpsLimit.HttpData))
		})
		It("Should return the unique IPs up until the request limit is hit across multiple connections", func() {
			// Write the logs
			WriteAndCollect([]string{basicLog, basicLog2, basicLog3, basicLogConn, basicLogRepeat, basicLog4, basicLog5, basicLog6})

			// Validate the result
			var result *proto.DataplaneStats
			var resultConn *proto.DataplaneStats
			Eventually(handler.StatsChan(), handler.Timeout(), handler.Interval()).Should(Receive(&result))
			// Cannot guarantee the order that the logs will be output for an interval.
			// This will allow the right logs to be checked properly.
			if len(result.HttpData) == len(basicLogDpsLimit.HttpData)-1 {
				Eventually(handler.StatsChan(), handler.Timeout(), handler.Interval()).Should(Receive(&resultConn))
			} else {
				resultConn = result
				Eventually(handler.StatsChan(), handler.Timeout(), handler.Interval()).Should(Receive(&result))
			}
			expected := DeepCopyDpsWithoutHttpData(basicLogDpsLimit)
			found := DeepCopyDpsWithoutHttpData(result)
			Expect(found).To(Equal(expected))
			Expect(result.HttpData).To(HaveLen(len(basicLogDpsLimit.HttpData) - 1))
			Expect(result.HttpData).Should(ContainElement(basicLogDpsLimit.HttpData[0]))
			Expect(result.HttpData).Should(ContainElement(basicLogDpsLimit.HttpData[1]))
			Expect(result.HttpData).Should(ContainElement(basicLogDpsLimit.HttpData[2]))
			Expect(result.HttpData).Should(ContainElement(basicLogDpsLimit.HttpData[3]))

			expectedConn := DeepCopyDpsWithoutHttpData(basicLogDpsConn)
			foundConn := DeepCopyDpsWithoutHttpData(resultConn)
			Expect(foundConn).To(Equal(expectedConn))
			Expect(resultConn.HttpData).To(HaveLen(len(basicLogDpsConn.HttpData)))
			Expect(resultConn.HttpData).Should(ContainElement(basicLogDpsConn.HttpData[0]))
		})
	})

	Context("With improperly formatted logs", func() {
		It("Should only read the properly formatted logs", func() {
			// Write the logs
			WriteAndCollect([]string{basicLog, basicLog2, badLog, basicLog3})

			// Validate the result
			var result *proto.DataplaneStats
			Eventually(handler.StatsChan(), handler.Timeout(), handler.Interval()).Should(Receive(&result))
			expected := DeepCopyDpsWithoutHttpData(basicLogDpsMultiple)
			found := DeepCopyDpsWithoutHttpData(result)
			Expect(found).To(Equal(expected))
			Expect(result.HttpData).To(HaveLen(len(basicLogDpsMultiple.HttpData)))
			Expect(result.HttpData).Should(ConsistOf(basicLogDpsMultiple.HttpData))
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
