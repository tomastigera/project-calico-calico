// Copyright (c) 2020 Tigera, Inc. All rights reserved.

package felixclient

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/l7-collector/pkg/collector"
)

var (
	httpLog = collector.EnvoyLog{
		Reporter:      "destination",
		StartTime:     "2020-11-24T22:24:29.237Z",
		Duration:      3,
		ResponseCode:  200,
		BytesSent:     33,
		BytesReceived: 0,
		UserAgent:     "curl/7.68.0",
		RequestPath:   "/ip",
		RequestMethod: "GET",
		RequestId:     "e23c0019-36b7-4142-8e86",
		RouteName:     "test-route",

		DSRemoteAddress: "192.168.138.2:34368",
		DSLocalAddress:  "192.168.35.210:80",
		// 5 tuple data
		Type:    "HTTP/1.1",
		SrcIp:   "192.168.138.2",
		DstIp:   "192.168.35.210",
		SrcPort: int32(34368),
		DstPort: int32(80),
	}
	httpLog1 = collector.EnvoyLog{
		Reporter:      "destination",
		StartTime:     "2020-11-24T22:24:29.237Z",
		Duration:      3,
		ResponseCode:  501,
		BytesSent:     33,
		BytesReceived: 0,
		UserAgent:     "curl/7.68.0",
		RequestPath:   "/ip",
		RequestMethod: "GET",
		RequestId:     "e23c0019-36b7-4142-8e860019-36b7-4142",
		RouteName:     "test-route-1",

		DSRemoteAddress: "193.16.18.264:56748",
		DSLocalAddress:  "192.168.35.210:8080",
		// 5 tuple data
		Type:    "HTTP/1.1",
		SrcIp:   "193.16.18.264",
		DstIp:   "192.168.35.210",
		SrcPort: int32(56748),
		DstPort: int32(8080),
	}
	httpLog2 = collector.EnvoyLog{
		Reporter:      "destination",
		StartTime:     "2020-11-24T22:24:29.237Z",
		Duration:      3,
		ResponseCode:  501,
		BytesSent:     33,
		BytesReceived: 0,
		UserAgent:     "curl/7.68.0",
		RequestPath:   "/ip",
		RequestMethod: "POST",
		RequestId:     "e23c0019-36b7-4142-8e860019-36b7-4142",
		RouteName:     "test-route-2",

		DSRemoteAddress: "193.16.18.264:56748",
		DSLocalAddress:  "192.168.35.210:8080",
		// 5 tuple data
		Type:    "HTTP/1.1",
		SrcIp:   "193.16.18.264",
		DstIp:   "192.168.35.210",
		SrcPort: int32(56748),
		DstPort: int32(8080),
	}
)

var _ = Describe("Felix Client Converting single EnvoyLog to DataplaneStats test", func() {
	converter := DefaultLogConverter{}
	Context("With a log with all fields filled in", func() {
		It("Should create dataplane stats with the correct fields", func() {
			dpStats := converter.DataplaneStatsFromL7Log(httpLog)
			httpData := dpStats.HttpData[0]
			Expect(dpStats.SrcIp).To(Equal(httpLog.SrcIp))
			Expect(dpStats.DstIp).To(Equal(httpLog.DstIp))
			Expect(dpStats.SrcPort).To(Equal(httpLog.SrcPort))
			Expect(dpStats.DstPort).To(Equal(httpLog.DstPort))
			// protocol should be tcp even when it's not passed in the log
			Expect(dpStats.Protocol).To(Equal(&proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}}))
			Expect(httpData.Type).To(Equal(httpLog.Type))
			Expect(httpData.RequestMethod).To(Equal(httpLog.RequestMethod))
			Expect(httpData.UserAgent).To(Equal(httpLog.UserAgent))
			Expect(httpData.BytesSent).To(Equal(httpLog.BytesSent))
			Expect(httpData.Duration).To(Equal(httpLog.Duration))
			Expect(httpData.ResponseCode).To(Equal(httpLog.ResponseCode))
			Expect(httpData.BytesReceived).To(Equal(httpLog.BytesReceived))
			Expect(httpData.RequestPath).To(Equal(httpLog.RequestPath))
			Expect(httpData.RouteName).To(Equal(httpLog.RouteName))
		})
	})
})

var _ = Describe("Felix Client converting Gateway API enrichment fields", func() {
	converter := DefaultLogConverter{}
	Context("With a log containing Gateway API enrichment fields", func() {
		It("Should convert Gateway API enrichment fields correctly", func() {
			enrichedLog := collector.EnvoyLog{
				Reporter:              "gateway",
				SrcIp:                 "10.0.0.1",
				DstIp:                 "10.0.0.2",
				SrcPort:               12345,
				DstPort:               80,
				RouteName:             "test-route",
				GatewayNamespace:      "default",
				GatewayClass:          "istio",
				GatewayStatus:         "active",
				GatewayListenerName:   "http",
				GatewayListenerPort:   80,
				GatewayRouteName:      "my-route",
				GatewayRouteNamespace: "default",
				CollectorName:         "gateway-collector",
				CollectorType:         "envoy-access-log",
			}

			dpStats := converter.DataplaneStatsFromL7Log(enrichedLog)

			// Verify Gateway API enrichment fields are included in HTTP data
			httpData := dpStats.HttpData[0]
			Expect(httpData.GatewayNamespace).To(Equal("default"))
			Expect(httpData.GatewayClass).To(Equal("istio"))
			Expect(httpData.GatewayStatus).To(Equal("active"))
			Expect(httpData.GatewayListenerName).To(Equal("http"))
			Expect(httpData.GatewayListenerPort).To(Equal(int32(80)))
			Expect(httpData.GatewayRouteName).To(Equal("my-route"))
			Expect(httpData.GatewayRouteNamespace).To(Equal("default"))
			Expect(httpData.CollectorName).To(Equal("gateway-collector"))
			Expect(httpData.CollectorType).To(Equal("envoy-access-log"))
		})
	})
})

var _ = Describe("Felix Client batching multiple EnvoyLogs to DataplaneStats", func() {
	testClient := &felixClient{converter: DefaultLogConverter{}}
	logKey := collector.GetEnvoyLogKey(httpLog)
	logKey1 := collector.GetEnvoyLogKey(httpLog1)
	logKey2 := collector.GetEnvoyLogKey(httpLog2)
	Context("when same 5 tuple EnvoyLogs are passed in envoy collector", func() {
		logs := map[collector.EnvoyLogKey]collector.EnvoyLog{logKey: httpLog, logKey1: httpLog}
		info := collector.EnvoyInfo{
			Logs: logs,
		}
		It("It Should create a single DataplaneStat with multiple HttpData objects", func() {
			data := testClient.batchAndConvertEnvoyLogs(info)
			value, found := data[collector.TupleKey{
				SrcIp:   "192.168.138.2",
				DstIp:   "192.168.35.210",
				SrcPort: 34368,
				DstPort: 80,
				Type:    "HTTP/1.1",
			}]
			Expect(len(data)).To(Equal(1))
			Expect(found).To(Equal(true))
			Expect(len(value.HttpData)).To(Equal(2))
		})
	})
	Context("when distinct 5 tuple EnvoyLogs are passed in envoy collector", func() {
		logs := map[collector.EnvoyLogKey]collector.EnvoyLog{logKey: httpLog, logKey1: httpLog1, logKey2: httpLog2}
		info := collector.EnvoyInfo{
			Logs: logs,
		}
		It("It Should create as many logs as distinct 5 tuple logs passed", func() {
			data := testClient.batchAndConvertEnvoyLogs(info)
			Expect(len(data)).To(Equal(2))
			value, found := data[collector.TupleKey{
				SrcIp:   "192.168.138.2",
				DstIp:   "192.168.35.210",
				SrcPort: 34368,
				DstPort: 80,
				Type:    "HTTP/1.1",
			}]
			Expect(found).To(Equal(true))
			Expect(len(value.HttpData)).To(Equal(1))

			value2, found := data[collector.TupleKey{
				SrcIp:   "193.16.18.264",
				DstIp:   "192.168.35.210",
				SrcPort: 56748,
				DstPort: 8080,
				Type:    "HTTP/1.1",
			}]
			Expect(found).To(Equal(true))
			Expect(len(value2.HttpData)).To(Equal(2))

		})
	})
})
