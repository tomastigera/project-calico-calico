// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package felixclient

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/ingress-collector/pkg/collector"
)

var (
	fullLog = collector.IngressLog{
		SrcIp:         "10.100.10.1",
		DstIp:         "10.100.100.1",
		SrcPort:       int32(40),
		DstPort:       int32(50),
		Protocol:      "tcp",
		XForwardedFor: "1.1.1.1",
		XRealIp:       "8.8.8.8",
	}
	noProtoLog = collector.IngressLog{
		SrcIp:         "10.100.1.1",
		DstIp:         "10.10.100.1",
		SrcPort:       int32(40),
		DstPort:       int32(50),
		XForwardedFor: "2.2.2.2",
		XRealIp:       "7.7.7.7",
	}
	multipleForwardLog = collector.IngressLog{
		SrcIp:         "10.100.10.1",
		DstIp:         "10.100.100.1",
		SrcPort:       int32(40),
		DstPort:       int32(50),
		Protocol:      "tcp",
		XForwardedFor: "1.1.1.1, 2.2.2.2",
		XRealIp:       "8.8.8.8",
	}
	emptyForwardLog = collector.IngressLog{
		SrcIp:         "10.100.10.1",
		DstIp:         "10.100.100.1",
		SrcPort:       int32(40),
		DstPort:       int32(50),
		Protocol:      "tcp",
		XForwardedFor: "",
		XRealIp:       "8.8.8.8",
	}
	emptyRealLog = collector.IngressLog{
		SrcIp:         "10.100.10.1",
		DstIp:         "10.100.100.1",
		SrcPort:       int32(40),
		DstPort:       int32(50),
		Protocol:      "tcp",
		XForwardedFor: "1.1.1.1",
		XRealIp:       "-",
	}
	emptyHeaderLog = collector.IngressLog{
		SrcIp:         "10.100.10.1",
		DstIp:         "10.100.100.1",
		SrcPort:       int32(40),
		DstPort:       int32(50),
		Protocol:      "tcp",
		XForwardedFor: "-",
		XRealIp:       "-",
	}
	similarLog1 = collector.IngressLog{
		SrcIp:         "10.100.10.1",
		DstIp:         "10.100.100.1",
		SrcPort:       int32(40),
		DstPort:       int32(50),
		Protocol:      "tcp",
		XForwardedFor: "1.1.1.2",
		XRealIp:       "8.8.8.9",
	}
	similarLog2 = collector.IngressLog{
		SrcIp:         "10.100.10.1",
		DstIp:         "10.100.100.1",
		SrcPort:       int32(40),
		DstPort:       int32(50),
		Protocol:      "tcp",
		XForwardedFor: "1.1.1.3",
		XRealIp:       "8.8.8.0",
	}
)

var _ = Describe("Felix Client Converting IngressLog to DataplaneStats test", func() {
	testClient := &felixClient{}
	Context("With a log with all fields filled in", func() {
		It("Should create dataplane stats with the correct fields", func() {
			dpStats := testClient.dataPlaneStatsFromIngressLog(fullLog)
			Expect(dpStats.SrcIp).To(Equal(fullLog.SrcIp))
			Expect(dpStats.DstIp).To(Equal(fullLog.DstIp))
			Expect(dpStats.SrcPort).To(Equal(fullLog.SrcPort))
			Expect(dpStats.DstPort).To(Equal(fullLog.DstPort))
			Expect(dpStats.Protocol).To(Equal(&proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: fullLog.Protocol}}))
			Expect(dpStats.HttpData[0].XForwardedFor).To(Equal(fullLog.XForwardedFor))
			Expect(dpStats.HttpData[0].XRealIp).To(Equal(fullLog.XRealIp))
		})
	})
	Context("With a log missing the protocol field", func() {
		It("Should create dataplane stats with a defaulted tcp protocol", func() {
			dpStats := testClient.dataPlaneStatsFromIngressLog(noProtoLog)
			Expect(dpStats.SrcIp).To(Equal(noProtoLog.SrcIp))
			Expect(dpStats.DstIp).To(Equal(noProtoLog.DstIp))
			Expect(dpStats.SrcPort).To(Equal(noProtoLog.SrcPort))
			Expect(dpStats.DstPort).To(Equal(noProtoLog.DstPort))
			Expect(dpStats.Protocol).To(Equal(&proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}}))
			Expect(dpStats.HttpData[0].XForwardedFor).To(Equal(noProtoLog.XForwardedFor))
			Expect(dpStats.HttpData[0].XRealIp).To(Equal(noProtoLog.XRealIp))
		})
	})
	Context("With a log with multiple IPs in the X-Forwarded-For field", func() {
		It("Should create dataplane stats with only the first IP from the field", func() {
			dpStats := testClient.dataPlaneStatsFromIngressLog(multipleForwardLog)
			Expect(dpStats.SrcIp).To(Equal(multipleForwardLog.SrcIp))
			Expect(dpStats.DstIp).To(Equal(multipleForwardLog.DstIp))
			Expect(dpStats.SrcPort).To(Equal(multipleForwardLog.SrcPort))
			Expect(dpStats.DstPort).To(Equal(multipleForwardLog.DstPort))
			Expect(dpStats.Protocol).To(Equal(&proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: multipleForwardLog.Protocol}}))
			Expect(dpStats.HttpData[0].XForwardedFor).To(Equal("1.1.1.1"))
			Expect(dpStats.HttpData[0].XRealIp).To(Equal(multipleForwardLog.XRealIp))
		})
	})
	Context("With a log with blanked out IPs in the X-Forwarded-For or X-Real-Ip fields", func() {
		It("Should create dataplane stats with empty X-Forwarded-For and X-Real-Ip fields", func() {
			dpStats := testClient.dataPlaneStatsFromIngressLog(emptyForwardLog)
			Expect(dpStats.SrcIp).To(Equal(emptyForwardLog.SrcIp))
			Expect(dpStats.DstIp).To(Equal(emptyForwardLog.DstIp))
			Expect(dpStats.SrcPort).To(Equal(emptyForwardLog.SrcPort))
			Expect(dpStats.DstPort).To(Equal(emptyForwardLog.DstPort))
			Expect(dpStats.Protocol).To(Equal(&proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: emptyForwardLog.Protocol}}))
			Expect(dpStats.HttpData[0].XForwardedFor).To(Equal(""))
			Expect(dpStats.HttpData[0].XRealIp).To(Equal(emptyForwardLog.XRealIp))

			dpStats = testClient.dataPlaneStatsFromIngressLog(emptyRealLog)
			Expect(dpStats.SrcIp).To(Equal(emptyRealLog.SrcIp))
			Expect(dpStats.DstIp).To(Equal(emptyRealLog.DstIp))
			Expect(dpStats.SrcPort).To(Equal(emptyRealLog.SrcPort))
			Expect(dpStats.DstPort).To(Equal(emptyRealLog.DstPort))
			Expect(dpStats.Protocol).To(Equal(&proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: emptyRealLog.Protocol}}))
			Expect(dpStats.HttpData[0].XForwardedFor).To(Equal(emptyRealLog.XForwardedFor))
			Expect(dpStats.HttpData[0].XRealIp).To(Equal(""))
		})
	})
	Context("With a log with blanked out IPs in both the X-Forwarded-For and X-Real-Ip fields", func() {
		It("Should create dataplane stats with no HTTPData", func() {
			dpStats := testClient.dataPlaneStatsFromIngressLog(emptyHeaderLog)
			Expect(dpStats.SrcIp).To(Equal(emptyHeaderLog.SrcIp))
			Expect(dpStats.DstIp).To(Equal(emptyHeaderLog.DstIp))
			Expect(dpStats.SrcPort).To(Equal(emptyHeaderLog.SrcPort))
			Expect(dpStats.DstPort).To(Equal(emptyHeaderLog.DstPort))
			Expect(dpStats.Protocol).To(Equal(&proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: emptyHeaderLog.Protocol}}))
			Expect(len(dpStats.HttpData)).To(Equal(0))
		})
	})
})

var _ = Describe("Felix Client batching and converting IngressLog to DataplaneStats test", func() {
	testClient := &felixClient{}
	Context("With a set of logs with different 5 tuple data", func() {
		logs := []collector.IngressLog{fullLog, noProtoLog}
		info := collector.IngressInfo{
			Logs: logs,
		}
		It("Should create dataplane stats with only one HttpData each", func() {
			data := testClient.batchAndConvertIngressLogs(info)
			Expect(len(data)).To(Equal(len(logs)))
			for _, dpStats := range data {
				Expect(len(dpStats.HttpData)).To(Equal(1))
			}
		})
	})
	Context("With a set of logs with same 5 tuple data", func() {
		logs := []collector.IngressLog{fullLog, similarLog1, similarLog2}
		info := collector.IngressInfo{
			Logs: logs,
		}
		It("Should create dataplane stats with multiple HttpData", func() {
			data := testClient.batchAndConvertIngressLogs(info)
			Expect(len(data)).To(Equal(1))
			for _, dpStats := range data {
				Expect(len(dpStats.HttpData)).To(Equal(len(logs)))
			}
		})
	})
})
