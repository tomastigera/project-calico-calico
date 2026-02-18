// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

package l7log

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/collector/types/endpoint"
)

var _ = Describe("L7 log type tests", func() {
	Describe("L7Spec", func() {
		Context("Merge", func() {
			It("Merges correctly", func() {
				a := L7Spec{
					Duration:      36,
					DurationMax:   14,
					BytesReceived: 45,
					BytesSent:     68,
					Count:         3,
				}
				b := L7Spec{
					Duration:      16,
					DurationMax:   16,
					BytesReceived: 64,
					BytesSent:     32,
					Count:         1,
				}

				a.Merge(b)
				Expect(a.Duration).Should(Equal(52))
				Expect(a.DurationMax).Should(Equal(16))
				Expect(a.BytesReceived).Should(Equal(109))
				Expect(a.BytesSent).Should(Equal(100))
				Expect(a.Count).Should(Equal(4))
			})
		})
	})

	Describe("L7Data Tests", func() {
		meta := L7Meta{
			SrcNameAggr:   "client-*",
			SrcNamespace:  "test-ns",
			SrcType:       endpoint.Wep,
			SourcePortNum: 80,

			DestNameAggr:  "server-*",
			DestNamespace: "test-ns",
			DestType:      endpoint.Wep,
			DestPortNum:   80,

			ServiceName:      "svc1",
			ServiceNamespace: "namespace1",
			ServicePortName:  "testPort",

			ResponseCode: "200",
			RouteName:    "test/route-name",
			GatewayName:  "eg",
			Protocol:     "TCP",
			Method:       "POST",
			Domain:       "www.server.com",
			Path:         "/test/path",
			UserAgent:    "firefox",
			Type:         "html/1.1",
		}
		spec := L7Spec{
			Duration:      52,
			DurationMax:   16,
			BytesReceived: 109,
			BytesSent:     100,
			Count:         4,
		}
		data := L7Data{meta, spec}

		specDurationRounding := L7Spec{
			Duration:      50,
			DurationMax:   2,
			BytesReceived: 109,
			BytesSent:     100,
			Count:         100,
		}
		dataDurationRounding := L7Data{meta, specDurationRounding}

		It("Should create an appropriate L7 Log", func() {
			now := time.Now()
			end := now.Add(3 * time.Second)
			log := data.ToL7Log(now, end)

			Expect(log.StartTime).To(Equal(now.Unix()))
			Expect(log.EndTime).To(Equal(end.Unix()))

			Expect(log.SourceNameAggr).To(Equal(meta.SrcNameAggr))
			Expect(log.SourceNamespace).To(Equal(meta.SrcNamespace))
			Expect(log.SourceType).To(Equal(meta.SrcType))
			Expect(log.SourcePortNum).To(Equal(80))

			Expect(log.DestNameAggr).To(Equal(meta.DestNameAggr))
			Expect(log.DestNamespace).To(Equal(meta.DestNamespace))
			Expect(log.DestType).To(Equal(meta.DestType))
			Expect(log.DestPortNum).To(Equal(80))

			Expect(log.DestServiceName).To(Equal("svc1"))
			Expect(log.DestServiceNamespace).To(Equal("namespace1"))
			Expect(log.DestServicePortName).To(Equal("testPort"))

			Expect(log.ResponseCode).To(Equal(meta.ResponseCode))
			Expect(log.RouteName).To(Equal(meta.RouteName))
			Expect(log.GatewayName).To(Equal(meta.GatewayName))
			Expect(log.Protocol).To(Equal(meta.Protocol))
			Expect(log.Method).To(Equal(meta.Method))
			Expect(log.URL).To(Equal("www.server.com/test/path"))
			Expect(log.UserAgent).To(Equal(meta.UserAgent))
			Expect(log.Type).To(Equal(meta.Type))
			Expect(log.DurationMean).To(Equal(13 * time.Millisecond))
			Expect(log.DurationMax).To(Equal(16 * time.Millisecond))
			Expect(log.BytesIn).To(Equal(109))
			Expect(log.BytesOut).To(Equal(100))
			Expect(log.Count).To(Equal(4))

		})

		It("Should round the duration mean properly", func() {
			now := time.Now()
			end := now.Add(3 * time.Second)
			log := dataDurationRounding.ToL7Log(now, end)

			Expect(log.StartTime).To(Equal(now.Unix()))
			Expect(log.EndTime).To(Equal(end.Unix()))

			Expect(log.SourceNameAggr).To(Equal(meta.SrcNameAggr))
			Expect(log.SourceNamespace).To(Equal(meta.SrcNamespace))
			Expect(log.SourceType).To(Equal(meta.SrcType))
			Expect(log.SourcePortNum).To(Equal(80))

			Expect(log.DestNameAggr).To(Equal(meta.DestNameAggr))
			Expect(log.DestNamespace).To(Equal(meta.DestNamespace))
			Expect(log.DestType).To(Equal(meta.DestType))
			Expect(log.DestPortNum).To(Equal(80))

			Expect(log.DestServiceName).To(Equal("svc1"))
			Expect(log.DestServiceNamespace).To(Equal("namespace1"))
			Expect(log.DestServicePortName).To(Equal("testPort"))

			Expect(log.ResponseCode).To(Equal(meta.ResponseCode))
			Expect(log.RouteName).To(Equal(meta.RouteName))
			Expect(log.GatewayName).To(Equal(meta.GatewayName))
			Expect(log.Protocol).To(Equal(meta.Protocol))
			Expect(log.Method).To(Equal(meta.Method))
			Expect(log.URL).To(Equal("www.server.com/test/path"))
			Expect(log.UserAgent).To(Equal(meta.UserAgent))
			Expect(log.Type).To(Equal(meta.Type))
			Expect(log.DurationMean).To(Equal(500 * time.Microsecond))
			Expect(log.DurationMax).To(Equal(2 * time.Millisecond))
			Expect(log.BytesIn).To(Equal(109))
			Expect(log.BytesOut).To(Equal(100))
			Expect(log.Count).To(Equal(100))
		})

	})
})
