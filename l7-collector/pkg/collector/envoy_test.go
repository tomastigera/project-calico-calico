// Copyright (c) 2020 Tigera, Inc. All rights reserved.

package collector

import (
	_ "embed"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/l7-collector/pkg/api"
	"github.com/projectcalico/calico/l7-collector/pkg/config"
)

var (
	//go:embed testdata/host_destination.json
	httpDestinationLog string
	//go:embed testdata/host_source.json
	httpSourceLog string
	//go:embed testdata/tcp_destination.json
	tcpDestinationLog string
	//go:embed testdata/bad_format.json
	badFormatLog string
	//go:embed testdata/http_ipv6.json
	httpIPv6Log string
	//go:embed testdata/upstream_service_time.json
	upstreamServiceTimeLog string
	//go:embed testdata/gateway_edge.json
	gatewayEdgeLog string
	//go:embed testdata/gateway_proxied.json
	gatewayProxiedLog string
	//go:embed testdata/gateway_proxied_no_xff.json
	gatewayProxiedNoXFFLog string
	//go:embed testdata/access_log.json
	accessLog string
)

var _ = Describe("Envoy Log Collector ParseRawLogs test", func() {
	// Can use an empty config since the config is not used in ParseRawLogs
	ch := make(chan api.EnvoyInfo)
	c := EnvoyCollectorNew(&config.Config{}, ch)

	Context("With a log with HTTP destination json format", func() {
		It("should return the expected EnvoyLog", func() {
			log, err := c.ParseRawLogs(httpDestinationLog)
			Expect(err).To(BeNil())
			Expect(log.SrcIp).To(Equal("192.168.138.208"))
			Expect(log.DstIp).To(Equal("192.168.35.210"))
			Expect(log.SrcPort).To(Equal(int32(34368)))
			Expect(log.DstPort).To(Equal(int32(80)))
		})

		It("(New)should return the expected EnvoyLog", func() {
			log, err := c.ParseAccessLogs(accessLog)
			Expect(err).To(BeNil())
			Expect(log.SrcIp).To(Equal("192.168.63.139"))
			Expect(log.DstIp).To(Equal("192.168.8.75"))
			Expect(log.SrcPort).To(Equal(int32(52638)))
			Expect(log.DstPort).To(Equal(int32(10080)))
		})
	})

	Context("With a log with TCP destination json format", func() {
		It("should return the expected EnvoyLog", func() {
			log, err := c.ParseRawLogs(tcpDestinationLog)
			Expect(err).To(BeNil())
			Expect(log.SrcIp).To(Equal("192.168.138.208"))
			Expect(log.DstIp).To(Equal("192.168.45.171"))
			Expect(log.SrcPort).To(Equal(int32(46330)))
			Expect(log.DstPort).To(Equal(int32(6379)))
		})
	})
	Context("With a log with no closing brace for the information json", func() {
		It("should return an error", func() {
			_, err := c.ParseRawLogs(badFormatLog)
			Expect(err).NotTo(BeNil())
		})
	})
	Context("With a log with IPv6 IP address format", func() {
		It("should return the expected EnvoyLog", func() {
			log, err := c.ParseRawLogs(httpIPv6Log)
			Expect(err).To(BeNil())
			Expect(log.SrcIp).To(Equal("2001:db8:a0b:12f0::1"))
			Expect(log.DstIp).To(Equal("192.168.35.210"))
			Expect(log.SrcPort).To(Equal(int32(56080)))
			Expect(log.DstPort).To(Equal(int32(80)))
		})
	})
	Context("With a log which is not a destination log", func() {
		It("should return empty EnvoyLog", func() {
			_, err := c.ParseRawLogs(httpSourceLog)
			Expect(err).NotTo(BeNil())
		})
	})
	Context("With a Upstream Service Time", func() {
		It("should return the EnvoyLog with latency", func() {
			log, err := c.ParseRawLogs(upstreamServiceTimeLog)
			Expect(err).NotTo(HaveOccurred())

			Expect(log.Duration).To(Equal(int32(2)))
			Expect(log.UpstreamServiceTime).To(Equal("1"))
			Expect(log.Latency).To(Equal(int32(1)))
		})
	})
	Context("With a gateway-edge reporter log", func() {
		It("should use upstream_host and downstream_direct_remote_address for tuple extraction", func() {
			log, err := c.ParseRawLogs(gatewayEdgeLog)
			Expect(err).NotTo(HaveOccurred())
			// Should use upstream_host (192.168.35.210:80) for destination
			// and downstream_direct_remote_address (192.168.138.208:34368) for source
			Expect(log.SrcIp).To(Equal("192.168.138.208"))
			Expect(log.DstIp).To(Equal("192.168.35.210"))
			Expect(log.SrcPort).To(Equal(int32(34368)))
			Expect(log.DstPort).To(Equal(int32(80)))
		})
	})
	Context("With a gateway-proxied reporter log with X-Forwarded-For", func() {
		It("should use upstream_host and first XFF IP for tuple extraction", func() {
			log, err := c.ParseRawLogs(gatewayProxiedLog)
			Expect(err).NotTo(HaveOccurred())
			// Should use upstream_host (192.168.35.210:80) for destination
			// and first XFF IP (10.1.1.1) for source, with source port from downstream_direct_remote_address
			Expect(log.SrcIp).To(Equal("10.1.1.1"))
			Expect(log.DstIp).To(Equal("192.168.35.210"))
			Expect(log.SrcPort).To(Equal(int32(34368)))
			Expect(log.DstPort).To(Equal(int32(80)))
		})
	})
	Context("With a gateway-proxied reporter log without X-Forwarded-For", func() {
		It("should fallback to gateway-edge behavior", func() {
			log, err := c.ParseRawLogs(gatewayProxiedNoXFFLog)
			Expect(err).NotTo(HaveOccurred())
			// Should fallback to using downstream_direct_remote_address for source
			Expect(log.SrcIp).To(Equal("192.168.138.208"))
			Expect(log.DstIp).To(Equal("192.168.35.210"))
			Expect(log.SrcPort).To(Equal(int32(34368)))
			Expect(log.DstPort).To(Equal(int32(80)))
		})
	})
})
