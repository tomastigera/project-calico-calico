// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package collector

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/ingress-collector/pkg/config"
)

var (
	testLogBeginning        = "tigera_secure_ee_ingress: {\"source_ip\": \"1.1.1.1\", \"destination_ip\": \"2.2.2.2\", \"source_port\": 80, \"destination_port\": 443, \"protocol\": \"tcp\"} log info stuff - fake ip"
	testLogMiddle           = "log info stuff - tigera_secure_ee_ingress: {\"source_ip\": \"1.1.1.1\", \"destination_ip\": \"2.2.2.2\", \"source_port\": 80, \"destination_port\": 443, \"protocol\": \"tcp\"} - fake ip"
	testLogEnd              = "log info stuff - fake ip tigera_secure_ee_ingress: {\"source_ip\": \"1.1.1.1\", \"destination_ip\": \"2.2.2.2\", \"source_port\": 80, \"destination_port\": 443, \"protocol\": \"tcp\"}"
	testLogMultipleSections = "log info - tigera_secure_ee_ingress: {\"source_ip\": \"1.1.1.1\", \"destination_ip\": \"2.2.2.2\", \"source_port\": 80, \"destination_port\": 443, \"protocol\": \"tcp\"} stuff tiger_secure_ee_ingress: {\"source_ip\": \"3.3.3.3\"} fake ip"
	testLogNoClosingBrace   = "log info stuff - tigera_secure_ee_ingress: {\"source_ip\": \"1.1.1.1\", \"destination_ip\": \"2.2.2.2\", \"source_port\": 80, \"destination_port\": 443, \"protocol\": \"tcp\" - fake ip"
	testLogNoSections       = "log info stuff fake ip"
	testLogWrongFields      = "log info stuff - tigera_secure_ee_ingress: {\"test\": 1}"
	testLogIpFields         = "tigera_secure_ee_ingress: {\"source_ip\": \"1.1.1.1\", \"destination_ip\": \"2.2.2.2\", \"source_port\": 80, \"destination_port\": 443, \"protocol\": \"tcp\", \"x-forwarded-for\": \"3.3.3.3\", \"x-real-ip\": \"4.4.4.4\"} log info stuff - fake ip"
)

var _ = Describe("NGINX Ingress Log Collector ParseRawLogs test", func() {
	// Can use an empty config since the config is not used in ParseRawLogs
	c := NewNginxCollector(&config.Config{})

	Context("With a log with the information json in the beginning of the log", func() {
		It("should return the expected IngressLog", func() {
			log, err := c.ParseRawLogs(testLogBeginning)
			Expect(err).To(BeNil())
			Expect(log.SrcIp).To(Equal("1.1.1.1"))
			Expect(log.DstIp).To(Equal("2.2.2.2"))
			Expect(log.SrcPort).To(Equal(int32(80)))
			Expect(log.DstPort).To(Equal(int32(443)))
			Expect(log.Protocol).To(Equal("tcp"))
		})
	})
	Context("With a log with the information json in the middle of the log", func() {
		It("should return the expected IngressLog", func() {
			log, err := c.ParseRawLogs(testLogMiddle)
			Expect(err).To(BeNil())
			Expect(log.SrcIp).To(Equal("1.1.1.1"))
			Expect(log.DstIp).To(Equal("2.2.2.2"))
			Expect(log.SrcPort).To(Equal(int32(80)))
			Expect(log.DstPort).To(Equal(int32(443)))
			Expect(log.Protocol).To(Equal("tcp"))
		})
	})
	Context("With a log with the information json in the end of the log", func() {
		It("should return the expected IngressLog", func() {
			log, err := c.ParseRawLogs(testLogEnd)
			Expect(err).To(BeNil())
			Expect(log.SrcIp).To(Equal("1.1.1.1"))
			Expect(log.DstIp).To(Equal("2.2.2.2"))
			Expect(log.SrcPort).To(Equal(int32(80)))
			Expect(log.DstPort).To(Equal(int32(443)))
			Expect(log.Protocol).To(Equal("tcp"))
		})
	})
	Context("With a log with the multiple sets of information json", func() {
		It("should return the IngressLog from the first blob of json", func() {
			log, err := c.ParseRawLogs(testLogMultipleSections)
			Expect(err).To(BeNil())
			Expect(log.SrcIp).To(Equal("1.1.1.1"))
			Expect(log.DstIp).To(Equal("2.2.2.2"))
			Expect(log.SrcPort).To(Equal(int32(80)))
			Expect(log.DstPort).To(Equal(int32(443)))
			Expect(log.Protocol).To(Equal("tcp"))
		})
	})
	Context("With a log with no closing brace for the information json", func() {
		It("should return an error", func() {
			_, err := c.ParseRawLogs(testLogNoClosingBrace)
			Expect(err).NotTo(BeNil())
		})
	})
	Context("With a log with no information json", func() {
		It("should return an error", func() {
			_, err := c.ParseRawLogs(testLogNoSections)
			Expect(err).NotTo(BeNil())
		})
	})
	Context("With a log with the wrong fields in the information json", func() {
		It("should return an empty log", func() {
			log, err := c.ParseRawLogs(testLogWrongFields)
			Expect(err).To(BeNil())
			Expect(log.SrcIp).To(Equal(""))
			Expect(log.DstIp).To(Equal(""))
			Expect(log.SrcPort).To(Equal(int32(0)))
			Expect(log.DstPort).To(Equal(int32(0)))
			Expect(log.Protocol).To(Equal(""))
		})
	})
	Context("With a log with x-forwarded-for and x-real-ip fields", func() {
		It("should return a log with x-forwarded-for and x-real-ip fields", func() {
			log, err := c.ParseRawLogs(testLogIpFields)
			Expect(err).To(BeNil())
			Expect(log.SrcIp).To(Equal("1.1.1.1"))
			Expect(log.DstIp).To(Equal("2.2.2.2"))
			Expect(log.SrcPort).To(Equal(int32(80)))
			Expect(log.DstPort).To(Equal(int32(443)))
			Expect(log.Protocol).To(Equal("tcp"))
			Expect(log.XForwardedFor).To(Equal("3.3.3.3"))
			Expect(log.XRealIp).To(Equal("4.4.4.4"))
		})
	})
})
