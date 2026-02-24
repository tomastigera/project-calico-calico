// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package calc_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/felix/calc"
)

var _ = Describe("BpfFilters tests for PacketCapture", func() {
	var tcpProtocol = numorstring.ProtocolFromString("TCP")
	var udpProtocol = numorstring.ProtocolFromString("UDP")
	var numericalProtocol = numorstring.ProtocolFromInt(6)
	var lowerCaseProtocol = numorstring.ProtocolFromString("tcp")
	var icmpv6Protocol = numorstring.ProtocolFromString(numorstring.ProtocolICMPv6)
	var udpliteProtocol = numorstring.ProtocolFromString(numorstring.ProtocolUDPLite)
	var port80 = numorstring.SinglePort(80)
	var port443 = numorstring.SinglePort(443)
	var portRange = mustParsePortRange(80, 100)

	DescribeTable("Parse BPF filters",
		func(rules []v3.PacketCaptureRule, expected string) {
			var filter = calc.RenderBPFFilter(rules, "")
			Expect(filter).To(Equal(expected))
		},
		Entry("No filters", compose(), ""),
		Entry("TCP protocol", compose(rule(&tcpProtocol)), "(tcp)"),
		Entry("Lower case TCP protocol", compose(rule(&lowerCaseProtocol)), "(tcp)"),
		Entry("Numerical protocol", compose(rule(&numericalProtocol)), "(ip proto 6)"),
		Entry("ICMPv6 protocol", compose(rule(&icmpv6Protocol)), "(icmp6)"),
		Entry("UDPLite protocol", compose(rule(&udpliteProtocol)), "(ip proto 136)"),
		Entry("Port 80", compose(rule(nil, port80)), "((port 80))"),
		Entry("PortRange 80-100", compose(rule(nil, portRange)), "((portrange 80-100))"),
		Entry("TCP protocol and port 80 as a single rule", compose(rule(&tcpProtocol, port80)), "(tcp and (port 80))"),
		Entry("TCP protocol and multiple ports", compose(rule(&tcpProtocol, port80, port443)), "(tcp and (port 80 or port 443))"),
		Entry("TCP protocol and portrange 80-100 as a single rule", compose(rule(&tcpProtocol, portRange)), "(tcp and (portrange 80-100))"),
		Entry("TCP protocol and udp protocol as two rules", compose(rule(&tcpProtocol), rule(&udpProtocol)), "(tcp) or (udp)"),
		Entry("Numerical protocol and port 80 as a single rule", compose(rule(&numericalProtocol, port80)), "(ip proto 6 and (port 80))"),
		Entry("Numerical protocol and multiple ports", compose(rule(&numericalProtocol, port80, port443)), "(ip proto 6 and (port 80 or port 443))"),
		Entry("Numerical protocol and portrange 80-100 as a single rule", compose(rule(&numericalProtocol, portRange)), "(ip proto 6 and (portrange 80-100))"),
		Entry("Numerical protocol and udp protocol as two rules", compose(rule(&numericalProtocol), rule(&udpProtocol)), "(ip proto 6) or (udp)"),
	)
})

func rule(protocol *numorstring.Protocol, ports ...numorstring.Port) v3.PacketCaptureRule {
	if ports == nil {
		return v3.PacketCaptureRule{Protocol: protocol}
	}

	return v3.PacketCaptureRule{Protocol: protocol, Ports: ports}
}

func compose(rules ...v3.PacketCaptureRule) []v3.PacketCaptureRule {
	return rules
}

func mustParsePortRange(min, max uint16) numorstring.Port {
	p, err := numorstring.PortFromRange(min, max)
	if err != nil {
		panic(err)
	}
	return p
}
