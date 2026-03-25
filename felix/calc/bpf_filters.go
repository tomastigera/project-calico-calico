// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package calc

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
)

// default rule action to be used when appending multiple rules
const defaultRuleAction = " or "

// default port action to be used when appending multiple ports
const defaultPortAction = " or "

// default inter-rule action to be used when appending protocol and ports
const defaultInterRuleAction = " and "

// RenderBPFFilter returns a BPF filter to be applied when capturing traffic
// from the given PacketCaptureRules
func RenderBPFFilter(rules []v3.PacketCaptureRule, loggingID string) string {
	log.WithField("CAPTURE", loggingID).Debugf("Rendering filters for %v", rules)
	var filter = strings.Join(renderRules(rules), defaultRuleAction)
	log.WithField("CAPTURE", loggingID).Debugf("Filters is %s", filter)
	return filter
}

func renderRules(filters []v3.PacketCaptureRule) []string {
	var renderedRules []string
	for _, rule := range filters {
		var renderedRule = renderRule(rule)
		// write ports if defined as "(tcp) or (udp)"
		if len(renderedRule) != 0 {
			renderedRules = append(renderedRules, fmt.Sprintf("(%s)", renderedRule))
		}
	}

	return renderedRules
}

// render rule will return a rule as either "tcp", "tcp and (port 80)" or "port 80"
func renderRule(rule v3.PacketCaptureRule) string {
	var buffer bytes.Buffer

	// write protocol if defined
	buffer.WriteString(renderProtocol(rule.Protocol))

	// write "and" if both protocol and ports are defined
	if rule.Protocol != nil && len(rule.Ports) != 0 {
		buffer.WriteString(defaultInterRuleAction)
	}

	// write ports if defined as "(port 80 or portrange 80-100)"
	var ports = strings.Join(renderPorts(rule.Ports), defaultPortAction)
	if len(ports) != 0 {
		fmt.Fprintf(&buffer, "(%s)", ports)
	}

	return buffer.String()
}

func renderProtocol(protocol *numorstring.Protocol) string {
	if protocol != nil {
		_, err := strconv.Atoi(protocol.String())
		if err != nil {
			switch protocol.String() {
			case numorstring.ProtocolUDPLite:
				return "ip proto 136"
			case numorstring.ProtocolICMPv6:
				return "icmp6"
			default:
				return strings.ToLower(protocol.String())
			}
		} else {
			return fmt.Sprintf("ip proto %d", protocol.NumVal)
		}
	}

	return ""
}

func renderPorts(ports []numorstring.Port) []string {
	var renderedPorts []string
	for _, port := range ports {
		renderedPorts = append(renderedPorts, renderPort(port))
	}

	return renderedPorts
}

func renderPort(port numorstring.Port) string {
	if port.MaxPort == port.MinPort {
		return fmt.Sprintf("port %d", port.MinPort)
	}

	return fmt.Sprintf("portrange %d-%d", port.MinPort, port.MaxPort)
}
