package net

import (
	"net"
	"strings"
)

// Input argument comes from EGRESS_POD_IPS containing the list of all addresses assigned to
// this egress gateway separated by comma. As an example, the value could be either 192.168.0.1 or
// 2001::1111:1,192.168.0.1. The value should not contain two IPv4, like 192.168.0.1,10.10.10.10,
// but if that happens (for whatever reason), we should always use the first IPv4 address.
func ParseEgressPodIPs(ips string) net.IP {
	for ip := range strings.SplitSeq(ips, ",") {
		addr := net.ParseIP(ip)
		if addr != nil && addr.To4() != nil {
			return addr
		}
	}
	return nil
}
