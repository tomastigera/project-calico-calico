// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package internet

import (
	"slices"

	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

var (
	private = []net.IPNet{
		net.MustParseCIDR("10.0.0.0/8"),
		net.MustParseCIDR("172.16.0.0/12"),
		net.MustParseCIDR("192.168.0.0/16"),
	}
)

func NetContainsInternetAddr(net net.IPNet) bool {
	for i := range private {
		if private[i].Contains(net.IP) {
			return false
		}
	}
	return true
}

func NetPointersContainInternetAddr(nets []*net.IPNet) bool {
	for i := range nets {
		if NetContainsInternetAddr(*nets[i]) {
			return true
		}
	}
	return false
}

func NetsContainInternetAddr(nets []net.IPNet) bool {
	return slices.ContainsFunc(nets, NetContainsInternetAddr)
}
