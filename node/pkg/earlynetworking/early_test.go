package earlynetworking_test

import (
	"fmt"
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/node/pkg/earlynetworking"
)

var _ = DescribeTable("sameSubnet",
	func(nlAddr netlink.Addr, peerIP string, expectedEqual bool) {
		same := earlynetworking.SameSubnet(nlAddr, peerIP)
		Expect(same).To(BeEquivalentTo(expectedEqual))
	},
	Entry("Addr in same subnet as peer",
		netlink.Addr{
			IPNet: ipNetFromString("172.31.11.3/24"),
		},
		"172.31.11.1",
		true,
	),
	Entry("Addr in different subnet to peer",
		netlink.Addr{
			IPNet: ipNetFromString("172.31.11.3/24"),
		},
		"172.31.12.1",
		false,
	),
)

func ipNetFromString(s string) *net.IPNet {
	ip, cidr, err := net.ParseCIDR(s)
	if err != nil {
		panic(fmt.Sprintf("Programmer error - bad test string given to ipNetFromString: %s", err))
	}

	return &net.IPNet{
		IP:   ip,
		Mask: cidr.Mask,
	}
}
