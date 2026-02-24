// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package dnsdeniedpacket_test

import (
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/nfqueue"
	"github.com/projectcalico/calico/felix/nfqueue/dnsdeniedpacket"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var (
	srcIPv4 = net.MustParseIP("10.10.10.0")
	srcIPv6 = net.MustParseIP("ff::00")
)

// Test NfQueueConnector
var _ = Describe("DNS Denied Packet handling", func() {
	var packetProcessor dnsdeniedpacket.PacketProcessor
	var handler nfqueue.Handler
	var id uint32

	newMockPacket := func(ip string) (packet nfqueue.Packet, released <-chan struct{}) {
		ipn := net.MustParseIP(ip)

		var payload []byte
		var hwProto uint16
		if ipn.Version() == 4 {
			hwProto = 0x0800
			pkt := gopacket.NewSerializeBuffer()
			err := gopacket.SerializeLayers(
				pkt,
				gopacket.SerializeOptions{ComputeChecksums: true},
				&layers.IPv4{
					Version:  4,
					IHL:      5,
					TTL:      64,
					Flags:    layers.IPv4DontFragment,
					SrcIP:    srcIPv4.IP,
					DstIP:    ipn.IP,
					Protocol: layers.IPProtocolTCP,
					Length:   5 * 4,
				},
			)
			Expect(err).NotTo(HaveOccurred())
			payload = pkt.Bytes()
		} else {
			hwProto = 0x86DD
			pkt := gopacket.NewSerializeBuffer()
			err := gopacket.SerializeLayers(
				pkt,
				gopacket.SerializeOptions{FixLengths: true},
				&layers.IPv6{
					Version:    6,
					HopLimit:   64,
					NextHeader: layers.IPProtocolTCP,
					SrcIP:      srcIPv6.IP,
					DstIP:      ipn.IP,
				},
				&layers.TCP{
					SrcPort: 31024,
					DstPort: 5060,
				},
				gopacket.Payload([]byte{1, 2, 3, 4}),
			)
			Expect(err).NotTo(HaveOccurred())
			payload = pkt.Bytes()
		}

		c := make(chan struct{})
		id++

		packetID := id
		p := nfqueue.Packet{
			ID:         packetID,
			Timestamp:  nil,
			Mark:       nil,
			HwProtocol: &hwProto,
			Payload:    payload,
			Release: func() {
				close(c)
			},
		}

		return p, c
	}

	BeforeEach(func() {
		id = 0
		packetProcessor, handler = dnsdeniedpacket.NewWithoutNFQueue()
		packetProcessor.Start()
	})

	AfterEach(func() {
		packetProcessor.Stop()
	})

	When("receiving a packet", func() {
		It("it handles release by timeout", func() {
			p, c := newMockPacket("1.2.3.4")
			handler.OnPacket(p)
			Expect(packetProcessor.DebugNumPackets(1)).NotTo(HaveOccurred())
			Expect(packetProcessor.DebugNumIPs(1)).NotTo(HaveOccurred())

			handler.OnRelease(p.ID, nfqueue.ReleasedByTimeout)
			Expect(packetProcessor.DebugNumPackets(0)).NotTo(HaveOccurred())
			Expect(packetProcessor.DebugNumIPs(0)).NotTo(HaveOccurred())
			Expect(c).NotTo(BeClosed())
		})

		It("it handles release by IPSet update", func() {
			p, c := newMockPacket("1.2.3.4")
			handler.OnPacket(p)
			Expect(packetProcessor.DebugNumPackets(1)).NotTo(HaveOccurred())
			Expect(packetProcessor.DebugNumIPs(1)).NotTo(HaveOccurred())

			packetProcessor.OnIPSetMemberUpdates(set.From("1.2.3.4", "1.2.2.2", "10.20.30.40"))
			Expect(c).To(BeClosed())

			handler.OnRelease(p.ID, nfqueue.ReleasedByConsumer)
			Expect(packetProcessor.DebugNumPackets(0)).NotTo(HaveOccurred())
			Expect(packetProcessor.DebugNumIPs(0)).NotTo(HaveOccurred())
		})

		It("it handles release of multiple packets with the same IP", func() {
			p1, c1 := newMockPacket("1.2.3.4")
			handler.OnPacket(p1)
			p2, c2 := newMockPacket("1.2.3.4")
			handler.OnPacket(p2)
			p3, c3 := newMockPacket("10.20.30.40")
			handler.OnPacket(p3)

			Expect(packetProcessor.DebugNumPackets(3)).NotTo(HaveOccurred())
			Expect(packetProcessor.DebugNumIPs(2)).NotTo(HaveOccurred())

			packetProcessor.OnIPSetMemberUpdates(set.From("1.2.3.4", "1.2.2.2"))
			Expect(c1).To(BeClosed())
			Expect(c2).To(BeClosed())
			Expect(c3).ToNot(BeClosed())

			handler.OnRelease(p1.ID, nfqueue.ReleasedByConsumer)
			handler.OnRelease(p2.ID, nfqueue.ReleasedByConsumer)
			Expect(packetProcessor.DebugNumPackets(1)).NotTo(HaveOccurred())
			Expect(packetProcessor.DebugNumIPs(1)).NotTo(HaveOccurred())

			handler.OnRelease(p3.ID, nfqueue.ReleasedByConsumer)
			Expect(packetProcessor.DebugNumPackets(0)).NotTo(HaveOccurred())
			Expect(packetProcessor.DebugNumIPs(0)).NotTo(HaveOccurred())
		})

		It("it handles immediate release of packet from previous IPSet update", func() {
			packetProcessor.OnIPSetMemberUpdates(set.From("1.2.3.4", "1.2.2.2"))

			p1, c1 := newMockPacket("1.2.3.4")
			handler.OnPacket(p1)
			p2, c2 := newMockPacket("1.2.3.4")
			handler.OnPacket(p2)
			p3, c3 := newMockPacket("10.20.30.40")
			handler.OnPacket(p3)

			Expect(c1).To(BeClosed())
			Expect(c2).To(BeClosed())
			Expect(c3).ToNot(BeClosed())

			// Cache is not updated with the automatically released packets.
			Expect(packetProcessor.DebugNumPackets(1)).NotTo(HaveOccurred())
			Expect(packetProcessor.DebugNumIPs(1)).NotTo(HaveOccurred())

			// But we still get OnRelease notifications from the NFQueueConn
			handler.OnRelease(p1.ID, nfqueue.ReleasedByConsumer)
			handler.OnRelease(p2.ID, nfqueue.ReleasedByConsumer)
			Expect(packetProcessor.DebugNumPackets(1)).NotTo(HaveOccurred())
			Expect(packetProcessor.DebugNumIPs(1)).NotTo(HaveOccurred())

			handler.OnRelease(p3.ID, nfqueue.ReleasedByConsumer)
			Expect(packetProcessor.DebugNumPackets(0)).NotTo(HaveOccurred())
			Expect(packetProcessor.DebugNumIPs(0)).NotTo(HaveOccurred())
		})

		It("it handles immediate release of packet from multiple previous IPSet updates", func() {
			packetProcessor.OnIPSetMemberUpdates(set.From("1.2.3.4", "1.2.2.2"))
			packetProcessor.OnIPSetMemberUpdates(set.From("10.20.30.40"))

			p1, c1 := newMockPacket("1.2.3.4")
			handler.OnPacket(p1)
			p2, c2 := newMockPacket("1.2.3.4")
			handler.OnPacket(p2)
			p3, c3 := newMockPacket("10.20.30.40")
			handler.OnPacket(p3)

			Expect(c1).To(BeClosed())
			Expect(c2).To(BeClosed())
			Expect(c3).To(BeClosed())

			// Cache is not updated with the automatically released packets.
			Expect(packetProcessor.DebugNumPackets(0)).NotTo(HaveOccurred())
			Expect(packetProcessor.DebugNumIPs(0)).NotTo(HaveOccurred())

			// But we still get OnRelease notifications from the NFQueueConn
			handler.OnRelease(p1.ID, nfqueue.ReleasedByConsumer)
			handler.OnRelease(p2.ID, nfqueue.ReleasedByConsumer)
			handler.OnRelease(p3.ID, nfqueue.ReleasedByConsumer)
			Expect(packetProcessor.DebugNumPackets(0)).NotTo(HaveOccurred())
			Expect(packetProcessor.DebugNumIPs(0)).NotTo(HaveOccurred())
		})

		It("it handles not releasing packet if IPSet updates expire", func() {
			// Send updates and then wait beyond the expiration time. Should not release from either set.
			packetProcessor.OnIPSetMemberUpdates(set.From("1.2.3.4", "1.2.2.2"))
			packetProcessor.OnIPSetMemberUpdates(set.From("10.20.30.40"))
			time.Sleep(2 * time.Second)

			p1, c1 := newMockPacket("1.2.3.4")
			handler.OnPacket(p1)
			p2, c2 := newMockPacket("1.2.3.4")
			handler.OnPacket(p2)
			p3, c3 := newMockPacket("10.20.30.40")
			handler.OnPacket(p3)

			Expect(c1).ToNot(BeClosed())
			Expect(c2).ToNot(BeClosed())
			Expect(c3).ToNot(BeClosed())

			Expect(packetProcessor.DebugNumPackets(3)).NotTo(HaveOccurred())
			Expect(packetProcessor.DebugNumIPs(2)).NotTo(HaveOccurred())

			handler.OnRelease(p1.ID, nfqueue.ReleasedByTimeout)
			handler.OnRelease(p2.ID, nfqueue.ReleasedByTimeout)
			handler.OnRelease(p3.ID, nfqueue.ReleasedByTimeout)
			Expect(packetProcessor.DebugNumPackets(0)).NotTo(HaveOccurred())
			Expect(packetProcessor.DebugNumIPs(0)).NotTo(HaveOccurred())
		})

		It("it handles immediate release of packet from recent (non-expired) IPSet updates", func() {
			// Send updates and then wait beyond the expiration time. Should not release from this set.
			packetProcessor.OnIPSetMemberUpdates(set.From("1.2.3.4", "1.2.2.2"))
			time.Sleep(2 * time.Second)
			// Send updates and don't expire.  Should release from this set.
			packetProcessor.OnIPSetMemberUpdates(set.From("10.20.30.40"))

			p1, c1 := newMockPacket("1.2.3.4")
			handler.OnPacket(p1)
			p2, c2 := newMockPacket("1.2.3.4")
			handler.OnPacket(p2)
			p3, c3 := newMockPacket("10.20.30.40")
			handler.OnPacket(p3)

			Expect(c1).ToNot(BeClosed())
			Expect(c2).ToNot(BeClosed())
			Expect(c3).To(BeClosed())

			// Cache is not updated with the automatically released packets.
			Expect(packetProcessor.DebugNumPackets(2)).NotTo(HaveOccurred())
			Expect(packetProcessor.DebugNumIPs(1)).NotTo(HaveOccurred())

			// But we still get OnRelease notifications from the NFQueueConn
			handler.OnRelease(p3.ID, nfqueue.ReleasedByConsumer)
			Expect(packetProcessor.DebugNumPackets(2)).NotTo(HaveOccurred())
			Expect(packetProcessor.DebugNumIPs(1)).NotTo(HaveOccurred())

			handler.OnRelease(p1.ID, nfqueue.ReleasedByTimeout)
			handler.OnRelease(p2.ID, nfqueue.ReleasedByTimeout)
			Expect(packetProcessor.DebugNumPackets(0)).NotTo(HaveOccurred())
			Expect(packetProcessor.DebugNumIPs(0)).NotTo(HaveOccurred())
		})
	})
})
