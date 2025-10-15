// Copyright (c) 2021-2025 Tigera, Inc. All rights reserved.

package dnsdeniedpacket

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/jitter"
	"github.com/projectcalico/calico/felix/nfnetlink"
	"github.com/projectcalico/calico/felix/nfnetlink/pkt"
	"github.com/projectcalico/calico/felix/nfqueue"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	cprometheus "github.com/projectcalico/calico/libcalico-go/lib/prometheus"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var (
	prometheusNfqueueShutdownCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_dns_policy_nfqueue_shutdown_count",
		Help: "Number of times nfqueue was shutdown due to a fatal error",
	})

	prometheusNfqueueVerdictFailCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_dns_policy_nfqueue_monitor_nf_verdict_failed",
		Help: "Count of the number of times that the monitor has failed to set the verdict",
	})

	prometheusNfqueueQueuedLatency = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_dns_policy_nfqueue_monitor_queued_latency",
		Help: "Summary of the length of time packets where in the nfqueue queue",
	})

	prometheusPacketReleaseLatency = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_dns_policy_nfqueue_monitor_release_latency",
		Help: "Summary of the latency for releasing packets",
	})

	prometheusReleasePacketBatchSizeGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_dns_policy_nfqueue_monitor_release_packets_batch_size",
		Help: "Gauge of the number of packets to release currently in memory",
	})

	prometheusPacketsInCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_dns_policy_nfqueue_monitor_packets_in",
		Help: "Count of the number of packets seen",
	})

	prometheusPacketsReleaseCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_dns_policy_nfqueue_monitor_packets_released",
		Help: "Count of the number of packets that have been released",
	})

	prometheusDNRDroppedCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_dns_policy_nfqueue_monitor_packets_dnr_dropped",
		Help: "Count of the number of packets that have been dropped because the DNR mark was present",
	})
)

func init() {
	prometheus.MustRegister(
		prometheusNfqueueShutdownCount,
		prometheusNfqueueVerdictFailCount,
		prometheusNfqueueQueuedLatency,
		prometheusPacketReleaseLatency,
		prometheusReleasePacketBatchSizeGauge,
		prometheusPacketsInCount,
		prometheusPacketsReleaseCount,
		prometheusDNRDroppedCount,
	)
}

const (
	// How often to check the hold time.
	holdTimeCheckInterval = 50 * time.Millisecond

	// 80 bytes is suficient to decode the IP header information.
	maxPacketSize = 80

	// defaultPacketReleaseTimeout is the maximum length of time to hold a packet while waiting for an IP set update
	// containing the destination IP of the packet.
	defaultPacketReleaseTimeout = 1000 * time.Millisecond

	// defaultIPCacheDuration is the default maximum length of time to store ips in the cache before deleting them. This
	// defaults to 1 second because that is the minimum TTL for an IP in a DNS response.
	defaultIPCacheDuration = 1000 * time.Millisecond
)

type PacketProcessor interface {
	Start()
	Stop()
	OnIPSetMemberUpdates(newMemberUpdates set.Set[string])
	DebugKillCurrentNfqueueConnection() error
	DebugNumPackets(num int) error
	DebugNumIPs(num int) error
}

func New(
	queueID uint16, queueLength uint32, dnrMark uint32, markBitsToPreserve uint32,
) PacketProcessor {
	options := []nfqueue.Option{
		nfqueue.OptMaxQueueLength(queueLength),
		nfqueue.OptMaxPacketLength(maxPacketSize),
		nfqueue.OptMaxHoldTime(defaultPacketReleaseTimeout),
		nfqueue.OptHoldTimeCheckInterval(holdTimeCheckInterval),
		nfqueue.OptDNRDroppedCounter(prometheusDNRDroppedCount),
		nfqueue.OptPacketsSeenCounter(prometheusPacketsInCount),
		nfqueue.OptPacketsHeldGauge(prometheusReleasePacketBatchSizeGauge),
		nfqueue.OptShutdownCounter(prometheusNfqueueShutdownCount),
		nfqueue.OptSetVerdictFailureCounter(prometheusNfqueueVerdictFailCount),
		nfqueue.OptPacketReleasedAfterHoldTimeCounter(prometheusPacketsReleaseCount),
		nfqueue.OptPacketReleasedCounter(prometheusPacketsReleaseCount),
		nfqueue.OptPacketInNfQueueSummary(prometheusNfqueueQueuedLatency),
		nfqueue.OptPacketHoldTimeSummary(prometheusPacketReleaseLatency),
		nfqueue.OptVerdictRepeat(dnrMark),
		nfqueue.OptMarkBitsToPreserve(markBitsToPreserve),
	}

	h := newHandler()

	p := &packetProcessor{
		nfc:     nfqueue.NewNfQueueConnector(queueID, h, options...),
		handler: h,
	}

	return p
}

// NewWithoutNFQueue returns a new PacketProcessor without a real NFQueue. Also returns the handler.
// This is used for unit testing.
func NewWithoutNFQueue() (PacketProcessor, nfqueue.Handler) {
	h := newHandler()

	p := &packetProcessor{
		handler: h,
	}

	return p, h
}

type packetProcessor struct {
	nfc     nfqueue.NfQueueConnector
	handler *handler
	cancel  context.CancelFunc
}

func (p *packetProcessor) Start() {
	log.Debug("Starting denied packet processor")
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	if p.nfc != nil {
		p.nfc.Connect(ctx)
	}
	go p.loop(ctx)
}

func (p *packetProcessor) Stop() {
	log.Debug("Stopping denied packet processor")
	p.cancel()
}

func (p *packetProcessor) DebugKillCurrentNfqueueConnection() error {
	return p.nfc.DebugKillConnection()
}

// DebugNumPackets is just used by the UTs for testing the bookeeping of the IP and ID data. This tests the number of
// packets (unique packet IDs) that are currently in the cache.
func (p *packetProcessor) DebugNumPackets(num int) error {
	p.handler.lock.Lock()
	defer p.handler.lock.Unlock()
	// Should be correct number of entries in ID map.
	if len(p.handler.idToPacket) != num {
		return fmt.Errorf("wrong number of packet IDs stored, expecting %d: %#v", num, p.handler.idToPacket)
	}
	// Also the total in the IPs map should be the same.
	tot := 0
	for _, packets := range p.handler.dstIPToPackets {
		tot += len(packets)
	}
	if tot != num {
		return fmt.Errorf("wrong number of packet stored by IP, expecting %d: %#v", num, p.handler.dstIPToPackets)
	}
	return nil
}

// DebugNumIPs is just used by the UTs for testing the bookeeping of the IP and ID data. This tests the number of
// IPs that are currently in the cache.
func (p *packetProcessor) DebugNumIPs(num int) error {
	p.handler.lock.Lock()
	defer p.handler.lock.Unlock()
	// Should be correct number of entries in ID map.
	if len(p.handler.dstIPToPackets) != num {
		return fmt.Errorf("wrong number of packet IPs stored, expecting %d: %#v", num, p.handler.dstIPToPackets)
	}
	return nil
}

func (p *packetProcessor) loop(ctx context.Context) {
	ticker := jitter.NewTicker(defaultIPCacheDuration, defaultIPCacheDuration/10)
	for {
		select {
		case <-ctx.Done():
			log.Debug("Denied packet stopped")
			return
		case t := <-ticker.Channel():
			p.handler.expireIPSetUpdates(t)
		}
	}
}

// OnIPSetMemberUpdates accepts a set of IPs which the packetProcessor uses to decide what, if any, packets should be
// released from the packetProcessor.
func (p *packetProcessor) OnIPSetMemberUpdates(newMemberUpdates set.Set[string]) {
	p.handler.onIPSetMemberUpdates(newMemberUpdates)
}

// handler implements the nfqueue.Handler interface and handles caching and release of packets due to IPSet update.
type handler struct {
	rateLimitedErrLogger *logutils.RateLimitedLogger

	// Arrays and maps used to store packets and IPs
	lock           sync.Mutex
	dstIPToPackets map[string][]*nfqueuePacket
	idToPacket     map[uint32]*nfqueuePacket

	// Programmed IPSets.
	ipsetUpdatesFirst *ipsetUpdates
	ipsetUpdatesLast  *ipsetUpdates
}

// newHandler creates a new handler instance.
func newHandler() *handler {
	return &handler{
		rateLimitedErrLogger: logutils.NewRateLimitedLogger(logutils.OptInterval(15 * time.Second)),
		dstIPToPackets:       make(map[string][]*nfqueuePacket),
		idToPacket:           make(map[uint32]*nfqueuePacket),
	}
}

// OnPacket is called for a newly queued denied packet.
func (h *handler) OnPacket(packet nfqueue.Packet) {
	if packet.HwProtocol == nil {
		h.rateLimitedErrLogger.Error("Releasing unknown packet type (no ethernet protocol)")
		packet.Release()
		return
	}

	var dstIP string
	switch *packet.HwProtocol {
	case nfnetlink.IPv4Proto:
		log.Debug("Process IPv4 packet")
		ipHeader := pkt.ParseIPv4Header(packet.Payload)
		dstIP = ipHeader.Daddr.String()
	case nfnetlink.IPv6Proto:
		log.Debug("Process IPv6 packet")
		ipHeader := pkt.ParseIPv6Header(packet.Payload)
		dstIP = ipHeader.Daddr.String()
	default:
		h.rateLimitedErrLogger.Error("Releasing unknown packet type (neither ipv4 nor ipv6)")
		packet.Release()
		return
	}

	// If the destination IP is in the IP cache then we received the IP set member update just before the packet so we
	// just release the packet immediately.
	h.lock.Lock()
	defer h.lock.Unlock()

	// Loop through the latest set of  IPSet updates to see if the destination IP was recently programmed.
	for updates := h.ipsetUpdatesFirst; updates != nil; updates = updates.next {
		if updates.ips.Contains(dstIP) {
			log.Debugf("Releasing new packet as already received IPSet update: %s", dstIP)
			packet.Release()
			return
		}
	}

	// The destination was not recently programmed, store this packet in our cache so that we can check again when we
	// get more IPSet updates.
	log.Debugf("Storing packet %d to %s until IPSet programmed or timeout", packet.ID, dstIP)
	np := &nfqueuePacket{
		packetID: packet.ID,
		dstIP:    dstIP,
		release:  packet.Release,
	}

	h.dstIPToPackets[dstIP] = append(h.dstIPToPackets[dstIP], np)
	h.idToPacket[packet.ID] = np
}

// OnRelease is called for ALL released packets (either through timeout or an explicit call to Release()). We can do
// all packet cache deletion here.
func (h *handler) OnRelease(id uint32, reason nfqueue.ReleaseReason) {
	h.lock.Lock()
	defer h.lock.Unlock()
	np := h.idToPacket[id]
	if np == nil {
		// Packet was never cached.
		return
	}

	// Remove the packet from our cache.
	log.Debugf("Packet %d released, reason: %v", id, reason)
	delete(h.idToPacket, id)
	packetsByIP := h.dstIPToPackets[np.dstIP]
	if len(packetsByIP) == 1 {
		delete(h.dstIPToPackets, np.dstIP)
	} else {
		for i := range packetsByIP {
			if packetsByIP[i] == np {
				packetsByIP[i] = packetsByIP[len(packetsByIP)-1]
				h.dstIPToPackets[np.dstIP] = packetsByIP[:len(packetsByIP)-1]
				break
			}
		}
	}
}

// onIPSetMemberUpdates accepts a set of IPs which the packetProcessor uses to decide what, if any, packets should be
// released from the packetProcessor.
func (h *handler) onIPSetMemberUpdates(newMemberUpdates set.Set[string]) {
	log.Debugf("IPSet updates containing: %#v", newMemberUpdates)
	h.lock.Lock()
	defer h.lock.Unlock()

	// Store this set of updaes for a short duration for denied packets arriving shortly that have just missed the
	// update. We store the updates in a singly linked list.
	updates := &ipsetUpdates{
		expiryTime: time.Now().Add(defaultIPCacheDuration),
		ips:        newMemberUpdates,
	}
	if h.ipsetUpdatesFirst == nil {
		h.ipsetUpdatesFirst = updates
		h.ipsetUpdatesLast = updates
	} else {
		h.ipsetUpdatesLast.next = updates
		h.ipsetUpdatesLast = updates
	}

	// Check if any of the IPs in the update are ones we are holding packets for. If so, release the packets. We will
	// get OnRelease() callbacks once complete and then we can remove the entries from our cache.
	for ip, packets := range h.dstIPToPackets {
		if newMemberUpdates.Contains(ip) {
			for _, p := range packets {
				log.Debugf("IPSet update contains destination IP %s, releasing packet with ID %d", p.dstIP, p.packetID)
				p.release()
			}
		}
	}
}

// expireIPSetUpdates removes IPSet updates that have expired.
func (h *handler) expireIPSetUpdates(t time.Time) {
	log.Debugf("Expiring IPSet updates with expiry time before %v", t)

	// Updates are in time order, so find the last entry that expired.
	h.lock.Lock()
	defer h.lock.Unlock()
	var expired *ipsetUpdates
	for updates := h.ipsetUpdatesFirst; updates != nil; updates = updates.next {
		if updates.expiryTime.Before(t) {
			expired = updates
			continue
		}
		break
	}
	if expired != nil {
		log.Debugf("Expiring updates with expiration %v", expired.expiryTime)
		h.ipsetUpdatesFirst = expired.next
		if expired.next == nil {
			h.ipsetUpdatesLast = nil
		}
		expired.next = nil
	}
}

// nfqueuePacket represents a packet pulled off the nfqueue that's being monitored. It contains a subset of the
// information given to the monitor about the nfqueued packets to leave a smaller memory imprint.
type nfqueuePacket struct {
	// packetID is the ID used to set a verdict for the packet.
	packetID uint32
	dstIP    string
	release  func()
}

// A set of IPSet member updates. We store these for a short time to cross reference with newly denied packets.
type ipsetUpdates struct {
	next       *ipsetUpdates
	expiryTime time.Time
	ips        set.Set[string]
}
