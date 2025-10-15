// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package dnsresponsepacket

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/projectcalico/calico/felix/dataplane/dns"
	"github.com/projectcalico/calico/felix/nfqueue"
	cprometheus "github.com/projectcalico/calico/libcalico-go/lib/prometheus"
)

var (
	prometheusNfqueueQueuedLatency = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_dns_packet_nfqueue_monitor_queued_latency",
		Help: "Summary of the length of time DNS response packets were in the nfqueue queue before they were received in userspace",
	})

	prometheusPacketHoldTime = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_dns_packet_nfqueue_monitor_hold_time",
		Help: "Summary of the length of time the DNS response packets were held in userspace",
	})

	prometheusPacketsHeld = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_dns_packet_nfqueue_monitor_num_unreleased_packets",
		Help: "Gauge of the number of DNS response packets to release currently in memory",
	})

	prometheusNfqueueShutdownCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_dns_packet_nfqueue_monitor_shutdown_count",
		Help: "Count of how many times nfqueue was shutdown due to a fatal error",
	})

	prometheusNfqueueVerdictFailCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_dns_packet_nfqueue_monitor_verdict_failed",
		Help: "Count of how many times that the packet processor has failed to set the verdict",
	})

	prometheusPacketsSeen = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_dns_packet_nfqueue_monitor_packets_in",
		Help: "Count of how many DNS response packets have been seen",
	})

	prometheusReleasedProgrammed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_dns_packet_nfqueue_monitor_packets_released_programmed",
		Help: "Count of how many DNS response packets have been released after programming",
	})

	prometheusReleasedTimeout = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_dns_packet_nfqueue_monitor_packets_released_timeout",
		Help: "Count of how many DNS response packets have been released due to timeout",
	})

	prometheusDroppedConnClosed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_dns_packet_nfqueue_monitor_packets_released_conn_closed",
		Help: "Count of how many DNS response packets in userspace have been dropped due to an NFQUEUE connection close",
	})
)

func init() {
	prometheus.MustRegister(
		prometheusNfqueueShutdownCount,
		prometheusNfqueueVerdictFailCount,
		prometheusNfqueueQueuedLatency,
		prometheusPacketHoldTime,
		prometheusPacketsHeld,
		prometheusPacketsSeen,
		prometheusReleasedProgrammed,
		prometheusReleasedTimeout,
		prometheusDroppedConnClosed,
	)
}

const (
	holdTimeCheckInterval = 50 * time.Millisecond
)

type PacketProcessor interface {
	Start()
	Stop()
	DebugKillCurrentNfqueueConnection() error
}

func New(
	queueID uint16, queueLength uint32, maxHoldDuration time.Duration, domainInfoStore *dns.DomainInfoStore,
) PacketProcessor {
	options := []nfqueue.Option{
		nfqueue.OptMaxQueueLength(queueLength),
		// Don't risk truncating DNS response packets.  Note that only DNS response packets
		// should be coming through this queue, and DNS response packets will never actually
		// be as big as this (65535 bytes).  The original spec for DNS over UDP only allows
		// 512 bytes, and the EDNS0 extension, which is now well deployed, allows up to 4096
		// bytes.  But there is no downside from configuring a larger limit here.  In
		// principle we always want the complete DNS response packet, and the kernel only
		// uses an amount of space in the NFQUEUE buffer that is equal to the actual size of
		// the packet.
		nfqueue.OptMaxPacketLength(0xFFFF),
		nfqueue.OptMaxHoldTime(maxHoldDuration),
		nfqueue.OptHoldTimeCheckInterval(holdTimeCheckInterval),
		// Fail open ensures packets are accepted if the queue is full.
		nfqueue.OptFailOpen(),
		nfqueue.OptPacketsSeenCounter(prometheusPacketsSeen),
		nfqueue.OptPacketsHeldGauge(prometheusPacketsHeld),
		nfqueue.OptShutdownCounter(prometheusNfqueueShutdownCount),
		nfqueue.OptSetVerdictFailureCounter(prometheusNfqueueVerdictFailCount),
		nfqueue.OptPacketReleasedAfterHoldTimeCounter(prometheusReleasedTimeout),
		nfqueue.OptPacketReleasedCounter(prometheusReleasedProgrammed),
		nfqueue.OptPacketInNfQueueSummary(prometheusNfqueueQueuedLatency),
		nfqueue.OptConnectionClosedDroppedCounter(prometheusDroppedConnClosed),
		nfqueue.OptPacketHoldTimeSummary(prometheusPacketHoldTime),
	}

	return &packetProcessor{
		nfc: nfqueue.NewNfQueueConnector(queueID, &handler{domainInfoStore}, options...),
	}
}

type packetProcessor struct {
	nfc    nfqueue.NfQueueConnector
	cancel context.CancelFunc
}

func (p *packetProcessor) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.nfc.Connect(ctx)
}

func (p *packetProcessor) Stop() {
	p.cancel()
}

func (p *packetProcessor) DebugKillCurrentNfqueueConnection() error {
	return p.nfc.DebugKillConnection()
}

type handler struct {
	domainInfoStore *dns.DomainInfoStore
}

func (h *handler) OnPacket(packet nfqueue.Packet) {
	var timestamp uint64
	if packet.Timestamp != nil {
		timestamp = uint64(packet.Timestamp.UnixNano())
	}
	h.domainInfoStore.MsgChannel() <- dns.DataWithTimestamp{
		Data:      packet.Payload,
		Timestamp: timestamp,
		Callback:  packet.Release,
	}
}

func (*handler) OnRelease(_ uint32, _ nfqueue.ReleaseReason) {
	// no-op
}
