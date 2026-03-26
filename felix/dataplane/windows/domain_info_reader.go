// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.

package windataplane

import (
	"time"

	log "github.com/sirupsen/logrus"

	fc "github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/dataplane/dns"
	"github.com/projectcalico/calico/felix/dataplane/windows/etw"
)

const (
	windowsPacketETWSession = "tigera-windows-etw-packet"
)

type domainInfoReader struct {
	// Channel that we write to when we want DNS response capture to stop.
	stopChannel chan struct{}

	// Channel on which we receive captured DNS responses (beginning with the IP header) from ETW.
	msgChannel chan *etw.PktEvent

	// Channel on which domainInfoStore receives captured DNS responses (beginning with the IP header).
	storeMsgChannel chan<- dns.DataWithTimestamp

	// Trusted Servers for DNS packet.
	trustedServers []etw.ServerPort

	// If pktMonStartArgs is not empty, it will be used as the preferred option to start pktmon.
	// This is useful when we would like to override the existing arguments on future OS versions.
	pktMonStartArgs string

	// ETW operations
	etwOps *etw.EtwOperations
}

func NewDomainInfoReader(trustedServers []fc.ServerPort, pktMonStartArgs string) *domainInfoReader {
	log.WithField("serverports", trustedServers).Info("Creating Windows domain info reader")
	if len(trustedServers) == 0 {
		log.Fatal("Should have at least one DNS trusted server.")
	}

	serverPorts := []etw.ServerPort{}

	for _, server := range trustedServers {
		serverPorts = append(serverPorts, etw.ServerPort{
			IP:   server.IP,
			Port: server.Port,
		})
	}

	etwOps, err := etw.NewEtwOperations([]int{etw.PKTMON_EVENT_ID_CAPTURE}, etw.EtwPktProcessor(windowsPacketETWSession))
	if err != nil {
		log.Fatalf("Failed to create ETW operations; %s", err)
	}

	return &domainInfoReader{
		stopChannel: make(chan struct{}, 1),
		// domainInfoReader forwards DNS message to domainInfoStore as soon as it gets it.
		// domainInfoStore has a buffered channel to receive messages with the capacity set to 1000,
		// hence the channel capacity for domainInfoReader to forward messages to domainInfoStore could be small
		// without blocking ETW event reader.
		// Set channel capacity to 10.
		msgChannel:      make(chan *etw.PktEvent, 10),
		trustedServers:  serverPorts,
		pktMonStartArgs: pktMonStartArgs,
		etwOps:          etwOps,
	}
}

// Start function starts the reader and connects it with domainInfoStore.
func (r *domainInfoReader) Start(msgChan chan<- dns.DataWithTimestamp) {
	log.Info("Starting Windows domain info reader")

	r.storeMsgChannel = msgChan

	if err := r.etwOps.SubscribeToPktMon(r.msgChannel, r.stopChannel, r.trustedServers, true, r.pktMonStartArgs); err != nil {
		log.WithError(err).Error("failed to subscribe to pktmon")
	}

	go r.loop()
}

func (r *domainInfoReader) Stop() {
	r.stopChannel <- struct{}{}
	r.etwOps.WaitForSessionClose()
}

func (r *domainInfoReader) loop() {
	startupTimer := time.NewTimer(30 * time.Second)
	receivedPacket := false
	for {
		select {
		case pktEvent := <-r.msgChannel:
			receivedPacket = true
			// Forward to domainInfoStore.
			r.storeMsgChannel <- dns.DataWithTimestamp{
				Timestamp: pktEvent.NanoSeconds(),
				Data:      pktEvent.Payload(),
			}
		case <-startupTimer.C:
			if !receivedPacket {
				log.Warning("No DNS packets received from ETW/pktmon after 30s. " +
					"DNS domain-based policies may not work. " +
					"Check for 'failed to subscribe to provider' errors above.")
			}
		}
	}
}
