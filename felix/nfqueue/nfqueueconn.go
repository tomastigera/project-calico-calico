// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package nfqueue

// This module implements an NFQUEUE connector used to capture and hold packets passed on a specific queue ID.
// The packets may be released by the consumer, or will otherwise be released after a configurable max hold-time.
// Packets are released by setting a packet verdict, and for REPEAT verdict also setting a do-not-repeat mark.
//
// The consumer registers a handler interface for handling queued and released packets. The packet contains a Release()
// method that should be invoked to release the packet at the earliest opportunity.
//
// The current implementation assumes all packets are released with the same verdict (except we do DROP packets that
// either have no payload or have the do-not-repeat mark set which could cause a packet processing loop).
//
// Implementation details, key highlights:
//   NewNfQueueConnector is the public constructor for initializing a connector. It returns an nfQueueConnector pointer
//                    which implements the NfQueueConnector interface.
//
//   nfQueueConnector provides the main connect/disconnect/packet-release processing. It implements the NfQueueConnector
//                    interface used starting connection processing and various debug functions.
//     .connect() -> connect to the underlying socket. Creates an nfQueueConnection. There is only one active
//                    nfQueueConnection at a time, although multiple disconnected nfQueueConnections may exist and
//                    linked to packets that are still referenced by the consumer.
//     .disconnect() -> disconnects from the socket (actually just calls through to the active nfQueueConnection to do
//                    the work.
//     .connectionLoop() -> the main connection loop which ensures a connection is open to the underlying NFQUEUE. This
//                    loop also handles actioning of packet release messages - this is done in the main loop to
//                    ensure we don't try to release packets on an already-closed connection. Processing is channel
//                    driven where there is a channel for triggering a disconnect, a channel for triggering packet
//                    release and a ticker based channel for releasing aged-out packets. The two release triggers
//                    call through to the active nfQueueConnection to perform any required packet releases.
//                    Packets associated with older connections have already been dropped by the kernel (this
//                    happens when the connection is closed).
//
//  nfQueueConnection encapsulates state relevant to a specific connection to the NFQUEUE. All packets received from
//                    a connection will be linked to the specific nfQueueConnection.
//    .packetHook() -> this is the packet processing hook invoked from a socket read. Packets are added to a
//                    "packetsHeld" list and then sent to the handler.
//    .errorHook() -> this is an error hook invoked from the socket read. For errors that are not recoverable, a trigger
//                    is sent to nfQueueConnection.connectionLoop() to disconnect (and reconnect).
//    .prepareForRelease() -> this is invoked from the Packet.Release() method. This moves the internal packet data from
//                    the "packetsHeld" list to the "packetsToRelease" list. It then sends a trigger to the
//                    nfQueueConnection.connectionLoop() to process pending releases. This ensures we don't have to
//                    worry about locking around the connection and only ever release packets on the active
//                    connection.
//    .releaseByAge() -> this checks the packets in the "packetsHeld" list, and releases any that have been held for
//                    the maximum required duration. To release them it moves packets from the "packetsHeld" list to
//                    the "packetsToRelease" list, and then calls .release()
//    .release() -> this sets the packet verdict on all of the packets in the "packetsToRelease" list, thereby
//                    releasing the packets back to the kernel for remaining processing in iptables. Where possible
//                    this attempts to do batch releases (e.g. release batch for packet 3 releases packets 1,2 and 3).
//                    There is a little packet ID bookkeeping to check if a packet is released out-of-order in which
//                    case that packet cannot be released as part of a batch (since all earlier packets are also
//                    released). There is also some handling of wrapped packet IDs where TBH I'm not sure exactly how
//                    reliable batch processing is when the packet ID wraps - if the currently in-userspace packets
//                    have IDs that wrap then we revert to releasing packets individually.... probably an overkill but
//                    better safe than sorry.
//
//  Packet encapsulates required packet attributes.
//    .Release() -> This calls through to the owning nfQueueConnection to start release processing.

// TODO(rlb): The processing in this single module combines ideas taken from
//            - nfqueue.go
//            - dnsdeniedpacket/packetprocessor.go
//            - dnsdeniedpacket.packetprocesseor_with_nfqueue_restarter.
//           Namely the nfqueue connection and reconnection processing, the packet release and the timed release. This
//           is the processing required for the delay DNS response handling. It would be nice to update the
//           dnsdeniedpacket processor to utilize this module as well as the two would benefit from common code paths
//           but I've no desire to destabilize a baked in solution at this time.
//
// TODO(rlb): Given the queue size is fixed we could avoid a lot of allocations and deallocations by instantiating
//           internal packet struct upfront and re-using them.

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	gonfqueue "github.com/florianl/go-nfqueue"
	"github.com/mdlayher/netlink"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/felix/timeshim"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

const (
	nfDefaultMaxPacketLen      = 1024
	nfDefaultMaxQueueLen       = 100
	nfDefaultMaxHoldTime       = 2 * time.Second
	nfHoldTimeCheckInterval    = 50 * time.Millisecond
	nfSetVerdictRepeatAttempts = 3
	nfReadTimeout              = 100 * time.Millisecond
	nfWriteTimeout             = 200 * time.Millisecond
)

const (
	failedToSetVerdictMessage         = "failed to set the nfqueue verdict for the packet"
	failedToSetVerdictBatchMessage    = "failed to set the nfqueue verdict for a batch of packets"
	failedToSetVerdictWithMarkMessage = "failed to set the nfqueue verdict with do-not-repeat mark for the packet"
	packetHasDoNotRepeatMarkMessage   = "dropping packet with do not repeat mark"
	packetHasNoPayload                = "packet has no payload"
)

// NewNfQueueConnector creates a new NfQueueConnector.
func NewNfQueueConnector(queueID uint16, handler Handler, options ...Option) NfQueueConnector {
	nfc := &nfQueueConnector{
		queueID:               queueID,
		handler:               handler,
		maxQueueLen:           nfDefaultMaxQueueLen,
		maxPacketLen:          nfDefaultMaxPacketLen,
		maxHoldTime:           nfDefaultMaxHoldTime,
		holdTimeCheckInterval: nfHoldTimeCheckInterval,
		verdict:               gonfqueue.NfAccept,
		nfqFactory:            netlinkshim.NewRealNfQueue,
		time:                  timeshim.RealTime(),

		// releaseChan is used to trigger the queue processing loop to release packets. It only needs to have
		// capacity 1 because it's used as a trigger.
		releaseChan: make(chan struct{}, 1),

		// The disconnect channel used to trigger disconnection and reconnection. The connection requesting
		// disconnection is sent so that the main queue processing loop will only trigger reconnection for the active
		// connection.
		disconnectChan: make(chan *nfQueueConnection, 1),

		// debugBlockChan is used by tests to block the main queue processing loop.
		debugBlockChan: make(chan struct{}, 1),

		// Context logger and rate limited error logger.
		logger:               log.WithField("queueID", queueID),
		rateLimitedErrLogger: logutils.NewRateLimitedLogger(logutils.OptInterval(15 * time.Second)),
	}
	for _, option := range options {
		option(nfc)
	}

	nfc.logger.WithFields(log.Fields{
		"maxQueueLen":           nfc.maxQueueLen,
		"maxPacketLen":          nfc.maxPacketLen,
		"maxHoldTime":           nfc.maxHoldTime,
		"holdTimeCheckInterval": nfc.holdTimeCheckInterval,
		"verdict":               nfc.verdict,
		"flags":                 nfc.flags,
		"dnrMark":               nfc.dnrMark,
	}).Debug("Creating nfQueueConnector")

	return nfc
}

// NfQueueConnector is used to start NfQueue connection processing and to provide debug level control over.
type NfQueueConnector interface {
	// Connect is a non-blocking method used to kick off connection and packet processing.
	Connect(ctx context.Context)

	// ConnectBlocking is a blocking method used to kick off connection and packet processing. It returns when the
	// context is cancelled.
	ConnectBlocking(ctx context.Context)

	// -- Debug helper methods --

	// DebugKillConnection finds the underlying file descriptor for the nfqueue connection and closes it. This is used to
	// simulate an unexpected closure of the connection. The underlying nfqueue library may close the connection without
	// notification and without restarting it if it encounters errors, so this function is used to force such an error
	// so the restart logic can be tested with FVs.
	//
	// In general, DO NOT USE THIS FUNCTION.
	DebugKillConnection() error

	// DebugBlockAndUnblock is used to block or unblock the main connection and release processing go routine. Call
	// once to block and again to unblock.
	DebugBlockAndUnblock()
}

type ReleaseReason byte

const (
	ReleasedByConsumer = iota
	ReleasedByTimeout
	ReleasedByConnFailure
)

// Handler is an interface that needs to be be implemented by the consumer of the NfQueue. Ideally, all packets sent to
// the handler should be released as soon as possible by invoking the Release() method on the packet. However, if not
// released by the consumer the packet will be released after the max hold time.
type Handler interface {
	// OnPacket is called when a new packet it queued for processing.
	OnPacket(packet Packet)

	// OnRelease is called when a packet is released either implicitly by timeout or reconnection, or explicitly
	// by calling Release() on the packet. The NFQueueConnector will always match an OnPacket call with an OnRelease
	// call.
	OnRelease(id uint32, reason ReleaseReason)
}

// Packet contains captured packet information.
type Packet struct {
	// The packet ID.
	ID uint32

	// Timestamp the packet was added to the NFQUEUE.
	Timestamp *time.Time

	// Mark on the packet.
	Mark *uint32

	// HW protocol.
	HwProtocol *uint16

	// The packet payload (up to the requested number of bytes).
	Payload []byte

	// Function used to release the packet. Added as a member variable rather than a method on the packet - not sure
	// it matters too much, but this should at least allow the remainder of the Packet allocation to be garbage
	// collected even if the Release function is still referenced.
	Release func()
}

// String returns a string representation of the packet (just summary information).
func (p Packet) String() string {
	b := strings.Builder{}
	b.WriteString("Packet(")
	b.WriteString(strconv.Itoa(int(p.ID)))
	if p.Timestamp != nil {
		b.WriteRune(';')
		b.WriteString(p.Timestamp.String())
	}
	if p.Mark != nil {
		b.WriteString(";mark=")
		b.WriteString(strconv.Itoa(int(*p.Mark)))
	}
	b.WriteRune(')')
	return b.String()
}

// nfQueueConnector orchestrates queue connection/disconnection and packet release processing. It implements the
// NfQueueConnnector interface used to provide some debug test facilities.
type nfQueueConnector struct {
	queueID               uint16
	handler               Handler
	maxQueueLen           uint32
	maxPacketLen          uint32
	maxHoldTime           time.Duration
	holdTimeCheckInterval time.Duration
	verdict               int
	flags                 uint32
	markBitsToPreserve    uint32
	dnrMark               uint32
	logger                *log.Entry
	holdTimeCheckTicker   timeshim.Ticker

	// Prometheus metrics
	prometheusPacketsHeldGauge               prometheus.Gauge
	prometheusPacketsSeenCounter             prometheus.Counter
	prometheusShutdownCounter                prometheus.Counter
	prometheusSetVerdictFailureCounter       prometheus.Counter
	prometheusDNRDroppedCounter              prometheus.Counter
	prometheusNoPayloadDroppedCounter        prometheus.Counter
	prometheusConnectionClosedDroppedCounter prometheus.Counter
	prometheusReleasedAfterHoldTimeCounter   prometheus.Counter
	prometheusReleasedCounter                prometheus.Counter
	prometheusTimeInQueueSummary             prometheus.Summary
	prometheusHoldTimeSummary                prometheus.Summary

	// NfQueue factory shim. Can be swapped out for testing.
	nfqFactory func(config *gonfqueue.Config) (netlinkshim.NfQueue, error)

	// Time shim. Can be swapped out for testing.
	time timeshim.Interface

	// Rate limited logger for non-terminating errors.
	rateLimitedErrLogger *logutils.RateLimitedLogger

	// Connection handling.
	activeConnection *nfQueueConnection
	disconnectChan   chan *nfQueueConnection
	releaseChan      chan struct{}

	// Debug processing to block connection and packet release processing.
	debugBlockChan chan struct{}
	debugBlockWG   sync.WaitGroup
}

// Connect connects to the NfQueue (and maintains connection) and starts processing packets.
func (nfc *nfQueueConnector) Connect(ctx context.Context) {
	go nfc.connectionLoop(ctx)
}

// ConnectBlocking is a blocking version of Connect.
func (nfc *nfQueueConnector) ConnectBlocking(ctx context.Context) {
	nfc.connectionLoop(ctx)
}

// DebugKillConnection finds the underlying file descriptor for the nfqueue connection and closes it. This is used to
// simulate an unexpected closure of the connection. The underlying nfqueue library may close the connection without
// notification and without restarting it if it encounters errors, so this function is used to force such an error
// so the restart logic can be tested with fv's.
//
// In general, DO NOT USE THIS FUNCTION.
func (nfc *nfQueueConnector) DebugKillConnection() error {
	if nfc.activeConnection != nil {
		return nfc.activeConnection.nfq.DebugKillConnection()
	}
	return nil
}

// DebugBlockAndUnblock is used to block or unblock the main connection and release processing go routine. Call
// once to block and again to unblock.
func (nfc *nfQueueConnector) DebugBlockAndUnblock() {
	nfc.debugBlockWG.Add(1)
	nfc.debugBlockChan <- struct{}{}
	nfc.debugBlockWG.Wait()
}

// connectionLoop loops continuously making sure Felix is connected to the nfqueue.
func (nfc *nfQueueConnector) connectionLoop(ctx context.Context) {
	// Create the hold time check ticker here so we just do it the once (makes mocking easier).
	nfc.holdTimeCheckTicker = nfc.time.NewTicker(nfc.holdTimeCheckInterval)
	defer nfc.holdTimeCheckTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			// Connect to the NF Queue.
			if err := nfc.connect(ctx); err == nil {
				// We are connected so process packets. This blocks until disconnection is requested.
				nfc.processQueueEvents(ctx)
				nfc.disconnect()
			} else {
				// Not connecting to the queue is a fatal problem.
				nfc.logger.WithError(err).Panic("unable to connect to the queue")
			}
		}
	}
}

// connect attempts to attach to the queue and registers handlers to process held packets and errors.
func (nfc *nfQueueConnector) connect(ctx context.Context) error {
	// Attempt to attach to the queue.
	defaultConfig := &gonfqueue.Config{
		NfQueue:      uint16(nfc.queueID),
		MaxPacketLen: nfc.maxPacketLen,
		MaxQueueLen:  nfc.maxQueueLen,
		Copymode:     gonfqueue.NfQnlCopyPacket,
		ReadTimeout:  nfReadTimeout,
		WriteTimeout: nfWriteTimeout,
		Flags:        nfc.flags,
	}

	nfc.logger.Debug("Connecting to NFQueue")
	nfRaw, err := nfc.nfqFactory(defaultConfig)
	if err != nil {
		return err
	}
	nfc.logger.Debug("Connected to NFQueue")

	nf := &nfQueueConnection{
		nfQueueConnector: nfc,
		nfq:              nfRaw,
	}

	if err = nfRaw.RegisterWithErrorFunc(ctx, nf.packetHook, nf.errorHook); err != nil {
		// If we didn't attach the callbacks then close immediately.
		nfc.logger.Warning("Failed to register callback functions with nfqueue socket")
		if cerr := nfRaw.Close(); cerr != nil {
			nfc.logger.WithError(cerr).Warning("Failed to close nfqueue socket")
		}
		return err
	}

	nfc.activeConnection = nf

	return nil
}

// disconnect performs disconnection from the queue socket.
func (nfc *nfQueueConnector) disconnect() {
	if nfc.activeConnection != nil {
		nfc.logger.Info("Disconnecting from nfqueue")
		nfc.activeConnection.disconnect()
		nfc.activeConnection = nil
	}
}

// processQueueEvents is the main loop that processes releasing of packets and reconnection to the socket.
func (nfc *nfQueueConnector) processQueueEvents(ctx context.Context) {
	for {
		select {
		case nfx := <-nfc.disconnectChan:
			// Disconnection request.
			//
			// Just return to the connection loop. Only do this for the active connection. This protects against
			// windows arising from the fact that disconnection may be triggered by the registered handler and by the
			// verdict callbacks. At the moment we only perform disconnection from the callback
			if nfx == nfc.activeConnection {
				return
			}
		case <-nfc.releaseChan:
			select {
			case nfx := <-nfc.disconnectChan:
				// Disconnection request - see comment above.
				//
				// Disconnection always take precedence because we have unregistered the queue at this point and all
				// packets in the queue have been dropped. This isn't strictly necessary because setting the verdict
				// doesn't fail in a bad way - in fact it passes which is a little misleading.
				if nfx == nfc.activeConnection {
					return
				}
			default:
			}
			// We have some packets to release.
			nfc.activeConnection.release()
		case <-nfc.holdTimeCheckTicker.Chan():
			select {
			case nfx := <-nfc.disconnectChan:
				// Disconnection request - see comment above.
				//
				// Disconnection always take precedence because we have unregistered the queue at this point and all
				// packets in the queue have been dropped. This isn't strictly necessary because setting the verdict
				// doesn't fail in a bad way - in fact it passes which is a little misleading.
				if nfx == nfc.activeConnection {
					return
				}
			default:
			}
			// Release packets that have been held for the maximum duration.
			nfc.activeConnection.releaseByAge()
		case <-ctx.Done():
			// Context is done we can exit.
			return
		case <-nfc.debugBlockChan:
			// Notify that we are blocked.
			nfc.debugBlockWG.Done()

			// Unblocking is by the same signaling.
			<-nfc.debugBlockChan
			nfc.debugBlockWG.Done()
		}
	}
}

// nfQueueConnection encapsulates data specific to a single nfq connection.
//
// The actual packet release messages (SetVerdict) are performed in processQueueEvents and are only ever sent for the
// active connection. Packets from previous connections will already have been dropped by the kernel if not released -
// so there is no need to explicitly release them.
type nfQueueConnection struct {
	// The owning connector.
	*nfQueueConnector

	// NfQueue interface - used for releasing packets and closing the connection.
	nfq netlinkshim.NfQueue

	// Data lock for accessing the data below.
	lock sync.Mutex

	// Linked list of held packets.
	packetsHeld packetDataList

	// Linked list of packets to release.
	packetsToRelease packetDataList

	// Current packet ID.
	currentPacketID uint32

	// The packet ID of the oldest packet that has yet to be released (this packet may be in either the held or
	// released lists.
	oldestPacketID uint32
}

// disconnect performs disconnection processing. This should only ever be called from the main connection handling
// goroutine.
func (nfx *nfQueueConnection) disconnect() {
	// Close the connection.
	if err := nfx.nfq.Close(); err != nil {
		nfx.logger.WithError(err).Warning("Failed to close nfqueue socket")
	}

	// Remove all packets from the release and held lists and send OnRelease updates for each.
	nfx.lock.Lock()

	// All packets held or pending release are being dropped.
	packetsDropped := nfx.packetsHeld.length + nfx.packetsToRelease.length

	// Copy across all the held and pending release to a local list so we can release the lock.
	var dropped packetDataList
	for data := nfx.packetsHeld.first; data != nil; data = nfx.packetsHeld.first {
		nfx.packetsHeld.remove(data)
		dropped.add(data)
	}
	for data := nfx.packetsToRelease.first; data != nil; data = nfx.packetsToRelease.first {
		nfx.packetsToRelease.remove(data)
		dropped.add(data)
	}
	nfx.lock.Unlock()

	// Invoke the OnRelease handler. All of these packets are dropped due to connection failure.
	for data := dropped.first; data != nil; data = dropped.first {
		dropped.remove(data)
		nfx.handler.OnRelease(data.packetID, ReleasedByConnFailure)
	}

	// The packets in the held and release queues will all be dropped. Update our stats if we are tracking this.
	if nfx.prometheusConnectionClosedDroppedCounter != nil {
		nfx.prometheusConnectionClosedDroppedCounter.Add(float64(packetsDropped))
	}
	if nfx.prometheusPacketsHeldGauge != nil {
		nfx.prometheusPacketsHeldGauge.Set(0)
	}
	// Increment shutdown stats if tracking.
	if nfx.prometheusShutdownCounter != nil {
		nfx.prometheusShutdownCounter.Inc()
	}
}

// packetHook is the packet handling hook registered with the underlying NFQueue netlink library.
func (nfx *nfQueueConnection) packetHook(a gonfqueue.Attribute) int {
	if nfx.prometheusPacketsSeenCounter != nil {
		// If recording, increment the total number of packets seen.
		nfx.prometheusPacketsSeenCounter.Inc()
	}

	var mark uint32
	if a.Mark != nil {
		mark = *a.Mark
	}
	if mark&nfx.dnrMark != 0x0 {
		nfx.rateLimitedErrLogger.Error(packetHasDoNotRepeatMarkMessage)
		nfx.setVerdict(*a.PacketID, gonfqueue.NfDrop, failedToSetVerdictMessage)

		if nfx.prometheusDNRDroppedCounter != nil {
			nfx.prometheusDNRDroppedCounter.Inc()
		}
		return 0
	}
	if a.Payload == nil {
		// There should always be a payload with these packets.  If not, drop the packet.
		nfx.rateLimitedErrLogger.Error(packetHasNoPayload)
		nfx.setVerdict(*a.PacketID, gonfqueue.NfDrop, failedToSetVerdictMessage)

		if nfx.prometheusNoPayloadDroppedCounter != nil {
			nfx.prometheusNoPayloadDroppedCounter.Inc()
		}
		return 0
	}

	// Create the internal packet data so that we can manage release of this packet.
	data := &packetData{
		holdTime:           nfx.time.Now(),
		packetID:           *a.PacketID,
		markBitsToPreserve: mark & nfx.markBitsToPreserve,
	}
	nfx.logger.Debugf("Received packet %d at %s", data.packetID, data.holdTime)

	// We need to add this packet to the held list. Also, store the current packet ID - this is used to
	// determine whether we are able to do batch releases or not.
	nfx.lock.Lock()
	nfx.packetsHeld.add(data)
	nfx.currentPacketID = *a.PacketID
	totalHeldPackets := nfx.packetsHeld.length + nfx.packetsToRelease.length
	nfx.lock.Unlock()

	// Record the total number of currently held packets (this includes those pending release since they are still
	// technically being held).
	if nfx.prometheusPacketsHeldGauge != nil {
		nfx.prometheusPacketsHeldGauge.Set(float64(totalHeldPackets))
	}

	// If we are recording, and there is a timestamp on the packet attempt to gather some metrics about how long
	// it took the packet to get to this point from the kernel.
	if a.Timestamp != nil && nfx.prometheusTimeInQueueSummary != nil {
		nfx.prometheusTimeInQueueSummary.Observe(nfx.time.Since(*a.Timestamp).Seconds())
	}

	// Invoke the handler for the packet.
	p := Packet{
		ID:         *a.PacketID,
		Timestamp:  a.Timestamp,
		Mark:       a.Mark,
		HwProtocol: a.HwProtocol,
		Payload:    *a.Payload,
		Release: func() {
			nfx.prepareForRelease(data)
		},
	}
	nfx.logger.Debugf("Invoking handler for queued packet: %s", p)
	nfx.handler.OnPacket(p)

	return 0
}

// errorHook is the error handling hook registered with the underlying NFQueue netlink library.
func (nfx *nfQueueConnection) errorHook(err error) int {
	if opError, ok := err.(*netlink.OpError); ok {
		if opError.Timeout() || opError.Temporary() {
			return 0
		}
	}

	// Send a disconnect message, the main processing loop will handle the disconnection. Returning 1 here ensures no
	// more messages will be processed for this connection.
	nfx.logger.WithError(err).Info("Handling error from NFQUEUE socket processing")
	nfx.disconnectChan <- nfx
	return 1
}

// prepareForRelease moves a packet in the held list over into the release list.
func (nfx *nfQueueConnection) prepareForRelease(data *packetData) {
	cxtLogger := nfx.logger.WithField("packetID", data.packetID)
	nfx.lock.Lock()

	// Only need to do anything if the packet is still in the held link list.
	if data.list != &nfx.packetsHeld {
		nfx.lock.Unlock()
		cxtLogger.Debug("Release packet request, but already released")
		return
	}

	// Move over to the released list, we can release the lock straight after that.
	cxtLogger.Debug("Release packet request")
	nfx.packetsHeld.remove(data)
	nfx.packetsToRelease.add(data)
	nfx.lock.Unlock()

	// If tracking stats then increment the number of packets explicitly released by the client.
	if nfx.prometheusReleasedCounter != nil {
		nfx.prometheusReleasedCounter.Inc()
	}

	// Send a tick to the packet loop to release any packets pending actual release. This is to ensure the actual
	// release processing occurs on the main connection goroutine - only the active connection can have calls, and it
	// is quite possible the connection associated with this nfQueueConnection has already been closed.
	select {
	case nfx.releaseChan <- struct{}{}:
	default:
		cxtLogger.Debug("Release event already pending - no need to add another")
	}
}

// releaseByAge releases held packets that have been held for the maxmimum hold time.
//
// This method may only be invoked from the main connection processing goroutine - because it should only ever be
// called while the connection is still active.
func (nfx *nfQueueConnection) releaseByAge() {
	// Calculate the hold time threshold.
	nt := nfx.time.Now().Add(-nfx.maxHoldTime)

	nfx.lock.Lock()
	var numReleased float64
	for data := nfx.packetsHeld.first; data != nil; data = nfx.packetsHeld.first {
		if nt.Before(data.holdTime) {
			// Since the packet timeouts will be in the order the packets arrive, as soon as we hit a packet that has
			// not timed-out we can stop enumeration.
			break
		}

		// Packet has timed out.  Remove from the held list and add to the released list.
		nfx.logger.Debugf("Packet %d has passed the max hold time", data.packetID)
		data.reason = ReleasedByTimeout
		nfx.packetsHeld.remove(data)
		nfx.packetsToRelease.add(data)
		numReleased++
	}
	nfx.lock.Unlock()

	// If tracking stats, set the number of packets released due to timeout.
	if nfx.prometheusReleasedAfterHoldTimeCounter != nil {
		nfx.prometheusReleasedAfterHoldTimeCounter.Add(numReleased)
	}

	// Call release() to actually set the verdict to release the packets.
	nfx.release()
}

// release releases all of the packets in the release list.
//
// This method may only be invoked from the main connection processing goroutine - because it should only ever be
// called while the connection is still active.
func (nfx *nfQueueConnection) release() {
	nfx.lock.Lock()

	// Short-circuit the no-op case.
	if nfx.packetsToRelease.length == 0 {
		nfx.lock.Unlock()
		return
	}

	// Start by draining the release list into some local slices so that we can access without locking and unlocking
	// excessive number of times.
	var batchReleaseID uint32
	var releaseBatch packetDataList
	var releaseIndividual packetDataList
	heldPacketsLength := nfx.packetsHeld.length

	// Get the packet ID of the oldest packet that is still being held and is not pending release. We use this in a
	// couple of places. 0 if there are no more held packets.
	var oldestHeldPacketID uint32
	if data := nfx.packetsHeld.first; data != nil {
		oldestHeldPacketID = data.packetID
	}

	// Where possible we'll release by batch since it requires fewer messages to the kernel and in general improves
	// kernel performance.  There are a couple of scenarios where we do not want to release by batch:
	// - We need to set a do-not-repeat mark and the nfqueue library does not support batch verdict with mark.
	// - The current packet ID is lower than the oldest packet ID that has not yet been released to the kernel. This
	//   implies packet ID has wrapped and the exact behavior feels less certain, so releasing individually seems like a
	//   sensible choice here.
	nfx.logger.WithFields(log.Fields{
		"dnrMark":         nfx.dnrMark,
		"currentPacketID": nfx.currentPacketID,
		"oldestPacketID":  nfx.oldestPacketID,
	}).Debug("Preparing to send packet release messages to kernel")

	if nfx.dnrMark != 0 || nfx.currentPacketID < nfx.oldestPacketID {
		for data := nfx.packetsToRelease.first; data != nil; data = nfx.packetsToRelease.first {
			nfx.packetsToRelease.remove(data)
			releaseIndividual.add(data)
		}
	} else {
		// Since we are not setting the dnrMark, we can preferentially use batch release. Get the ID of the oldest
		// packet that is being held - this puts an upper bound on whether, or not, a specific packet may be
		// released as part of a batch or individually. If a packetID is higher than the first held packet then it is
		// being released out of order, we cannot use a batch release for that.
		for data := nfx.packetsToRelease.first; data != nil; data = nfx.packetsToRelease.first {
			nfx.packetsToRelease.remove(data)
			if nfx.packetsHeld.first == nil || oldestHeldPacketID > data.packetID {
				// There are no more held packets, or the oldest held packet has a higher packet ID that the one being
				// released. It is safe to do a batch release for this packet.
				nfx.logger.Debugf("Will release packet %d in batch message", data.packetID)
				if data.packetID > batchReleaseID {
					batchReleaseID = data.packetID
				}
				releaseBatch.add(data)
			} else {
				releaseIndividual.add(data)
			}
		}
	}

	// Since we are releasing all of the packets that were pending release, the new oldestPacketID will just be the ID
	// of the oldest packet in the held list.
	nfx.oldestPacketID = oldestHeldPacketID

	// Unlock before we send the netlink messages.
	nfx.lock.Unlock()

	// If we are recording, then set the number of held packets - the released packets list should be empty now.
	if nfx.prometheusPacketsHeldGauge != nil {
		nfx.prometheusPacketsHeldGauge.Set(float64(heldPacketsLength))
	}

	// Start by doing the batch release since that will also make the individual releases more performant. Batch release
	// is only ever without setting the Mark.
	if releaseBatch.length > 0 {
		nfx.logger.Debugf("Sending batch release for packet %d", batchReleaseID)
		nfx.setVerdictBatch(batchReleaseID, nfx.verdict, failedToSetVerdictBatchMessage)

		if nfx.prometheusHoldTimeSummary != nil {
			now := nfx.time.Now()
			for data := releaseBatch.first; data != nil; data = data.next {
				nfx.prometheusHoldTimeSummary.Observe(now.Sub(data.holdTime).Seconds())
			}
		}

		for data := releaseBatch.first; data != nil; data = data.next {
			nfx.handler.OnRelease(data.packetID, data.reason)
		}
	}

	// Now do the individual releases. These may not be ordered - but probably still more efficient than sorting the
	// list first.
	if releaseIndividual.length > 0 {
		for data := releaseIndividual.first; data != nil; data = data.next {
			if nfx.dnrMark == 0 {
				nfx.logger.Debugf("Sending release for packet %d", data.packetID)
				nfx.setVerdict(data.packetID, nfx.verdict, failedToSetVerdictMessage)
			} else {
				nfx.logger.Debugf("Sending release with mark for packet %d", data.packetID)
				nfx.setVerdictWithMark(data.packetID, nfx.verdict, int(nfx.dnrMark|data.markBitsToPreserve), failedToSetVerdictWithMarkMessage)
			}

			if nfx.prometheusHoldTimeSummary != nil {
				now := nfx.time.Now()
				nfx.prometheusHoldTimeSummary.Observe(now.Sub(data.holdTime).Seconds())
			}

			nfx.handler.OnRelease(data.packetID, data.reason)
		}
	}
}

// setVerdict attempts to set the verdict for the specified packet. It retries in the event of a failure.
func (nfx *nfQueueConnection) setVerdict(id uint32, verdict int, failureMessages ...string) {
	var err error
	for range nfSetVerdictRepeatAttempts {
		if err = nfx.nfq.SetVerdict(id, verdict); err == nil {
			return
		}
	}

	if nfx.prometheusSetVerdictFailureCounter != nil {
		nfx.prometheusSetVerdictFailureCounter.Inc()
	}
	nfx.rateLimitedErrLogger.WithError(err).Error(failureMessages)
}

// setVerdictWithMark attempts to set the verdict (with mark) for the specified packet. It retries in the event of a
// failure.
func (nfx *nfQueueConnection) setVerdictWithMark(id uint32, verdict int, mark int, failureMessages ...string) {
	var err error
	for range nfSetVerdictRepeatAttempts {
		if err = nfx.nfq.SetVerdictWithMark(id, verdict, mark); err == nil {
			return
		}
	}

	if nfx.prometheusSetVerdictFailureCounter != nil {
		nfx.prometheusSetVerdictFailureCounter.Inc()
	}
	nfx.rateLimitedErrLogger.WithError(err).Error(failureMessages)
}

// setVerdictBatch attempts to set the verdict for the specified batch of packets. It retries in the event of a failure.
func (nfx *nfQueueConnection) setVerdictBatch(id uint32, verdict int, failureMessage string) {
	var err error
	for range nfSetVerdictRepeatAttempts {
		if err = nfx.nfq.SetVerdictBatch(id, verdict); err == nil {
			return
		}
	}

	// Increment the prometheus stats for verdict failure if we are tracking.
	if nfx.prometheusSetVerdictFailureCounter != nil {
		nfx.prometheusSetVerdictFailureCounter.Inc()
	}
	nfx.rateLimitedErrLogger.WithError(err).Error(failureMessage)
}

// packetData is used for internal tracking of the packets.
type packetData struct {
	// --- List data ---
	list *packetDataList
	prev *packetData
	next *packetData

	// --- Packet data ---

	// The original hold time. This is the time the packet was first received from the socket.
	holdTime time.Time

	// The packet ID. Note that this packet ID is only valid in conjunction with its corresponding NfQueue connection
	// since new connections start the IDs again from 1.
	packetID uint32

	markBitsToPreserve uint32

	// Release reason
	reason ReleaseReason
}

// packetDataList is the list root for storing an ordered set of packetDatas.
type packetDataList struct {
	length int
	first  *packetData
	last   *packetData
}

// add a packetData to the end of a packetDataList. The packetData must not already be in a list.
func (l *packetDataList) add(data *packetData) {
	if data.list != nil {
		panic("Linked list handling of packets is incorrect")
	}

	if l.first == nil {
		l.first, l.last, data.list = data, data, l
	} else {
		l.last, l.last.next, data.prev, data.list = data, data, l.last, l
	}
	l.length++
}

// remove a packetData from a packetDataList. The packetData must be in the list.
func (l *packetDataList) remove(data *packetData) {
	if data.list != l {
		panic("Linked list handling of packets is incorrect")
	}

	prev, next := data.prev, data.next

	if prev != nil {
		prev.next = next
	} else if l.first == data {
		l.first = next
	}

	if next != nil {
		next.prev = prev
	} else if l.last == data {
		l.last = prev
	}

	data.prev, data.next, data.list = nil, nil, nil
	l.length--
}
