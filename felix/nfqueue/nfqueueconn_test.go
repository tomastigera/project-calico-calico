// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package nfqueue_test

import (
	"context"
	"errors"
	"os"
	"strconv"
	"sync"
	"time"

	gonfqueue "github.com/florianl/go-nfqueue"
	"github.com/mdlayher/netlink"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"

	"github.com/projectcalico/calico/felix/netlinkshim/mocknetlink"
	"github.com/projectcalico/calico/felix/nfqueue"
	"github.com/projectcalico/calico/felix/timeshim"
)

// timeoutTemporaryError is a mock error type used to test Timeout and Temporary error handling of the nfqueue.
type timeoutTemporaryError struct {
	timeout   bool
	temporary bool
}

func (t timeoutTemporaryError) Timeout() bool {
	return t.timeout
}

func (t timeoutTemporaryError) Temporary() bool {
	return t.temporary
}

func (t timeoutTemporaryError) Error() string {
	return ""
}

type releaseInfo struct {
	id     uint32
	reason nfqueue.ReleaseReason
}

// Handler used to consume the packets fro the NfQueue.
type handler struct {
	lock     sync.Mutex
	packets  []nfqueue.Packet
	released []releaseInfo
}

func (h *handler) OnPacket(p nfqueue.Packet) {
	// Called synchronously from the mock nfqueue event, so no need to lock this for our tests.
	h.packets = append(h.packets, p)
}

func (h *handler) OnRelease(id uint32, reason nfqueue.ReleaseReason) {
	h.lock.Lock()
	defer h.lock.Unlock()
	h.released = append(h.released, releaseInfo{id, reason})
}

func (h *handler) getReleased() []releaseInfo {
	h.lock.Lock()
	defer h.lock.Unlock()
	r := make([]releaseInfo, len(h.released))
	copy(r, h.released)
	return r
}

// Prometheus counter, gauge and summary implementations.
type counter struct {
	prometheus.Counter
	lock sync.Mutex
	num  int
}

func (c *counter) Inc() {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.num++
}

func (c *counter) Add(n float64) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.num += int(n)
}

func (c *counter) get() int {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.num
}

type gauge struct {
	prometheus.Gauge
	lock sync.Mutex
	num  float64
}

func (g *gauge) Set(n float64) {
	g.lock.Lock()
	defer g.lock.Unlock()
	g.num = n
}

// get returns the value as an int since for our specific use case our gauges only record int values.
func (g *gauge) get() int {
	g.lock.Lock()
	defer g.lock.Unlock()
	return int(g.num)
}

type summary struct {
	prometheus.Summary
	nums []float64
}

func (c *summary) Observe(n float64) {
	c.nums = append(c.nums, n)
}

// Test NfQueueConnector
var _ = Describe("NfQueueConnector processing", func() {
	var nfc nfqueue.NfQueueConnector
	var packetHandler *handler
	var tickerChan chan time.Time
	var mockTime *timeshim.MockInterface
	var mockTicker *timeshim.MockTicker
	var factory *mocknetlink.NfQueueFactory
	var held *gauge
	var seen, shutdown, verdictFailure, dnrDropped, payloadDropped, closedDropped, releasedAfterHoldTime, released *counter
	var inNfQueue, holdTime *summary
	var ctx context.Context
	var cancel func()
	var options []nfqueue.Option
	var mocknfq *mocknetlink.MockNfQueue

	BeforeEach(func() {
		packetHandler = &handler{}

		tickerChan = make(chan time.Time, 1)
		mockTime = &timeshim.MockInterface{}
		mockTicker = &timeshim.MockTicker{}
		mockTicker.On("Chan").Return((<-chan time.Time)(tickerChan))
		mockTicker.On("Stop").Return(true)
		mockTime.On("NewTicker", mock.Anything).Return(mockTicker)
		factory = &mocknetlink.NfQueueFactory{}
		held = &gauge{}
		seen = &counter{}
		shutdown = &counter{}
		verdictFailure = &counter{}
		dnrDropped = &counter{}
		payloadDropped = &counter{}
		closedDropped = &counter{}
		releasedAfterHoldTime = &counter{}
		released = &counter{}
		inNfQueue = &summary{}
		holdTime = &summary{}
		ctx, cancel = context.WithCancel(context.Background())
		options = []nfqueue.Option{
			nfqueue.OptMaxQueueLength(10),
			nfqueue.OptMaxPacketLength(1000),
			nfqueue.OptMaxHoldTime(5 * time.Second),
			nfqueue.OptHoldTimeCheckInterval(1 * time.Second),
			nfqueue.OptFailOpen(),
			nfqueue.OptTimeShim(mockTime),
			nfqueue.OptNfQueueFactoryShim(factory.New),
			nfqueue.OptPacketsSeenCounter(seen),
			nfqueue.OptPacketsHeldGauge(held),
			nfqueue.OptShutdownCounter(shutdown),
			nfqueue.OptSetVerdictFailureCounter(verdictFailure),
			nfqueue.OptDNRDroppedCounter(dnrDropped),
			nfqueue.OptNoPayloadDroppedCounter(payloadDropped),
			nfqueue.OptPacketReleasedAfterHoldTimeCounter(releasedAfterHoldTime),
			nfqueue.OptPacketReleasedCounter(released),
			nfqueue.OptPacketInNfQueueSummary(inNfQueue),
			nfqueue.OptConnectionClosedDroppedCounter(closedDropped),
			nfqueue.OptPacketHoldTimeSummary(holdTime),
		}
	})

	AfterEach(func() {
		cancel()
	})

	Context("verdict accept processing", func() {
		BeforeEach(func() {
			options = append(options, nfqueue.OptVerdictAccept())
			nfc = nfqueue.NewNfQueueConnector(10, packetHandler, options...)
		})

		When("kicking off connection processing", func() {
			It("panics if it errors during connecting", func() {
				factory.OpenErr = errors.New("connection error")
				Expect(func() { nfc.ConnectBlocking(ctx) }).To(Panic())
			})

			It("panics if callback registration errors", func() {
				factory.RegisterErr = errors.New("register error")
				factory.CloseErr = errors.New("close error")
				Expect(func() { nfc.ConnectBlocking(ctx) }).To(Panic())
				Expect(factory.MockNfQueue).NotTo(BeNil())

				// Registration happens after a successful open, so close should be invoked.
				Expect(factory.MockNfQueue.Closed).To(BeTrue())
			})

			It("does not reconnect if a recoverable socket error occurs", func() {
				nfc.Connect(ctx)

				Eventually(factory.NumOpenCalls).Should(Equal(1))
				Consistently(factory.NumOpenCalls).Should(Equal(1))

				mock := factory.MockNfQueue
				Expect(mock).NotTo(BeNil())
				Eventually(mock.IsRegistered).Should(BeTrue())
				Expect(mock.SendError(&netlink.OpError{
					Err: &os.SyscallError{
						Err: timeoutTemporaryError{timeout: true},
					},
				})).To(Equal(0))
				Consistently(factory.NumOpenCalls).Should(Equal(1))

				Expect(mock.SendError(&netlink.OpError{
					Err: &os.SyscallError{
						Err: timeoutTemporaryError{temporary: true},
					},
				})).To(Equal(0))
				Consistently(factory.NumOpenCalls).Should(Equal(1))
				Expect(shutdown.num).To(Equal(0))
			})

			It("reconnects if an unrecoverable socket error occurs", func() {
				nfc.Connect(ctx)

				Eventually(factory.NumOpenCalls).Should(Equal(1))
				Consistently(factory.NumOpenCalls).Should(Equal(1))

				mock := factory.MockNfQueue
				Expect(mock).NotTo(BeNil())
				Eventually(mock.IsRegistered).Should(BeTrue())
				Expect(mock.Closed).To(BeFalse())
				Expect(mock.SendError(errors.New("unrecoverable socket error"))).To(Equal(1))

				Eventually(factory.NumOpenCalls).Should(Equal(2))
				Consistently(factory.NumOpenCalls).Should(Equal(2))
				Expect(shutdown.num).To(Equal(1))
				Expect(mock.Closed).To(BeTrue())

				mock = factory.MockNfQueue
				Expect(mock).NotTo(BeNil())
				Eventually(mock.IsRegistered).Should(BeTrue())
				Expect(mock.Closed).To(BeFalse())
				Expect(mock.SendError(errors.New("unrecoverable socket error"))).To(Equal(1))

				Eventually(factory.NumOpenCalls).Should(Equal(3))
				Consistently(factory.NumOpenCalls).Should(Equal(3))
				Expect(shutdown.num).To(Equal(2))
				Expect(mock.Closed).To(BeTrue())
			})

			It("disconnects and connection loop exits when context is cancelled and not before", func() {
				finished := make(chan struct{})
				go func() {
					nfc.ConnectBlocking(ctx)
					close(finished)
				}()

				// Wait for the open to happen. The connection loop should still be running.
				Eventually(factory.NumOpenCalls).Should(Equal(1))
				Consistently(factory.NumOpenCalls).Should(Equal(1))
				Expect(finished).ShouldNot(BeClosed())

				// Cancel the context.
				cancel()

				// Should eventually exit and should have disconnected. It should not attempt to reconnect.
				Eventually(finished).Should(BeClosed())
				Expect(factory.NumOpenCalls()).To(Equal(1))
				mock := factory.MockNfQueue
				Expect(mock).NotTo(BeNil())
				Expect(mock.Closed).To(BeTrue())
			})
		})

		Context("connection processing completes", func() {
			BeforeEach(func() {
				nfc.Connect(ctx)

				Eventually(factory.NumOpenCalls).Should(Equal(1))
				mocknfq = factory.MockNfQueue
				Eventually(mocknfq.IsRegistered).Should(BeTrue())
			})

			When("packets are received", func() {
				BeforeEach(func() {
					// Not testing time related features here, so just return a fixed time.
					mockTime.On("Now", mock.Anything).Return(time.Now())
				})

				It("sets the verdict on packets released out of order", func() {
					payload := []byte("packet")
					Expect(mocknfq.SendAttributes(gonfqueue.Attribute{
						Payload: &payload,
					})).To(Equal(0))
					Expect(mocknfq.SendAttributes(gonfqueue.Attribute{
						Payload: &payload,
					})).To(Equal(0))
					Expect(packetHandler.packets).To(HaveLen(2))

					// Release second packet. First packet should have no verdict.
					packetHandler.packets[1].Release()
					Eventually(held.get).Should(Equal(1))
					Eventually(func() int { return mocknfq.GetVerdict(2) }).Should(Equal(gonfqueue.NfAccept))
					Expect(mocknfq.HasVerdict(1)).To(BeFalse())

					// Release first packet. Since this is the lowest packet we know about we'll actually use batch
					// release.
					packetHandler.packets[0].Release()
					Eventually(held.get).Should(Equal(0))
					Eventually(func() int { return mocknfq.GetBatchVerdict(1) }).Should(Equal(gonfqueue.NfAccept))

					// Marks should not be set on either.
					Expect(mocknfq.GetMark(1)).To(BeZero())
					Expect(mocknfq.GetMark(2)).To(BeZero())

					// Check release packet callback.
					Eventually(packetHandler.getReleased).Should(Equal([]releaseInfo{
						{2, nfqueue.ReleasedByConsumer}, {1, nfqueue.ReleasedByConsumer},
					}))
				})

				It("sets uses batch verdict on packets released in order", func() {
					// Send 4 packets.
					payload := []byte("packet")
					ts := time.Now()
					mockTime.On("Since", mock.Anything).Return(160 * time.Second).Once()
					Expect(mocknfq.SendAttributes(gonfqueue.Attribute{
						Payload:   &payload,
						Timestamp: &ts,
					})).To(Equal(0))
					Expect(mocknfq.SendAttributes(gonfqueue.Attribute{
						Payload: &payload,
					})).To(Equal(0))
					Expect(packetHandler.packets).To(HaveLen(2))
					Expect(mocknfq.SendAttributes(gonfqueue.Attribute{
						Payload: &payload,
					})).To(Equal(0))
					Expect(packetHandler.packets).To(HaveLen(3))
					Expect(mocknfq.SendAttributes(gonfqueue.Attribute{
						Payload: &payload,
					})).To(Equal(0))
					Expect(packetHandler.packets).To(HaveLen(4))

					// Check the packets seen counter.
					Expect(seen.num).To(Equal(4))

					// Block the main event loop.
					nfc.DebugBlockAndUnblock()

					// Release fourth, second and first packets.
					packetHandler.packets[3].Release()
					packetHandler.packets[1].Release()
					packetHandler.packets[0].Release()

					// Unblock the main event loop.
					nfc.DebugBlockAndUnblock()

					// There should be one held packet and three released.
					Eventually(held.get).Should(Equal(1))
					Eventually(released.get).Should(Equal(3))

					// Should receive a verdict for 4 and a batch verdict for 2 (which will include 1).
					Eventually(func() bool { return mocknfq.HasVerdict(4) }).Should(BeTrue())
					Eventually(func() bool { return mocknfq.HasBatchVerdict(2) }).Should(BeTrue())
					Expect(mocknfq.GetVerdict(4)).To(Equal(gonfqueue.NfAccept))
					Expect(mocknfq.GetBatchVerdict(2)).To(Equal(gonfqueue.NfAccept))
					Expect(mocknfq.HasVerdict(1)).To(BeFalse())
					Expect(mocknfq.HasBatchVerdict(1)).To(BeFalse())

					// Send a 5th packet.
					Expect(mocknfq.SendAttributes(gonfqueue.Attribute{
						Payload: &payload,
					})).To(Equal(0))
					Expect(packetHandler.packets).To(HaveLen(5))

					// Block the main event loop.
					nfc.DebugBlockAndUnblock()

					// Release third and fifth packets.
					packetHandler.packets[2].Release()
					packetHandler.packets[4].Release()

					// Unblock the main event loop.
					nfc.DebugBlockAndUnblock()

					// There should be no held packets and five released.
					Eventually(held.get).Should(Equal(0))
					Eventually(released.get).Should(Equal(5))

					// Should receive a batch verdict for 5.
					Eventually(func() bool { return mocknfq.HasBatchVerdict(5) }).Should(BeTrue())
					Expect(mocknfq.GetBatchVerdict(5)).To(Equal(gonfqueue.NfAccept))
					Expect(mocknfq.HasVerdict(3)).To(BeFalse())
					Expect(mocknfq.HasBatchVerdict(3)).To(BeFalse())

					// Check release packet callback. Batched packets get released first.
					Eventually(packetHandler.getReleased).Should(Equal([]releaseInfo{
						{2, nfqueue.ReleasedByConsumer}, {1, nfqueue.ReleasedByConsumer}, // batch
						{4, nfqueue.ReleasedByConsumer},                                  // single
						{3, nfqueue.ReleasedByConsumer}, {5, nfqueue.ReleasedByConsumer}, // batch
					}))
				})

				It("updates stats when failing to set the verdict", func() {
					// Send 4 packets.
					payload := []byte("packet")
					Expect(mocknfq.SendAttributes(gonfqueue.Attribute{
						Payload: &payload,
					})).To(Equal(0))
					Expect(mocknfq.SendAttributes(gonfqueue.Attribute{
						Payload: &payload,
					})).To(Equal(0))
					Expect(packetHandler.packets).To(HaveLen(2))
					Expect(mocknfq.SendAttributes(gonfqueue.Attribute{
						Payload: &payload,
					})).To(Equal(0))
					Expect(packetHandler.packets).To(HaveLen(3))
					Expect(mocknfq.SendAttributes(gonfqueue.Attribute{
						Payload: &payload,
					})).To(Equal(0))
					Expect(packetHandler.packets).To(HaveLen(4))

					// Set 8 verdict errors. We are releasing packets such that we expect 1 batch verict + 1 verdict
					// followed by another batch verdict. 8 verdict errors means the first two will fail the final
					// batch verdict will succeed.
					err := errors.New("error")
					mocknfq.SetVerdictErrs = []error{err, err, err, err, err, err, err, err}

					// Block the main event loop.
					nfc.DebugBlockAndUnblock()

					// Release fourth, second and first packets.
					packetHandler.packets[3].Release()
					packetHandler.packets[1].Release()
					packetHandler.packets[0].Release()

					// Unblock the main event loop.
					nfc.DebugBlockAndUnblock()

					// There should be one held packet and three released.
					Eventually(held.get).Should(Equal(1))
					Eventually(released.get).Should(Equal(3))

					// This will fail to set verdict (x1) and batch verdict (x1).
					Eventually(verdictFailure.get).Should(Equal(2))
					Consistently(func() bool { return mocknfq.HasBatchVerdict(2) }).Should(BeFalse())
					Consistently(func() bool { return mocknfq.HasVerdict(4) }).Should(BeFalse())

					// Send a 5th packet.
					Expect(mocknfq.SendAttributes(gonfqueue.Attribute{
						Payload: &payload,
					})).To(Equal(0))
					Expect(packetHandler.packets).To(HaveLen(5))

					// Block the main event loop.
					nfc.DebugBlockAndUnblock()

					// Release third and fifth packets.
					packetHandler.packets[2].Release()
					packetHandler.packets[4].Release()

					// Unblock the main event loop.
					nfc.DebugBlockAndUnblock()

					// There should be no held packets and five released.
					Eventually(held.get).Should(Equal(0))
					Eventually(released.get).Should(Equal(5))

					// Should receive a batch verdict for 5 with no more failures.
					Consistently(verdictFailure.get).Should(Equal(2))
					Eventually(func() bool { return mocknfq.HasBatchVerdict(5) }).Should(BeTrue())

					// Check release packet callback. We still get the callbacks even if the SetVerdict call fails.
					// Batch verdict happens first.
					Eventually(packetHandler.getReleased).Should(Equal([]releaseInfo{
						{2, nfqueue.ReleasedByConsumer}, {1, nfqueue.ReleasedByConsumer}, // batch
						{4, nfqueue.ReleasedByConsumer},                                  // single
						{3, nfqueue.ReleasedByConsumer}, {5, nfqueue.ReleasedByConsumer}, // batch
					}))
				})
			})

			When("when packets are held beyond the max hold time", func() {
				It("sets the verdict on packets released out of order", func() {
					payload := []byte("packet")
					mockTime.On("Now", mock.Anything).Return(time.Unix(1, 0)).Once()
					Expect(mocknfq.SendAttributes(gonfqueue.Attribute{
						Payload: &payload,
					})).To(Equal(0))
					mockTime.On("Now", mock.Anything).Return(time.Unix(2, 0)).Once()
					Expect(mocknfq.SendAttributes(gonfqueue.Attribute{
						Payload: &payload,
					})).To(Equal(0))
					Expect(packetHandler.packets).To(HaveLen(2))
					mockTime.On("Now", mock.Anything).Return(time.Unix(3, 0)).Once()
					Expect(mocknfq.SendAttributes(gonfqueue.Attribute{
						Payload: &payload,
					})).To(Equal(0))
					Expect(packetHandler.packets).To(HaveLen(3))

					Eventually(held.get).Should(Equal(3))

					// Calculate the expected expiry times.
					//p1Expire := time.Unix(0, 0).Add(5 * time.Second)
					p2Expire := time.Unix(2, 0).Add(5 * time.Second)
					p3Expire := time.Unix(3, 0).Add(5 * time.Second)

					logrus.Debugf("p2Expire: %s", p2Expire)
					logrus.Debugf("p3Expire: %s", p3Expire)

					// Set time to the p2 expiration time and send in a hold check tick. Both p1 and p2 should be released.
					// This should use batch release. Time is measure twice - once for the check and once for the batch
					// release.
					mockTime.On("Now", mock.Anything).Return(p2Expire).Twice()
					tickerChan <- p2Expire

					Eventually(held.get).Should(Equal(1))
					Eventually(releasedAfterHoldTime.get).Should(Equal(2))
					Eventually(func() bool { return mocknfq.HasBatchVerdict(2) }).Should(BeTrue())
					Expect(mocknfq.GetBatchVerdict(2)).To(Equal(gonfqueue.NfAccept))

					// Set time to the p2 expiration time and send in a hold check tick. Both p1 and p2 should be
					// released. This should use batch release.
					mockTime.On("Now", mock.Anything).Return(p3Expire).Twice()
					tickerChan <- p3Expire

					Eventually(held.get).Should(Equal(0))
					Eventually(releasedAfterHoldTime.get).Should(Equal(3))
					Eventually(func() bool { return mocknfq.HasBatchVerdict(3) }).Should(BeTrue())
					Expect(mocknfq.GetBatchVerdict(3)).To(Equal(gonfqueue.NfAccept))

					// It should be safe to release the packets even though they have already been released.
					packetHandler.packets[2].Release()
					Consistently(held.get).Should(Equal(0))
					Consistently(releasedAfterHoldTime.get).Should(Equal(3))
					Consistently(released.get).Should(Equal(0))

					// Check release packet callback.
					Eventually(packetHandler.getReleased).Should(Equal([]releaseInfo{
						{1, nfqueue.ReleasedByTimeout}, {2, nfqueue.ReleasedByTimeout},
						{3, nfqueue.ReleasedByTimeout},
					}))
				})
			})
		})
	})

	Context("verdict repeat processing", func() {
		// Verdict repeat processing is much the same as verdict allow except that:
		// - a DNR mark is set
		// - batch release is not used.
		BeforeEach(func() {
			// Connect and wait for registration to complete.
			options = append(options, nfqueue.OptVerdictRepeat(8))
			nfc = nfqueue.NewNfQueueConnector(10, packetHandler, options...)
			nfc.Connect(ctx)

			Eventually(factory.NumOpenCalls).Should(Equal(1))
			mocknfq = factory.MockNfQueue
			Eventually(mocknfq.IsRegistered).Should(BeTrue())
			mockTime.On("Now", mock.Anything).Return(time.Now())
		})

		When("packets are received", func() {
			It("DROPs any packet immediately if the DNR flag is set", func() {
				payload := []byte("packet")
				mark := uint32(8)
				Expect(mocknfq.SendAttributes(gonfqueue.Attribute{
					Mark:    &mark,
					Payload: &payload,
				})).To(Equal(0))
				Expect(mocknfq.Verdicts[1]).To(Equal(gonfqueue.NfDrop))
				Expect(dnrDropped.num).To(Equal(1))
				Expect(payloadDropped.num).To(Equal(0))
				Expect(seen.num).To(Equal(1))
				Expect(held.get()).To(Equal(0))
			})

			It("DROPs any packet immediately if there is no payload", func() {
				mark := uint32(1)
				Expect(mocknfq.SendAttributes(gonfqueue.Attribute{
					Mark: &mark,
				})).To(Equal(0))
				Expect(mocknfq.Verdicts[1]).To(Equal(gonfqueue.NfDrop))
				Expect(payloadDropped.num).To(Equal(1))
				Expect(dnrDropped.num).To(Equal(0))
				Expect(seen.num).To(Equal(1))
				Expect(held.get()).To(Equal(0))
			})

			It("calls handler for valid packets", func() {
				payload := []byte("packet")
				Expect(mocknfq.SendAttributes(gonfqueue.Attribute{
					Payload: &payload,
				})).To(Equal(0))
				Expect(mocknfq.SendAttributes(gonfqueue.Attribute{
					Payload: &payload,
				})).To(Equal(0))
				Expect(packetHandler.packets).To(HaveLen(2))
				Expect(packetHandler.packets[0].ID).To(Equal(uint32(1)))
				Expect(packetHandler.packets[1].ID).To(Equal(uint32(2)))
				Expect(held.get()).To(Equal(2))
			})

			It("sets the verdict on released packets", func() {
				payload := []byte("packet")
				Expect(mocknfq.SendAttributes(gonfqueue.Attribute{
					Payload: &payload,
				})).To(Equal(0))
				Expect(mocknfq.SendAttributes(gonfqueue.Attribute{
					Payload: &payload,
				})).To(Equal(0))
				Expect(packetHandler.packets).To(HaveLen(2))

				// Release second packet. First packet should have no verdict.
				packetHandler.packets[1].Release()
				Eventually(held.get).Should(Equal(1))
				Eventually(func() int { return mocknfq.GetVerdict(2) }).Should(Equal(gonfqueue.NfRepeat))
				Eventually(func() int { return mocknfq.GetMark(2) }).Should(Equal(8))
				Expect(mocknfq.HasVerdict(1)).To(BeFalse())

				// Release first packet.
				packetHandler.packets[0].Release()
				Eventually(held.get).Should(Equal(1))
				Eventually(func() int { return mocknfq.GetVerdict(1) }).Should(Equal(gonfqueue.NfRepeat))
				Eventually(func() int { return mocknfq.GetMark(1) }).Should(Equal(8))
			})

			It("updates stats when failing to set verdict", func() {
				payload := []byte("packet")
				Expect(mocknfq.SendAttributes(gonfqueue.Attribute{
					Payload: &payload,
				})).To(Equal(0))
				Expect(mocknfq.SendAttributes(gonfqueue.Attribute{
					Payload: &payload,
				})).To(Equal(0))
				Expect(packetHandler.packets).To(HaveLen(2))

				// Set 5 verdict errors. This means the verdict for the first packet will not be set, but the second
				// packet will be.
				err := errors.New("error")
				mocknfq.SetVerdictErrs = []error{err, err, err, err, err}

				// Release the packets.
				packetHandler.packets[0].Release()
				packetHandler.packets[1].Release()

				// Release second packet. First packet should have no verdict. We should have a single verdict failure.
				Eventually(held.get).Should(Equal(0))
				Eventually(func() int { return mocknfq.GetVerdict(2) }).Should(Equal(gonfqueue.NfRepeat))
				Eventually(func() int { return mocknfq.GetMark(2) }).Should(Equal(8))
				Expect(mocknfq.HasVerdict(1)).To(BeFalse())
				Expect(verdictFailure.get()).To(Equal(1))
			})

			It("does not set the verdict when releasing packets associated with a closed connection", func() {
				payload := []byte("packet")

				// This test sets connection failed events when a connection close event occurs - even if packets
				// are pending release. We repeat this test a number of times to attempt to get code coverage up
				// because the main queue loop can handle disconnection processing from one of three select cases.
				for i := 1; i < 50; i++ {
					By("Testing connection number " + strconv.Itoa(i))

					// Drain the ticker channel in case it is full from the previous run. Empty the packet and release
					// data from the previous run.
					select {
					case <-tickerChan:
					default:
					}
					packetHandler.packets = nil
					packetHandler.released = nil

					// Make sure we are connected.
					Eventually(factory.NumOpenCalls).Should(Equal(i))
					mocknfq = factory.MockNfQueue
					Eventually(mocknfq.IsRegistered).Should(BeTrue())

					// Check verdicts from a previous connection have not leaked into the current connection.
					Expect(mocknfq.HasVerdict(1)).To(BeFalse())
					Expect(mocknfq.HasVerdict(2)).To(BeFalse())

					// Send some packets.
					Expect(mocknfq.SendAttributes(gonfqueue.Attribute{
						Payload: &payload,
					})).To(Equal(0))
					Expect(mocknfq.SendAttributes(gonfqueue.Attribute{
						Payload: &payload,
					})).To(Equal(0))
					Expect(packetHandler.packets).To(HaveLen(2))

					// Block the main thread. Release one of the packets, send a ticker event and send an error to
					// close the connection. When we unblock the main thread we may trigger release processing, but it
					// should attempt disconnection processing instead.
					nfc.DebugBlockAndUnblock()
					packetHandler.packets[0].Release()
					Expect(mocknfq.SendError(errors.New("unrecoverable socket error"))).To(Equal(1))
					tickerChan <- time.Now()
					nfc.DebugBlockAndUnblock()

					// Send an error to close the old connection.
					Eventually(shutdown.get).Should(Equal(i))
					Expect(mocknfq.Closed).To(BeTrue())
					Expect(held.get()).To(Equal(0))
					Expect(closedDropped.get()).To(Equal(2 * i))

					// Release packets. First and second packets should have no verdict on either the new or old
					// connections.
					packetHandler.packets[0].Release()
					packetHandler.packets[1].Release()

					Consistently(func() bool { return mocknfq.HasVerdict(1) }).Should(BeFalse())
					Expect(mocknfq.HasVerdict(2)).To(BeFalse())

					// Check release packet callback. Despite us calling release on a packet, the verdict is not set and
					// the packet is released due to conn closing. We do the callbacks for the held packets followed by
					// the pending release.
					Expect(packetHandler.released).To(Equal([]releaseInfo{
						{2, nfqueue.ReleasedByConnFailure}, {1, nfqueue.ReleasedByConnFailure},
					}))
				}
			})
		})
	})
})

// Test Packet methods
var _ = Describe("Packet", func() {
	When("invoking String()", func() {
		It("renders correctly if all of the optional fields are present", func() {
			m := uint32(2)
			t := time.Now()

			p := nfqueue.Packet{
				ID:        32,
				Timestamp: &t,
				Mark:      &m,
			}
			Expect(p.String()).To(Equal("Packet(32;" + t.String() + ";mark=2)"))
		})

		It("renders correctly if none of the optional fields are present", func() {
			p := nfqueue.Packet{
				ID: 32,
			}
			Expect(p.String()).To(Equal("Packet(32)"))
		})
	})
})
