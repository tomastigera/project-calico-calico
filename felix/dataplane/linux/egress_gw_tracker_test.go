// Copyright (c) 2022  All rights reserved.

package intdataplane

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/labelindex/ipsetmember"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

func TestEgressHealthMainline(t *testing.T) {
	tracker, h, fromPollerC, cancel := setupEgressHealthTest(t, 100*time.Millisecond, 1, 3)
	defer cancel()

	// Set shouldn't exist before we add it...
	gws, exists := tracker.GatewaysByID("set-1")
	Expect(exists).To(BeFalse())
	Expect(gws).To(BeNil())

	// Send in an egress IP set with health.  This should trigger pollers to start.
	tracker.OnIPSetUpdate(&proto.IPSetUpdate{
		Type: proto.IPSetUpdate_EGRESS_IP,
		Id:   "set-1",
		Members: []string{
			MakeIPPortEgressMember(h[0].IP, h[0].Port).ToProtobufFormat(),
			MakeIPPortEgressMember(h[1].IP, h[1].Port).ToProtobufFormat(),
		},
	})

	// Set should get marked dirty.
	dirtySets := tracker.UpdatePollersGetAndClearDirtySetIDs()
	Expect(dirtySets).To(ConsistOf("set-1"))
	Expect(tracker.UpdatePollersGetAndClearDirtySetIDs()).To(BeEmpty(), "UpdatePollersGetAndClearDirtySetIDs should clear the set IDs")

	// Gateways should start in state EGWHealthUnknown.
	gws, exists = tracker.GatewaysByID("set-1")
	Expect(exists).To(BeTrue())
	Expect(gws).To(HaveLen(2))
	gw1 := gws[h[0].IP]
	Expect(gw1.addr).To(Equal(h[0].IP))
	Expect(gw1.healthPort).To(Equal(uint16(h[0].Port)))
	Expect(gw1.healthStatus).To(Equal(EGWHealthUnknown))
	gw2 := gws[h[1].IP]
	Expect(gw2.addr).To(Equal(h[1].IP))
	Expect(gw2.healthPort).To(Equal(uint16(h[1].Port)))
	Expect(gw2.healthStatus).To(Equal(EGWHealthUnknown))
	Expect(gws.failedGateways()).To(BeEmpty())

	// Expect a report from each poller, which we feed back to the tracker.
	var healthReport EGWHealthReport
	Eventually(fromPollerC, "200ms", "1ms").Should(Receive(&healthReport), "expected pollers to send a message when first poll succeeds")
	tracker.OnEGWHealthReport(healthReport)
	Eventually(fromPollerC, "200ms", "1ms").Should(Receive(&healthReport))
	tracker.OnEGWHealthReport(healthReport)

	// Set should get marked dirty.
	dirtySets = tracker.UpdatePollersGetAndClearDirtySetIDs()
	Expect(dirtySets).To(ConsistOf("set-1"), "Expected health reports to cause EGW IP set to be marked dirty.")
	Expect(tracker.UpdatePollersGetAndClearDirtySetIDs()).To(BeEmpty(), "UpdatePollersGetAndClearDirtySetIDs should clear the set IDs")

	gws, exists = tracker.GatewaysByID("set-1")
	Expect(exists).To(BeTrue())
	Expect(gws).To(HaveLen(2))
	gw1 = gws[h[0].IP]
	Expect(gw1.addr).To(Equal(h[0].IP))
	Expect(gw1.healthStatus).To(Equal(EGWHealthUp))
	gw2 = gws[h[1].IP]
	Expect(gw2.addr).To(Equal(h[1].IP))
	Expect(gw2.healthStatus).To(Equal(EGWHealthUp))
	Expect(gws.failedGateways()).To(BeEmpty())
	Expect(gws.allIPs()).To(Equal(set.From(h[0].IP, h[1].IP)))
	Expect(gws.activeGateways()).To(HaveLen(2))

	// Pollers shouldn't return any more reports after the initial one.  They only send reports when something
	// changes.
	Consistently(fromPollerC, "150ms", "1ms").ShouldNot(Receive())

	// Tell one gateway to start failing.
	h[0].SetStatusToReturn(500)

	Eventually(fromPollerC).Should(Receive(&healthReport), "expected poller to send a health report once remote EGW returns an error")
	Expect(healthReport.Health).To(Equal(EGWHealthProbeFailed))
	tracker.OnEGWHealthReport(healthReport)

	// Set should get marked dirty.
	dirtySets = tracker.UpdatePollersGetAndClearDirtySetIDs()
	Expect(dirtySets).To(ConsistOf("set-1"), "Expected health reports to cause EGW IP set to be marked dirty.")
	Expect(tracker.UpdatePollersGetAndClearDirtySetIDs()).To(BeEmpty(), "UpdatePollersGetAndClearDirtySetIDs should clear the set IDs")

	// Gateway that failed should be reported as such.
	gws, exists = tracker.GatewaysByID("set-1")
	Expect(exists).To(BeTrue())
	Expect(gws).To(HaveLen(2))
	failedGWs := gws.failedGateways()
	Expect(failedGWs).To(HaveLen(1))
	Expect(failedGWs).To(HaveKey(h[0].IP))
	Expect(failedGWs[h[0].IP].healthStatus).To(Equal(EGWHealthProbeFailed))
	activeGWs := gws.activeGateways()
	Expect(activeGWs).To(HaveLen(1))
	Expect(activeGWs).To(HaveKey(h[1].IP))

	// Tell gateway to stop failing.
	h[0].SetStatusToReturn(200)

	// Should get the report...
	Eventually(fromPollerC).Should(Receive(&healthReport))
	Expect(healthReport.Health).To(Equal(EGWHealthUp))
	tracker.OnEGWHealthReport(healthReport)

	gws, exists = tracker.GatewaysByID("set-1")
	Expect(exists).To(BeTrue())
	Expect(gws).To(HaveLen(2))
	Expect(gws.activeGateways()).To(Equal(gws)) // Should all be active now.

	// Add a new gw to the set and remove one of the others.
	tracker.OnIPSetDeltaUpdate(&proto.IPSetDeltaUpdate{
		Id: "set-1",
		RemovedMembers: []string{
			MakeIPPortEgressMember(ip.FromString("127.0.0.2"), h[1].Port).ToProtobufFormat(),
		},
		AddedMembers: []string{
			MakeIPPortEgressMember(ip.FromString("127.0.0.3"), h[2].Port).ToProtobufFormat(),
		},
	})
	Expect(tracker.UpdatePollersGetAndClearDirtySetIDs()).To(ConsistOf("set-1"))

	Eventually(fromPollerC).Should(Receive(&healthReport))
	Expect(healthReport.Health).To(Equal(EGWHealthUp))
	Expect(healthReport.Addr).To(Equal(h[2].IP))
	tracker.OnEGWHealthReport(healthReport)

	gws, exists = tracker.GatewaysByID("set-1")
	Expect(exists).To(BeTrue())
	Expect(gws).To(HaveLen(2))
	Expect(gws).To(HaveKey(h[0].IP))
	Expect(gws).To(HaveKey(h[2].IP))
	Expect(gws.activeGateways()).To(Equal(gws)) // Should all be active.

	// Should have stopped polling gw2.
	Eventually(h[1].SinceLastPoll, "1s", "1ms").Should(BeNumerically(">", 150*time.Millisecond))
	Expect(h[0].SinceLastPoll()).To(BeNumerically("<", 150*time.Millisecond))
	Expect(h[2].SinceLastPoll()).To(BeNumerically("<", 150*time.Millisecond))

	tracker.OnIPSetRemove(&proto.IPSetRemove{
		Id: "set-1",
	})
	Expect(tracker.UpdatePollersGetAndClearDirtySetIDs()).To(ConsistOf("set-1"))

	gws, exists = tracker.GatewaysByID("set-1")
	Expect(exists).To(BeFalse())

	// Should stop polling.
	Eventually(h[0].SinceLastPoll, "1s", "1ms").Should(BeNumerically(">", 150*time.Millisecond))
	Eventually(h[2].SinceLastPoll, "1s", "1ms").Should(BeNumerically(">", 150*time.Millisecond))
	Expect(fromPollerC).ToNot(Receive())
}

func setupEgressHealthTest(t *testing.T, pollInterval time.Duration, pollFailCount, numListeners int) (*EgressGWTracker, []*healthHandler, chan EGWHealthReport, func()) {
	RegisterTestingT(t)

	// Create the tracker and the channel that its EGW poll threads will use to send messages back to the
	// main thread.  The tracker doesn't listen on its own channel, it expects the main thread to give it a call back
	// when a message arrives.
	fromPollerC := make(chan EGWHealthReport, 1) // Need buffered chan since Should(Receive()) doesn't block.
	ctx, cancel1 := context.WithCancel(context.Background())
	tracker := NewEgressGWTracker(ctx, fromPollerC, pollInterval, pollFailCount)

	// Set up local sockets; these are our pretend remote egress gateways.  We can trigger one of them to time out.
	h, cancel2, err := createMockHealthListeners(numListeners)
	Expect(err).NotTo(HaveOccurred())

	return tracker, h, fromPollerC, func() {
		cancel1()
		cancel2()
	}
}

func TestEgressHealthTimeout(t *testing.T) {
	tracker, h, fromPollerC, cancel := setupEgressHealthTest(t, 100*time.Millisecond, 1, 1)
	defer cancel()

	// Send in an egress IP set with health.  This should trigger pollers to start.
	tracker.OnIPSetUpdate(&proto.IPSetUpdate{
		Type: proto.IPSetUpdate_EGRESS_IP,
		Id:   "set-1",
		Members: []string{
			MakeIPPortEgressMember(h[0].IP, h[0].Port).ToProtobufFormat(),
		},
	})

	// Set should get marked dirty.
	Expect(tracker.UpdatePollersGetAndClearDirtySetIDs()).To(ConsistOf("set-1"))

	// Expect a report from each poller, which we feed back to the tracker.
	var healthReport EGWHealthReport
	Eventually(fromPollerC, "200ms", "1ms").Should(Receive(&healthReport), "expected pollers to send a message when first poll succeeds")
	tracker.OnEGWHealthReport(healthReport)

	// Should be active to start with.
	gws, _ := tracker.GatewaysByID("set-1")
	Expect(gws.activeGateways()).To(HaveLen(1))

	// Tell one gateway to start timing out.
	h[0].SetTimeOut(true)

	// Should get a report (more thorough test of this area in the mainline test).
	Eventually(fromPollerC, "500ms", "1ms").Should(Receive(&healthReport), "expected poller to send a health report once remote EGW returns an error")
	Expect(healthReport.Health).To(Equal(EGWHealthProbeFailed))
	tracker.OnEGWHealthReport(healthReport)
	gws, _ = tracker.GatewaysByID("set-1")
	Expect(gws).To(HaveLen(1))
	Expect(gws.activeGateways()).To(HaveLen(0))

	// Tell one gateway to stop timing out.
	h[0].SetTimeOut(false)

	// Should get a report (more thorough test of this area in the mainline test).
	Eventually(fromPollerC, "500ms", "1ms").Should(Receive(&healthReport), "expected poller to send a health report once EGW restored")
	Expect(healthReport.Health).To(Equal(EGWHealthUp))
	tracker.OnEGWHealthReport(healthReport)
	gws, _ = tracker.GatewaysByID("set-1")
	Expect(gws.activeGateways()).To(HaveLen(1))
	Expect(gws.activeGateways()).To(HaveKey(h[0].IP))
}

func TestEgressHealthFailCount(t *testing.T) {
	tracker, h, fromPollerC, cancel := setupEgressHealthTest(t, 100*time.Millisecond, 3, 1)
	defer cancel()

	// Send in an egress IP set with health.  This should trigger pollers to start.
	tracker.OnIPSetUpdate(&proto.IPSetUpdate{
		Type: proto.IPSetUpdate_EGRESS_IP,
		Id:   "set-1",
		Members: []string{
			MakeIPPortEgressMember(h[0].IP, h[0].Port).ToProtobufFormat(),
		},
	})

	// Set should get marked dirty.
	Expect(tracker.UpdatePollersGetAndClearDirtySetIDs()).To(ConsistOf("set-1"))

	// Expect a report from the poller, which we feed back to the tracker.
	var healthReport EGWHealthReport
	Eventually(fromPollerC, "200ms", "1ms").Should(Receive(&healthReport), "expected pollers to send a message when first poll succeeds")

	// Tell one gateway to start timing out.
	h[0].SetTimeOut(true)

	// Shouldn't receive anything while the fail count increases.
	Consistently(fromPollerC, "250ms", "1ms").ShouldNot(Receive())

	// Should then get a report.
	Eventually(fromPollerC, "200ms", "1ms").Should(Receive(&healthReport), "expected poller to send a health report once remote EGW returns an error")
	Expect(healthReport.Health).To(Equal(EGWHealthProbeFailed))

	// Remove the timeout.
	h[0].SetTimeOut(false)

	// Response should be fast.
	Eventually(fromPollerC, "200ms", "1ms").Should(Receive(&healthReport), "expected poller to send a health report once remote EGW returns an error")
	Expect(healthReport.Health).To(Equal(EGWHealthUp))
}

func TestEgressHealthDefunctPoller(t *testing.T) {
	tracker, h, fromPollerC, cancel := setupEgressHealthTest(t, 100*time.Millisecond, 1, 1)
	defer cancel()

	// Send in an egress IP set with health.  This should trigger pollers to start.
	tracker.OnIPSetUpdate(&proto.IPSetUpdate{
		Type: proto.IPSetUpdate_EGRESS_IP,
		Id:   "set-1",
		Members: []string{
			MakeIPPortEgressMember(h[0].IP, h[0].Port).ToProtobufFormat(),
		},
	})
	Expect(tracker.UpdatePollersGetAndClearDirtySetIDs()).To(ConsistOf("set-1"))

	// Expect a report from the poller but we stash it to simulate a race with recreating the poller...
	var healthReport EGWHealthReport
	Eventually(fromPollerC, "200ms", "1ms").Should(Receive(&healthReport), "expected poller to send a message when first poll succeeds")

	// Full IP set update (for variety).  We remove the member...
	tracker.OnIPSetUpdate(&proto.IPSetUpdate{
		Type:    proto.IPSetUpdate_EGRESS_IP,
		Id:      "set-1",
		Members: []string{},
	})
	Expect(tracker.UpdatePollersGetAndClearDirtySetIDs()).To(ConsistOf("set-1"))

	// Check poller was stopped.
	Eventually(h[0].SinceLastPoll, "1s", "1ms").Should(BeNumerically(">", 150*time.Millisecond))

	// Send in the first report, should be ignored.
	tracker.OnEGWHealthReport(healthReport)
	gws, _ := tracker.GatewaysByID("set-1")
	Expect(gws).To(BeEmpty())

	// Break the EGW so that the poller we're about to create will fail...
	h[0].SetStatusToReturn(500)

	// Re-add the member.
	tracker.OnIPSetUpdate(&proto.IPSetUpdate{
		Type: proto.IPSetUpdate_EGRESS_IP,
		Id:   "set-1",
		Members: []string{
			MakeIPPortEgressMember(h[0].IP, h[0].Port).ToProtobufFormat(),
		},
	})
	Expect(tracker.UpdatePollersGetAndClearDirtySetIDs()).To(ConsistOf("set-1"))

	var healthReport2 EGWHealthReport
	Eventually(fromPollerC, "200ms", "1ms").Should(Receive(&healthReport2), "expected poller to send a message when first poll succeeds")

	// Send in the second report, should be accepted.
	tracker.OnEGWHealthReport(healthReport2)
	gws, _ = tracker.GatewaysByID("set-1")
	Expect(gws[h[0].IP].healthStatus).To(Equal(EGWHealthProbeFailed))

	// Send in the first report again for good measure, should _still_ be ignored.
	tracker.OnEGWHealthReport(healthReport)
	gws, _ = tracker.GatewaysByID("set-1")
	Expect(gws[h[0].IP].healthStatus).To(Equal(EGWHealthProbeFailed))
}

type healthHandler struct {
	IP             ip.Addr
	Port           int
	lock           sync.Mutex
	statusToReturn int
	lastPollTime   time.Time
	timeOut        bool
}

func (h *healthHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	logCtx := logrus.WithField("ip", h.IP.String())
	body, err := io.ReadAll(request.Body)
	if err != nil {
		logrus.WithError(err).Info("Error reading from client.")
	}
	logCtx.Infof("Health request from %q: %q %q", request.RemoteAddr, request.RequestURI, string(body))

	h.lock.Lock()
	s := h.statusToReturn
	to := h.timeOut
	h.lastPollTime = time.Now()
	h.lock.Unlock()

	if to {
		logCtx.WithError(err).Info("Timing out...")
		time.Sleep(200 * time.Millisecond)
	}

	writer.WriteHeader(s)
	_, err = fmt.Fprintf(writer, "Response from test harness: %d", s)
	if err != nil {
		logCtx.WithError(err).Info("Error writing to client.")
	}
}

func (h *healthHandler) SetStatusToReturn(s int) {
	h.lock.Lock()
	defer h.lock.Unlock()
	logrus.WithField("status", s).Info("Setting status.")
	h.statusToReturn = s
}

func (h *healthHandler) LastPollTime() time.Time {
	h.lock.Lock()
	defer h.lock.Unlock()
	return h.lastPollTime
}

func (h *healthHandler) SinceLastPoll() time.Duration {
	return time.Since(h.LastPollTime())
}

func (h *healthHandler) SetTimeOut(b bool) {
	h.lock.Lock()
	defer h.lock.Unlock()
	logrus.WithField("timeOut", b).Info("Setting timeout.")
	h.timeOut = b
}

func createMockHealthListeners(n int) (hs []*healthHandler, cancel func(), err error) {
	var cancelFns []func()
	cancel = func() {
		for _, c := range cancelFns {
			c()
		}
	}
	for i := range n {
		h, cancelFn, err := newMockHealthListener(fmt.Sprintf("127.0.0.%d", i+1))
		if err != nil {
			cancel()
			return nil, nil, err
		}
		cancelFns = append(cancelFns, cancelFn)
		hs = append(hs, h)
	}
	return
}

func newMockHealthListener(localIP string) (handler *healthHandler, cancel func(), err error) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   net.ParseIP(localIP),
		Port: 0, // Pick a random port.
	})
	if err != nil {
		return
	}
	handler = &healthHandler{
		IP:             ip.FromIPOrCIDRString(localIP),
		statusToReturn: http.StatusOK,
		Port:           listener.Addr().(*net.TCPAddr).Port,
	}
	go func() {
		err := http.Serve(listener, handler)
		logrus.WithError(err).Debug("Serve finished.")
	}()
	Eventually(func() error {
		resp, err := http.Get(fmt.Sprintf("http://%s:%d", localIP, handler.Port))
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected response from mock gw: %d", resp.StatusCode)
		}
		_, err = io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		err = resp.Body.Close()
		if err != nil {
			return err
		}
		return nil
	}, "100ms", "1ms").ShouldNot(HaveOccurred())
	cancel = func() {
		logrus.Info("Shutting down listener.")
		_ = listener.Close()
	}
	return
}

func MakeIPPortEgressMember(addr ip.Addr, healthPort int) ipsetmember.IPSetMember {
	return ipsetmember.MakeEgressGateway(
		addr.(ip.V4Addr),
		time.Time{},
		0,
		"",
		uint16(healthPort),
	)
}
