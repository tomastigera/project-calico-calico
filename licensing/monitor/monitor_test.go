package monitor

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	lapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/jitter"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	lclient "github.com/projectcalico/calico/licensing/client"
)

func init() {
	logutils.ConfigureFormatter("test")
	log.SetLevel(log.DebugLevel)
}

func TestBasicFunction(t *testing.T) {
	t.Run("With no datastore connection", func(t *testing.T) {
		RegisterTestingT(t)

		// Create a monitor, passing in a nil client.
		m := New(nil)

		// Expect that feature status is returned as false.
		status := m.GetFeatureStatus("foo")
		Expect(status).To(BeFalse())

		// Expect the license to be listed as not loaded.
		Expect(m.GetLicenseStatus()).To(Equal(lclient.NoLicenseLoaded))
	})
}

func TestMonitorLoop(t *testing.T) {
	RegisterTestingT(t)
	m, h := setUpMonitorAndMocks()
	// Increase poll interval and make sure it's out of phase with 30m license expiry time so that we hit the
	// license transition timer.
	m.SetPollInterval(11 * time.Minute)
	defer h.cancel()
	go func() {
		_ = m.MonitorForever(h.ctx)
	}()

	Eventually(h.HasActiveWatch).Should(BeTrue())
	h.SetLicense("good", h.Now().Add(30*time.Minute))
	// Wait for the timers to be set up.  Two pollers and one transition.
	Eventually(h.GetNumTimers).Should(Equal(3))

	// Fast poller pops once at 2s but then blocks.
	numPops := h.AdvanceTime(3 * time.Second) // 10m
	Expect(numPops).To(Equal(1))
	// Slow poller shouldn't pop until 11m
	numPops = h.AdvanceTime(10 * time.Minute) // 10m
	Expect(numPops).To(BeZero())
	numPops = h.AdvanceTime(2 * time.Minute)
	Expect(numPops).To(Equal(1)) // 12m
	Eventually(h.GetSignalledLicenseStatus).Should(Equal(lclient.Valid))

	Eventually(h.GetNumTimers).Should(Equal(3))

	numPops = h.AdvanceTime(11 * time.Minute) // 23m
	Expect(numPops).To(Equal(1))

	// Expect the license to go into grace after 30 minutes so jump forward to 29 minutes and check it's still valid...
	h.AdvanceTime(6 * time.Minute) // 29m
	Consistently(h.GetSignalledLicenseStatus, "100ms", "10ms").Should(Equal(lclient.Valid))

	// Then jump past 30 minutes...
	h.AdvanceTime(2 * time.Minute)
	Eventually(h.GetSignalledLicenseStatus).Should(Equal(lclient.InGracePeriod))

	// Then jump forward a day, which should end the grace period.
	h.AdvanceTime(23 * time.Hour)
	Consistently(h.GetSignalledLicenseStatus, "100ms", "10ms").Should(Equal(lclient.InGracePeriod))
	h.AdvanceTime(1 * time.Hour)
	Eventually(h.GetSignalledLicenseStatus).Should(Equal(lclient.Expired))

	// Update the license and we should go back to valid again...
	h.SetLicense("good2", h.Now().Add(30*time.Minute))
	h.AdvanceTime(12 * time.Minute)
	Eventually(h.GetSignalledLicenseStatus).Should(Equal(lclient.Valid))

	// Then jump past 30 minutes...
	h.AdvanceTime(31 * time.Minute)
	Eventually(h.GetSignalledLicenseStatus).Should(Equal(lclient.InGracePeriod))

	// Then jump past 24 hours...
	h.AdvanceTime(24 * time.Hour)
	Eventually(h.GetSignalledLicenseStatus).Should(Equal(lclient.Expired))
}

func TestRefreshLicense(t *testing.T) {
	t.Run("mainline valid license then expiry test", func(t *testing.T) {
		RegisterTestingT(t)
		m, h := setUpMonitorAndMocks()
		defer h.cancel()
		go func() {
			_ = m.MonitorForever(h.ctx)
		}()

		Eventually(h.HasActiveWatch).Should(BeTrue())
		h.SetLicense("good", h.Now().Add(30*time.Minute))

		_ = m.RefreshLicense(h.ctx)
		log.WithField("status", m.GetLicenseStatus()).Info("License status")

		Expect(m.GetLicenseStatus()).To(Equal(lclient.Valid))
		Expect(m.GetFeatureStatus("allowed")).To(BeTrue(), "expected feature to be allowed but it wasn't")
		Expect(m.GetFeatureStatus("foobar")).To(BeFalse(), "expected feature to be disallowed but it wasn't")
		Expect(h.OnFeaturesChangedCalled).To(BeTrue(), "expected feature change to be signalled")

		t.Log("Second call with exactly the same license shouldn't trigger feature change")
		h.OnFeaturesChangedCalled = false
		_ = m.RefreshLicense(h.ctx)
		Expect(h.OnFeaturesChangedCalled).To(BeFalse(), "expected feature change not to be signalled")

		t.Log("After updating license with new features")
		// Need to make some tweak to avoid "raw license hasn't changed" optimisation.
		h.allowedFeatures = []string{"some", "new", "features"}
		h.SetLicense("good2", h.Now().Add(30*time.Minute))
		_ = m.RefreshLicense(h.ctx)
		Expect(h.OnFeaturesChangedCalled).To(BeTrue(), "expected new features to be signalled")

		t.Log("Changing the license without changing the features")
		// Need to make some tweak to avoid "raw license hasn't changed" optimisation.
		h.SetLicense("good", h.Now().Add(30*time.Minute))
		h.OnFeaturesChangedCalled = false
		_ = m.RefreshLicense(h.ctx)
		Expect(h.OnFeaturesChangedCalled).To(BeFalse(), "expected feature change not to be signalled")

		t.Log("changing to a grace-period license")
		h.SetLicense("in-grace", h.Now().Add(-1*time.Minute))
		_ = m.RefreshLicense(h.ctx)
		Expect(h.OnFeaturesChangedCalled).To(BeFalse(), "expected feature change not to be signalled")
		Expect(m.GetLicenseStatus()).To(Equal(lclient.InGracePeriod))
	})
	t.Run("in grace period", func(t *testing.T) {
		RegisterTestingT(t)
		m, h := setUpMonitorAndMocks()
		defer h.cancel()
		go func() {
			_ = m.MonitorForever(h.ctx)
		}()
		Eventually(h.HasActiveWatch).Should(BeTrue())
		h.SetLicense("in-grace", h.Now().Add(-1*time.Minute))

		_ = m.RefreshLicense(h.ctx)
		log.WithField("status", m.GetLicenseStatus()).Info("License status")

		Expect(m.GetLicenseStatus()).To(Equal(lclient.InGracePeriod))
		Expect(m.GetFeatureStatus("allowed")).To(BeTrue(), "expected feature to be allowed in grace period but it wasn't")
		Expect(m.GetFeatureStatus("foobar")).To(BeFalse(), "expected feature to be disallowed but it wasn't")
	})
	t.Run("with expired license", func(t *testing.T) {
		RegisterTestingT(t)
		m, h := setUpMonitorAndMocks()
		defer h.cancel()
		go func() {
			_ = m.MonitorForever(h.ctx)
		}()
		Eventually(h.HasActiveWatch).Should(BeTrue())
		h.SetLicense("expired", h.Now().Add(-25*time.Hour))

		_ = m.RefreshLicense(h.ctx)
		log.WithField("status", m.GetLicenseStatus()).Info("License status")

		Expect(m.GetLicenseStatus()).To(Equal(lclient.Expired))
		Expect(m.GetFeatureStatus("allowed")).To(BeTrue(), "expected feature to be allowed after expiration but it wasn't")
		Expect(m.GetFeatureStatus("foobar")).To(BeFalse(), "expected feature to be disallowed but it wasn't")
	})
}

func TestWatch(t *testing.T) {
	RegisterTestingT(t)
	m, h := setUpMonitorAndMocks()
	m.SetPollInterval(10 * time.Minute)
	defer h.cancel()
	go func() {
		_ = m.MonitorForever(h.ctx)
	}()
	Eventually(h.HasActiveWatch).Should(BeTrue())

	// Add slight delay to make sure the routine is running.
	time.Sleep(50 * time.Millisecond)
	Expect(m.GetLicenseStatus()).To(Equal(lclient.NoLicenseLoaded))

	h.SetLicense("good", h.Now().Add(30*time.Minute))
	time.Sleep(50 * time.Millisecond)
	Expect(m.GetLicenseStatus()).To(Equal(lclient.Valid))

	h.SetLicense("expired", h.Now().Add(-25*time.Hour))
	time.Sleep(50 * time.Millisecond)
	Expect(m.GetLicenseStatus()).To(Equal(lclient.Expired))

	h.SetLicense("in-grace", h.Now().Add(-1*time.Minute))
	time.Sleep(50 * time.Millisecond)
	Expect(m.GetLicenseStatus()).To(Equal(lclient.InGracePeriod))
}

func TestChanClosed(t *testing.T) {
	RegisterTestingT(t)
	m, h := setUpMonitorAndMocks()
	m.SetPollInterval(10 * time.Minute)
	defer h.cancel()
	go func() {
		_ = m.MonitorForever(h.ctx)
	}()
	Eventually(h.HasActiveWatch).Should(BeTrue())
	Expect(h.WatcherCreationCount()).To(Equal(1))

	h.SetLicense("expired", h.Now().Add(-25*time.Hour))
	Eventually(m.GetLicenseStatus).Should(Equal(lclient.Expired))

	h.CloseWatchChan()
	Eventually(h.GetNumTimers).Should(Equal(2))
	h.AdvanceTime(3 * time.Second) // trip the fast poller
	Eventually(h.WatcherCreationCount).Should(Equal(2))
	Eventually(h.HasActiveWatch).Should(BeTrue())
	h.SetLicense("good", h.Now().Add(30*time.Minute))
	Eventually(m.GetLicenseStatus).Should(Equal(lclient.Valid))
	Expect(h.StopCount()).To(Equal(0))
}

func TestChanError(t *testing.T) {
	RegisterTestingT(t)
	m, h := setUpMonitorAndMocks()
	m.SetPollInterval(10 * time.Minute)
	defer h.cancel()
	go func() {
		_ = m.MonitorForever(h.ctx)
	}()
	Eventually(h.HasActiveWatch).Should(BeTrue())
	Expect(h.WatcherCreationCount()).To(Equal(1))

	h.SetLicense("expired", h.Now().Add(-25*time.Hour))
	Eventually(m.GetLicenseStatus).Should(Equal(lclient.Expired))

	h.SendError()
	Eventually(h.GetNumTimers).Should(Equal(2))
	h.AdvanceTime(3 * time.Second) // trip the fast poller
	Eventually(h.WatcherCreationCount).Should(Equal(2))
	Eventually(h.HasActiveWatch).Should(BeTrue())
	h.SetLicense("good", h.Now().Add(30*time.Minute))
	Eventually(m.GetLicenseStatus).Should(Equal(lclient.Valid))
	Expect(h.StopCount()).To(Equal(1))
}

func setUpMonitorAndMocks() (*licenseMonitor, *harness) {
	mockBapiClient := &mockBapiClient{}
	m := New(mockBapiClient).(*licenseMonitor)
	mockTime := &mockTime{
		now: time.Now(), // Start the time epoch now because we can't easily mock the license logic itself.
	}
	m.now = mockTime.Now
	m.newTimer = mockTime.NewTimer
	m.newJitteredTicker = mockTime.NewJitteredTicker
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	h := &harness{
		ctx:             ctx,
		cancel:          cancel,
		mockBapiClient:  mockBapiClient,
		mockTime:        mockTime,
		allowedFeatures: []string{"allowed"},
	}
	m.decodeLicense = h.decodeMockLicense
	m.SetFeaturesChangedCallback(h.OnFeaturesChanged)
	m.SetStatusChangedCallback(h.OnLicenseStateChanged)
	m.PollInterval = 10 * time.Second
	return m, h
}

type harness struct {
	ctx    context.Context
	cancel context.CancelFunc

	*mockBapiClient
	*mockTime

	allowedFeatures []string

	lock                    sync.Mutex
	OnFeaturesChangedCalled bool
	SignalledLicenseStatus  lclient.LicenseStatus
}

type mockBapiClient struct {
	lock sync.Mutex

	license      string
	licenseTime  time.Time
	watchChan    chan lapi.WatchEvent
	terminated   bool
	watchActive  bool
	watcherCount int
	stopCount    int
}

func (m *mockBapiClient) Stop() {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.terminated = true
	m.stopCount++
}

func (m *mockBapiClient) ResultChan() <-chan lapi.WatchEvent {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.watchActive = true
	return m.watchChan
}

func (m *mockBapiClient) HasTerminated() bool {
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.terminated
}

func (m *mockBapiClient) SetLicense(l string, licenseTime time.Time) {
	log.WithField("license", l).Info("Set license to")
	m.lock.Lock()

	m.license = l
	m.licenseTime = licenseTime

	event := lapi.WatchEvent{
		New: &model.KVPair{Value: &v3.LicenseKey{Spec: v3.LicenseKeySpec{Token: m.license}}},
	}

	c := m.watchChan
	if c == nil {
		m.lock.Unlock()
		panic("no active watch")
	}

	m.lock.Unlock()
	select {
	case c <- event:
	case <-time.After(time.Second):
		panic("timed out trying to send license update event")
	}
}

func (m *mockBapiClient) SendError() {
	m.lock.Lock()

	event := lapi.WatchEvent{
		Error: errors.New("bang!"),
	}

	c := m.watchChan
	if c == nil {
		m.lock.Unlock()
		panic("no active watch")
	}

	m.lock.Unlock()
	select {
	case c <- event:
	case <-time.After(time.Second):
		panic("timed out trying to send error event")
	}
}

func (m *mockBapiClient) Watch(ctx context.Context, list model.ListInterface, opts lapi.WatchOptions) (lapi.WatchInterface, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.watcherCount++
	m.watchChan = make(chan lapi.WatchEvent)
	m.terminated = false

	return m, nil
}

func (m *mockBapiClient) WatcherCreationCount() int {
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.watcherCount
}

func (m *mockBapiClient) StopCount() int {
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.stopCount
}

func (m *mockBapiClient) HasActiveWatch() bool {
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.watchActive
}

func (m *mockBapiClient) CloseWatchChan() {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.watchActive = false
	close(m.watchChan)
}

func (m *mockBapiClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	return &model.KVPair{Value: &v3.LicenseKey{Spec: v3.LicenseKeySpec{Token: m.license}}}, nil
}

func (h *harness) OnFeaturesChanged() {
	h.lock.Lock()
	defer h.lock.Unlock()
	h.OnFeaturesChangedCalled = true
}

func (h *harness) OnLicenseStateChanged(newLicenseStatus lclient.LicenseStatus) {
	h.lock.Lock()
	defer h.lock.Unlock()
	h.SignalledLicenseStatus = newLicenseStatus
}

func (h *harness) GetSignalledLicenseStatus() lclient.LicenseStatus {
	h.lock.Lock()
	defer h.lock.Unlock()
	return h.SignalledLicenseStatus
}

func (h *harness) decodeMockLicense(lic v3.LicenseKey) (lclient.LicenseClaims, error) {
	log.WithField("raw", lic).Debug("(Mock) decoding license")

	return lclient.LicenseClaims{
		Features: h.allowedFeatures,
		Claims: jwt.Claims{
			Expiry: jwt.NewNumericDate(h.licenseTime),
		},
		GracePeriod: 1,
	}, nil
}

type mockTime struct {
	lock       sync.Mutex
	now        time.Time
	timerQueue []*queueEntry
}

type queueEntry struct {
	PopTime  time.Time
	Timer    *time.Timer
	Ticker   *jitter.Ticker
	Duration time.Duration
	Stopped  chan struct{}
	C        chan time.Time
	Info     string
}

func (q *queueEntry) Stop() bool {
	close(q.Stopped)
	return false
}

func (q *queueEntry) Chan() <-chan time.Time {
	return q.C
}

func (t *mockTime) Now() time.Time {
	t.lock.Lock()
	defer t.lock.Unlock()
	return t.now
}

func (t *mockTime) NewTimer(d time.Duration) timer {
	_, file, line, ok := runtime.Caller(1)
	callerInfo := "<unknown>"
	if ok {
		callerInfo = fmt.Sprintf("%s:%d", file, line)
	}

	t.lock.Lock()
	defer t.lock.Unlock()
	c := make(chan time.Time, 1)
	timer := &time.Timer{C: c}
	popTime := t.now.Add(d)
	queueEntry := queueEntry{
		PopTime: popTime,
		Timer:   timer,
		C:       c,
		Stopped: make(chan struct{}),
		Info:    fmt.Sprintf("Timer: %v from %s", popTime, callerInfo),
	}
	t.timerQueue = append(t.timerQueue, &queueEntry)
	return &queueEntry
}

func (t *mockTime) NewJitteredTicker(d time.Duration, jit time.Duration) *jitter.Ticker {
	_, file, line, ok := runtime.Caller(1)
	callerInfo := "<unknown>"
	if ok {
		callerInfo = fmt.Sprintf("%s:%d", file, line)
	}

	t.lock.Lock()
	defer t.lock.Unlock()

	c := make(chan time.Time, 1)
	timer := &jitter.Ticker{C: c}
	queueEntry := queueEntry{
		PopTime:  t.now.Add(d),
		Ticker:   timer,
		Duration: d,
		C:        c,
		Stopped:  make(chan struct{}),
		Info:     fmt.Sprintf("Ticker: every %v from %s", d, callerInfo),
	}
	t.timerQueue = append(t.timerQueue, &queueEntry)
	return timer
}

func (t *mockTime) AdvanceTime(d time.Duration) int {
	newTime := t.now.Add(d)
	log.Infof("MOCK: Advancing by %v time to %v", d, newTime)
	numPops := 0

	sanity := 100000
	for {
		sanity--
		if sanity == 0 {
			panic("Popped too many times while advancing time")
		}
		t.lock.Lock()
		if len(t.timerQueue) == 0 {
			// No timers left...
			t.lock.Unlock()
			break
		}
		t.sortQueue()
		t.discardStoppedTimers()

		firstTimer := t.timerQueue[0]
		if firstTimer.PopTime.After(newTime) {
			// Timer is in the future so there's nothing to do.
			t.lock.Unlock()
			break
		}
		t.now = firstTimer.PopTime
		t.timerQueue = t.timerQueue[1:]
		t.lock.Unlock()

		// Can't hold the lock while we pop the timer or we might deadlock with the code under test scheduling a new
		// one.
		select {
		case firstTimer.C <- firstTimer.PopTime:
			log.Debugf("Popped: %s", firstTimer.Info)
			numPops++
		case <-firstTimer.Stopped:
			log.Debugf("Stopped: %s", firstTimer.Info)
			continue
		default:
			// Needed to support blocked tickers.
		}

		if firstTimer.Ticker != nil {
			// This is a ticker, reschedule it.
			firstTimer.PopTime = firstTimer.PopTime.Add(firstTimer.Duration)
			t.lock.Lock()
			t.timerQueue = append(t.timerQueue, firstTimer)
			t.lock.Unlock()
		}
	}

	t.now = newTime
	return numPops
}

func (t *mockTime) sortQueue() {
	sort.Slice(t.timerQueue, func(i, j int) bool {
		return t.timerQueue[i].PopTime.Before(t.timerQueue[j].PopTime)
	})
}

func (t *mockTime) discardStoppedTimers() {
	newTimers := t.timerQueue[:0]
	for _, tmr := range t.timerQueue {
		select {
		case <-tmr.Stopped:
			log.Debugf("Stopped: %s", tmr.Info)
			continue
		default:
		}
		newTimers = append(newTimers, tmr)
	}
	t.timerQueue = newTimers
}

func (t *mockTime) GetNumTimers() int {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.discardStoppedTimers()
	return len(t.timerQueue)
}
