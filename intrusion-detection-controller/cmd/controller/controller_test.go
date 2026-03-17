// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package main

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

// mockLicenseChecker returns a configurable license status.
type mockLicenseChecker struct {
	mu         sync.Mutex
	hasFeature bool
}

func (m *mockLicenseChecker) GetFeatureStatus(_ string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hasFeature
}

func (m *mockLicenseChecker) setFeature(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hasFeature = v
}

// mockController tracks Run/Close calls for test assertions.
type mockController struct {
	runCount atomic.Int32
	running  atomic.Bool
	closed   atomic.Bool
}

func newMockController() *mockController {
	return &mockController{}
}

func (m *mockController) Run(_ context.Context) {
	m.runCount.Add(1)
	m.running.Store(true)
}

func (m *mockController) Close() {
	m.closed.Store(true)
	m.running.Store(false)
}

// TestLicenseLoop_StartsControllersOnLicense verifies that controllers are
// started when a license is present, and that shutdown closes them.
func TestLicenseLoop_StartsControllersOnLicense(t *testing.T) {
	g := NewGomegaWithT(t)

	lc := &mockLicenseChecker{hasFeature: true}
	licenseChangedChan := make(chan struct{}, 1)
	shutdownChan := make(chan struct{})

	c1 := newMockController()
	c2 := newMockController()

	done := make(chan struct{})
	go func() {
		licenseLoop(
			context.Background(),
			lc,
			"ThreatDefense",
			licenseChangedChan,
			shutdownChan,
			[]runnableCloser{c1, c2},
		)
		close(done)
	}()

	// Wait for controllers to be started.
	g.Eventually(func() bool { return c1.running.Load() }, 5*time.Second, 10*time.Millisecond).Should(BeTrue())
	g.Eventually(func() bool { return c2.running.Load() }, 5*time.Second, 10*time.Millisecond).Should(BeTrue())

	// Shutdown.
	close(shutdownChan)
	g.Eventually(done, 5*time.Second, 10*time.Millisecond).Should(BeClosed())

	// Controllers should have been closed on shutdown.
	g.Expect(c1.closed.Load()).Should(BeTrue())
	g.Expect(c2.closed.Load()).Should(BeTrue())
}

// TestLicenseLoop_ControllersKeepRunningOnLicenseExpiry is the key
// regression test: when the license expires after controllers have started,
// they must NOT be stopped. The old code had an "else if !hasLicense &&
// runningControllers" branch that would call Close() on all controllers,
// permanently breaking health checks.
func TestLicenseLoop_ControllersKeepRunningOnLicenseExpiry(t *testing.T) {
	g := NewGomegaWithT(t)

	lc := &mockLicenseChecker{hasFeature: true}
	licenseChangedChan := make(chan struct{}, 1)
	shutdownChan := make(chan struct{})

	c1 := newMockController()

	done := make(chan struct{})
	go func() {
		licenseLoop(
			context.Background(),
			lc,
			"ThreatDefense",
			licenseChangedChan,
			shutdownChan,
			[]runnableCloser{c1},
		)
		close(done)
	}()

	// Wait for controller to start.
	g.Eventually(func() bool { return c1.running.Load() }, 5*time.Second, 10*time.Millisecond).Should(BeTrue())

	// Expire the license and notify.
	lc.setFeature(false)
	licenseChangedChan <- struct{}{}

	// Give the loop time to process the license change.
	time.Sleep(100 * time.Millisecond)

	// Controller must still be running — NOT closed.
	g.Expect(c1.running.Load()).Should(BeTrue(), "controller should still be running after license expiry")
	g.Expect(c1.closed.Load()).Should(BeFalse(), "controller should not be closed on license expiry")

	// Now shutdown — this is the only time Close() should be called.
	close(shutdownChan)
	g.Eventually(done, 5*time.Second, 10*time.Millisecond).Should(BeClosed())
	g.Expect(c1.closed.Load()).Should(BeTrue())
}

// TestLicenseLoop_NoLicenseNoStart verifies that controllers are NOT started
// if no license is ever granted, and that shutdown does not call Close().
func TestLicenseLoop_NoLicenseNoStart(t *testing.T) {
	g := NewGomegaWithT(t)

	lc := &mockLicenseChecker{hasFeature: false}
	licenseChangedChan := make(chan struct{}, 1)
	shutdownChan := make(chan struct{})

	c1 := newMockController()

	done := make(chan struct{})
	go func() {
		licenseLoop(
			context.Background(),
			lc,
			"ThreatDefense",
			licenseChangedChan,
			shutdownChan,
			[]runnableCloser{c1},
		)
		close(done)
	}()

	// Send a license change (still no license) and then shutdown.
	licenseChangedChan <- struct{}{}
	time.Sleep(50 * time.Millisecond)
	close(shutdownChan)

	g.Eventually(done, 5*time.Second, 10*time.Millisecond).Should(BeClosed())

	// Controller should never have been Run or Closed.
	g.Expect(c1.running.Load()).Should(BeFalse())
	g.Expect(c1.closed.Load()).Should(BeFalse())
}

// TestLicenseLoop_LateArrivalLicense verifies that controllers start when
// the license arrives after the loop has already been waiting.
func TestLicenseLoop_LateArrivalLicense(t *testing.T) {
	g := NewGomegaWithT(t)

	lc := &mockLicenseChecker{hasFeature: false}
	licenseChangedChan := make(chan struct{}, 1)
	shutdownChan := make(chan struct{})

	c1 := newMockController()

	done := make(chan struct{})
	go func() {
		licenseLoop(
			context.Background(),
			lc,
			"ThreatDefense",
			licenseChangedChan,
			shutdownChan,
			[]runnableCloser{c1},
		)
		close(done)
	}()

	// No license yet — controller should not be running.
	time.Sleep(50 * time.Millisecond)
	g.Expect(c1.running.Load()).Should(BeFalse())

	// License arrives.
	lc.setFeature(true)
	licenseChangedChan <- struct{}{}

	// Controller should start.
	g.Eventually(func() bool { return c1.running.Load() }, 5*time.Second, 10*time.Millisecond).Should(BeTrue())

	close(shutdownChan)
	g.Eventually(done, 5*time.Second, 10*time.Millisecond).Should(BeClosed())
}

// TestLicenseLoop_ControllersStartedOnlyOnce verifies that even with
// multiple license-changed signals, Run() is only called once.
func TestLicenseLoop_ControllersStartedOnlyOnce(t *testing.T) {
	g := NewGomegaWithT(t)

	lc := &mockLicenseChecker{hasFeature: true}
	licenseChangedChan := make(chan struct{}, 5)
	shutdownChan := make(chan struct{})

	c1 := newMockController()

	done := make(chan struct{})
	go func() {
		licenseLoop(
			context.Background(),
			lc,
			"ThreatDefense",
			licenseChangedChan,
			shutdownChan,
			[]runnableCloser{c1},
		)
		close(done)
	}()

	// Wait for initial start.
	g.Eventually(func() bool { return c1.running.Load() }, 5*time.Second, 10*time.Millisecond).Should(BeTrue())

	// Send several license-changed signals.
	for range 5 {
		licenseChangedChan <- struct{}{}
	}
	time.Sleep(100 * time.Millisecond)

	close(shutdownChan)
	g.Eventually(done, 5*time.Second, 10*time.Millisecond).Should(BeClosed())

	g.Expect(c1.runCount.Load()).Should(Equal(int32(1)), "Run() should only be called once")
}
