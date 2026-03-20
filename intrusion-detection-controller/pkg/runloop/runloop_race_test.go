// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package runloop

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

// TestRunLoopCancelDuringFunc verifies that cancelling the context while
// the user function f() is executing does not race with the done flag.
// This is a regression test for the data race on the `done` variable
// that was read in the goroutine without holding the cond lock.
func TestRunLoopCancelDuringFunc(t *testing.T) {
	g := NewGomegaWithT(t)

	ctx, cancel := context.WithCancel(context.Background())

	var calls atomic.Int32
	// Block f() until we cancel the context to maximise the chance of
	// exercising the done-check path.
	unblock := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = RunLoop(ctx, func() {
			calls.Add(1)
			<-unblock
		}, time.Hour) // long period — we don't want the ticker to drive iterations
	}()

	// Wait for f() to be called at least once.
	g.Eventually(func() int32 { return calls.Load() }, 5*time.Second, 10*time.Millisecond).Should(BeNumerically(">=", 1))

	// Cancel context while f() is blocked, then unblock.
	cancel()
	close(unblock)

	// RunLoop should return promptly.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	g.Eventually(done, 5*time.Second, 10*time.Millisecond).Should(BeClosed())
}

// TestRunLoopWithRescheduleStartedAtomic verifies that RescheduleFunc
// correctly returns an error before RunLoop starts, and succeeds after.
// This is a regression test for the data race on the `started` variable.
func TestRunLoopWithRescheduleStartedAtomic(t *testing.T) {
	g := NewGomegaWithT(t)

	run, reschedule := RunLoopWithReschedule()

	// Before RunLoop starts, reschedule should return an error.
	err := reschedule()
	g.Expect(err).Should(HaveOccurred())
	g.Expect(err.Error()).Should(ContainSubstring("not yet started"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = run(ctx, func() {
			select {
			case <-started:
			default:
				close(started)
			}
			// Block until signalled so we don't spin.
			<-ctx.Done()
		}, time.Hour, func() {}, time.Millisecond)
	}()

	// Wait for the loop to start.
	g.Eventually(started, 5*time.Second, 10*time.Millisecond).Should(BeClosed())

	// After RunLoop starts, reschedule should succeed.
	g.Expect(reschedule()).ShouldNot(HaveOccurred())

	cancel()
	wg.Wait()
}
