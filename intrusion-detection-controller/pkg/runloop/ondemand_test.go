// Copyright 2019 Tigera Inc. All rights reserved.

package runloop

import (
	"context"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

func TestOnDemand(t *testing.T) {
	g := NewGomegaWithT(t)

	var done bool
	var lock sync.Mutex
	wake := sync.NewCond(&lock)

	ctx, cancel := context.WithCancel(context.TODO())
	defer func() {
		cancel()
		lock.Lock()
		wake.Broadcast()
		lock.Unlock()
		g.Eventually(func() bool { return done }, 10*time.Second, 1*time.Second).Should(BeTrue(), "run terminates on context cancellation")
	}()

	run, enqueue := OnDemand()

	var last int
	var wg sync.WaitGroup
	go func() {
		run(ctx, func(ctx context.Context, i any) {
			last = i.(int)
			g.Expect(last).ShouldNot(Equal(2))
			lock.Lock()
			wg.Done()
			wake.Wait()
			lock.Unlock()
		})
		done = true
	}()

	enqueue(1)
	wg.Add(1)
	g.Eventually(func() int { return last }, 10*time.Second, 1*time.Second).Should(Equal(1))

	// wait for wake.Wait() in run() to be called before adding items to enqueue and sending wake.Signal()
	wg.Wait()

	lock.Lock()
	enqueue(2)
	enqueue(3)
	wg.Add(1)
	wake.Signal()
	lock.Unlock()

	g.Eventually(func() int { return last }, 10*time.Second, 1*time.Second).Should(Equal(3))
	// wait for wake.Wait() in run() to be called before sending wake.Broadcast() in defer()
	wg.Wait()
}
