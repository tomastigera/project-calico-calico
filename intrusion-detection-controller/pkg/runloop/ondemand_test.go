// Copyright 2019 Tigera Inc. All rights reserved.

package runloop

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

func TestOnDemand(t *testing.T) {
	g := NewGomegaWithT(t)

	var done atomic.Bool
	var lock sync.Mutex
	wake := sync.NewCond(&lock)

	ctx, cancel := context.WithCancel(context.TODO())
	defer func() {
		cancel()
		lock.Lock()
		wake.Broadcast()
		lock.Unlock()
		g.Eventually(func() bool { return done.Load() }, 10*time.Second, 1*time.Second).Should(BeTrue(), "run terminates on context cancellation")
	}()

	run, enqueue := OnDemand()

	var last atomic.Int64
	var wg sync.WaitGroup
	go func() {
		run(ctx, func(ctx context.Context, i any) {
			v := int64(i.(int))
			last.Store(v)
			g.Expect(v).ShouldNot(Equal(int64(2)))
			lock.Lock()
			wg.Done()
			wake.Wait()
			lock.Unlock()
		})
		done.Store(true)
	}()

	enqueue(1)
	wg.Add(1)
	g.Eventually(func() int64 { return last.Load() }, 10*time.Second, 1*time.Second).Should(Equal(int64(1)))

	// wait for wake.Wait() in run() to be called before adding items to enqueue and sending wake.Signal()
	wg.Wait()

	lock.Lock()
	enqueue(2)
	enqueue(3)
	wg.Add(1)
	wake.Signal()
	lock.Unlock()

	g.Eventually(func() int64 { return last.Load() }, 10*time.Second, 1*time.Second).Should(Equal(int64(3)))
	// wait for wake.Wait() in run() to be called before sending wake.Broadcast() in defer()
	wg.Wait()
}
