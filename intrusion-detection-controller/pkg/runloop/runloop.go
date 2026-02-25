// Copyright 2019 Tigera Inc. All rights reserved.

package runloop

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"
)

// RunLoop periodically executes f
func RunLoop(ctx context.Context, f func(), period time.Duration) error {
	// The channel is closed within RunLoop
	return runLoop(ctx, func() {}, f, period, make(chan struct{}), func() {}, 0)
}

func RunLoopRecvChannel(ctx context.Context, f func(any), c any) error {
	ch := reflect.ValueOf(c)
	for {
		chosen, v, ok := reflect.Select([]reflect.SelectCase{
			{
				Dir:  reflect.SelectRecv,
				Chan: reflect.ValueOf(ctx.Done()),
			},
			{
				Dir:  reflect.SelectRecv,
				Chan: ch,
			},
		})
		switch chosen {
		case 0:
			return ctx.Err()
		case 1:
			if ok {
				f(v.Interface())
			} else {
				return nil
			}
		}
	}
}

// RunFuncWithReschedule periodically executes f, or executes rescheduleFunc, sleeps for reschedulePeriod and then executes f
type RunFuncWithReschedule func(ctx context.Context, f func(), period time.Duration, rescheduleFunc func(), reschedulePeriod time.Duration) error

// RescheduleFunc triggers a reschedule event in RunFuncWithReschedule
type RescheduleFunc func() error

// RunLoopWithReschedule returns a RunFuncWithReschedule and RescheduleFunc tuple. It does not execute a run loop.
func RunLoopWithReschedule() (RunFuncWithReschedule, RescheduleFunc) {
	// Closed within runLoop
	ch := make(chan struct{})
	var started bool

	initFunc := func() {
		started = true
	}
	runFunc := func(ctx context.Context, f func(), period time.Duration, rescheduleFunc func(), reschedulePeriod time.Duration) error {
		return runLoop(ctx, initFunc, f, period, ch, rescheduleFunc, reschedulePeriod)
	}
	rescheduleFunc := func() (err error) {
		if !started {
			err = errors.New("RunFunc has not yet started")
			return
		}
		// runLoop closes the channel when it exits. When we write to it
		// below, this will panic, which we reinterpret as a simple error.
		defer func() {
			if r := recover(); r != nil {
				err = errors.New("RunFunc has terminated")
			}
		}()
		ch <- struct{}{}
		return
	}

	return runFunc, rescheduleFunc
}

func runLoop(ctx context.Context, initFunc func(), f func(), period time.Duration, rescheduleCh chan struct{}, rescheduleFunc func(), reschedulePeriod time.Duration) error {
	t := time.NewTicker(period)
	defer func() {
		t.Stop()
	}()

	// We close the rescheduleCh here on the receiver side so that the RescheduleFunc is able to know that the
	// RunLoop has terminated and that the job could not be successfully rescheduled. This is not idiomatic Go and
	// there may be a better way to implement this communication method.
	defer close(rescheduleCh)

	var done bool
	cond := sync.NewCond(&sync.Mutex{})
	// This ensures that the f() wait loop always terminates.
	defer func() {
		done = true
		cond.L.Lock()
		cond.Broadcast()
		cond.L.Unlock()
	}()

	initFunc()
	go func() {
		for {
			if done {
				return
			}
			f()
			cond.L.Lock()
			cond.Wait()
			cond.L.Unlock()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-rescheduleCh:
			rescheduleFunc()
			sleep := time.After(reschedulePeriod)
		sleeping:
			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-rescheduleCh:
					// nothing
				case <-sleep:
					t.Stop()
					t = time.NewTicker(period)
					break sleeping
					// continue
				}
			}
		case <-t.C:
			// continue
		}
		cond.L.Lock()
		cond.Signal()
		cond.L.Unlock()
	}
}
