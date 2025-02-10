// Copyright (c) 2025 Tigera, Inc. All rights reserved.
package cache

// TODO: remove this package in favour of
// https://github.com/tigera/calico-private/blob/voltron-throttling/lma/pkg/cache/loading.go once it gets merged

import (
	"sync"

	"github.com/projectcalico/calico/lma/pkg/cache"
)

// LoadingCache is a Cache that loads the value when is not found in the cache,
// ensuring that concurrent requests for the same key will wait for the first
// request to load the value.
//
// If the load fails, the same error will be returned to all requests waiting for that value to load.
type LoadingCache[Key ~string, Value any] interface {
	GetOrLoad(key Key, loader func() (Value, error)) (Value, error)
}

// loading is a generic cache that automatically loads values on cache misses.
type loading[Key ~string, Value any] struct {
	cache      cache.Cache[Key, Value]
	mutex      sync.Mutex
	inProgress map[Key]*loaderStatus[Value]
}

// NewLoadingCache wraps an expiring Cache with a function that loads the value when it is not found in the cache.
//
// Concurrent requests for the same key will wait for the first request to load the value, avoiding duplicate work.
func NewLoadingCache[Key ~string, Value any](cache cache.Cache[Key, Value]) LoadingCache[Key, Value] {
	return newLoading(cache)
}

func newLoading[Key ~string, Value any](cache cache.Cache[Key, Value]) *loading[Key, Value] {
	return &loading[Key, Value]{
		cache:      cache,
		inProgress: make(map[Key]*loaderStatus[Value]),
	}
}

func (l *loading[Key, Value]) GetOrLoad(key Key, loader func() (Value, error)) (Value, error) {
	if value, ok := l.cache.Get(key); ok {
		return value, nil
	}

	l.mutex.Lock()

	if status, fetching := l.inProgress[key]; fetching {
		l.mutex.Unlock()
		value, err := status.wait()
		return value, err
	}

	status := &loaderStatus[Value]{
		mutex: sync.Mutex{},
	}
	done := status.start()

	l.inProgress[key] = status

	// unlock while loading
	l.mutex.Unlock()
	value, err := loader()
	l.mutex.Lock()

	// set the value in the cache and remove the status while locked
	l.cache.Set(key, value)
	delete(l.inProgress, key)
	l.mutex.Unlock()

	// notify others waiting on this result
	done(value, err)

	return value, err
}

type loaderStatus[Value any] struct {
	mutex sync.Mutex
	value Value
	err   error
}

// wait for the loader function to unlock the mutex (by attempting to lock and immediately unlock it), then return the result.
func (s *loaderStatus[Value]) wait() (Value, error) {
	s.mutex.Lock()
	s.mutex.Unlock()
	return s.value, s.err
}

// start locks the status and returns a function that will store the result and unlock the status.
func (s *loaderStatus[Value]) start() func(value Value, err error) {
	s.mutex.Lock()
	return func(value Value, err error) {
		s.value = value
		s.err = err
		s.mutex.Unlock()
	}
}
