// Copyright (c) 2018 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package statscache_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/projectcalico/calico/app-policy/statscache"
)

var (
	tuple1 = statscache.Tuple{
		SrcIp:    "1.2.3.4",
		DstIp:    "2.3.4.5",
		SrcPort:  10,
		DstPort:  10020,
		Protocol: "TCP",
	}

	tuple2 = statscache.Tuple{
		SrcIp:    "10.20.30.40",
		DstIp:    "20.30.40.50",
		SrcPort:  100,
		DstPort:  20020,
		Protocol: "TCP",
	}
)

func TestFlushCallback(t *testing.T) {
	var actual map[statscache.Tuple]statscache.Values
	interval := 50 * time.Millisecond
	mt := newMockTicker().(*mockTickerImpl)
	sc := statscache.NewWithFlushInterval(interval, statscache.WithTicker(mt))
	cb := func(callbackValue map[statscache.Tuple]statscache.Values) {
		actual = callbackValue
	}
	sc.RegisterFlushCallback(cb)
	sc.Add(statscache.DPStats{
		Tuple: tuple1,
		Values: statscache.Values{
			HTTPRequestsAllowed: 1,
			HTTPRequestsDenied:  3,
		},
	})
	sc.Flush()
	expected := map[statscache.Tuple]statscache.Values{
		tuple1: {
			HTTPRequestsAllowed: 1,
			HTTPRequestsDenied:  3,
		},
	}
	assert.Equal(t, expected, actual)
}

func TestMultipleFlushes(t *testing.T) {
	interval := 50 * time.Millisecond
	sc := statscache.NewWithFlushInterval(interval)
	var actual map[statscache.Tuple]statscache.Values
	sc.RegisterFlushCallback(func(callbackValue map[statscache.Tuple]statscache.Values) {
		actual = callbackValue
	})

	// Send in a couple of stats with the same tuple.
	sc.Add(statscache.DPStats{
		Tuple: tuple1,
		Values: statscache.Values{
			HTTPRequestsAllowed: 1,
		},
	})
	sc.Add(statscache.DPStats{
		Tuple: tuple1,
		Values: statscache.Values{
			HTTPRequestsDenied: 3,
		},
	})

	// Flush the stats and check that we get the expected aggregated stats.
	sc.Flush()
	assert.Equal(t, map[statscache.Tuple]statscache.Values{
		tuple1: {
			HTTPRequestsAllowed: 1,
			HTTPRequestsDenied:  3,
		},
	}, actual)

	// Send in more stats with different tuples.
	sc.Add(statscache.DPStats{
		Tuple: tuple1,
		Values: statscache.Values{
			HTTPRequestsAllowed: 10,
			HTTPRequestsDenied:  33,
		},
	})
	sc.Add(statscache.DPStats{
		Tuple: tuple2,
		Values: statscache.Values{
			HTTPRequestsAllowed: 15,
		},
	})

	// Flush the stats and check that we get the expected aggregated stats, again.
	sc.Flush()
	assert.Equal(t, map[statscache.Tuple]statscache.Values{
		tuple1: {
			HTTPRequestsAllowed: 10,
			HTTPRequestsDenied:  33,
		},
		tuple2: {
			HTTPRequestsAllowed: 15,
			HTTPRequestsDenied:  0,
		},
	}, actual)
}

func TestNoData(t *testing.T) {
	var (
		numCallbacks  int
		lastValueSeen = make(chan map[statscache.Tuple]statscache.Values, 1)
	)

	ctx := t.Context()

	interval := 200 * time.Millisecond
	mt := newMockTicker().(*mockTickerImpl)
	sc := statscache.NewWithFlushInterval(interval, statscache.WithTicker(mt))
	cb := func(m map[statscache.Tuple]statscache.Values) {
		numCallbacks++
		lastValueSeen <- m
	}
	sc.RegisterFlushCallback(cb)
	go sc.Start(ctx)

	// Do multiple ticks without sending in any data. We should not receive any empty
	// aggregated stats.
	mt.tick()
	assert.Empty(t, numCallbacks)

	// Send in some stats now.
	sc.Add(statscache.DPStats{
		Tuple: tuple2,
		Values: statscache.Values{
			HTTPRequestsDenied: 13,
		},
	})
	mt.tick()
	assert.Equal(t, map[statscache.Tuple]statscache.Values{
		tuple2: {
			HTTPRequestsDenied: 13,
		},
	}, <-lastValueSeen)
}

type mockTickerImpl struct {
	ch chan struct{}
}

func (t *mockTickerImpl) Start(context.Context) {}

func (t *mockTickerImpl) tick() {
	t.ch <- struct{}{}
}

func (t *mockTickerImpl) C() <-chan struct{} {
	return t.ch
}

func newMockTicker() statscache.LazyTicker {
	return &mockTickerImpl{
		ch: make(chan struct{}),
	}
}
