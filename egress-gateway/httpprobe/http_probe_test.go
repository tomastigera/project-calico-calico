// Copyright (c) 2025 Tigera, Inc. All rights reserved

package httpprobe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectcalico/calico/libcalico-go/lib/health"
)

// mockHealthAgg is a minimal mock of the health aggregator used by tests.
type mockHealthAgg struct {
	mu                sync.Mutex
	regName           string
	regReports        *health.HealthReport
	regTimeout        time.Duration
	reportCalls       int32
	reportedNames     []string
	reportedSummaries []*health.HealthReport
}

func (m *mockHealthAgg) RegisterReporter(name string, reports *health.HealthReport, timeout time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.regName = name
	// store a copy to avoid mutation issues
	repCopy := *reports
	m.regReports = &repCopy
	m.regTimeout = timeout
}

func (m *mockHealthAgg) Report(name string, report *health.HealthReport) {
	m.mu.Lock()
	defer m.mu.Unlock()
	atomic.AddInt32(&m.reportCalls, 1)
	m.reportedNames = append(m.reportedNames, name)
	reportCopy := *report
	m.reportedSummaries = append(m.reportedSummaries, &reportCopy)
}

func TestStartBackgroundHTTPProbe_URLValidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := &mockHealthAgg{}

	// invalid URL with bad percent-escape should cause parse error
	urls := []string{"http://%zz"}
	err := StartBackgroundHTTPProbe(ctx, urls, 50*time.Millisecond, 200*time.Millisecond, m)
	if err == nil {
		t.Fatalf("expected error for invalid URL, got nil")
	}
	// RegisterReporter is invoked before validation; ensure it was called.
	if m.regName != HealthName {
		t.Fatalf("expected RegisterReporter with name %q, got %q", HealthName, m.regName)
	}
	if m.regReports == nil || !m.regReports.Ready {
		t.Fatalf("expected RegisterReporter reports Ready: true, got %+v", m.regReports)
	}
}

func TestLoopDoingProbes_ReportsAndClosesConnections(t *testing.T) {
	// Create an HTTP server with ConnState tracking.
	var (
		reqCount    int32
		activeConns = make(map[string]struct{})
		closedConns = make(map[string]struct{})
		mu          sync.Mutex
	)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqCount, 1)
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	})

	ts := httptest.NewUnstartedServer(h)
	// Track connection lifecycle to assert no keep-alive reuse and closed after each request.
	ts.Config.ConnState = func(c net.Conn, state http.ConnState) {
		addr := c.RemoteAddr().String()
		mu.Lock()
		defer mu.Unlock()
		switch state {
		case http.StateNew:
			// seen when connection is accepted
		case http.StateActive:
			activeConns[addr] = struct{}{}
		case http.StateIdle:
			// not expected with DisableKeepAlives=true but handle for completeness
		case http.StateHijacked:
			// not used in this test
		case http.StateClosed:
			closedConns[addr] = struct{}{}
		}
	}
	ts.Start()
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := &mockHealthAgg{}

	// Start the prober with a short interval.
	interval := 30 * time.Millisecond
	timeout := 200 * time.Millisecond
	if err := StartBackgroundHTTPProbe(ctx, []string{ts.URL}, interval, timeout, m); err != nil {
		t.Fatalf("failed to start probe: %v", err)
	}

	// Wait for a few successful probes.
	target := int32(4)
	deadline := time.Now().Add(3 * time.Second)
	for atomic.LoadInt32(&reqCount) < target {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d requests, saw %d", target, atomic.LoadInt32(&reqCount))
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Cancel and allow goroutine to wind down.
	cancel()
	time.Sleep(50 * time.Millisecond)

	// Validate we reported readiness for each successful request.
	reports := atomic.LoadInt32(&m.reportCalls)
	if reports < target {
		t.Fatalf("expected at least %d reports, got %d", target, reports)
	}
	for i, name := range m.reportedNames {
		if name != HealthName {
			t.Fatalf("report %d had unexpected name %q", i, name)
		}
	}
	for i, r := range m.reportedSummaries {
		if !r.Ready {
			t.Fatalf("report %d should be Ready=true, got %+v", i, r)
		}
	}

	// Validate that we didn't reuse connections and that each became closed.
	mu.Lock()
	activeN := len(activeConns)
	mu.Unlock()
	if activeN == 0 {
		t.Fatalf("expected some active connections to have been observed")
	}
	if activeN != int(target) {
		t.Fatalf("expected %d unique connections (one per request), saw %d", target, activeN)
	}
	// Allow time for all connections to transition to Closed, then re-check.
	deadline = time.Now().Add(2 * time.Second)
	var closedN int
	for {
		mu.Lock()
		closedN = len(closedConns)
		mu.Unlock()
		if closedN >= activeN {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if closedN != activeN {
		t.Fatalf("expected %d closed connections, saw %d", activeN, closedN)
	}
}
