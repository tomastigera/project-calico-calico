// Copyright (c) 2025 Tigera, Inc. All rights reserved

package httpprobe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
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

func (m *mockHealthAgg) NumReportCalls() int {
	return int(atomic.LoadInt32(&m.reportCalls))
}

func (m *mockHealthAgg) ReportedNames() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.reportedNames)
}

func (m *mockHealthAgg) ReportedSummaries() []*health.HealthReport {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.reportedSummaries)
}

func TestStartBackgroundHTTPProbe_URLValidation(t *testing.T) {
	ctx := t.Context()
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
		reqCount       int32
		activatedConns = make(map[string]struct{})
		closedConns    = make(map[string]struct{})
		mu             sync.Mutex
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
			activatedConns[addr] = struct{}{}
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
	const target = 4
	deadline := time.Now().Add(3 * time.Second)
	for atomic.LoadInt32(&reqCount) < target && m.NumReportCalls() < target {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d requests/reports, saw %d/%d", target, atomic.LoadInt32(&reqCount), m.NumReportCalls())
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Stop any further reports from starting.
	cancel()

	// Make sure all connections are closed.
	deadline = time.Now().Add(2 * time.Second)
	var closedN, activeN int
	for time.Now().Before(deadline) {
		mu.Lock()
		activeN = len(activatedConns)
		closedN = len(closedConns)
		mu.Unlock()
		if activeN == target && closedN == target {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if activeN != target || closedN != target {
		t.Fatalf("after wait, expected %d active and closed connections, got %d active and %d closed", target, activeN, closedN)
	}

	for i, name := range m.ReportedNames() {
		if name != HealthName {
			t.Fatalf("report %d had unexpected name %q", i, name)
		}
	}
	for i, r := range m.ReportedSummaries() {
		if !r.Ready {
			t.Fatalf("report %d should be Ready=true, got %+v", i, r)
		}
	}
}
