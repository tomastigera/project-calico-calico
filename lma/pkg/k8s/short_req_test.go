// Copyright (c) 2025 Tigera, Inc. All rights reserved

package k8s

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestShortRequestTimeoutRoundTripperWatch(t *testing.T) {
	start := time.Now()
	timeout, rtErr := roundTripURLGetTimeout(t, "http://example.com/apis/projectcalico.org/v3/policyrecommendationscopes?allowWatchBookmarks=true&resourceVersion=31813&watch=true")
	if timeout != "" {
		t.Errorf("Expected timeout to be empty, got %s", timeout)
	}
	if rtErr != nil {
		t.Errorf("Unexpected error: %v", rtErr)
	}
	if time.Since(start) > 900*time.Millisecond {
		t.Errorf("Expected timeout to be >200ms, got %v", time.Since(start))
	}
}

func TestShortRequestTimeoutRoundTripperList(t *testing.T) {
	start := time.Now()
	timeout, rtErr := roundTripURLGetTimeout(t, "http://example.com/apis/projectcalico.org/v3/policyrecommendationscopes")
	if timeout != "100ms" {
		t.Errorf("Expected timeout to be 100ms, got %s", timeout)
	}
	if !errors.Is(rtErr, context.DeadlineExceeded) {
		t.Errorf("Expected context deadline error, got %v", rtErr)
	}
	if time.Since(start) < 90*time.Millisecond {
		t.Errorf("Expected timeout to be ~100ms, got %v", time.Since(start))
	}
	if time.Since(start) > 150*time.Millisecond {
		t.Errorf("Expected timeout to be ~100ms, got %v", time.Since(start))
	}
}

func roundTripURLGetTimeout(t *testing.T, url string) (string, error) {
	defer func(oldTimeout time.Duration) {
		ShortRequestTimeout = oldTimeout
	}(ShortRequestTimeout)
	ShortRequestTimeout = 100 * time.Millisecond
	mockRT := &mockRoundTripper{
		Response: &http.Response{},
	}
	wrapped := wrapWithShortRequestTimeoutRoundTripper(mockRT)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	reqCopy := req.Clone(req.Context())

	_, rtErr := wrapped.RoundTrip(req)
	if req.URL.String() != reqCopy.URL.String() {
		t.Errorf("RoundTripper modified URL in-place: got %#v, expected %#v", req.URL.String(), reqCopy.URL.String())
	}

	timeout := mockRT.SeenRequest.URL.Query().Get("timeout")
	return timeout, rtErr
}

type mockRoundTripper struct {
	SeenRequest *http.Request
	Response    *http.Response
	Err         error
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	m.SeenRequest = req
	select {
	case <-time.After(200 * time.Millisecond):
		return m.Response, m.Err
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
}
