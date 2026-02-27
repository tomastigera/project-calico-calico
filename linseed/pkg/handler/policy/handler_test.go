// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package policy

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/testutils"
)

func setupTest(t *testing.T) func() {
	cancel := logutils.RedirectLogrusToTestingT(t)
	return func() {
		cancel()
	}
}

func TestGetPolicyActivities(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)

	successResponse := &v1.PolicyActivityResponse{
		Items: []v1.PolicyActivityResult{
			{
				Policy: v1.PolicyInfo{
					Kind:      "NetworkPolicy",
					Namespace: "my-namespace-1",
					Name:      "my-network-policy-1",
				},
				LastEvaluated: &now,
				Rules: []v1.PolicyActivityRuleResult{
					{Direction: "ingress", Index: "0", LastEvaluated: now},
				},
			},
		},
	}

	type testResult struct {
		httpStatus int
		wantErr    bool
		errorMsg   string
	}

	tests := []struct {
		name            string
		reqBody         string
		backendResponse *v1.PolicyActivityResponse
		backendError    error
		want            testResult
	}{
		{
			name:    "malformed json returns 400",
			reqBody: "{#}",
			want: testResult{
				httpStatus: http.StatusBadRequest,
				wantErr:    true,
				errorMsg:   `{"Msg":"Request body contains badly-formed JSON (at position 2)", "Status":400}`,
			},
		},
		{
			name: "invalid time range (to before from) returns 400",
			reqBody: `{
				"from": "2026-01-27T00:00:00Z",
				"to":   "2026-01-01T00:00:00Z",
				"policies": [{"kind": "NetworkPolicy", "namespace": "ns", "name": "pol", "generation": 1}]
			}`,
			want: testResult{
				httpStatus: http.StatusBadRequest,
				wantErr:    true,
			},
		},
		{
			name: "backend error returns 500",
			reqBody: `{
				"policies": [{"kind": "NetworkPolicy", "namespace": "ns", "name": "pol", "generation": 1}]
			}`,
			backendError: errors.New("elasticsearch unavailable"),
			want: testResult{
				httpStatus: http.StatusInternalServerError,
				wantErr:    true,
				errorMsg:   `{"Msg":"elasticsearch unavailable", "Status":500}`,
			},
		},
		{
			name: "valid request with time range returns 200",
			reqBody: `{
				"from": "2026-01-01T00:00:00Z",
				"to":   "2026-01-27T00:00:00Z",
				"policies": [
					{"kind": "NetworkPolicy", "namespace": "my-namespace-1", "name": "my-network-policy-1", "generation": 1}
				]
			}`,
			backendResponse: successResponse,
			want:            testResult{httpStatus: http.StatusOK},
		},
		{
			name:            "empty policies list returns 200",
			reqBody:         `{"policies": []}`,
			backendResponse: &v1.PolicyActivityResponse{Items: []v1.PolicyActivityResult{}},
			want:            testResult{httpStatus: http.StatusOK},
		},
		{
			name: "request without time range is valid",
			reqBody: `{
				"policies": [{"kind": "NetworkPolicy", "namespace": "ns", "name": "pol", "generation": 2}]
			}`,
			backendResponse: successResponse,
			want:            testResult{httpStatus: http.StatusOK},
		},
		{
			name: "multiple policies in request",
			reqBody: `{
				"from": "2026-01-01T00:00:00Z",
				"to":   "2026-01-27T00:00:00Z",
				"policies": [
					{"kind": "NetworkPolicy", "namespace": "my-namespace-1", "name": "my-network-policy-1", "generation": 1},
					{"kind": "NetworkPolicy", "namespace": "my-namespace-2", "name": "my-network-policy-2", "generation": 2}
				]
			}`,
			backendResponse: successResponse,
			want:            testResult{httpStatus: http.StatusOK},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			h := policyHandlerWithMock(t, tt.backendResponse, tt.backendError)

			rec := httptest.NewRecorder()
			req, err := http.NewRequest("POST", ReadPolicyActivityPath, bytes.NewBufferString(tt.reqBody))
			req.Header.Set("Content-Type", "application/json")
			require.NoError(t, err)

			h.GetPolicyActivities().ServeHTTP(rec, req)

			bodyBytes, err := io.ReadAll(rec.Body)
			require.NoError(t, err)

			assert.Equal(t, tt.want.httpStatus, rec.Result().StatusCode)
			if tt.want.wantErr {
				if tt.want.errorMsg != "" {
					assert.JSONEq(t, tt.want.errorMsg, string(bodyBytes))
				}
			} else {
				assert.JSONEq(t, testutils.Marshal(t, tt.backendResponse), string(bodyBytes))
			}
		})
	}
}

// policyHandlerWithMock creates a policy handler with a mock backend.
// The mock only expects GetPolicyActivities to be called when the handler will
// reach the backend (i.e. not for malformed-JSON or invalid time range requests).
func policyHandlerWithMock(t *testing.T, response *v1.PolicyActivityResponse, backendErr error) *policy {
	mockBackend := api.NewMockPolicyBackend(t)

	if response != nil || backendErr != nil {
		mockBackend.On("GetPolicyActivities",
			mock.Anything,
			mock.AnythingOfType("api.ClusterInfo"),
			mock.AnythingOfType("*v1.PolicyActivityRequest"),
		).Return(response, backendErr)
	}

	return New(mockBackend)
}
