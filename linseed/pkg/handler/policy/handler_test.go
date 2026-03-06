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
	"github.com/projectcalico/calico/linseed/pkg/middleware"
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
			name:    "malformed JSON returns 400",
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
			name:            "empty policies list returns 200 with empty items",
			reqBody:         `{"policies": []}`,
			backendResponse: &v1.PolicyActivityResponse{Items: []v1.PolicyActivityResult{}},
			want:            testResult{httpStatus: http.StatusOK},
		},
		{
			name: "missing policy kind returns 400",
			reqBody: `{
				"policies": [{"name": "p", "generation": 1}]
			}`,
			want: testResult{
				httpStatus: http.StatusBadRequest,
				wantErr:    true,
			},
		},
		{
			name: "missing policy name returns 400",
			reqBody: `{
				"policies": [{"kind": "NetworkPolicy", "generation": 1}]
			}`,
			want: testResult{
				httpStatus: http.StatusBadRequest,
				wantErr:    true,
			},
		},
		{
			name: "non-positive generation returns 400",
			reqBody: `{
				"policies": [{"kind": "NetworkPolicy", "name": "p", "generation": 0}]
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
			name: "request without time range returns 200",
			reqBody: `{
				"policies": [{"kind": "NetworkPolicy", "namespace": "ns", "name": "pol", "generation": 2}]
			}`,
			backendResponse: successResponse,
			want:            testResult{httpStatus: http.StatusOK},
		},
		{
			name: "multiple policies in request returns 200",
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
			req, err := http.NewRequest("POST", ReadPath, bytes.NewBufferString(tt.reqBody))
			req.Header.Set("Content-Type", "application/json")
			require.NoError(t, err)

			// Set cluster ID in request context as the middleware would.
			req = req.WithContext(middleware.WithClusterID(req.Context(), "test-cluster"))

			h.GetPolicyActivities().ServeHTTP(rec, req)

			bodyBytes, err := io.ReadAll(rec.Body)
			require.NoError(t, err)

			assert.Equal(t, tt.want.httpStatus, rec.Result().StatusCode)
			if tt.want.wantErr {
				if tt.want.errorMsg != "" {
					assert.JSONEq(t, tt.want.errorMsg, string(bodyBytes))
				}
			} else {
				// Assert against hardcoded JSON for the success case to verify wire format.
				if tt.name == "valid request with time range returns 200" {
					expectedJSON := `{
						"items": [
							{
								"policy": {
									"kind": "NetworkPolicy",
									"namespace": "my-namespace-1",
									"name": "my-network-policy-1"
								},
								"last_evaluated": "` + now.Format(time.RFC3339Nano) + `",
								"rules": [
									{
										"direction": "ingress",
										"index": "0",
										"last_evaluated": "` + now.Format(time.RFC3339Nano) + `"
									}
								]
							}
						]
					}`
					assert.JSONEq(t, expectedJSON, string(bodyBytes))
				}
			}
		})
	}
}

// policyHandlerWithMock creates a policy handler with a mock backend.
// The mock only expects GetPolicyActivities to be called when the handler will
// reach the backend (i.e. not for malformed-JSON or invalid request parameters).
func policyHandlerWithMock(t *testing.T, response *v1.PolicyActivityResponse, backendErr error) *policy {
	mockBackend := api.NewMockPolicyBackend(t)

	if response != nil || backendErr != nil {
		mockBackend.On("GetPolicyActivities",
			mock.Anything,
			mock.AnythingOfType("api.ClusterInfo"),
			mock.AnythingOfType("*v1.PolicyActivityParams"),
		).Return(response, backendErr)
	}

	return New(mockBackend)
}
