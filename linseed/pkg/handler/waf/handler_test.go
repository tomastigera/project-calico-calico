// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package waf

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

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

func TestWAFBulkIngestion(t *testing.T) {
	type testResult struct {
		wantErr    bool
		httpStatus int
		errorMsg   string
	}

	tests := []struct {
		name            string
		backendWAFLogs  []v1.WAFLog
		backendResponse *v1.BulkResponse
		backendError    error
		reqBody         string
		want            testResult
	}{
		// Failure to parse request and validate
		{
			name:            "malformed json",
			backendWAFLogs:  noWAFLogs,
			backendError:    nil,
			backendResponse: nil,
			reqBody:         "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON", "Status":400}`,
			},
		},

		// Ingest all waf logs
		{
			name:            "ingest waf logs",
			backendWAFLogs:  wafLogs,
			backendError:    nil,
			backendResponse: bulkResponseSuccess,
			reqBody:         testutils.MarshalBulkParams[v1.WAFLog](wafLogs),
			want:            testResult{false, 200, ""},
		},

		// Fails to ingest all waf logs
		{
			name:            "fail to ingest all waf logs",
			backendWAFLogs:  wafLogs,
			backendError:    errors.New("any error"),
			backendResponse: nil,
			reqBody:         testutils.MarshalBulkParams[v1.WAFLog](wafLogs),
			want:            testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},

		// Ingest some waf logs
		{
			name:            "ingest some waf logs",
			backendWAFLogs:  wafLogs,
			backendError:    nil,
			backendResponse: bulkResponsePartialSuccess,
			reqBody:         testutils.MarshalBulkParams[v1.WAFLog](wafLogs),
			want:            testResult{false, 200, ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := bulkWAFLogs(tt.backendResponse, tt.backendError)

			rec := httptest.NewRecorder()
			req, err := http.NewRequest("POST", dummyURL, bytes.NewBufferString(tt.reqBody))
			req.Header.Set("Content-Type", "application/x-ndjson")
			require.NoError(t, err)

			b.logs.Create().ServeHTTP(rec, req)

			bodyBytes, err := io.ReadAll(rec.Body)
			require.NoError(t, err)

			var wantBody string
			if tt.want.wantErr {
				wantBody = tt.want.errorMsg
			} else {
				wantBody = testutils.Marshal(t, tt.backendResponse)
			}
			assert.Equal(t, tt.want.httpStatus, rec.Result().StatusCode)
			assert.JSONEq(t, wantBody, string(bodyBytes))
		})
	}
}

func bulkWAFLogs(response *v1.BulkResponse, err error) *waf {
	mockLogBackend := &api.MockWAFBackend{}
	n := New(mockLogBackend)

	// mock backend to return the required backendWAF
	mockLogBackend.On("Create", mock.Anything,
		mock.AnythingOfType("api.ClusterInfo"), mock.AnythingOfType("[]v1.WAFLog")).Return(response, err)

	return n
}

func TestWAFGetLogs(t *testing.T) {
	withinTimeRange := `{
  "time_range": {
    "from": "2021-04-19T14:25:30.169821857-07:00",
    "to": "2021-04-19T14:25:30.169827009-07:00"
  },
  "timeout": "60s"
}`
	type testResult struct {
		wantErr    bool
		httpStatus int
		errorMsg   string
	}

	tests := []struct {
		name            string
		backendWAFLogs  []v1.WAFLog
		backendResponse *v1.BulkResponse
		backendError    error
		reqBody         string
		want            testResult
	}{
		// Failure to parse request and validate
		{
			name:           "malformed json",
			backendWAFLogs: noWAFLogs,
			backendError:   nil,
			reqBody:        "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON (at position 2)", "Status":400}`,
			},
		},

		// Get all WAF logs
		{
			name:           "get all waf logs",
			backendWAFLogs: wafLogs,
			backendError:   nil,
			reqBody:        withinTimeRange,
			want:           testResult{false, 200, ""},
		},

		// Get all WAF logs
		{
			name:            "get all waf logs",
			backendWAFLogs:  wafLogs,
			backendError:    nil,
			backendResponse: bulkResponseSuccess,
			reqBody:         withinTimeRange,
			want:            testResult{false, 200, ""},
		},

		// Fails to get WAF logs
		{
			name:           "fail to ingest all waf logs",
			backendWAFLogs: wafLogs,
			backendError:   errors.New("any error"),
			reqBody:        withinTimeRange,
			want:           testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := wafGetLogs(tt.backendWAFLogs, tt.backendError)

			rec := httptest.NewRecorder()
			req, err := http.NewRequest("POST", dummyURL, bytes.NewBufferString(tt.reqBody))
			req.Header.Set("Content-Type", "application/json")
			require.NoError(t, err)

			b.logs.List().ServeHTTP(rec, req)

			bodyBytes, err := io.ReadAll(rec.Body)
			require.NoError(t, err)

			var wantBody string
			if tt.want.wantErr {
				wantBody = tt.want.errorMsg
			} else {
				wantBody = marshalResponse(t, tt.backendWAFLogs)
			}
			assert.Equal(t, tt.want.httpStatus, rec.Result().StatusCode)
			assert.JSONEq(t, wantBody, string(bodyBytes))
		})
	}
}

func wafGetLogs(response []v1.WAFLog, err error) *waf {
	mockLogBackend := &api.MockWAFBackend{}
	n := New(mockLogBackend)

	// mock backend to return the required backendWAF
	mockLogBackend.On("List", mock.Anything,
		mock.AnythingOfType("api.ClusterInfo"), mock.AnythingOfType("*v1.WAFLogParams")).Return(&v1.List[v1.WAFLog]{Items: response}, err)

	return n
}

func marshalResponse(t *testing.T, logs []v1.WAFLog) string {
	response := v1.List[v1.WAFLog]{}
	response.Items = logs
	newData, err := json.Marshal(response)
	require.NoError(t, err)
	return string(newData)
}
