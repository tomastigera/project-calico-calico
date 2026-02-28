// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package bgp

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

func TestBGPBulkIngestion(t *testing.T) {
	type testResult struct {
		wantErr    bool
		httpStatus int
		errorMsg   string
	}

	tests := []struct {
		name            string
		backendBGPLogs  []v1.BGPLog
		backendResponse *v1.BulkResponse
		backendError    error
		reqBody         string
		want            testResult
	}{
		// Failure to parse request and validate
		{
			name:            "malformed json",
			backendBGPLogs:  noBGPLogs,
			backendError:    nil,
			backendResponse: nil,
			reqBody:         "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON", "Status":400}`,
			},
		},

		// Ingest all bgp logs
		{
			name:            "ingest bgp logs",
			backendBGPLogs:  bgpLogs,
			backendError:    nil,
			backendResponse: bulkResponseSuccess,
			reqBody:         testutils.MarshalBulkParams[v1.BGPLog](bgpLogs),
			want:            testResult{false, 200, ""},
		},

		// Fails to ingest all bgp logs
		{
			name:            "fail to ingest all bgp logs",
			backendBGPLogs:  bgpLogs,
			backendError:    errors.New("any error"),
			backendResponse: nil,
			reqBody:         testutils.MarshalBulkParams[v1.BGPLog](bgpLogs),
			want:            testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},

		// Ingest some bgp logs
		{
			name:            "ingest some bgp logs",
			backendBGPLogs:  bgpLogs,
			backendError:    nil,
			backendResponse: bulkResponsePartialSuccess,
			reqBody:         testutils.MarshalBulkParams[v1.BGPLog](bgpLogs),
			want:            testResult{false, 200, ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := bulkBGPLogs(tt.backendResponse, tt.backendError)

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

func bulkBGPLogs(response *v1.BulkResponse, err error) *bgp {
	mockLogBackend := &api.MockBGPBackend{}
	n := New(mockLogBackend)

	// mock backend to return the required backendBGP
	mockLogBackend.On("Create", mock.Anything,
		mock.AnythingOfType("api.ClusterInfo"), mock.AnythingOfType("[]v1.BGPLog")).Return(response, err)

	return n
}

func TestBGPGetLogs(t *testing.T) {
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
		backendBGPLogs  []v1.BGPLog
		backendResponse *v1.BulkResponse
		backendError    error
		reqBody         string
		want            testResult
	}{
		// Failure to parse request and validate
		{
			name:           "malformed json",
			backendBGPLogs: noBGPLogs,
			backendError:   nil,
			reqBody:        "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON (at position 2)", "Status":400}`,
			},
		},

		// Get all BGP logs
		{
			name:           "get all bgp logs",
			backendBGPLogs: bgpLogs,
			backendError:   nil,
			reqBody:        withinTimeRange,
			want:           testResult{false, 200, ""},
		},

		// Get all BGP logs
		{
			name:            "get all bgp logs",
			backendBGPLogs:  bgpLogs,
			backendError:    nil,
			backendResponse: bulkResponseSuccess,
			reqBody:         withinTimeRange,
			want:            testResult{false, 200, ""},
		},

		// Fails to get BGP logs
		{
			name:           "fail to ingest all bgp logs",
			backendBGPLogs: bgpLogs,
			backendError:   errors.New("any error"),
			reqBody:        withinTimeRange,
			want:           testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := bgpGetLogs(tt.backendBGPLogs, tt.backendError)

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
				wantBody = marshalResponse(t, tt.backendBGPLogs)
			}
			assert.Equal(t, tt.want.httpStatus, rec.Result().StatusCode)
			assert.JSONEq(t, wantBody, string(bodyBytes))
		})
	}
}

func bgpGetLogs(response []v1.BGPLog, err error) *bgp {
	mockLogBackend := &api.MockBGPBackend{}
	n := New(mockLogBackend)

	// mock backend to return the required backendBGP
	mockLogBackend.On("List", mock.Anything,
		mock.AnythingOfType("api.ClusterInfo"), mock.AnythingOfType("*v1.BGPLogParams")).Return(&v1.List[v1.BGPLog]{Items: response}, err)

	return n
}

func marshalResponse(t *testing.T, logs []v1.BGPLog) string {
	response := v1.List[v1.BGPLog]{}
	response.Items = logs
	newData, err := json.Marshal(response)
	require.NoError(t, err)
	return string(newData)
}
