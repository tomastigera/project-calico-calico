// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package dns

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

// A valid query input that provides the necessary time range parameters.
const withinTimeRange = `
{
  "time_range": {
    "from": "2021-04-19T14:25:30.169821857-07:00",
    "to": "2021-04-19T14:25:30.169827009-07:00"
  },
  "timeout": "60s"
}
`

func TestDNSFlowsHandler(t *testing.T) {
	type testResult struct {
		httpStatus int
		errorMsg   string
	}

	tests := []struct {
		name         string
		reqBody      string
		want         testResult
		backendFlows []v1.DNSFlow
	}{
		// OK response, no data
		{
			name:         "empty json",
			reqBody:      "{}",
			want:         testResult{200, ""},
			backendFlows: []v1.DNSFlow{},
		},

		// Retrieve all  flow logs within a time range
		{
			name:         "retrieve all flows within time range",
			reqBody:      withinTimeRange,
			want:         testResult{200, ""},
			backendFlows: []v1.DNSFlow{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			n := flowHandler(tt.backendFlows)
			url := n.APIS()[0].URL

			rec := httptest.NewRecorder()
			req, err := http.NewRequest("POST", url, bytes.NewBufferString(tt.reqBody))
			req.Header.Set("Content-Type", "application/json")
			require.NoError(t, err)

			// Serve the request and read the response.
			n.flows.List().ServeHTTP(rec, req)
			bodyBytes, err := io.ReadAll(rec.Body)
			require.NoError(t, err)

			var wantBody string
			if tt.want.errorMsg != "" {
				wantBody = tt.want.errorMsg
			} else {
				wantBody = marshalResponse(t, tt.backendFlows)
			}
			assert.Equal(t, tt.want.httpStatus, rec.Result().StatusCode)
			assert.JSONEq(t, wantBody, string(bodyBytes))
		})
	}
}

func flowHandler(flows []v1.DNSFlow) *dns {
	mockFlowBackend := &api.MockDNSFlowBackend{}
	mockLogBackend := &api.MockDNSLogBackend{}
	n := New(mockFlowBackend, mockLogBackend)

	res := v1.List[v1.DNSFlow]{
		Items:    flows,
		AfterKey: nil,
	}

	// mock backend to return the required flows
	mockFlowBackend.On("List", mock.Anything,
		mock.AnythingOfType("api.ClusterInfo"), mock.AnythingOfType("*v1.DNSFlowParams")).Return(&res, nil)

	return n
}

func marshalResponse(t *testing.T, flows []v1.DNSFlow) string {
	response := v1.List[v1.DNSFlow]{}
	response.Items = flows
	newData, err := json.Marshal(response)
	require.NoError(t, err)
	return string(newData)
}

func TestBulkIngestion(t *testing.T) {
	type testResult struct {
		wantErr    bool
		httpStatus int
		errorMsg   string
	}

	tests := []struct {
		name            string
		backendDNSLogs  []v1.DNSLog
		backendResponse *v1.BulkResponse
		backendError    error
		reqBody         string
		want            testResult
	}{
		// Failure to parse request and validate
		{
			name:            "malformed json",
			backendDNSLogs:  noDNSLogs,
			backendError:    nil,
			backendResponse: nil,
			reqBody:         "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON", "Status":400}`,
			},
		},

		// Ingest all dns logs
		{
			name:            "ingest dns logs",
			backendDNSLogs:  dnsLogs,
			backendError:    nil,
			backendResponse: bulkResponseSuccess,
			reqBody:         testutils.MarshalBulkParams[v1.DNSLog](dnsLogs),
			want:            testResult{false, 200, ""},
		},

		// Fails to ingest all dns logs
		{
			name:            "fail to ingest all DNSs logs",
			backendDNSLogs:  dnsLogs,
			backendError:    errors.New("any error"),
			backendResponse: nil,
			reqBody:         testutils.MarshalBulkParams[v1.DNSLog](dnsLogs),
			want:            testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},

		// Ingest some dns logs
		{
			name:            "ingest some DNSs logs",
			backendDNSLogs:  dnsLogs,
			backendError:    nil,
			backendResponse: bulkResponsePartialSuccess,
			reqBody:         testutils.MarshalBulkParams[v1.DNSLog](dnsLogs),
			want:            testResult{false, 200, ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := bulkDNSLogs(tt.backendResponse, tt.backendError)

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

func bulkDNSLogs(response *v1.BulkResponse, err error) *dns {
	mockFlowBackend := &api.MockDNSFlowBackend{}
	mockLogBackend := &api.MockDNSLogBackend{}
	n := New(mockFlowBackend, mockLogBackend)

	// mock backend to return the required backendDNSLogs
	mockLogBackend.On("Create", mock.Anything,
		mock.AnythingOfType("api.ClusterInfo"), mock.AnythingOfType("[]v1.DNSLog")).Return(response, err)

	return n
}
