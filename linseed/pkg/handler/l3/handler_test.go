// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package l3

import (
	"bytes"
	_ "embed"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/libcalico-go/lib/json"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/testutils"
)

var withinTimeRange = `{
  "time_range": {
    "from": "2021-04-19T14:25:30.169821857-07:00",
    "to": "2021-04-19T14:25:30.169827009-07:00"
  },
  "timeout": "60s"
}`

func TestFlows_Post(t *testing.T) {
	type testResult struct {
		wantErr    bool
		httpStatus int
		errorMsg   string
	}

	tests := []struct {
		name           string
		reqBody        string
		want           testResult
		backendL3Flows []v1.L3Flow
	}{
		// Failure to parse request and validate
		{
			name:    "malformed json",
			reqBody: "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON (at position 2)", "Status":400}`,
			},
			backendL3Flows: noFlows,
		},

		// Retrieve all L3 flow logs within a time range
		{
			name:           "retrieve all l3 flows within a certain time range",
			reqBody:        withinTimeRange,
			want:           testResult{false, 200, ""},
			backendL3Flows: flows,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := mockFlows(tt.backendL3Flows)

			rec := httptest.NewRecorder()
			req, err := http.NewRequest("POST", dummyURL, bytes.NewBufferString(tt.reqBody))
			req.Header.Set("Content-Type", "application/json")
			require.NoError(t, err)

			n.flows.List().ServeHTTP(rec, req)

			bodyBytes, err := io.ReadAll(rec.Body)
			require.NoError(t, err)

			var wantBody string
			if tt.want.wantErr {
				wantBody = tt.want.errorMsg
			} else {
				wantBody = marshalResponse(t, tt.backendL3Flows)
			}
			assert.Equal(t, tt.want.httpStatus, rec.Result().StatusCode)
			assert.JSONEq(t, wantBody, string(bodyBytes))
		})
	}
}

func TestFlowLogs_Bulk(t *testing.T) {
	type testResult struct {
		wantErr    bool
		httpStatus int
		errorMsg   string
	}

	tests := []struct {
		name            string
		backendFlowLogs []v1.FlowLog
		backendResponse *v1.BulkResponse
		backendError    error
		reqBody         string
		want            testResult
	}{
		// Failure to parse request and validate
		{
			name:            "malformed json",
			backendFlowLogs: noFlowLogs,
			backendError:    nil,
			backendResponse: nil,
			reqBody:         "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON", "Status":400}`,
			},
		},

		// Ingest all flow logs
		{
			name:            "ingest flows logs",
			backendFlowLogs: flowLogs,
			backendError:    nil,
			backendResponse: bulkResponseSuccess,
			reqBody:         testutils.MarshalBulkParams[v1.FlowLog](flowLogs),
			want:            testResult{false, 200, ""},
		},

		// Fails to ingest all flow logs
		{
			name:            "fail to ingest all flows logs",
			backendFlowLogs: flowLogs,
			backendError:    errors.New("any error"),
			backendResponse: nil,
			reqBody:         testutils.MarshalBulkParams[v1.FlowLog](flowLogs),
			want:            testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},

		// Ingest some flow logs
		{
			name:            "ingest some flows logs",
			backendFlowLogs: flowLogs,
			backendError:    nil,
			backendResponse: bulkResponsePartialSuccess,
			reqBody:         testutils.MarshalBulkParams[v1.FlowLog](flowLogs),
			want:            testResult{false, 200, ""},
		},

		// All lines malformed
		{
			name:            "all lines malformed",
			backendFlowLogs: noFlowLogs,
			backendError:    nil,
			backendResponse: nil,
			reqBody:         "BAD1\nBAD2\nBAD3\n",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON", "Status":400}`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := mockBulk(tt.backendResponse, tt.backendError)

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

func mockFlows(flows []v1.L3Flow) *Flows {
	mockFlowBackend := &api.MockFlowBackend{}
	mockLogBackend := &api.MockFlowLogBackend{}
	n := New(mockFlowBackend, mockLogBackend)

	res := v1.List[v1.L3Flow]{
		Items:    flows,
		AfterKey: nil,
	}

	// mock backend to return the required flows
	mockFlowBackend.On("List", mock.Anything,
		mock.AnythingOfType("api.ClusterInfo"), mock.AnythingOfType("*v1.L3FlowParams")).Return(&res, nil)

	return n
}

func mockBulk(response *v1.BulkResponse, err error) *Flows {
	mockFlowBackend := &api.MockFlowBackend{}
	mockLogBackend := &api.MockFlowLogBackend{}
	b := New(mockFlowBackend, mockLogBackend)

	// mock backend to return the required backendFlowLogs
	mockLogBackend.On("Create", mock.Anything,
		mock.AnythingOfType("api.ClusterInfo"), mock.AnythingOfType("[]v1.FlowLog")).Return(response, err)

	return b
}

func mockGoldmaneBulk(response *v1.BulkResponse, err error) *GoldmaneFlows {
	mockLogBackend := &api.MockFlowLogBackend{}
	b := NewGoldmane(mockLogBackend)

	// mock backend to return the required backendFlowLogs
	mockLogBackend.On("Create", mock.Anything,
		mock.AnythingOfType("api.ClusterInfo"), mock.AnythingOfType("[]v1.FlowLog")).Return(response, err)

	return b
}

func marshalResponse(t *testing.T, flows []v1.L3Flow) string {
	response := v1.List[v1.L3Flow]{}
	response.Items = flows
	newData, err := json.Marshal(response)
	require.NoError(t, err)
	return string(newData)
}
