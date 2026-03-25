// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package runtime

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

func TestRuntimeBulkIngestion(t *testing.T) {
	type testResult struct {
		wantErr    bool
		httpStatus int
		errorMsg   string
	}

	tests := []struct {
		name                  string
		backendRuntimeReports []v1.Report
		backendResponse       *v1.BulkResponse
		backendError          error
		reqBody               string
		want                  testResult
	}{
		// Failure to parse request and validate
		{
			name:                  "malformed json",
			backendRuntimeReports: noReports,
			backendError:          nil,
			backendResponse:       nil,
			reqBody:               "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON", "Status":400}`,
			},
		},

		// Ingest all runtime reports
		{
			name:                  "ingest runtime reports",
			backendRuntimeReports: reports,
			backendError:          nil,
			backendResponse:       bulkResponseSuccess,
			reqBody:               testutils.MarshalBulkParams[v1.Report](reports),
			want:                  testResult{false, 200, ""},
		},

		// Fails to ingest all runtime reports
		{
			name:                  "fail to ingest all runtime reports",
			backendRuntimeReports: reports,
			backendError:          errors.New("any error"),
			backendResponse:       nil,
			reqBody:               testutils.MarshalBulkParams[v1.Report](reports),
			want:                  testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},

		// Ingest some runtime reports
		{
			name:                  "ingest some runtime reports",
			backendRuntimeReports: reports,
			backendError:          nil,
			backendResponse:       bulkResponsePartialSuccess,
			reqBody:               testutils.MarshalBulkParams[v1.Report](reports),
			want:                  testResult{false, 200, ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := bulkRuntimeReports(tt.backendResponse, tt.backendError)

			rec := httptest.NewRecorder()
			req, err := http.NewRequest("POST", dummyURL, bytes.NewBufferString(tt.reqBody))
			req.Header.Set("Content-Type", "application/x-ndjson")
			require.NoError(t, err)

			b.reports.Create().ServeHTTP(rec, req)

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

func bulkRuntimeReports(response *v1.BulkResponse, err error) *runtime {
	mockBackend := &api.MockRuntimeBackend{}
	n := New(mockBackend)

	// mock backend to return the required backendRuntime
	mockBackend.On("Create", mock.Anything,
		mock.AnythingOfType("api.ClusterInfo"), mock.Anything).Return(response, err)

	return n
}

func TestRuntimeGetLogs(t *testing.T) {
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
		name                  string
		backendRuntimeReports []v1.RuntimeReport
		backendResponse       *v1.BulkResponse
		backendError          error
		reqBody               string
		want                  testResult
	}{
		// Failure to parse request and validate
		{
			name:                  "malformed json",
			backendRuntimeReports: noRuntimeReports,
			backendError:          nil,
			reqBody:               "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON (at position 2)", "Status":400}`,
			},
		},

		// Get all runtime reports
		{
			name:                  "get all runtime reports",
			backendRuntimeReports: runtimeReports,
			backendError:          nil,
			reqBody:               withinTimeRange,
			want:                  testResult{false, 200, ""},
		},

		// Get all runtime reports
		{
			name:                  "get all runtime reports",
			backendRuntimeReports: runtimeReports,
			backendError:          nil,
			backendResponse:       bulkResponseSuccess,
			reqBody:               withinTimeRange,
			want:                  testResult{false, 200, ""},
		},

		// Fails to get runtime reports
		{
			name:                  "fail to ingest all runtime reports",
			backendRuntimeReports: runtimeReports,
			backendError:          errors.New("any error"),
			reqBody:               withinTimeRange,
			want:                  testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := runtimeGetReports(tt.backendRuntimeReports, tt.backendError)

			rec := httptest.NewRecorder()
			req, err := http.NewRequest("POST", dummyURL, bytes.NewBufferString(tt.reqBody))
			req.Header.Set("Content-Type", "application/json")
			require.NoError(t, err)

			b.reports.List().ServeHTTP(rec, req)

			bodyBytes, err := io.ReadAll(rec.Body)
			require.NoError(t, err)

			var wantBody string
			if tt.want.wantErr {
				wantBody = tt.want.errorMsg
			} else {
				wantBody = marshalResponse(t, tt.backendRuntimeReports)
			}
			assert.Equal(t, tt.want.httpStatus, rec.Result().StatusCode)
			assert.JSONEq(t, wantBody, string(bodyBytes))
		})
	}
}

func runtimeGetReports(response []v1.RuntimeReport, err error) *runtime {
	mockBackend := &api.MockRuntimeBackend{}
	n := New(mockBackend)

	// mock backend to return the required backendRuntime
	mockBackend.On("List", mock.Anything,
		mock.AnythingOfType("api.ClusterInfo"), mock.AnythingOfType("*v1.RuntimeReportParams")).Return(&v1.List[v1.RuntimeReport]{Items: response}, err)

	return n
}

func marshalResponse(t *testing.T, logs []v1.RuntimeReport) string {
	response := v1.List[v1.RuntimeReport]{}
	response.Items = logs
	newData, err := json.Marshal(response)
	require.NoError(t, err)
	return string(newData)
}
