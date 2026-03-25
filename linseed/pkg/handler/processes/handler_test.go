// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package processes

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
)

func setupTest(t *testing.T) func() {
	cancel := logutils.RedirectLogrusToTestingT(t)
	return func() {
		cancel()
	}
}

func TestProcessesList(t *testing.T) {
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
		backendResponse []v1.ProcessInfo
		backendError    error
		reqBody         string
		want            testResult
	}{
		// Failure to parse request and validate
		{
			name:            "malformed json",
			backendResponse: noProcess,
			backendError:    nil,
			reqBody:         "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON (at position 2)", "Status":400}`,
			},
		},

		// Get all Processes logs
		{
			name:            "get all processes",
			backendResponse: processes,
			backendError:    nil,
			reqBody:         withinTimeRange,
			want:            testResult{false, 200, ""},
		},

		// Fails to get Processes logs
		{
			name:            "fail to ingest all processes",
			backendResponse: processes,
			backendError:    errors.New("any error"),
			reqBody:         withinTimeRange,
			want:            testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := getProcessHandler(tt.backendResponse, tt.backendError)

			rec := httptest.NewRecorder()
			req, err := http.NewRequest("POST", "dummyURL", bytes.NewBufferString(tt.reqBody))
			req.Header.Set("Content-Type", "application/json")
			require.NoError(t, err)

			b.processes.List().ServeHTTP(rec, req)

			bodyBytes, err := io.ReadAll(rec.Body)
			require.NoError(t, err)

			var wantBody string
			if tt.want.wantErr {
				wantBody = tt.want.errorMsg
			} else {
				wantBody = marshalResponse(t, tt.backendResponse)
			}
			assert.Equal(t, tt.want.httpStatus, rec.Result().StatusCode)
			assert.JSONEq(t, wantBody, string(bodyBytes))
		})
	}
}

func getProcessHandler(response []v1.ProcessInfo, err error) *procHandler {
	mockLogBackend := &api.MockProcessBackend{}
	n := New(mockLogBackend)

	// mock backend to return the required response
	mockLogBackend.On("List", mock.Anything,
		mock.AnythingOfType("api.ClusterInfo"), mock.AnythingOfType("*v1.ProcessParams")).Return(&v1.List[v1.ProcessInfo]{Items: response}, err)

	return n.(*procHandler)
}

func marshalResponse(t *testing.T, logs []v1.ProcessInfo) string {
	response := v1.List[v1.ProcessInfo]{}
	response.Items = logs
	newData, err := json.Marshal(response)
	require.NoError(t, err)
	return string(newData)
}
