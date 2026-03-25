// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package audit

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

func TestEEBulkIngestion(t *testing.T) {
	type testResult struct {
		wantErr    bool
		httpStatus int
		errorMsg   string
	}

	tests := []struct {
		name             string
		backendAuditLogs []v1.AuditLog
		backendResponse  *v1.BulkResponse
		backendError     error
		reqBody          string
		want             testResult
	}{
		// Failure to parse request and validate
		{
			name:             "malformed json",
			backendAuditLogs: noAuditLogs,
			backendError:     nil,
			backendResponse:  nil,
			reqBody:          "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON", "Status":400}`,
			},
		},

		// Ingest all audit logs
		{
			name:             "ingest EE audit logs",
			backendAuditLogs: eeAuditLogs,
			backendError:     nil,
			backendResponse:  bulkResponseSuccess,
			reqBody:          testutils.MarshalBulkParams[v1.AuditLog](eeAuditLogs),
			want:             testResult{false, 200, ""},
		},

		// Fails to ingest all audit logs
		{
			name:             "fail to ingest all EE audits logs",
			backendAuditLogs: eeAuditLogs,
			backendError:     errors.New("any error"),
			backendResponse:  nil,
			reqBody:          testutils.MarshalBulkParams[v1.AuditLog](eeAuditLogs),
			want:             testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},

		// Ingest some audit logs
		{
			name:             "ingest some EE audits logs",
			backendAuditLogs: eeAuditLogs,
			backendError:     nil,
			backendResponse:  bulkResponsePartialSuccess,
			reqBody:          testutils.MarshalBulkParams[v1.AuditLog](eeAuditLogs),
			want:             testResult{false, 200, ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := bulkAuditLogs(v1.AuditLogTypeEE, tt.backendResponse, tt.backendError)

			rec := httptest.NewRecorder()
			req, err := http.NewRequest("POST", dummyURL, bytes.NewBufferString(tt.reqBody))
			req.Header.Set("Content-Type", "application/x-ndjson")
			require.NoError(t, err)

			b.BulkAuditEE().ServeHTTP(rec, req)

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

func TestKubeBulkIngestion(t *testing.T) {
	type testResult struct {
		wantErr    bool
		httpStatus int
		errorMsg   string
	}

	tests := []struct {
		name             string
		backendAuditLogs []v1.AuditLog
		backendResponse  *v1.BulkResponse
		backendError     error
		reqBody          string
		want             testResult
	}{
		// Failure to parse request and validate
		{
			name:             "malformed json",
			backendAuditLogs: noAuditLogs,
			backendError:     nil,
			backendResponse:  nil,
			reqBody:          "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON", "Status":400}`,
			},
		},

		// Ingest all audit logs
		{
			name:             "ingest Kube audit logs",
			backendAuditLogs: kubeAuditLogs,
			backendError:     nil,
			backendResponse:  bulkResponseSuccess,
			reqBody:          testutils.MarshalBulkParams[v1.AuditLog](kubeAuditLogs),
			want:             testResult{false, 200, ""},
		},

		// Fails to ingest all audit logs
		{
			name:             "fail to ingest all Kube audits logs",
			backendAuditLogs: kubeAuditLogs,
			backendError:     errors.New("any error"),
			backendResponse:  nil,
			reqBody:          testutils.MarshalBulkParams[v1.AuditLog](kubeAuditLogs),
			want:             testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},

		// Ingest some audit logs
		{
			name:             "ingest some Kube audits logs",
			backendAuditLogs: kubeAuditLogs,
			backendError:     nil,
			backendResponse:  bulkResponsePartialSuccess,
			reqBody:          testutils.MarshalBulkParams[v1.AuditLog](kubeAuditLogs),
			want:             testResult{false, 200, ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := bulkAuditLogs(v1.AuditLogTypeKube, tt.backendResponse, tt.backendError)

			rec := httptest.NewRecorder()
			req, err := http.NewRequest("POST", dummyURL, bytes.NewBufferString(tt.reqBody))
			req.Header.Set("Content-Type", "application/x-ndjson")
			require.NoError(t, err)

			b.BulkAuditKube().ServeHTTP(rec, req)

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

func bulkAuditLogs(auditLogsType v1.AuditLogType, response *v1.BulkResponse, err error) *audit {
	mockLogBackend := &api.MockAuditBackend{}
	n := New(mockLogBackend)

	// mock backend to return the required backendAudit
	mockLogBackend.On("Create", mock.Anything, auditLogsType,
		mock.AnythingOfType("api.ClusterInfo"), mock.AnythingOfType("[]v1.AuditLog")).Return(response, err)

	return n
}

func TestEEGetLogs(t *testing.T) {
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
		name             string
		backendAuditLogs []v1.AuditLog
		backendResponse  *v1.BulkResponse
		backendError     error
		reqBody          string
		want             testResult
	}{
		// Failure to parse request and validate
		{
			name:             "malformed json",
			backendAuditLogs: noAuditLogs,
			backendError:     nil,
			reqBody:          "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON (at position 2)", "Status":400}`,
			},
		},

		// Get all EE audit logs
		{
			name:             "get all EE audit logs",
			backendAuditLogs: eeAuditLogs,
			backendError:     nil,
			reqBody:          withinTimeRange,
			want:             testResult{false, 200, ""},
		},

		// Get all Kube audit logs
		{
			name:             "get all Kube audit logs",
			backendAuditLogs: kubeAuditLogs,
			backendError:     nil,
			backendResponse:  bulkResponseSuccess,
			reqBody:          withinTimeRange,
			want:             testResult{false, 200, ""},
		},

		// Fails to get audit logs
		{
			name:             "fail to ingest all EE audits logs",
			backendAuditLogs: eeAuditLogs,
			backendError:     errors.New("any error"),
			reqBody:          withinTimeRange,
			want:             testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := auditLogs(tt.backendAuditLogs, tt.backendError)

			rec := httptest.NewRecorder()
			req, err := http.NewRequest("POST", dummyURL, bytes.NewBufferString(tt.reqBody))
			req.Header.Set("Content-Type", "application/json")
			require.NoError(t, err)

			b.GetLogs().ServeHTTP(rec, req)

			bodyBytes, err := io.ReadAll(rec.Body)
			require.NoError(t, err)

			var wantBody string
			if tt.want.wantErr {
				wantBody = tt.want.errorMsg
			} else {
				wantBody = marshalResponse(t, tt.backendAuditLogs)
			}
			assert.Equal(t, tt.want.httpStatus, rec.Result().StatusCode)
			assert.JSONEq(t, wantBody, string(bodyBytes))
		})
	}
}

func auditLogs(response []v1.AuditLog, err error) *audit {
	mockLogBackend := &api.MockAuditBackend{}
	n := New(mockLogBackend)

	// mock backend to return the required backendAudit
	mockLogBackend.On("List", mock.Anything,
		mock.AnythingOfType("api.ClusterInfo"), mock.AnythingOfType("*v1.AuditLogParams")).Return(&v1.List[v1.AuditLog]{Items: response}, err)

	return n
}

func marshalResponse(t *testing.T, logs []v1.AuditLog) string {
	response := v1.List[v1.AuditLog]{}
	response.Items = logs
	newData, err := json.Marshal(response)
	require.NoError(t, err)
	return string(newData)
}
