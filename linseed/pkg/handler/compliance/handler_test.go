// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package compliance

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/libcalico-go/lib/json"
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

func TestComplianceReportsBulkIngestion(t *testing.T) {
	type testResult struct {
		wantErr    bool
		httpStatus int
		errorMsg   string
	}

	tests := []struct {
		name            string
		backendReports  []v1.ReportData
		backendResponse *v1.BulkResponse
		backendError    error
		reqBody         string
		want            testResult
	}{
		// Failure to parse request and validate
		{
			name:            "malformed json",
			backendReports:  noReport,
			backendError:    nil,
			backendResponse: nil,
			reqBody:         "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON", "Status":400}`,
			},
		},

		// Ingest all compliance reports
		{
			name:            "ingest compliance reports",
			backendReports:  multipleReports,
			backendError:    nil,
			backendResponse: bulkResponseSuccess,
			reqBody:         testutils.MarshalBulkParams[v1.ReportData](multipleReports),
			want:            testResult{false, 200, ""},
		},

		// Fails to ingest all compliance reports
		{
			name:            "fail to ingest all compliance reports",
			backendReports:  multipleReports,
			backendError:    errors.New("any error"),
			backendResponse: nil,
			reqBody:         testutils.MarshalBulkParams[v1.ReportData](multipleReports),
			want:            testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},

		// Ingest some compliance reports
		{
			name:            "ingest some compliance reports",
			backendReports:  multipleReports,
			backendError:    nil,
			backendResponse: bulkResponsePartialSuccess,
			reqBody:         testutils.MarshalBulkParams[v1.ReportData](multipleReports),
			want:            testResult{false, 200, ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := bulkComplianceData(tt.backendResponse, tt.backendError)

			rec := httptest.NewRecorder()
			req, err := http.NewRequest("POST", dummyURL, bytes.NewBufferString(tt.reqBody))
			req.Header.Set("Content-Type", "application/x-ndjson")
			require.NoError(t, err)

			b.APIS()[1].Handler.ServeHTTP(rec, req)

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
func TestComplianceBenchmarksBulkIngestion(t *testing.T) {
	type testResult struct {
		wantErr    bool
		httpStatus int
		errorMsg   string
	}

	tests := []struct {
		name            string
		backendReports  []v1.Benchmarks
		backendResponse *v1.BulkResponse
		backendError    error
		reqBody         string
		want            testResult
	}{
		// Failure to parse request and validate
		{
			name:            "malformed json",
			backendReports:  noBenchmarks,
			backendError:    nil,
			backendResponse: nil,
			reqBody:         "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON", "Status":400}`,
			},
		},

		// Ingest all Benchmark reports
		{
			name:            "ingest compliance reports",
			backendReports:  multipleBenchmark,
			backendError:    nil,
			backendResponse: bulkResponseSuccess,
			reqBody:         testutils.MarshalBulkParams[v1.Benchmarks](multipleBenchmark),
			want:            testResult{false, 200, ""},
		},

		// Fails to ingest all Benchmark reports
		{
			name:            "fail to ingest all compliance reports",
			backendReports:  multipleBenchmark,
			backendError:    errors.New("any error"),
			backendResponse: nil,
			reqBody:         testutils.MarshalBulkParams[v1.Benchmarks](multipleBenchmark),
			want:            testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},

		// Ingest some benchmark reports
		{
			name:            "ingest some Benchmark reports",
			backendReports:  multipleBenchmark,
			backendError:    nil,
			backendResponse: bulkResponsePartialSuccess,
			reqBody:         testutils.MarshalBulkParams[v1.Benchmarks](multipleBenchmark),
			want:            testResult{false, 200, ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := bulkComplianceData(tt.backendResponse, tt.backendError)

			rec := httptest.NewRecorder()
			req, err := http.NewRequest("POST", dummyURL, bytes.NewBufferString(tt.reqBody))
			req.Header.Set("Content-Type", "application/x-ndjson")
			require.NoError(t, err)

			b.APIS()[3].Handler.ServeHTTP(rec, req)

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
func TestComplianceSnapshotsBulkIngestion(t *testing.T) {
	type testResult struct {
		wantErr    bool
		httpStatus int
		errorMsg   string
	}

	tests := []struct {
		name            string
		backendReports  []v1.Snapshot
		backendResponse *v1.BulkResponse
		backendError    error
		reqBody         string
		want            testResult
	}{
		// Failure to parse request and validate
		{
			name:            "malformed json",
			backendReports:  noSnapshot,
			backendError:    nil,
			backendResponse: nil,
			reqBody:         "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON", "Status":400}`,
			},
		},

		// Ingest all Snapshot
		{
			name:            "ingest compliance Snapshot",
			backendReports:  multipleSnapshot,
			backendError:    nil,
			backendResponse: bulkResponseSuccess,
			reqBody:         testutils.MarshalBulkParams[v1.Snapshot](multipleSnapshot),
			want:            testResult{false, 200, ""},
		},

		// Fails to ingest all Snapshot
		{
			name:            "fail to ingest all compliance Snapshot",
			backendReports:  multipleSnapshot,
			backendError:    errors.New("any error"),
			backendResponse: nil,
			reqBody:         testutils.MarshalBulkParams[v1.Snapshot](multipleSnapshot),
			want:            testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},

		// Ingest some compliance snapshot
		{
			name:            "ingest some Benchmark reports",
			backendReports:  multipleSnapshot,
			backendError:    nil,
			backendResponse: bulkResponsePartialSuccess,
			reqBody:         testutils.MarshalBulkParams[v1.Snapshot](multipleSnapshot),
			want:            testResult{false, 200, ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := bulkComplianceData(tt.backendResponse, tt.backendError)

			rec := httptest.NewRecorder()
			req, err := http.NewRequest("POST", dummyURL, bytes.NewBufferString(tt.reqBody))
			req.Header.Set("Content-Type", "application/x-ndjson")
			require.NoError(t, err)

			b.APIS()[5].Handler.ServeHTTP(rec, req)

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

func bulkComplianceData(response *v1.BulkResponse, err error) *compliance {
	mockBenchmarksBackend := &api.MockBenchmarksBackend{}
	mockSnapshotsBackend := &api.MockSnapshotsBackend{}
	mockReportsBackend := &api.MockReportsBackend{}

	n := New(mockBenchmarksBackend, mockSnapshotsBackend, mockReportsBackend)

	// mock backend to return the required compliance backend
	mockReportsBackend.On("Create", mock.Anything,
		mock.AnythingOfType("api.ClusterInfo"), mock.AnythingOfType("[]v1.ReportData")).Return(response, err)
	mockBenchmarksBackend.On("Create", mock.Anything,
		mock.AnythingOfType("api.ClusterInfo"), mock.AnythingOfType("[]v1.Benchmarks")).Return(response, err)
	mockSnapshotsBackend.On("Create", mock.Anything,
		mock.AnythingOfType("api.ClusterInfo"), mock.AnythingOfType("[]v1.Snapshot")).Return(response, err)

	return n
}

func TestComplianceGetReportData(t *testing.T) {
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
		backendReports  []v1.ReportData
		backendResponse *v1.BulkResponse
		backendError    error
		reqBody         string
		want            testResult
	}{
		// Failure to parse request and validate
		{
			name:           "malformed json",
			backendReports: noReport,
			backendError:   nil,
			reqBody:        "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON (at position 2)", "Status":400}`,
			},
		},

		// Get all compliance reports
		{
			name:           "get all compliance reports",
			backendReports: multipleReports,
			backendError:   nil,
			reqBody:        withinTimeRange,
			want:           testResult{false, 200, ""},
		},

		// Get all compliance reports
		{
			name:            "get all compliance reports",
			backendReports:  multipleReports,
			backendError:    nil,
			backendResponse: bulkResponseSuccess,
			reqBody:         withinTimeRange,
			want:            testResult{false, 200, ""},
		},

		// Fails to get compliance reports
		{
			name:           "fail to ingest all compliance reports",
			backendReports: multipleReports,
			backendError:   errors.New("any error"),
			reqBody:        withinTimeRange,
			want:           testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := complianceGetReports(tt.backendReports, tt.backendError)

			rec := httptest.NewRecorder()
			req, err := http.NewRequest("POST", dummyURL, bytes.NewBufferString(tt.reqBody))
			req.Header.Set("Content-Type", "application/json")
			require.NoError(t, err)

			b.APIS()[0].Handler.ServeHTTP(rec, req)

			bodyBytes, err := io.ReadAll(rec.Body)
			require.NoError(t, err)

			var wantBody string
			if tt.want.wantErr {
				wantBody = tt.want.errorMsg
			} else {
				wantBody = marshalReportDataResponse(t, tt.backendReports)
			}
			assert.Equal(t, tt.want.httpStatus, rec.Result().StatusCode)
			assert.JSONEq(t, wantBody, string(bodyBytes))
		})
	}
}
func TestComplianceGetSnapshot(t *testing.T) {
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
		backendReports  []v1.Snapshot
		backendResponse *v1.BulkResponse
		backendError    error
		reqBody         string
		want            testResult
	}{
		// Failure to parse request and validate
		{
			name:           "malformed json",
			backendReports: noSnapshot,
			backendError:   nil,
			reqBody:        "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON (at position 2)", "Status":400}`,
			},
		},

		// Get all compliance snapshot
		{
			name:           "get all compliance snapshot",
			backendReports: multipleSnapshot,
			backendError:   nil,
			reqBody:        withinTimeRange,
			want:           testResult{false, 200, ""},
		},

		// Get all compliance snapshot
		{
			name:            "get all compliance snapshot",
			backendReports:  multipleSnapshot,
			backendError:    nil,
			backendResponse: bulkResponseSuccess,
			reqBody:         withinTimeRange,
			want:            testResult{false, 200, ""},
		},

		// Fails to get compliance snapshot
		{
			name:           "fail to ingest all compliance snapshot",
			backendReports: multipleSnapshot,
			backendError:   errors.New("any error"),
			reqBody:        withinTimeRange,
			want:           testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := complianceGetReports(tt.backendReports, tt.backendError)

			rec := httptest.NewRecorder()
			req, err := http.NewRequest("POST", dummyURL, bytes.NewBufferString(tt.reqBody))
			req.Header.Set("Content-Type", "application/json")
			require.NoError(t, err)

			b.APIS()[4].Handler.ServeHTTP(rec, req)

			bodyBytes, err := io.ReadAll(rec.Body)
			require.NoError(t, err)

			var wantBody string
			if tt.want.wantErr {
				wantBody = tt.want.errorMsg
			} else {
				wantBody = marshalSnapshotResponse(t, tt.backendReports)
			}
			assert.Equal(t, tt.want.httpStatus, rec.Result().StatusCode)
			assert.JSONEq(t, wantBody, string(bodyBytes))
		})
	}
}
func TestComplianceGetBenchmark(t *testing.T) {
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
		backendReports  []v1.Benchmarks
		backendResponse *v1.BulkResponse
		backendError    error
		reqBody         string
		want            testResult
	}{
		// Failure to parse request and validate
		{
			name:           "malformed json",
			backendReports: noBenchmarks,
			backendError:   nil,
			reqBody:        "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON (at position 2)", "Status":400}`,
			},
		},

		// Get all compliance benchmark
		{
			name:           "get all benchmark reports",
			backendReports: multipleBenchmark,
			backendError:   nil,
			reqBody:        withinTimeRange,
			want:           testResult{false, 200, ""},
		},

		// Get all compliance benchmark
		{
			name:            "get all compliance benchmark",
			backendReports:  multipleBenchmark,
			backendError:    nil,
			backendResponse: bulkResponseSuccess,
			reqBody:         withinTimeRange,
			want:            testResult{false, 200, ""},
		},

		// Fails to get compliance benchmark
		{
			name:           "fail to ingest all compliance benchmark",
			backendReports: multipleBenchmark,
			backendError:   errors.New("any error"),
			reqBody:        withinTimeRange,
			want:           testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := complianceGetReports(tt.backendReports, tt.backendError)

			rec := httptest.NewRecorder()
			req, err := http.NewRequest("POST", dummyURL, bytes.NewBufferString(tt.reqBody))
			req.Header.Set("Content-Type", "application/json")
			require.NoError(t, err)

			b.APIS()[2].Handler.ServeHTTP(rec, req)

			bodyBytes, err := io.ReadAll(rec.Body)
			require.NoError(t, err)

			var wantBody string
			if tt.want.wantErr {
				wantBody = tt.want.errorMsg
			} else {
				wantBody = marshalBenchMarkResponse(t, tt.backendReports)
			}
			assert.Equal(t, tt.want.httpStatus, rec.Result().StatusCode)
			assert.JSONEq(t, wantBody, string(bodyBytes))
		})
	}
}

func complianceGetReports(response any, err error) *compliance {
	mockBenchmarksBackend := &api.MockBenchmarksBackend{}
	mockSnapshotsBackend := &api.MockSnapshotsBackend{}
	mockReportsBackend := &api.MockReportsBackend{}

	n := New(mockBenchmarksBackend, mockSnapshotsBackend, mockReportsBackend)

	// mock backend to return the required backendRuntime
	if report, ok := response.([]v1.ReportData); ok {
		mockReportsBackend.On("List", mock.Anything,
			mock.AnythingOfType("api.ClusterInfo"), mock.AnythingOfType("*v1.ReportDataParams")).Return(&v1.List[v1.ReportData]{Items: report}, err)
	} else if snap, ok := response.([]v1.Snapshot); ok {
		mockSnapshotsBackend.On("List", mock.Anything,
			mock.AnythingOfType("api.ClusterInfo"), mock.AnythingOfType("*v1.SnapshotParams")).Return(&v1.List[v1.Snapshot]{Items: snap}, err)
	} else if benchmark, ok := response.([]v1.Benchmarks); ok {
		mockBenchmarksBackend.On("List", mock.Anything,
			mock.AnythingOfType("api.ClusterInfo"), mock.AnythingOfType("*v1.BenchmarksParams")).Return(&v1.List[v1.Benchmarks]{Items: benchmark}, err)
	}
	return n
}

func marshalReportDataResponse(t *testing.T, logs []v1.ReportData) string {
	response := v1.List[v1.ReportData]{}
	response.Items = logs
	newData, err := json.Marshal(response)
	require.NoError(t, err)
	return string(newData)
}

func marshalSnapshotResponse(t *testing.T, logs []v1.Snapshot) string {
	response := v1.List[v1.Snapshot]{}
	response.Items = logs
	newData, err := json.Marshal(response)
	require.NoError(t, err)
	return string(newData)
}
func marshalBenchMarkResponse(t *testing.T, logs []v1.Benchmarks) string {
	response := v1.List[v1.Benchmarks]{}
	response.Items = logs
	newData, err := json.Marshal(response)
	require.NoError(t, err)
	return string(newData)
}
