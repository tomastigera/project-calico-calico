package events

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

func TestEventBulkIngestion(t *testing.T) {
	type testResult struct {
		wantErr    bool
		httpStatus int
		errorMsg   string
	}

	tests := []struct {
		name            string
		backendEvents   []v1.Event
		backendResponse *v1.BulkResponse
		backendError    error
		reqBody         string
		want            testResult
	}{
		// Failure to parse request and validate
		{
			name:            "malformed json",
			backendEvents:   noEvents,
			backendError:    nil,
			backendResponse: nil,
			reqBody:         "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON", "Status":400}`,
			},
		},

		//Ingest all Events
		{
			name:            "ingest Events",
			backendEvents:   multipleEvent,
			backendError:    nil,
			backendResponse: bulkResponseSuccess,
			reqBody:         testutils.MarshalBulkParams[v1.Event](multipleEvent),
			want:            testResult{false, 200, ""},
		},

		// Fails to ingest all Event logs
		{
			name:            "fail to ingest all Events",
			backendEvents:   multipleEvent,
			backendError:    errors.New("any error"),
			backendResponse: nil,
			reqBody:         testutils.MarshalBulkParams[v1.Event](multipleEvent),
			want:            testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},

		// Ingest some Event logs
		{
			name:            "ingest some events",
			backendEvents:   multipleEvent,
			backendError:    nil,
			backendResponse: bulkResponsePartialSuccess,
			reqBody:         testutils.MarshalBulkParams[v1.Event](multipleEvent),
			want:            testResult{false, 200, ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := bulkEvents(tt.backendResponse, tt.backendError)

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
func TestPUTEvent(t *testing.T) {
	type testResult struct {
		wantErr    bool
		httpStatus int
		errorMsg   string
	}

	tests := []struct {
		name            string
		backendEvents   []v1.Event
		backendResponse *v1.BulkResponse
		backendError    error
		reqBody         string
		want            testResult
	}{
		// Failure to parse request and validate
		{
			name:            "malformed json",
			backendEvents:   noEvents,
			backendError:    nil,
			backendResponse: nil,
			reqBody:         "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON", "Status":400}`,
			},
		},

		//Ingest all Events
		{
			name:            "ingest Events",
			backendEvents:   multipleEvent,
			backendError:    nil,
			backendResponse: bulkResponseSuccess,
			reqBody:         testutils.MarshalBulkParams[v1.Event](multipleEvent),
			want:            testResult{false, 200, ""},
		},

		// Fails to ingest all Event logs
		{
			name:            "fail to ingest all Events",
			backendEvents:   multipleEvent,
			backendError:    errors.New("any error"),
			backendResponse: nil,
			reqBody:         testutils.MarshalBulkParams[v1.Event](multipleEvent),
			want:            testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},

		// Ingest some Event logs
		{
			name:            "ingest some events",
			backendEvents:   multipleEvent,
			backendError:    nil,
			backendResponse: bulkResponsePartialSuccess,
			reqBody:         testutils.MarshalBulkParams[v1.Event](multipleEvent),
			want:            testResult{false, 200, ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := bulkEvents(tt.backendResponse, tt.backendError)

			rec := httptest.NewRecorder()
			req, err := http.NewRequest("PUT", dummyURL, bytes.NewBufferString(tt.reqBody))
			req.Header.Set("Content-Type", "application/x-ndjson")
			require.NoError(t, err)

			b.APIS()[2].Handler.ServeHTTP(rec, req)

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

func TestDeleteEvent(t *testing.T) {
	type testResult struct {
		wantErr    bool
		httpStatus int
		errorMsg   string
	}

	tests := []struct {
		name            string
		backendEvents   []v1.Event
		backendResponse *v1.BulkResponse
		backendError    error
		reqBody         string
		want            testResult
	}{
		// Failure to parse request and validate
		{
			name:            "malformed json",
			backendEvents:   noEvents,
			backendError:    nil,
			backendResponse: nil,
			reqBody:         "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON", "Status":400}`,
			},
		},

		//Delete all Events
		{
			name:            "ingest Events",
			backendEvents:   multipleEvent,
			backendError:    nil,
			backendResponse: bulkResponseSuccess,
			reqBody:         testutils.MarshalBulkParams[v1.Event](multipleEvent),
			want:            testResult{false, 200, ""},
		},

		// Fails to Delete all Event logs
		{
			name:            "fail to ingest all Events",
			backendEvents:   multipleEvent,
			backendError:    errors.New("any error"),
			backendResponse: nil,
			reqBody:         testutils.MarshalBulkParams[v1.Event](multipleEvent),
			want:            testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},

		// Ingest Delete Event logs
		{
			name:            "ingest some events",
			backendEvents:   multipleEvent,
			backendError:    nil,
			backendResponse: bulkResponsePartialSuccess,
			reqBody:         testutils.MarshalBulkParams[v1.Event](multipleEvent),
			want:            testResult{false, 200, ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := bulkEvents(tt.backendResponse, tt.backendError)

			rec := httptest.NewRecorder()
			req, err := http.NewRequest("DELETE", dummyURL, bytes.NewBufferString(tt.reqBody))
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

func TestUnsupportedMethodEvent(t *testing.T) {
	type testResult struct {
		wantErr    bool
		httpStatus int
		errorMsg   string
	}

	tests := []struct {
		name            string
		backendEvents   []v1.Event
		backendResponse *v1.BulkResponse
		backendError    error
		reqBody         string
		want            testResult
	}{
		// Validate unsupported method
		{
			name:            "unsupported method",
			backendEvents:   multipleEvent,
			backendError:    nil,
			backendResponse: nil,
			reqBody:         testutils.MarshalBulkParams[v1.Event](multipleEvent),
			want: testResult{
				true, 405,
				`{"Msg":"unsupported method", "Status":405}`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := bulkEvents(tt.backendResponse, tt.backendError)

			rec := httptest.NewRecorder()
			req, err := http.NewRequest("PATCH", dummyURL, bytes.NewBufferString(tt.reqBody))
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

func bulkEvents(response *v1.BulkResponse, err error) *events {
	mockLogBackend := &api.MockEventsBackend{}
	n := New(mockLogBackend)

	// mock backend to return the required backendEvent
	mockLogBackend.On("Create", mock.Anything,
		mock.AnythingOfType("api.ClusterInfo"), mock.AnythingOfType("[]v1.Event")).Return(response, err)
	// mock backend to return the required backendEvent
	mockLogBackend.On("UpdateDismissFlag", mock.Anything,
		mock.AnythingOfType("api.ClusterInfo"), mock.AnythingOfType("[]v1.Event")).Return(response, err)
	// mock backend to return the required backendEvent
	mockLogBackend.On("Delete", mock.Anything,
		mock.AnythingOfType("api.ClusterInfo"), mock.AnythingOfType("[]v1.Event")).Return(response, err)

	return n
}

func TestGetEvents(t *testing.T) {
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
		backendEvents   []v1.Event
		backendResponse *v1.BulkResponse
		backendError    error
		reqBody         string
		want            testResult
	}{
		// Failure to parse request and validate
		{
			name:          "malformed json",
			backendEvents: noEvents,
			backendError:  nil,
			reqBody:       "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON (at position 2)", "Status":400}`,
			},
		},

		// Get all Event logs
		{
			name:          "fetch all the events",
			backendEvents: multipleEvent,
			backendError:  nil,
			reqBody:       withinTimeRange,
			want:          testResult{false, 200, ""},
		},

		// Fails to get the events
		{
			name:          "fail to fetch the events",
			backendEvents: multipleEvent,
			backendError:  errors.New("any error"),
			reqBody:       withinTimeRange,
			want:          testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := EventLog(tt.backendEvents, tt.backendError)

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
				wantBody = marshalResponse(t, tt.backendEvents)
			}
			assert.Equal(t, tt.want.httpStatus, rec.Result().StatusCode)
			assert.JSONEq(t, wantBody, string(bodyBytes))
		})
	}
}

func EventLog(response []v1.Event, err error) *events {
	mockEventBackend := &api.MockEventsBackend{}
	n := New(mockEventBackend)

	// mock backend to return the required backendAudit
	mockEventBackend.On("List", mock.Anything,
		mock.AnythingOfType("api.ClusterInfo"), mock.AnythingOfType("*v1.EventParams")).Return(&v1.List[v1.Event]{Items: response}, err)

	return n
}

func marshalResponse(t *testing.T, logs []v1.Event) string {
	response := v1.List[v1.Event]{}
	response.Items = logs
	newData, err := json.Marshal(response)
	require.NoError(t, err)
	return string(newData)
}
