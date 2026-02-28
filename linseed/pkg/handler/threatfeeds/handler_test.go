// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package threatfeeds

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

func TestIPSetBulkIngestion(t *testing.T) {
	type testResult struct {
		wantErr    bool
		httpStatus int
		errorMsg   string
	}

	tests := []struct {
		name            string
		backendIpSets   []v1.IPSetThreatFeed
		backendResponse *v1.BulkResponse
		backendError    error
		reqBody         string
		want            testResult
	}{
		// Failure to parse request and validate
		{
			name:            "malformed json",
			backendIpSets:   noIpSet,
			backendError:    nil,
			backendResponse: nil,
			reqBody:         "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON", "Status":400}`,
			},
		},

		// Ingest all threat feeds
		{
			name:            "ingest threat feed",
			backendIpSets:   ipSets,
			backendError:    nil,
			backendResponse: bulkResponseSuccess,
			reqBody:         testutils.MarshalBulkParams[v1.IPSetThreatFeed](ipSets),
			want:            testResult{false, 200, ""},
		},

		// Fails to ingest all threat feeds
		{
			name:            "fail to ingest all thread feeds",
			backendIpSets:   ipSets,
			backendError:    errors.New("any error"),
			backendResponse: nil,
			reqBody:         testutils.MarshalBulkParams[v1.IPSetThreatFeed](ipSets),
			want:            testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},

		// Ingest some threat feeds
		{
			name:            "ingest some threat feeds",
			backendIpSets:   ipSets,
			backendError:    nil,
			backendResponse: bulkResponsePartialSuccess,
			reqBody:         testutils.MarshalBulkParams[v1.IPSetThreatFeed](ipSets),
			want:            testResult{false, 200, ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := bulkThreatFeeds(tt.backendResponse, tt.backendError)

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

func TestDomainSetBulkIngestion(t *testing.T) {
	type testResult struct {
		wantErr    bool
		httpStatus int
		errorMsg   string
	}

	tests := []struct {
		name              string
		backendDomainSets []v1.DomainNameSetThreatFeed
		backendResponse   *v1.BulkResponse
		backendError      error
		reqBody           string
		want              testResult
	}{
		// Failure to parse request and validate
		{
			name:              "malformed json",
			backendDomainSets: noDomainSet,
			backendError:      nil,
			backendResponse:   nil,
			reqBody:           "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON", "Status":400}`,
			},
		},

		// Ingest all threat feeds
		{
			name:              "ingest threat feed",
			backendDomainSets: domainSets,
			backendError:      nil,
			backendResponse:   bulkResponseSuccess,
			reqBody:           testutils.MarshalBulkParams[v1.DomainNameSetThreatFeed](domainSets),
			want:              testResult{false, 200, ""},
		},

		// Fails to ingest all threat feeds
		{
			name:              "fail to ingest all thread feeds",
			backendDomainSets: domainSets,
			backendError:      errors.New("any error"),
			backendResponse:   nil,
			reqBody:           testutils.MarshalBulkParams[v1.DomainNameSetThreatFeed](domainSets),
			want:              testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},

		// Ingest some threat feeds
		{
			name:              "ingest some threat feeds",
			backendDomainSets: domainSets,
			backendError:      nil,
			backendResponse:   bulkResponsePartialSuccess,
			reqBody:           testutils.MarshalBulkParams[v1.DomainNameSetThreatFeed](domainSets),
			want:              testResult{false, 200, ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := bulkThreatFeeds(tt.backendResponse, tt.backendError)

			rec := httptest.NewRecorder()
			req, err := http.NewRequest("POST", dummyURL, bytes.NewBufferString(tt.reqBody))
			req.Header.Set("Content-Type", "application/x-ndjson")
			require.NoError(t, err)

			b.APIS()[4].Handler.ServeHTTP(rec, req)

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

func TestIPSetBulkDelete(t *testing.T) {
	type testResult struct {
		wantErr    bool
		httpStatus int
		errorMsg   string
	}

	tests := []struct {
		name            string
		backendIpSets   []v1.IPSetThreatFeed
		backendResponse *v1.BulkResponse
		backendError    error
		reqBody         string
		want            testResult
	}{
		// Failure to parse request and validate
		{
			name:            "malformed json",
			backendIpSets:   noIpSet,
			backendError:    nil,
			backendResponse: nil,
			reqBody:         "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON", "Status":400}`,
			},
		},

		// Delete all threat feeds
		{
			name:            "delete threat feed",
			backendIpSets:   ipSets,
			backendError:    nil,
			backendResponse: bulkResponseSuccess,
			reqBody:         testutils.MarshalBulkParams[v1.IPSetThreatFeed](ipSets),
			want:            testResult{false, 200, ""},
		},

		// Fails to delete all threat feeds
		{
			name:            "fail to delete all thread feeds",
			backendIpSets:   ipSets,
			backendError:    errors.New("any error"),
			backendResponse: nil,
			reqBody:         testutils.MarshalBulkParams[v1.IPSetThreatFeed](ipSets),
			want:            testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},

		// Delete some threat feeds
		{
			name:            "delete some threat feeds",
			backendIpSets:   ipSets,
			backendError:    nil,
			backendResponse: bulkResponsePartialSuccess,
			reqBody:         testutils.MarshalBulkParams[v1.IPSetThreatFeed](ipSets),
			want:            testResult{false, 200, ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := bulkThreatFeeds(tt.backendResponse, tt.backendError)

			rec := httptest.NewRecorder()
			req, err := http.NewRequest("DELETE", dummyURL, bytes.NewBufferString(tt.reqBody))
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

func TestDomainSetBulkDelete(t *testing.T) {
	type testResult struct {
		wantErr    bool
		httpStatus int
		errorMsg   string
	}

	tests := []struct {
		name              string
		backendDomainSets []v1.DomainNameSetThreatFeed
		backendResponse   *v1.BulkResponse
		backendError      error
		reqBody           string
		want              testResult
	}{
		// Failure to parse request and validate
		{
			name:              "malformed json",
			backendDomainSets: noDomainSet,
			backendError:      nil,
			backendResponse:   nil,
			reqBody:           "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON", "Status":400}`,
			},
		},

		// Delete all threat feeds
		{
			name:              "delete threat feed",
			backendDomainSets: domainSets,
			backendError:      nil,
			backendResponse:   bulkResponseSuccess,
			reqBody:           testutils.MarshalBulkParams[v1.DomainNameSetThreatFeed](domainSets),
			want:              testResult{false, 200, ""},
		},

		// Fails to delete all threat feeds
		{
			name:              "fail to delete all thread feeds",
			backendDomainSets: domainSets,
			backendError:      errors.New("any error"),
			backendResponse:   nil,
			reqBody:           testutils.MarshalBulkParams[v1.DomainNameSetThreatFeed](domainSets),
			want:              testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},

		// Delete some threat feeds
		{
			name:              "delete some threat feeds",
			backendDomainSets: domainSets,
			backendError:      nil,
			backendResponse:   bulkResponsePartialSuccess,
			reqBody:           testutils.MarshalBulkParams[v1.DomainNameSetThreatFeed](domainSets),
			want:              testResult{false, 200, ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := bulkThreatFeeds(tt.backendResponse, tt.backendError)

			rec := httptest.NewRecorder()
			req, err := http.NewRequest("DELETE", dummyURL, bytes.NewBufferString(tt.reqBody))
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

func bulkThreatFeeds(response *v1.BulkResponse, err error) *threatFeeds {
	mockIPSetBackend := &api.MockIPSetBackend{}
	mockDomainNameBackend := &api.MockDomainNameSetBackend{}
	n := New(mockIPSetBackend, mockDomainNameBackend)

	// mock backend to return the required backendRuntime
	mockIPSetBackend.On("Create", mock.Anything,
		mock.AnythingOfType("api.ClusterInfo"), mock.Anything).Return(response, err)
	mockIPSetBackend.On("Delete", mock.Anything,
		mock.AnythingOfType("api.ClusterInfo"), mock.Anything).Return(response, err)

	mockDomainNameBackend.On("Create", mock.Anything,
		mock.AnythingOfType("api.ClusterInfo"), mock.Anything).Return(response, err)
	mockDomainNameBackend.On("Delete", mock.Anything,
		mock.AnythingOfType("api.ClusterInfo"), mock.Anything).Return(response, err)

	return n
}

func TestGetIPSet(t *testing.T) {
	validRequest := `{"id": "any"}`

	type testResult struct {
		wantErr    bool
		httpStatus int
		errorMsg   string
	}

	tests := []struct {
		name            string
		backendIPSet    []v1.IPSetThreatFeed
		backendResponse *v1.BulkResponse
		backendError    error
		reqBody         string
		want            testResult
	}{
		// Failure to parse request and validate
		{
			name:         "malformed json",
			backendIPSet: noIpSet,
			backendError: nil,
			reqBody:      "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON (at position 2)", "Status":400}`,
			},
		},

		// Get all threat feeds
		{
			name:         "get all threat feeds",
			backendIPSet: ipSets,
			backendError: nil,
			reqBody:      validRequest,
			want:         testResult{false, 200, ""},
		},

		// Fails to get threat feeds
		{
			name:         "fail to read all threat feeds",
			backendIPSet: ipSets,
			backendError: errors.New("any error"),
			reqBody:      validRequest,
			want:         testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := threatFeedsRead(tt.backendIPSet, nil, tt.backendError)

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
				wantBody = marshalResponse(t, tt.backendIPSet)
			}
			assert.Equal(t, tt.want.httpStatus, rec.Result().StatusCode)
			assert.JSONEq(t, wantBody, string(bodyBytes))
		})
	}
}

func TestGetDomainSet(t *testing.T) {
	validRequest := `{"id": "any"}`

	type testResult struct {
		wantErr    bool
		httpStatus int
		errorMsg   string
	}

	tests := []struct {
		name              string
		backendDomainSets []v1.DomainNameSetThreatFeed
		backendResponse   *v1.BulkResponse
		backendError      error
		reqBody           string
		want              testResult
	}{
		// Failure to parse request and validate
		{
			name:              "malformed json",
			backendDomainSets: noDomainSet,
			backendError:      nil,
			reqBody:           "{#}",
			want: testResult{
				true, 400,
				`{"Msg":"Request body contains badly-formed JSON (at position 2)", "Status":400}`,
			},
		},

		// Get all threat feeds
		{
			name:              "get all threat feeds",
			backendDomainSets: domainSets,
			backendError:      nil,
			reqBody:           validRequest,
			want:              testResult{false, 200, ""},
		},

		// Fails to get threat feeds
		{
			name:              "fail to read all threat feeds",
			backendDomainSets: domainSets,
			backendError:      errors.New("any error"),
			reqBody:           validRequest,
			want:              testResult{true, 500, `{"Msg":"any error", "Status":500}`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTest(t)()

			b := threatFeedsRead(nil, tt.backendDomainSets, tt.backendError)

			rec := httptest.NewRecorder()
			req, err := http.NewRequest("POST", dummyURL, bytes.NewBufferString(tt.reqBody))
			req.Header.Set("Content-Type", "application/json")
			require.NoError(t, err)

			b.APIS()[3].Handler.ServeHTTP(rec, req)

			bodyBytes, err := io.ReadAll(rec.Body)
			require.NoError(t, err)

			var wantBody string
			if tt.want.wantErr {
				wantBody = tt.want.errorMsg
			} else {
				wantBody = marshalResponse(t, tt.backendDomainSets)
			}
			assert.Equal(t, tt.want.httpStatus, rec.Result().StatusCode)
			assert.JSONEq(t, wantBody, string(bodyBytes))
		})
	}
}

func threatFeedsRead(ipSet []v1.IPSetThreatFeed, domainSet []v1.DomainNameSetThreatFeed, err error) *threatFeeds {
	mockIPSetBackend := &api.MockIPSetBackend{}
	mockDomainSetBackend := &api.MockDomainNameSetBackend{}
	n := New(mockIPSetBackend, mockDomainSetBackend)

	// mock backend to return the required response
	mockIPSetBackend.On("List", mock.Anything,
		mock.AnythingOfType("api.ClusterInfo"),
		&v1.IPSetThreatFeedParams{ID: "any"}).Return(&v1.List[v1.IPSetThreatFeed]{Items: ipSet}, err)
	// mock backend to return the required response
	mockDomainSetBackend.On("List", mock.Anything,
		mock.AnythingOfType("api.ClusterInfo"),
		&v1.DomainNameSetThreatFeedParams{ID: "any"}).Return(&v1.List[v1.DomainNameSetThreatFeed]{Items: domainSet}, err)

	return n
}

func marshalResponse[T any](t *testing.T, items []T) string {
	response := v1.List[T]{}
	response.Items = items
	newData, err := json.Marshal(response)
	require.NoError(t, err)
	return string(newData)
}
