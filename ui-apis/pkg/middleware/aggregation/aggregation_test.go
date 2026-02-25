// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package aggregation_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	lapi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	lmaapi "github.com/projectcalico/calico/lma/pkg/apis/v1"
	"github.com/projectcalico/calico/lma/pkg/httputils"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
	. "github.com/projectcalico/calico/ui-apis/pkg/middleware/aggregation"
)

// MockAuthorizer implements both Authorizer interface to allow mock results.
type MockAuthorizer struct {
	// Fill in by test.
	AuthorizationReviewResp    []v3.AuthorizedResourceVerbs
	AuthorizationReviewRespErr error

	// Filled in by backend processing.
	RequestData *RequestData
}

func (m *MockAuthorizer) PerformUserAuthorizationReview(ctx context.Context, rd *RequestData) ([]v3.AuthorizedResourceVerbs, error) {
	m.RequestData = rd
	return m.AuthorizationReviewResp, m.AuthorizationReviewRespErr
}

type MockLinseedResponse struct {
	LinseedResp map[string]json.RawMessage
	LinseedErr  error
}

var (
	timeFrom, _     = time.Parse(time.RFC3339, "2021-05-30T21:23:10Z")
	timeTo5Mins, _  = time.Parse(time.RFC3339, "2021-05-30T21:28:10Z")
	timeTo60Mins, _ = time.Parse(time.RFC3339, "2021-05-30T22:23:10Z")
)

var query5Mins, query5MinsNoTS, query60Mins lapi.FlowLogAggregationParams

func init() {
	// Initialize the expected flow aggregation params used in the tests.
	query5Mins = lapi.FlowLogAggregationParams{}
	query5Mins.TimeRange = &lmaapi.TimeRange{}
	query5Mins.TimeRange.From = timeFrom
	query5Mins.TimeRange.To = timeTo5Mins
	query5Mins.Permissions = []v3.AuthorizedResourceVerbs{
		{
			APIGroup: "projectcalico.org",
			Resource: "networksets",
			Verbs: []v3.AuthorizedResourceVerb{
				{
					Verb: "list",
					ResourceGroups: []v3.AuthorizedResourceGroup{
						{Tier: "", Namespace: "ns1"},
					},
				},
			},
		},
	}
	query5Mins.Selector = "dest_namespace = 'abc'"
	query5Mins.Aggregations = map[string]json.RawMessage{
		"agg1": json.RawMessage(`{"abc":"def"}`),
	}
	query5Mins.NumBuckets = 6

	// Make a copy that is not a time-series request.
	cp := query5Mins
	cp.NumBuckets = 0
	query5MinsNoTS = cp

	// 60min query, copy of 5 min query with different time
	query60Mins = lapi.FlowLogAggregationParams{}
	query60Mins.TimeRange = &lmaapi.TimeRange{}
	query60Mins.TimeRange.From = timeFrom
	query60Mins.TimeRange.To = timeTo60Mins
	query60Mins.Permissions = []v3.AuthorizedResourceVerbs{
		{
			APIGroup: "projectcalico.org",
			Resource: "networksets",
			Verbs: []v3.AuthorizedResourceVerb{
				{
					Verb: "list",
					ResourceGroups: []v3.AuthorizedResourceGroup{
						{Tier: "", Namespace: "ns1"},
					},
				},
			},
		},
	}
	query60Mins.Selector = "dest_namespace = 'abc'"
	query60Mins.Aggregations = map[string]json.RawMessage{
		"agg1": json.RawMessage(`{"abc":"def"}`),
	}
	query60Mins.NumBuckets = 6
}

const (
	bucketsNoTimeSeries = `{
            "buckets": [
                {
                    "start_time": "2021-05-30T21:23:10Z",
                    "aggregations": {
                        "agg1": {"abc": "123"}
                    }
                }
            ]
        }`
)

var _ = Describe("Aggregation tests", func() {
	DescribeTable("valid request parameters",
		func(ar v1.AggregationRequest, authz *MockAuthorizer, lsr *MockLinseedResponse, code int, params *lapi.FlowLogAggregationParams, resp string) {
			// Create a service graph.
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			results := []rest.MockResult{}
			if lsr != nil {
				if lsr.LinseedErr != nil {
					results = append(results, rest.MockResult{Err: lsr.LinseedErr, StatusCode: http.StatusInternalServerError})
				} else {
					results = append(results, rest.MockResult{Body: lsr.LinseedResp, StatusCode: http.StatusOK})
				}
			}
			c := client.NewMockClient("", results...)
			handler := NewFlowHandler(c, authz)

			// Marshal the request and create an HTTP request
			requestBytes, err := json.Marshal(ar)
			Expect(err).NotTo(HaveOccurred())
			body := io.NopCloser(bytes.NewReader(requestBytes))
			req, err := http.NewRequest("POST", "/aggregation", body)
			Expect(err).NotTo(HaveOccurred())
			req = req.WithContext(ctx)

			// Pass it through the handler
			writer := httptest.NewRecorder()
			handler.ServeHTTP(writer, req)
			Expect(writer.Code).To(Equal(code))

			// The remaining checks are only applicable if the response was 200 OK.
			if code != http.StatusOK {
				Expect(strings.TrimSpace(writer.Body.String())).To(Equal(resp))
				return
			}

			// Check the query matches.
			if authz.AuthorizationReviewRespErr == nil {
				// We only send a single query.
				requests := c.Requests()
				Expect(len(requests)).To(Equal(1))
				request := requests[0]
				res := request.Result
				Expect(res.Called).To(BeTrue())

				// Compare the params passed to Linseed.
				if params != nil {
					actualParams := request.GetParams().(*lapi.FlowLogAggregationParams)
					Expect(actualParams).NotTo(BeNil())
					Expect(*actualParams).To(Equal(*params))
				}
			}

			// Parse the response. Unmarshal into a generic map for easier comparison (also we haven't implemented
			// all the unmarshal methods required)
			var actual v1.AggregationResponse
			err = json.Unmarshal(writer.Body.Bytes(), &actual)
			Expect(err).NotTo(HaveOccurred())

			var expected v1.AggregationResponse
			err = json.Unmarshal([]byte(resp), &expected)
			Expect(err).NotTo(HaveOccurred())

			Expect(writer.Body.String()).To(MatchJSON(resp), writer.Body.String())
		},

		Entry("Simple request with selector, 5 min interval, no time series",
			v1.AggregationRequest{
				Cluster:           "",
				TimeRange:         &lmaapi.TimeRange{From: timeFrom, To: timeTo5Mins},
				Selector:          "dest_namespace = 'abc'",
				IncludeTimeSeries: false,
				Aggregations:      map[string]json.RawMessage{"agg1": json.RawMessage(`{"abc": "def"}`)},
				Timeout:           1000,
			},
			&MockAuthorizer{
				AuthorizationReviewResp: []v3.AuthorizedResourceVerbs{{
					APIGroup: "projectcalico.org",
					Resource: "networksets",
					Verbs: []v3.AuthorizedResourceVerb{{
						Verb: "list",
						ResourceGroups: []v3.AuthorizedResourceGroup{{
							Namespace: "ns1",
						}},
					}},
				}},
				AuthorizationReviewRespErr: nil,
			},
			&MockLinseedResponse{
				LinseedResp: map[string]json.RawMessage{
					"agg1": json.RawMessage(`{"abc": "123"}`),
				},
				LinseedErr: nil,
			},
			http.StatusOK,
			&query5MinsNoTS,
			bucketsNoTimeSeries,
		),

		Entry("Simple request with selector, 45 min interval, request time series",
			v1.AggregationRequest{
				Cluster:           "",
				TimeRange:         &lmaapi.TimeRange{From: timeFrom, To: timeTo60Mins},
				Selector:          "dest_namespace = 'abc'",
				IncludeTimeSeries: true,
				Aggregations:      map[string]json.RawMessage{"agg1": json.RawMessage(`{"abc": "def"}`)},
				Timeout:           1000,
			},
			&MockAuthorizer{
				AuthorizationReviewResp: []v3.AuthorizedResourceVerbs{{
					APIGroup: "projectcalico.org",
					Resource: "networksets",
					Verbs: []v3.AuthorizedResourceVerb{{
						Verb: "list",
						ResourceGroups: []v3.AuthorizedResourceGroup{{
							Namespace: "ns1",
						}},
					}},
				}},
				AuthorizationReviewRespErr: nil,
			},
			&MockLinseedResponse{
				LinseedResp: map[string]json.RawMessage{
					"tb": json.RawMessage(`{"buckets":[
                        {"key":1622409790,"agg1":{"abc": "def0"}},
                        {"key":1622410690,"agg1":{"abc": "def1"}},
                        {"key":1622411590,"agg1":{"abc": "def2"}},
                        {"key":1622412490,"agg1":{"abc": "def3"}}
                    ]}`),
				},
				LinseedErr: nil,
			},
			http.StatusOK,
			&query60Mins,
			`{
          "buckets": [
            {
              "start_time": "1970-01-19T18:40:09Z",
              "aggregations": {
                "agg1": {
                  "abc": "def0"
                }
              }
            },
            {
              "start_time": "1970-01-19T18:40:10Z",
              "aggregations": {
                "agg1": {
                  "abc": "def1"
                }
              }
            },
            {
              "start_time": "1970-01-19T18:40:11Z",
              "aggregations": {
                "agg1": {
                  "abc": "def2"
                }
              }
            },
            {
              "start_time": "1970-01-19T18:40:12Z",
              "aggregations": {
                "agg1": {
                  "abc": "def3"
                }
              }
            }
          ]
        }`,
		),

		Entry("Linseed responds with bad request",
			v1.AggregationRequest{
				Cluster:           "",
				TimeRange:         &lmaapi.TimeRange{From: timeFrom, To: timeTo60Mins},
				Selector:          "dest_namespace = 'abc'",
				IncludeTimeSeries: true,
				Aggregations:      map[string]json.RawMessage{"agg1": json.RawMessage("[]")},
				Timeout:           1000,
			},
			&MockAuthorizer{
				AuthorizationReviewResp: []v3.AuthorizedResourceVerbs{{
					APIGroup: "projectcalico.org",
					Resource: "networksets",
					Verbs: []v3.AuthorizedResourceVerb{{
						Verb: "list",
						ResourceGroups: []v3.AuthorizedResourceGroup{{
							Namespace: "ns1",
						}},
					}},
				}},
				AuthorizationReviewRespErr: nil,
			},
			&MockLinseedResponse{
				LinseedResp: nil,
				LinseedErr: &httputils.HttpStatusError{
					Status: http.StatusBadRequest,
					Msg:    "bad request",
				},
			},
			http.StatusBadRequest,
			nil,
			"bad request",
		),

		Entry("Linseed responds with empty request",
			v1.AggregationRequest{
				Cluster:           "",
				TimeRange:         &lmaapi.TimeRange{From: timeFrom, To: timeTo60Mins},
				Selector:          "dest_namespace = 'abc'",
				IncludeTimeSeries: true,
				Aggregations:      map[string]json.RawMessage{"agg1": json.RawMessage("[]")},
				Timeout:           1000,
			},
			&MockAuthorizer{
				AuthorizationReviewResp: []v3.AuthorizedResourceVerbs{{
					APIGroup: "projectcalico.org",
					Resource: "networksets",
					Verbs: []v3.AuthorizedResourceVerb{{
						Verb: "list",
						ResourceGroups: []v3.AuthorizedResourceGroup{{
							Namespace: "ns1",
						}},
					}},
				}},
				AuthorizationReviewRespErr: nil,
			},
			&MockLinseedResponse{
				LinseedResp: nil,
				LinseedErr:  nil,
			},
			http.StatusOK,
			nil,
			`{"buckets":[{"start_time":"2021-05-30T21:23:10Z","aggregations":null}]}`,
		),

		Entry("Forbidden response from authorization review",
			v1.AggregationRequest{
				Cluster:           "",
				TimeRange:         &lmaapi.TimeRange{From: timeFrom, To: timeTo60Mins},
				Selector:          "dest_namespace = 'abc'",
				IncludeTimeSeries: true,
				Aggregations:      map[string]json.RawMessage{"agg1": json.RawMessage("[]")},
				Timeout:           1000,
			},
			&MockAuthorizer{
				AuthorizationReviewResp: nil,
				AuthorizationReviewRespErr: &httputils.HttpStatusError{
					Status: http.StatusForbidden,
					Msg:    "Forbidden",
				},
			},
			&MockLinseedResponse{
				LinseedResp: nil,
				LinseedErr:  nil,
			},
			http.StatusForbidden,
			nil,
			"Forbidden",
		),

		Entry("Empty response from authorization review",
			v1.AggregationRequest{
				Cluster:           "",
				TimeRange:         &lmaapi.TimeRange{From: timeFrom, To: timeTo60Mins},
				Selector:          "dest_namespace = 'abc'",
				IncludeTimeSeries: true,
				Aggregations:      map[string]json.RawMessage{"agg1": json.RawMessage("[]")},
				Timeout:           1000,
			},
			&MockAuthorizer{
				AuthorizationReviewResp:    []v3.AuthorizedResourceVerbs{},
				AuthorizationReviewRespErr: nil,
			},
			&MockLinseedResponse{
				LinseedResp: nil,
				LinseedErr:  nil,
			},
			http.StatusForbidden,
			nil,
			"Forbidden",
		),
	)

	DescribeTable("invalid request parameters",
		func(reqest string, code int, resp string) {
			// Create a service graph.
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			authz := &MockAuthorizer{
				AuthorizationReviewRespErr: errors.New("should not hit this"),
			}

			results := []rest.MockResult{{Err: errors.New("should not hit this")}}
			c := client.NewMockClient("", results...)
			handler := NewFlowHandler(c, authz)

			// Marshal the request and create an HTTP request
			body := io.NopCloser(strings.NewReader(reqest))
			req, err := http.NewRequest("POST", "/aggregation", body)
			Expect(err).NotTo(HaveOccurred())
			req = req.WithContext(ctx)

			// Pass it through the handler
			writer := httptest.NewRecorder()
			handler.ServeHTTP(writer, req)
			Expect(writer.Code).To(Equal(code))
			Expect(strings.TrimSpace(writer.Body.String())).To(Equal(resp), writer.Body.String())
		},

		Entry("Missing time range",
			`{"aggregations": {"test": {}}}`,
			http.StatusBadRequest,
			"Request body contains invalid data: error with field TimeRange = '<nil>' (Reason: failed to validate Field: TimeRange because of Tag: required )",
		),

		Entry("Missing time range fields",
			`{"time_range": {}, "aggregations": {"test": {}}}`,
			http.StatusBadRequest,
			"Request body contains an invalid value for the time range: missing `to` and `from` fields",
		),
	)
})
