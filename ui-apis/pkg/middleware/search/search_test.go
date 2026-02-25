// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.
package search

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"

	lapi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	"github.com/projectcalico/calico/lma/pkg/httputils"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	"github.com/projectcalico/calico/lma/pkg/test/thirdpartymock"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
	"github.com/projectcalico/calico/ui-apis/pkg/middleware"
)

var (
	//go:embed testdata/valid_request_body_no_cluster.json
	validRequestBodyNoCluster string
	//go:embed testdata/valid_request_body_page_size_greater_than_lte.json
	validRequestBodyPageSizeGreaterThanLTE string
	//go:embed testdata/valid_request_body_page_size_less_than_gte.json
	validRequestBodyPageSizeLessThanGTE string
	//go:embed testdata/valid_request_body_only_from.json
	validRequestBodyOnlyFrom string
	//go:embed testdata/valid_request_body_only_to.json
	validRequestBodyOnlyTo string
	//go:embed testdata/invalid_request_body_time_range_contains_invalid_time_value.json
	invalidRequestBodyTimeRangeContainsInvalidTimeValue string

	//go:embed testdata/event_search_request_from_manager.json
	eventSearchRequestFromManager string
	//go:embed testdata/event_search_request.json
	eventSearchRequest string
	//go:embed testdata/event_search_response.json
	eventSearchResponse string
)

// The user authentication review mock struct implementing the authentication review interface.
type userAuthorizationReviewMock struct {
	verbs []v3.AuthorizedResourceVerbs
	err   error
}

// PerformReviewForElasticLogs wraps a mocked version of the authorization review method
// PerformReviewForElasticLogs.
func (a userAuthorizationReviewMock) PerformReview(
	ctx context.Context, cluster string,
) ([]v3.AuthorizedResourceVerbs, error) {
	return a.verbs, a.err
}

func mustParseTime(s string) time.Time {
	out, err := time.Parse(time.RFC3339, s)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return out
}

var _ = Describe("SearchElasticHits", func() {
	var (
		fakeClientSet  lmak8s.ClientSet
		mockDoer       *thirdpartymock.MockDoer
		userAuthReview userAuthorizationReviewMock
		ctx            context.Context

		server              *httptest.Server
		expectedQueryParams []byte
		linseedResponse     []byte
		linseedDelay        time.Duration
		linseedError        error
	)

	setLinseedResponse := func(searchResult any) {
		// Support passing a struct, or an already serialized
		// json blob.
		if byts, ok := searchResult.([]byte); !ok {
			byts, err := json.Marshal(searchResult)
			if err != nil {
				panic(err)
			}
			linseedResponse = byts
		} else {
			linseedResponse = byts
		}
	}

	setLinseedResponseError := func(e error) {
		linseedError = e
	}

	setExpectedQuery := func(p any) {
		// Support passing a struct, or an already serialized
		// json blob.
		if byts, ok := p.([]byte); !ok {
			byts, _ := json.Marshal(p)
			expectedQueryParams = byts
		} else {
			expectedQueryParams = byts
		}
	}

	setLinseedDelay := func(d time.Duration) {
		linseedDelay = d
	}

	type SomeLog struct {
		ID     string       `json:"id"`
		Index  string       `json:"index"`
		Source lapi.FlowLog `json:"source"`
	}

	startTime := time.Now()
	alertExceptions := v3.AlertExceptionList{
		Items: []v3.AlertException{
			// no expiry
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "alert-exception-no-expiry",
					CreationTimestamp: metav1.Now(),
				},
				Spec: v3.AlertExceptionSpec{
					Description: "AlertException no expiry",
					Selector:    "origin = origin1",
					StartTime:   metav1.Time{Time: startTime.Add(-time.Hour)},
				},
			},
			// not expired
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "alert-exception-not-expired",
					CreationTimestamp: metav1.Now(),
				},
				Spec: v3.AlertExceptionSpec{
					Description: "AlertException not expired",
					Selector:    "origin = origin2",
					StartTime:   metav1.Time{Time: startTime.Add(-time.Hour)},
					EndTime:     &metav1.Time{Time: startTime.Add(time.Hour)},
				},
			},
			// expired
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "alert-exception-expired",
					CreationTimestamp: metav1.Time{Time: metav1.Now().Add(-2 * time.Hour)}, // make this one expire
				},
				Spec: v3.AlertExceptionSpec{
					Description: "AlertException expired",
					Selector:    "origin = origin3",
					StartTime:   metav1.Time{Time: startTime.Add(-2 * time.Hour)},
					EndTime:     &metav1.Time{Time: startTime.Add(-time.Hour)},
				},
			},
		},
	}
	BeforeEach(func() {
		ctx = context.Background()

		// Create a mock server to mimic linseed.
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer GinkgoRecover()

			if expectedQueryParams != nil {
				// Test wants to assert on the query.
				reqBody, err := io.ReadAll(r.Body)
				Expect(err).ShouldNot(HaveOccurred())
				r.Body = io.NopCloser(bytes.NewBuffer(reqBody))

				var params, expectedParams lapi.FlowLogParams
				err = json.Unmarshal(reqBody, &params)
				Expect(err).ShouldNot(HaveOccurred())
				err = json.Unmarshal(expectedQueryParams, &expectedParams)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(params).To(Equal(expectedParams))
			}

			// Sleep a few milliseconds to make sure we populate the response time field.
			time.Sleep(5 * time.Millisecond)

			// Allows tests to simulate a delayed response.
			if linseedDelay != 0 {
				time.Sleep(linseedDelay)
			}

			if linseedError != nil {
				w.WriteHeader(500)
				httputils.JSONError(w, linseedError, 500)
			} else {
				w.WriteHeader(200)
				logrus.Warnf("Mock server called! Returning BODY=%s", linseedResponse)
				_, err := w.Write(linseedResponse)
				Expect(err).ShouldNot(HaveOccurred())
			}
		}))

		// fakeClientSet = datastore.NewClientSet(nil, fake.NewSimpleClientset().ProjectcalicoV3())
		mockClientSet := &lmak8s.MockClientSet{}
		mockClientSet.On("ProjectcalicoV3").Return(fake.NewSimpleClientset().ProjectcalicoV3()).Maybe()
		fakeClientSet = mockClientSet

		mockDoer = new(thirdpartymock.MockDoer)
		userAuthReview = userAuthorizationReviewMock{
			verbs: []v3.AuthorizedResourceVerbs{
				{
					APIGroup: "APIGroupVal1",
					Resource: "hostendpoints",
					Verbs: []v3.AuthorizedResourceVerb{
						{
							Verb: "list",
							ResourceGroups: []v3.AuthorizedResourceGroup{
								{
									Tier:      "tierVal1",
									Namespace: "namespaceVal1",
								},
								{
									Tier:      "tierVal2",
									Namespace: "namespaceVal2",
								},
							},
						},
						{
							Verb: "list",
							ResourceGroups: []v3.AuthorizedResourceGroup{
								{
									Tier:      "tierVal1",
									Namespace: "namespaceVal1",
								},
								{
									Tier:      "tierVal2",
									Namespace: "namespaceVal2",
								},
							},
						},
					},
				},
			},
			err: nil,
		}
	})

	AfterEach(func() {
		mockDoer.AssertExpectations(GinkgoT())
		expectedQueryParams = nil
		linseedResponse = nil
		linseedDelay = 0
		linseedError = nil
	})

	Context("/search request and response validation", func() {
		fromTime := time.Date(2021, 0o4, 19, 14, 25, 30, 169827009, time.Local)
		toTime := time.Date(2021, 0o4, 19, 15, 25, 30, 169827009, time.Local)

		// Configure response from mock linseed server.
		lsResp := lapi.List[lapi.FlowLog]{
			TotalHits: 2,
			Items: []lapi.FlowLog{
				{
					Timestamp: mustParseTime("2021-04-19T14:25:30.169827011-07:00").Unix(),
					StartTime: mustParseTime("2021-04-19T14:25:30.169821857-07:00").Unix(),
					EndTime:   mustParseTime("2021-04-19T14:25:30.169827009-07:00").Unix(),
					Action:    "action1",
					BytesIn:   int64(5456),
					BytesOut:  int64(48245),
				},
				{
					Timestamp: mustParseTime("2021-04-19T15:25:30.169827010-07:00").Unix(),
					StartTime: mustParseTime("2021-04-19T15:25:30.169821857-07:00").Unix(),
					EndTime:   mustParseTime("2021-04-19T15:25:30.169827009-07:00").Unix(),
					Action:    "action2",
					BytesIn:   int64(3436),
					BytesOut:  int64(68547),
				},
			},
		}

		// Set the expected query to linseed.
		lsQuery := &lapi.FlowLogParams{
			QueryParams: lapi.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: mustParseTime("2021-04-19T21:25:30Z"),
					To:   mustParseTime("2021-04-19T22:25:30Z"),
				},
				Timeout:     &metav1.Duration{Duration: 60 * time.Second},
				MaxPageSize: 100,
			},
			QuerySortParams: lapi.QuerySortParams{
				Sort: []lapi.SearchRequestSortBy{{Field: "test2", Descending: false}},
			},
			LogSelectionParams: lapi.LogSelectionParams{
				Selector: "",
				Permissions: []v3.AuthorizedResourceVerbs{
					{
						APIGroup: "APIGroupVal1",
						Resource: "hostendpoints",
						Verbs: []v3.AuthorizedResourceVerb{
							{
								Verb: "list",
								ResourceGroups: []v3.AuthorizedResourceGroup{
									{
										Tier:      "tierVal1",
										Namespace: "namespaceVal1",
									},
									{
										Tier:      "tierVal2",
										Namespace: "namespaceVal2",
									},
								},
							},
							{
								Verb: "list",
								ResourceGroups: []v3.AuthorizedResourceGroup{
									{
										Tier:      "tierVal1",
										Namespace: "namespaceVal1",
									},
									{
										Tier:      "tierVal2",
										Namespace: "namespaceVal2",
									},
								},
							},
						},
					},
				},
			},
		}

		// The expected resposne from the search handler.
		expectedJSONResponse := []*SomeLog{
			{
				ID:     "id1",
				Index:  "index1",
				Source: lsResp.Items[0],
			},
			{
				ID:     "id2",
				Index:  "index2",
				Source: lsResp.Items[1],
			},
		}

		It("Should return a valid search response for flow logs", func() {
			client, err := lsclient.NewClient("", rest.Config{URL: server.URL})
			Expect(err).NotTo(HaveOccurred())

			// Set expected query and mock response.
			setLinseedResponse(lsResp)
			setExpectedQuery(lsQuery)

			pageSize := 100
			params := &v1.FlowLogSearchRequest{
				CommonSearchRequest: v1.CommonSearchRequest{
					ClusterName: "cl_name_val",
					PageSize:    &pageSize,
					PageNum:     0,
					TimeRange: &lmav1.TimeRange{
						From: mustParseTime("2021-04-19T21:25:30Z"),
						To:   mustParseTime("2021-04-19T22:25:30Z"),
					},
					SortBy: []v1.SearchRequestSortBy{{
						Field:      "test",
						Descending: true,
					}, {
						Field:      "test2",
						Descending: false,
					}},
					Timeout: &metav1.Duration{Duration: 60 * time.Second},
				},
				PolicyMatches: []lapi.PolicyMatch{},
			}

			results, err := searchFlowLogs(ctx, client, params, userAuthReview)
			Expect(err).NotTo(HaveOccurred())
			Expect(results.NumPages).To(Equal(1))
			Expect(results.TotalHits).To(Equal(2))
			Expect(results.TimedOut).To(BeFalse())
			Expect(results.Took.Milliseconds()).To(BeNumerically(">", (int64(0))))
			var someLog *SomeLog
			for i, hit := range results.Hits {
				s, _ := hit.MarshalJSON()
				umerr := json.Unmarshal(s, &someLog)
				Expect(umerr).NotTo(HaveOccurred())
				Expect(someLog.Source.Timestamp).To(Equal(expectedJSONResponse[i].Source.Timestamp))
				Expect(someLog.Source.StartTime).To(Equal(expectedJSONResponse[i].Source.StartTime))
				Expect(someLog.Source.EndTime).To(Equal(expectedJSONResponse[i].Source.EndTime))
				Expect(someLog.Source.Action).To(Equal(expectedJSONResponse[i].Source.Action))
				Expect(someLog.Source.BytesIn).To(Equal(expectedJSONResponse[i].Source.BytesIn))
				Expect(someLog.Source.BytesOut).To(Equal(expectedJSONResponse[i].Source.BytesOut))
			}
		})

		It("Should return a valid search response (event request with filter)", func() {
			// TODO: Unskip once we've implemented.
			Skip("event filtering not yet implemented for Linseed")

			client, err := lsclient.NewClient("", rest.Config{URL: server.URL})
			Expect(err).NotTo(HaveOccurred())

			// Set expected query and mock response.
			setLinseedResponse(lsResp)

			// Set the expected query to linseed.
			setExpectedQuery(
				&lapi.FlowLogParams{
					QueryParams: lapi.QueryParams{
						TimeRange: &lmav1.TimeRange{
							From: mustParseTime("2022-01-24T00:00:00Z"),
							To:   mustParseTime("2022-01-31T23:59:59Z"),
						},
						Timeout:     &metav1.Duration{Duration: 60 * time.Second},
						MaxPageSize: 100,
					},
					QuerySortParams: lapi.QuerySortParams{
						Sort: []lapi.SearchRequestSortBy{{Field: "test2", Descending: false}},
					},

					LogSelectionParams: lapi.LogSelectionParams{
						Selector: "",
						Permissions: []v3.AuthorizedResourceVerbs{
							{
								APIGroup: "APIGroupVal1",
								Resource: "hostendpoints",
								Verbs: []v3.AuthorizedResourceVerb{
									{
										Verb: "list",
										ResourceGroups: []v3.AuthorizedResourceGroup{
											{
												Tier:      "tierVal1",
												Namespace: "namespaceVal1",
											},
											{
												Tier:      "tierVal2",
												Namespace: "namespaceVal2",
											},
										},
									},
									{
										Verb: "list",
										ResourceGroups: []v3.AuthorizedResourceGroup{
											{
												Tier:      "tierVal1",
												Namespace: "namespaceVal1",
											},
											{
												Tier:      "tierVal2",
												Namespace: "namespaceVal2",
											},
										},
									},
								},
							},
						},
					},
				},
			)

			pageSize := 100
			params := &v1.CommonSearchRequest{
				ClusterName: "cl_name_val",
				PageSize:    &pageSize,
				PageNum:     0,
				Filter: []json.RawMessage{
					json.RawMessage(`{"range":{"time":{"gte":"2022-01-24T00:00:00Z","lte":"2022-01-31T23:59:59Z"}}}`),
					json.RawMessage(`{"term":{"type":"global_alert"}}`),
				},
				SortBy: []v1.SearchRequestSortBy{{
					Field:      "time",
					Descending: true,
				}},
				Timeout: &metav1.Duration{Duration: 60 * time.Second},
			}

			results, err := searchEvents(ctx, client, params, userAuthReview, fakeClientSet)
			Expect(err).NotTo(HaveOccurred())
			Expect(results.NumPages).To(Equal(1))
			Expect(results.TotalHits).To(Equal(2))
			Expect(results.TimedOut).To(BeFalse())
			Expect(results.Took.Milliseconds()).To(BeNumerically(">", (int64(0))))
			var someLog *SomeLog
			for i, hit := range results.Hits {
				s, _ := hit.MarshalJSON()
				umerr := json.Unmarshal(s, &someLog)
				Expect(umerr).NotTo(HaveOccurred())
				Expect(someLog.Source.Timestamp).To(Equal(expectedJSONResponse[i].Source.Timestamp))
				Expect(someLog.Source.StartTime).To(Equal(expectedJSONResponse[i].Source.StartTime))
				Expect(someLog.Source.EndTime).To(Equal(expectedJSONResponse[i].Source.EndTime))
				Expect(someLog.Source.Action).To(Equal(expectedJSONResponse[i].Source.Action))
				Expect(someLog.Source.BytesIn).To(Equal(expectedJSONResponse[i].Source.BytesIn))
				Expect(someLog.Source.BytesOut).To(Equal(expectedJSONResponse[i].Source.BytesOut))
			}
		})

		It("Should return no hits when TotalHits are equal to zero", func() {
			client, err := lsclient.NewClient("", rest.Config{URL: server.URL})
			Expect(err).NotTo(HaveOccurred())

			setLinseedResponse(lapi.List[lapi.FlowLog]{
				TotalHits: 0,
				Items:     []lapi.FlowLog{},
			})

			pageSize := 100
			params := &v1.FlowLogSearchRequest{
				CommonSearchRequest: v1.CommonSearchRequest{
					ClusterName: "cl_name_val",
					PageSize:    &pageSize,
					PageNum:     0,
					TimeRange: &lmav1.TimeRange{
						From: fromTime,
						To:   toTime,
					},
					Timeout: &metav1.Duration{Duration: 60 * time.Second},
				},
			}

			results, err := searchFlowLogs(ctx, client, params, userAuthReview)
			Expect(err).NotTo(HaveOccurred())
			Expect(results.NumPages).To(Equal(1))
			Expect(results.Took.Milliseconds()).To(BeNumerically(">", (int64(0))))
			Expect(results.TotalHits).To(Equal(0))
			Expect(results.TimedOut).To(BeFalse())
			var emptyHitsResponse []json.RawMessage
			Expect(results.Hits).To(Equal(emptyHitsResponse))
		})

		It("Should return an error with data on timeout", func() {
			client, err := lsclient.NewClient("", rest.Config{URL: server.URL})
			Expect(err).NotTo(HaveOccurred())

			// Delay linseed response by 1 second.
			setLinseedDelay(1 * time.Second)

			pageSize := 100
			params := &v1.FlowLogSearchRequest{
				CommonSearchRequest: v1.CommonSearchRequest{
					ClusterName: "cl_name_val",
					PageSize:    &pageSize,
					PageNum:     0,
					TimeRange: &lmav1.TimeRange{
						From: fromTime,
						To:   toTime,
					},
					Timeout: &metav1.Duration{Duration: 5 * time.Millisecond}, // Timeout after just a few ms.
				},
			}

			ctx, cancel := context.WithTimeout(ctx, 5*time.Millisecond)
			defer cancel()

			results, err := searchFlowLogs(ctx, client, params, userAuthReview)
			Expect(err).To(HaveOccurred())
			var se *httputils.HttpStatusError
			Expect(errors.As(err, &se)).To(BeTrue())
			Expect(se.Status).To(Equal(500))
			Expect(strings.HasPrefix(se.Msg, "error performing search")).To(BeTrue())
			Expect(results).To(BeNil())
		})

		It("Should return an error when Linseed returns an error", func() {
			client, err := lsclient.NewClient("", rest.Config{URL: server.URL})
			Expect(err).NotTo(HaveOccurred())

			setLinseedResponseError(fmt.Errorf("An error!"))

			pageSize := 100
			params := &v1.FlowLogSearchRequest{
				CommonSearchRequest: v1.CommonSearchRequest{
					ClusterName: "cl_name_val",
					PageSize:    &pageSize,
					PageNum:     0,
					TimeRange: &lmav1.TimeRange{
						From: fromTime,
						To:   toTime,
					},
					Timeout: &metav1.Duration{Duration: 60 * time.Second},
				},
			}

			results, err := searchFlowLogs(ctx, client, params, userAuthReview)
			Expect(err).To(HaveOccurred())

			var httpErr *httputils.HttpStatusError
			Expect(errors.As(err, &httpErr)).To(BeTrue())
			Expect(httpErr.Status).To(Equal(500))
			Expect(strings.HasPrefix(httpErr.Msg, "error performing search")).To(BeTrue())
			Expect(results).To(BeNil())
		})
	})

	Context("defaultAndValidateCommonRequest defaulting and validating parseBody result", func() {
		It("Should parse x-cluster-id in the request header when cluster is missing in body", func() {
			r, err := http.NewRequest(
				http.MethodGet, "", bytes.NewReader([]byte(validRequestBodyNoCluster)))
			Expect(err).NotTo(HaveOccurred())
			r.Header.Add("x-cluster-id", "cluster-id-in-header")

			var w http.ResponseWriter
			searchRequest, err := middleware.ParseBody[v1.CommonSearchRequest](w, r)
			Expect(err).NotTo(HaveOccurred())
			err = defaultAndValidateCommonRequest(r, searchRequest)
			Expect(err).NotTo(HaveOccurred())
			Expect(searchRequest.ClusterName).To(Equal("cluster-id-in-header"))
		})

		It("Should return an error when validating a page size that is greater than lte", func() {
			r, err := http.NewRequest(
				http.MethodGet, "", bytes.NewReader([]byte(validRequestBodyPageSizeGreaterThanLTE)))
			Expect(err).NotTo(HaveOccurred())

			var w http.ResponseWriter
			searchRequest, err := middleware.ParseBody[v1.CommonSearchRequest](w, r)
			Expect(err).NotTo(HaveOccurred())
			err = defaultAndValidateCommonRequest(r, searchRequest)
			Expect(err).To(HaveOccurred())

			var se *httputils.HttpStatusError
			Expect(errors.As(err, &se)).To(BeTrue())
			Expect(se.Status).To(Equal(400))
			Expect(se.Msg).To(Equal("error with field PageSize = '1001' (Reason: failed to validate Field: PageSize because of Tag: lte )"))
		})

		It("Should return an error when validating a page size that is less than gte", func() {
			r, err := http.NewRequest(
				http.MethodGet, "", bytes.NewReader([]byte(validRequestBodyPageSizeLessThanGTE)))
			Expect(err).NotTo(HaveOccurred())

			var w http.ResponseWriter
			searchRequest, err := middleware.ParseBody[v1.CommonSearchRequest](w, r)
			Expect(err).NotTo(HaveOccurred())
			err = defaultAndValidateCommonRequest(r, searchRequest)
			Expect(err).To(HaveOccurred())

			var se *httputils.HttpStatusError
			Expect(errors.As(err, &se)).To(BeTrue())
			Expect(se.Status).To(Equal(400))
			Expect(se.Msg).To(Equal("error with field PageSize = '-1' (Reason: failed to validate Field: PageSize because of Tag: gt )"), se.Msg)
		})

		It("Should return an error when validating an invalid value for time_range value", func() {
			r, err := http.NewRequest(
				http.MethodGet, "", bytes.NewReader([]byte(invalidRequestBodyTimeRangeContainsInvalidTimeValue)))
			Expect(err).NotTo(HaveOccurred())

			var w http.ResponseWriter
			_, err = middleware.ParseBody[v1.CommonSearchRequest](w, r)
			Expect(err).To(HaveOccurred())

			var se *httputils.HttpStatusError
			Expect(errors.As(err, &se)).To(BeTrue())
			Expect(se.Status).To(Equal(400))
			Expect(se.Msg).To(Equal("Request body contains an invalid value for the \"time_range.from\" field (at position 20)"), se.Msg)
		})

		It("Should parse & validate request that have only from", func() {
			r, err := http.NewRequest(
				http.MethodGet, "", bytes.NewReader([]byte(validRequestBodyOnlyFrom)))
			Expect(err).NotTo(HaveOccurred())

			var w http.ResponseWriter
			searchRequest, err := middleware.ParseBody[v1.CommonSearchRequest](w, r)
			Expect(err).NotTo(HaveOccurred())
			err = defaultAndValidateCommonRequest(r, searchRequest)
			Expect(err).NotTo(HaveOccurred())

			Expect(searchRequest.TimeRange.From).NotTo(Equal(time.Time{}))
			Expect(searchRequest.TimeRange.To).NotTo(Equal(time.Time{}))
		})

		It("Should parse & validate request that have only to", func() {
			r, err := http.NewRequest(
				http.MethodGet, "", bytes.NewReader([]byte(validRequestBodyOnlyTo)))
			Expect(err).NotTo(HaveOccurred())

			var w http.ResponseWriter
			searchRequest, err := middleware.ParseBody[v1.CommonSearchRequest](w, r)
			Expect(err).NotTo(HaveOccurred())
			err = defaultAndValidateCommonRequest(r, searchRequest)
			Expect(err).NotTo(HaveOccurred())

			Expect(searchRequest.TimeRange.From).To(Equal(time.Time{}))
			Expect(searchRequest.TimeRange.To).NotTo(Equal(time.Time{}))
		})
	})

	Context("UpdateSelectorWithAlertExceptions() function", func() {
		It("should should update existing selector with alert exceptions selectors", func() {
			updatedSelector := UpdateSelectorWithAlertExceptions(&alertExceptions, "NOT dismissed = true")
			Expect(updatedSelector).To(Equal("(NOT dismissed = true) AND NOT (( origin = origin1 ) OR ( origin = origin2 ))"))
		})

		It("should should update empty selector with alert exceptions selectors", func() {
			updatedSelector := UpdateSelectorWithAlertExceptions(&alertExceptions, "")
			Expect(updatedSelector).To(Equal("NOT (( origin = origin1 ) OR ( origin = origin2 ))"))
		})

		It("should handle alert exceptions selector AND/OR conditions", func() {
			alertExceptions := v3.AlertExceptionList{
				Items: []v3.AlertException{
					// AND
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:              "alert-exception-and",
							CreationTimestamp: metav1.Now(),
						},
						Spec: v3.AlertExceptionSpec{
							Description: "AlertException all AND",
							Selector:    "origin = origin1 AND type = global_alert",
						},
					},
					// OR
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:              "alert-exception-or",
							CreationTimestamp: metav1.Now(),
						},
						Spec: v3.AlertExceptionSpec{
							Description: "AlertException OR",
							Selector:    "origin = origin2 OR type = waf",
						},
					},
					// mixed AND / OR
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:              "alert-exception-and-or",
							CreationTimestamp: metav1.Now(),
						},
						Spec: v3.AlertExceptionSpec{
							Description: "AlertException AND OR",
							Selector:    "origin = origin3 AND type = alert OR source_namespace = ns3",
						},
					},
				},
			}

			updatedSelector := UpdateSelectorWithAlertExceptions(&alertExceptions, "NOT dismissed = true")
			Expect(updatedSelector).To(Equal("(NOT dismissed = true) AND NOT (( origin = origin1 AND type = global_alert ) OR ( origin = origin2 OR type = waf ) OR ( origin = origin3 AND type = alert OR source_namespace = ns3 ))"))
		})

		It("should skip invalid alert exceptions selector", func() {
			alertExceptions := v3.AlertExceptionList{
				Items: []v3.AlertException{
					// valid selector
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:              "alert-exception-valid-selector",
							CreationTimestamp: metav1.Now(),
						},
						Spec: v3.AlertExceptionSpec{
							Description: "AlertException valid selector",
							Selector:    "origin = origin1",
						},
					},
					// invalid selector
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:              "alert-exception-invalid-selector",
							CreationTimestamp: metav1.Now(),
						},
						Spec: v3.AlertExceptionSpec{
							Description: "AlertException invalid selector",
							Selector:    "invalid selector",
						},
					},
				},
			}
			updatedSelector := UpdateSelectorWithAlertExceptions(&alertExceptions, "NOT dismissed = true")
			Expect(updatedSelector).To(Equal("(NOT dismissed = true) AND NOT ( origin = origin1 )"))
		})
	})

	Context("/events/search request and response validation", func() {
		BeforeEach(func() {
			// Create a mock server to mimic linseed. We use a different one here from the root Describe
			// in order to handle event specific changes in logic.
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer GinkgoRecover()

				if expectedQueryParams != nil {
					// Test wants to assert on the query.
					reqBody, err := io.ReadAll(r.Body)
					Expect(err).ShouldNot(HaveOccurred())
					r.Body = io.NopCloser(bytes.NewBuffer(reqBody))

					var params, expectedParams lapi.EventParams
					err = json.Unmarshal(reqBody, &params)
					Expect(err).ShouldNot(HaveOccurred())
					err = json.Unmarshal(expectedQueryParams, &expectedParams)

					logrus.Infof("REQ: %s", string(reqBody))
					Expect(err).ShouldNot(HaveOccurred())
					Expect(params).To(Equal(expectedParams))
				}

				// Sleep a few milliseconds to make sure we populate the response time field.
				time.Sleep(5 * time.Millisecond)

				// Allows tests to simulate a delayed response.
				if linseedDelay != 0 {
					time.Sleep(linseedDelay)
				}

				if linseedError != nil {
					w.WriteHeader(500)
					httputils.JSONError(w, linseedError, 500)
				} else {
					w.WriteHeader(200)
					logrus.Warnf("Mock server called! Returning BODY=%s", linseedResponse)
					_, err := w.Write(linseedResponse)
					Expect(err).ShouldNot(HaveOccurred())
				}
			}))
		})

		testAlertExceptionsInSearchRequests := func(requestFromManager string, eventSearchRequest string, eventSearchResponse string) {
			client, err := lsclient.NewClient("", rest.Config{URL: server.URL})
			Expect(err).NotTo(HaveOccurred())

			// set the search response.
			setLinseedResponse([]byte(eventSearchResponse))
			setExpectedQuery([]byte(eventSearchRequest))

			// create some alert exceptions
			for _, alertException := range alertExceptions.Items {
				_, err := fakeClientSet.ProjectcalicoV3().AlertExceptions().Create(context.Background(), &alertException, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
			}

			// validate responses
			req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader([]byte(requestFromManager)))
			req = req.Clone(request.WithUser(context.Background(), &user.DefaultInfo{Name: "test"}))
			Expect(err).NotTo(HaveOccurred())

			mockClientSetFactory := &lmak8s.MockClientSetFactory{}
			mockClientSetFactory.On("NewClientSetForUser", mock.Anything, "cluster").Return(fakeClientSet, nil)
			// mockClientSet.On("ProjectcalicoV3").Return(fake.NewSimpleClientset().ProjectcalicoV3())

			rr := httptest.NewRecorder()
			handler := SearchHandler(SearchTypeEvents, userAuthReview, mockClientSetFactory, client)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusOK))

			var resp v1.SearchResponse
			err = json.Unmarshal(rr.Body.Bytes(), &resp)
			Expect(err).NotTo(HaveOccurred())

			Expect(resp.Hits).To(HaveLen(2))
			Expect(resp.NumPages).To(Equal(1))
			Expect(resp.TimedOut).To(BeFalse())
			Expect(resp.TotalHits).To(Equal(2))
		}

		It("should inject alert exceptions in search request with a selector", func() {
			testAlertExceptionsInSearchRequests(eventSearchRequestFromManager, eventSearchRequest, eventSearchResponse)
		})

		It("should return error when request is not GET or POST", func() {
			client, err := lsclient.NewClient("", rest.Config{URL: server.URL})
			Expect(err).NotTo(HaveOccurred())

			req, err := http.NewRequest(http.MethodPatch, "", bytes.NewReader([]byte("any")))
			req = req.Clone(request.WithUser(context.Background(), &user.DefaultInfo{Name: "test"}))
			Expect(err).NotTo(HaveOccurred())

			mockClientSetFactory := &lmak8s.MockClientSetFactory{}
			mockClientSetFactory.On("NewClientSetForUser", mock.Anything, "cluster").Return(fakeClientSet, nil)

			rr := httptest.NewRecorder()
			handler := SearchHandler(SearchTypeEvents, userAuthReview, mockClientSetFactory, client)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusMethodNotAllowed))
		})

		It("should return error when request body is not valid", func() {
			client, err := lsclient.NewClient("", rest.Config{URL: server.URL})
			Expect(err).NotTo(HaveOccurred())

			req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader([]byte("invalid-json-body")))
			req = req.Clone(request.WithUser(context.Background(), &user.DefaultInfo{Name: "test"}))
			Expect(err).NotTo(HaveOccurred())

			mockClientSetFactory := &lmak8s.MockClientSetFactory{}
			mockClientSetFactory.On("NewClientSetForUser", mock.Anything, "cluster").Return(fakeClientSet, nil)

			rr := httptest.NewRecorder()
			handler := SearchHandler(SearchTypeEvents, userAuthReview, mockClientSetFactory, client)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusBadRequest))
		})

		It("should return error when request body is not valid", func() {
			client, err := lsclient.NewClient("", rest.Config{URL: server.URL})
			Expect(err).NotTo(HaveOccurred())

			req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader([]byte("{\"policy_matches\": [{}]}")))
			req = req.Clone(request.WithUser(context.Background(), &user.DefaultInfo{Name: "test"}))
			Expect(err).NotTo(HaveOccurred())

			mockClientSetFactory := &lmak8s.MockClientSetFactory{}
			mockClientSetFactory.On("NewClientSetForUser", mock.Anything, "cluster").Return(fakeClientSet, nil)

			rr := httptest.NewRecorder()
			handler := SearchHandler(SearchTypeEvents, userAuthReview, mockClientSetFactory, client)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusBadRequest))
		})
	})
})
