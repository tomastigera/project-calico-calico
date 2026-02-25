// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package middleware

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/json"
	lapi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	lmaapi "github.com/projectcalico/calico/lma/pkg/apis/v1"
	"github.com/projectcalico/calico/lma/pkg/httputils"
	querycacheclient "github.com/projectcalico/calico/queryserver/pkg/querycache/client"
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

var _ = Describe("", func() {
	var (
		req *http.Request
		ctx context.Context
	)

	BeforeEach(func() {
		ctx = context.Background()
	})

	It("test buildQueryServerEndpointKeyString result", func() {
		result := buildQueryServerEndpointKeyString("ns", "name", "nameaggr")
		Expect(result).To(Equal("(.*?ns/.*?-name)"))

		result = buildQueryServerEndpointKeyString("ns", "-", "nameaggr")
		Expect(result).To(Equal("(.*?ns/.*?-nameaggr)"))
	})

	Context("test validateEndpointsAggregationRequest", func() {
		DescribeTable("validate ClusterName",
			func(clusterName, clusterIdHeader, expectedCluster string) {
				endpointReq := &EndpointsAggregationRequest{
					TimeRange: &lmaapi.TimeRange{
						From: time.Now(),
						To:   time.Now(),
					},
				}

				if len(clusterName) > 0 {
					endpointReq.ClusterName = clusterName
				}

				reqBodyBytes, err := json.Marshal(endpointReq)
				Expect(err).ShouldNot(HaveOccurred())

				req, err = http.NewRequest("POST", "https://test", bytes.NewBuffer(reqBodyBytes))
				Expect(err).ShouldNot(HaveOccurred())

				if len(clusterIdHeader) > 0 {
					req.Header.Add("x-cluster-id", clusterIdHeader)
				}

				err = validateEndpointsAggregationRequest(req, endpointReq)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(endpointReq.ClusterName).To(Equal(expectedCluster))

			},
			Entry("should not change ClusterName if it is set in the request body", "cluster-a", "cluster-b", "cluster-a"),
			Entry("should set ClusterName from request header if it is not provided in the request body", "", "cluster-b", "cluster-b"),
			Entry("should set ClusterName to default if it neither provided in the request body nor header", "", "", "cluster"),
		)

		DescribeTable("validate ShowDeniedEndpoints",
			func(filterDeniedEndpoints bool, endpointList []string, expectErr bool, errMsg string) {

				epReq := EndpointsAggregationRequest{
					ClusterName: "",
					TimeRange: &lmaapi.TimeRange{
						From: time.Now(),
						To:   time.Now(),
					},
					Timeout: nil,
				}

				epReq.ShowDeniedEndpoints = filterDeniedEndpoints

				if len(endpointList) > 0 {
					epReq.EndpointsList = endpointList
				}

				reqBodyBytes, err := json.Marshal(epReq)
				Expect(err).ShouldNot(HaveOccurred())

				req, err = http.NewRequest("POST", "https://test", bytes.NewBuffer(reqBodyBytes))
				Expect(err).ShouldNot(HaveOccurred())

				err = validateEndpointsAggregationRequest(req, &epReq)

				if expectErr {
					Expect(err).Should(HaveOccurred())
					Expect(err.(*httputils.HttpStatusError).Msg).To(Equal(errMsg))
				} else {
					Expect(err).ShouldNot(HaveOccurred())
				}

			},
			Entry("pass validation when both ShowDeniedEndpoints and endpointlist are not set",
				false, []string{}, false, nil),
			Entry("pass validation when only endpointlist is provided ",
				false, []string{"endpoint1"}, false, nil),
			Entry("fail validation when both ShowDeniedEndpoints and endpointlist are provided",
				true, []string{"endpoint1"}, true, "both ShowDeniedEndpoints and endpointList can not be provided in the same request"),
			Entry("pass validation when ShowDeniedEndpoints is set to true",
				true, []string{}, false, nil),
		)

		DescribeTable("validate TimeOut",
			func(timeout, expectedTimeout *v1.Duration) {
				endpointReq := &EndpointsAggregationRequest{
					TimeRange: &lmaapi.TimeRange{
						From: time.Now(),
						To:   time.Now(),
					},
				}

				if timeout != nil {
					endpointReq.Timeout = timeout
				}

				reqBodyBytes, err := json.Marshal(endpointReq)
				Expect(err).ShouldNot(HaveOccurred())

				req, err = http.NewRequest("POST", "https://test", bytes.NewBuffer(reqBodyBytes))
				Expect(err).ShouldNot(HaveOccurred())

				err = validateEndpointsAggregationRequest(req, endpointReq)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(endpointReq.Timeout).To(Equal(expectedTimeout))
			},
			Entry("should not change timeout if provided",
				&v1.Duration{Duration: 10 * time.Second}, &v1.Duration{Duration: 10 * time.Second}),
			Entry("should set default timeout if not provided",
				nil, &v1.Duration{Duration: DefaultRequestTimeout}),
		)

		testTime := time.Now().UTC()
		DescribeTable("validate TimeRange",
			func(timerange *lmaapi.TimeRange, expectedFrom *time.Time, expectErr bool, errMsg string) {
				endpointReq := &EndpointsAggregationRequest{}

				if timerange != nil {
					endpointReq.TimeRange = timerange
				}

				reqBodyBytes, err := json.Marshal(endpointReq)
				Expect(err).ShouldNot(HaveOccurred())

				req, err = http.NewRequest("POST", "https://test", bytes.NewBuffer(reqBodyBytes))
				Expect(err).ShouldNot(HaveOccurred())

				err = validateEndpointsAggregationRequest(req, endpointReq)

				if expectErr {
					Expect(err).Should(HaveOccurred())
					Expect(err.(*httputils.HttpStatusError).Err).To(Equal(errors.New(errMsg)))
				} else {
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpointReq.TimeRange.To).ToNot(BeNil())
					Expect(endpointReq.TimeRange.From).ToNot(BeNil())
				}

			},
			Entry("should fail if timeRange.To is not set",
				&lmaapi.TimeRange{From: time.Now().UTC()}, nil, true, TimeRangeError),
			Entry("should fail if timeRange.From is not set",
				&lmaapi.TimeRange{From: testTime}, &testTime, true, TimeRangeError),
			Entry("should not set timeRange if timeRange in empty",
				&lmaapi.TimeRange{}, nil, true, TimeRangeError),
			Entry("should not fail if both timeRange.From and timeRange.To are set",
				&lmaapi.TimeRange{From: testTime, To: time.Now()}, &testTime, false, ""),
		)
	})

	Context("test getQueryServerRequestParams", func() {
		DescribeTable("validate getQueryServerRequestParams result",
			func(endpoints []string, showDeniedEndpoint bool, expectedList []string) {
				params := EndpointsAggregationRequest{
					ShowDeniedEndpoints: showDeniedEndpoint,
				}

				queryEndpointsRespBody := getQueryServerRequestParams(&params, endpoints)

				Expect(queryEndpointsRespBody.EndpointsList).To(Equal(expectedList))

			},
			Entry("should not add endpoints list when endpoints map is nil", nil, false, nil),
			Entry("should add endpoints list when endpoints list is empty", []string{}, true, []string{}),
			Entry("should add endpoints list when endpoints map has values", []string{"pod1", "pod2", "pod10", "pod20"},
				true,
				[]string{"pod1", "pod2", "pod10", "pod20"}),
		)
	})

	Context("test buildFlowLogParamsForDeniedTrafficSearch", func() {
		It("policyMatch action=deny should be added to params when calling linseed", func() {
			req := &EndpointsAggregationRequest{}
			ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
			defer cancel()
			authReview := userAuthorizationReviewMock{
				verbs: []v3.AuthorizedResourceVerbs{},
				err:   nil,
			}
			pageNumber := 2
			pageSize := 1

			flParams, err := buildFlowLogParamsForDeniedTrafficSearch(ctx, authReview, req, pageNumber, pageSize)

			Expect(err).ShouldNot(HaveOccurred())
			Expect(flParams.PolicyMatches).ToNot(BeNil())
			Expect(flParams.PolicyMatches).To(HaveLen(1))
			Expect(*flParams.PolicyMatches[0].Action).To(Equal(lapi.FlowActionDeny))

		})
	})

	Context("test updateResults", func() {
		var (
			endpointsRespBody querycacheclient.QueryEndpointsResp
			deniedEndpoints   []string
		)
		BeforeEach(func() {
			deniedEndpoints = []string{".*ns1/.*-ep1", ".*ns2/.*-ep10"}

			endpointsRespBody = querycacheclient.QueryEndpointsResp{
				Count: 5,
				Items: []querycacheclient.Endpoint{
					{Name: "node1-ep1", Namespace: "ns1", Node: "node1", Pod: "ep1"},
					{Name: "node2-ep2", Namespace: "ns1", Node: "node2", Pod: "ep2"},
					{Name: "node1-ep10", Namespace: "ns2", Node: "node1", Pod: "ep10"},
					{Name: "node1-ep11", Namespace: "ns2", Node: "node1", Pod: "bp11"},
					{Name: "node2-ep10", Namespace: "ns3", Node: "node2", Pod: "ep10"},
				},
			}
		})
		It("should add hasDeniedTraffic: true for endpoints in the deniedEndponts map if flowAccess is true", func() {
			endpointsResponse, err := updateResults(&endpointsRespBody, deniedEndpoints, true)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(endpointsResponse.Count).To(Equal(5))

			for _, item := range endpointsResponse.Item {
				Expect(item.HasFlowAccess).To(BeTrue())
				if item.Namespace == "ns1" && item.Pod == "ep1" {
					Expect(*item.HasDeniedTraffic).To(BeTrue())
				} else if item.Namespace == "ns2" && item.Pod == "ep10" {
					Expect(*item.HasDeniedTraffic).To(BeTrue())
				} else {
					Expect(*item.HasDeniedTraffic).To(BeFalse())
				}
			}
		})
		It("should set hasDeniedTraffic to error if flowAccess is false", func() {
			endpointsResponse, err := updateResults(&endpointsRespBody, deniedEndpoints, false)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(endpointsResponse.Count).To(Equal(5))

			for _, item := range endpointsResponse.Item {
				Expect(item.HasDeniedTraffic).To(BeNil())
				Expect(item.HasFlowAccess).To(BeFalse())
				Expect(item.Warnings).To(HaveLen(1))
				Expect(item.Warnings[0]).To(Equal(flowAccessWarning))
			}
		})
	})

	Context("test deniedEndpointsRegex", func() {

		endpointsAggregatedReq := &EndpointsAggregationRequest{
			ClusterName: "cluster",
		}

		authReview := userAuthorizationReviewMock{
			verbs: []v3.AuthorizedResourceVerbs{
				{
					APIGroup: "",
					Resource: "flows",
					Verbs: []v3.AuthorizedResourceVerb{
						{
							Verb: "get",
						},
					},
				},
			},
			err: nil,
		}
		It("get deniedendpoints when there are denied flowlogs", func() {
			results := []rest.MockResult{
				{
					Body: lapi.List[lapi.FlowLog]{
						Items:     []lapi.FlowLog{},
						AfterKey:  nil,
						TotalHits: 0,
					},
				},
			}
			lsc := client.NewMockClient("", results...)

			deniedEndpoints, err := deniedEndpointsRegex(ctx, endpointsAggregatedReq, lsc, authReview)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(deniedEndpoints).To(HaveLen(0))
		})
		It("return empty slice when there is no denied flowlogs", func() {
			results := []rest.MockResult{
				{
					Body: lapi.List[lapi.FlowLog]{
						Items: []lapi.FlowLog{
							{
								SourceName:      "-",
								SourceNameAggr:  "ep-src-*",
								SourceNamespace: "ns-src",
								DestName:        "-",
								DestNameAggr:    "ep-dst-*",
								DestNamespace:   "ns-dst",
								Action:          "deny",
							},
						},
						AfterKey:  nil,
						TotalHits: 1,
					},
				},
			}
			lsc := client.NewMockClient("", results...)

			deniedEndpoints, err := deniedEndpointsRegex(ctx, endpointsAggregatedReq, lsc, authReview)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(deniedEndpoints).To(HaveLen(2))

		})

		It("should return nil as deniedEndpoints if user does not have \"get\" or \"list\" to \"flows\"", func() {
			authReviewNoGetToFlows := userAuthorizationReviewMock{
				verbs: []v3.AuthorizedResourceVerbs{
					{
						APIGroup: "",
						Resource: "flows",
						// no "list" or "get" in the rbac verbs
						Verbs: []v3.AuthorizedResourceVerb{},
					},
				},
				err: nil,
			}

			results := []rest.MockResult{
				{
					Body: lapi.List[lapi.FlowLog]{
						Items:     []lapi.FlowLog{},
						AfterKey:  nil,
						TotalHits: 0,
					},
				},
			}
			lsc := client.NewMockClient("", results...)

			deniedEndpoints, err := deniedEndpointsRegex(ctx, endpointsAggregatedReq, lsc, authReviewNoGetToFlows)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(deniedEndpoints).To(BeNil())
		})
	})

})
