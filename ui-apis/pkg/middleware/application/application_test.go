// Copyright (c) 2022 Tigera, Inc. All rights reserved.
package application

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	libcalicov3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/json"
	lapi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
	"github.com/projectcalico/calico/ui-apis/test/thirdpartymock"
)

var (
	// requests from manager to ui-apis
	//go:embed testdata/application_request_from_manager.json
	ApplicationRequest string
	//go:embed testdata/application_request_with_selector_from_manager.json
	ApplicationRequestWithSelector string

	// responses from elastic to ui-apis
	//go:embed testdata/l7_response.json
	l7Response string
	//go:embed testdata/l7_response_zero_duration.json
	l7ResponseZeroDuration string
	//go:embed testdata/l7_response_with_namespace.json
	l7ResponseWithNamespace string
)

// The user authorization review mock struct implementing the authentication review interface.
type userAuthorizationReviewMock struct {
	verbs []libcalicov3.AuthorizedResourceVerbs
	err   error
}

// PerformReviewForElasticLogs wraps a mocked version of the authorization review method
// PerformReviewForElasticLogs.
func (a userAuthorizationReviewMock) PerformReview(
	ctx context.Context, cluster string,
) ([]libcalicov3.AuthorizedResourceVerbs, error) {
	return a.verbs, a.err
}

var _ = Describe("Application middleware tests", func() {
	var (
		mockDoer       *thirdpartymock.MockDoer
		userAuthReview userAuthorizationReviewMock
	)

	BeforeEach(func() {
		mockDoer = new(thirdpartymock.MockDoer)
		userAuthReview = userAuthorizationReviewMock{
			verbs: []libcalicov3.AuthorizedResourceVerbs{
				{
					APIGroup: "api-group-1",
					Resource: "pods",
					Verbs: []libcalicov3.AuthorizedResourceVerb{
						{
							Verb: "list",
							ResourceGroups: []libcalicov3.AuthorizedResourceGroup{
								{Tier: "tier-1"},
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
	})

	Context("Elasticsearch /services request and response validation", func() {
		It("should return a valid services response", func() {
			// Unmarshal L7 response
			response := lapi.List[lapi.L7Log]{}
			err := json.Unmarshal([]byte(l7Response), &response)
			Expect(err).NotTo(HaveOccurred())

			// Build mock response from Linseed.
			results := []rest.MockResult{}
			results = append(results, rest.MockResult{
				Body: lapi.List[lapi.L7Log]{
					Items:     response.Items,
					TotalHits: response.TotalHits,
				},
			})

			// mock linseed client
			lsc := client.NewMockClient("", results...)

			// validate responses
			req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader([]byte(ApplicationRequest)))
			Expect(err).NotTo(HaveOccurred())

			rr := httptest.NewRecorder()
			handler := ApplicationHandler(userAuthReview, lsc, ApplicationTypeService)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusOK))

			var resp v1.ServiceResponse
			err = json.Unmarshal(rr.Body.Bytes(), &resp)
			Expect(err).NotTo(HaveOccurred())

			Expect(resp.Services).To(HaveLen(2))

			// sort services slice as the order isn't guaranteed when translated from map.
			sort.Slice(resp.Services, func(i, j int) bool {
				return resp.Services[i].Name < resp.Services[j].Name
			})

			Expect(resp.Services[0].Name).To(Equal("checkoutservice-69c8ff664b-*"))
			Expect(resp.Services[0].ErrorRate).To(Equal(0.0))
			Expect(resp.Services[0].Latency).To(BeNumerically("~", 3449.98, 0.01))
			Expect(resp.Services[0].InboundThroughput).To(BeNumerically("~", 14990.34, 0.01))
			Expect(resp.Services[0].OutboundThroughput).To(BeNumerically("~", 12463.77, 0.01))
			Expect(resp.Services[0].RequestThroughput).To(BeNumerically("~", 0.095, 0.001))

			Expect(resp.Services[1].Name).To(Equal("frontend-99684f7f8-*"))
			Expect(resp.Services[1].ErrorRate).To(BeNumerically("~", 5.577, 0.001))
			Expect(resp.Services[1].Latency).To(BeNumerically("~", 5338.46, 0.01))
			Expect(resp.Services[1].InboundThroughput).To(BeNumerically("~", 4251.80, 0.01))
			Expect(resp.Services[1].OutboundThroughput).To(BeNumerically("~", 19909.94, 0.01))
			Expect(resp.Services[1].RequestThroughput).To(BeNumerically("~", 0.804, 0.001))
		})

		It("should return a valid services response filtered by namespace", func() {
			// Unmarshal L7 response
			response := lapi.List[lapi.L7Log]{}
			err := json.Unmarshal([]byte(l7ResponseWithNamespace), &response)
			Expect(err).NotTo(HaveOccurred())

			// Build mock response from Linseed.
			results := []rest.MockResult{}
			results = append(results, rest.MockResult{
				Body: lapi.List[lapi.L7Log]{
					Items:     response.Items,
					TotalHits: response.TotalHits,
				},
			})

			// mock linseed client
			lsc := client.NewMockClient("", results...)

			// validate responses
			req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader([]byte(ApplicationRequestWithSelector)))
			Expect(err).NotTo(HaveOccurred())

			rr := httptest.NewRecorder()
			handler := ApplicationHandler(userAuthReview, lsc, ApplicationTypeService)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusOK))

			var resp v1.ServiceResponse
			err = json.Unmarshal(rr.Body.Bytes(), &resp)
			Expect(err).NotTo(HaveOccurred())

			Expect(resp.Services).To(HaveLen(2))

			// sort services slice as the order isn't guaranteed when translated from map.
			sort.Slice(resp.Services, func(i, j int) bool {
				return resp.Services[i].Name < resp.Services[j].Name
			})

			Expect(resp.Services[0].Name).To(Equal("checkoutservice-69c8ff664b-*"))
			Expect(resp.Services[0].ErrorRate).To(Equal(0.0))
			Expect(resp.Services[0].Latency).To(BeNumerically("~", 3193.52, 0.01))
			Expect(resp.Services[0].InboundThroughput).To(BeNumerically("~", 16202.02, 0.01))
			Expect(resp.Services[0].OutboundThroughput).To(BeNumerically("~", 13464.65, 0.01))
			Expect(resp.Services[0].RequestThroughput).To(BeNumerically("~", 0.102, 0.001))

			Expect(resp.Services[1].Name).To(Equal("frontend-99684f7f8-*"))
			Expect(resp.Services[1].ErrorRate).To(BeNumerically("~", 100, 0.001))
			Expect(resp.Services[1].Latency).To(BeNumerically("~", 72103.41, 0.01))
			Expect(resp.Services[1].InboundThroughput).To(BeNumerically("~", 2316.12, 0.01))
			Expect(resp.Services[1].OutboundThroughput).To(BeNumerically("~", 3217.60, 0.01))
			Expect(resp.Services[1].RequestThroughput).To(BeNumerically("~", 0.090, 0.001))
		})

		It("should ignore zero duration log entries", func() {
			// Unmarshal L7 response
			response := lapi.List[lapi.L7Log]{}
			err := json.Unmarshal([]byte(l7ResponseZeroDuration), &response)
			Expect(err).NotTo(HaveOccurred())

			// Build mock response from Linseed.
			results := []rest.MockResult{}
			results = append(results, rest.MockResult{
				Body: lapi.List[lapi.L7Log]{
					Items:     response.Items,
					TotalHits: response.TotalHits,
				},
			})

			// mock linseed client
			lsc := client.NewMockClient("", results...)

			// validate responses
			req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader([]byte(ApplicationRequest)))
			Expect(err).NotTo(HaveOccurred())

			rr := httptest.NewRecorder()
			handler := ApplicationHandler(userAuthReview, lsc, ApplicationTypeService)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusOK))

			var resp v1.ServiceResponse
			err = json.Unmarshal(rr.Body.Bytes(), &resp)
			Expect(err).NotTo(HaveOccurred())

			Expect(resp.Services).To(BeEmpty())
		})

		It("should return error when request is not POST", func() {
			req, err := http.NewRequest(http.MethodGet, "", bytes.NewReader([]byte("any")))
			Expect(err).NotTo(HaveOccurred())

			// mock linseed client
			lsc := client.NewMockClient("")

			rr := httptest.NewRecorder()
			handler := ApplicationHandler(userAuthReview, lsc, ApplicationTypeService)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusMethodNotAllowed))
		})

		It("should return error when request body is not valid", func() {
			req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader([]byte("invalid-json-body")))
			Expect(err).NotTo(HaveOccurred())

			// mock linseed client
			lsc := client.NewMockClient("")

			rr := httptest.NewRecorder()
			handler := ApplicationHandler(userAuthReview, lsc, ApplicationTypeService)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusBadRequest))
		})

		It("should return error when missing time range", func() {
			req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader([]byte(`{"cluster": "test-cluster-name"}`)))
			Expect(err).NotTo(HaveOccurred())

			// mock linseed client
			lsc := client.NewMockClient("")

			rr := httptest.NewRecorder()
			handler := ApplicationHandler(userAuthReview, lsc, ApplicationTypeService)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusBadRequest))
		})

		It("should return error when response from linseed errors out", func() {
			// mock linseed client
			lsc := client.NewMockClient("", []rest.MockResult{{Err: fmt.Errorf("mock error")}}...)

			// validate responses
			req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader([]byte(ApplicationRequestWithSelector)))
			Expect(err).NotTo(HaveOccurred())

			rr := httptest.NewRecorder()
			handler := ApplicationHandler(userAuthReview, lsc, ApplicationTypeService)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusInternalServerError))
		})

		It("should return error when failed to perform AuthorizationReview", func() {
			req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader([]byte(ApplicationRequest)))
			Expect(err).NotTo(HaveOccurred())

			// mock linseed client
			lsc := client.NewMockClient("")

			// mock auth review returns error
			mockUserAuthReviewFailed := userAuthorizationReviewMock{
				verbs: []libcalicov3.AuthorizedResourceVerbs{},
				err:   fmt.Errorf("PerformReview failed"),
			}

			rr := httptest.NewRecorder()
			handler := ApplicationHandler(mockUserAuthReviewFailed, lsc, ApplicationTypeService)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusInternalServerError))
		})
	})

	Context("Elasticsearch /urls request and response validation", func() {
		It("should return a valid urls response", func() {
			// Unmarshal L7 response
			response := lapi.List[lapi.L7Log]{}
			err := json.Unmarshal([]byte(l7Response), &response)
			Expect(err).NotTo(HaveOccurred())

			// Build mock response from Linseed.
			results := []rest.MockResult{}
			results = append(results, rest.MockResult{
				Body: lapi.List[lapi.L7Log]{
					Items:     response.Items,
					TotalHits: response.TotalHits,
				},
			})

			// mock linseed client
			lsc := client.NewMockClient("", results...)

			// validate responses
			req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader([]byte(ApplicationRequest)))
			Expect(err).NotTo(HaveOccurred())

			rr := httptest.NewRecorder()
			handler := ApplicationHandler(userAuthReview, lsc, ApplicationTypeURL)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusOK))

			var resp v1.URLResponse
			err = json.Unmarshal(rr.Body.Bytes(), &resp)
			Expect(err).NotTo(HaveOccurred())

			Expect(resp.URLs).To(HaveLen(3))

			// sort urls slice as the order isn't guaranteed when translated from map.
			sort.Slice(resp.URLs, func(i, j int) bool {
				li := resp.URLs[i].URL
				si := resp.URLs[i].Service
				lj := resp.URLs[j].URL
				sj := resp.URLs[j].Service
				return li+si < lj+sj
			})

			Expect(resp.URLs[0].URL).To(Equal("adservice:9555/hipstershop.AdService/GetAds"))
			Expect(resp.URLs[0].Service).To(Equal("frontend-99684f7f8-*"))
			Expect(resp.URLs[0].RequestCount).To(Equal(491))

			Expect(resp.URLs[1].URL).To(Equal("checkoutservice:5050/hipstershop.CheckoutService/PlaceOrder"))
			Expect(resp.URLs[1].Service).To(Equal("frontend-99684f7f8-*"))
			Expect(resp.URLs[1].RequestCount).To(Equal(29))

			Expect(resp.URLs[2].URL).To(Equal("paymentservice:50051/hipstershop.PaymentService/Charge"))
			Expect(resp.URLs[2].Service).To(Equal("checkoutservice-69c8ff664b-*"))
			Expect(resp.URLs[2].RequestCount).To(Equal(60)) // 31+29
		})

		It("should return a valid services response filtered by namespace", func() {
			// Unmarshal L7 response
			response := lapi.List[lapi.L7Log]{}
			err := json.Unmarshal([]byte(l7ResponseWithNamespace), &response)
			Expect(err).NotTo(HaveOccurred())

			// Build mock response from Linseed.
			results := []rest.MockResult{}
			results = append(results, rest.MockResult{
				Body: lapi.List[lapi.L7Log]{
					Items:     response.Items,
					TotalHits: response.TotalHits,
				},
			})

			// mock linseed client
			lsc := client.NewMockClient("", results...)

			// validate responses
			req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader([]byte(ApplicationRequestWithSelector)))
			Expect(err).NotTo(HaveOccurred())

			rr := httptest.NewRecorder()
			handler := ApplicationHandler(userAuthReview, lsc, ApplicationTypeURL)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusOK))

			var resp v1.URLResponse
			err = json.Unmarshal(rr.Body.Bytes(), &resp)
			Expect(err).NotTo(HaveOccurred())

			Expect(resp.URLs).To(HaveLen(2))

			// sort urls slice as the order isn't guaranteed when translated from map.
			sort.Slice(resp.URLs, func(i, j int) bool {
				li := resp.URLs[i].URL
				si := resp.URLs[i].Service
				lj := resp.URLs[j].URL
				sj := resp.URLs[j].Service
				return li+si < lj+sj
			})

			Expect(resp.URLs[0].URL).To(Equal("checkoutservice:5050/hipstershop.CheckoutService/PlaceOrder"))
			Expect(resp.URLs[0].Service).To(Equal("frontend-99684f7f8-*"))
			Expect(resp.URLs[0].RequestCount).To(Equal(29))

			Expect(resp.URLs[1].URL).To(Equal("paymentservice:50051/hipstershop.PaymentService/Charge"))
			Expect(resp.URLs[1].Service).To(Equal("checkoutservice-69c8ff664b-*"))
			Expect(resp.URLs[1].RequestCount).To(Equal(31))
		})

		It("should return error when request is not POST", func() {
			req, err := http.NewRequest(http.MethodGet, "", bytes.NewReader([]byte("any")))
			Expect(err).NotTo(HaveOccurred())

			// mock linseed client
			lsc := client.NewMockClient("")

			rr := httptest.NewRecorder()
			handler := ApplicationHandler(userAuthReview, lsc, ApplicationTypeURL)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusMethodNotAllowed))
		})

		It("should return error when request body is not valid", func() {
			req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader([]byte("invalid-json-body")))
			Expect(err).NotTo(HaveOccurred())

			// mock linseed client
			lsc := client.NewMockClient("")

			rr := httptest.NewRecorder()
			handler := ApplicationHandler(userAuthReview, lsc, ApplicationTypeURL)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusBadRequest))
		})

		It("should return error when missing time range", func() {
			req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader([]byte(`{"cluster": "test-cluster-name"}`)))
			Expect(err).NotTo(HaveOccurred())

			// mock linseed client
			lsc := client.NewMockClient("")

			rr := httptest.NewRecorder()
			handler := ApplicationHandler(userAuthReview, lsc, ApplicationTypeService)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusBadRequest))
		})

		It("should return error when response from linseed errors out", func() {
			// mock linseed client
			lsc := client.NewMockClient("", []rest.MockResult{{Err: fmt.Errorf("mock error")}}...)

			// validate responses
			req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader([]byte(ApplicationRequestWithSelector)))
			Expect(err).NotTo(HaveOccurred())

			rr := httptest.NewRecorder()
			handler := ApplicationHandler(userAuthReview, lsc, ApplicationTypeURL)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusInternalServerError))
		})

		It("should return error when failed to perform AuthorizationReview", func() {
			req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader([]byte(ApplicationRequest)))
			Expect(err).NotTo(HaveOccurred())

			// mock linseed client
			lsc := client.NewMockClient("")

			// mock auth review returns error
			mockUserAuthReviewFailed := userAuthorizationReviewMock{
				verbs: []libcalicov3.AuthorizedResourceVerbs{},
				err:   fmt.Errorf("PerformReview failed"),
			}

			rr := httptest.NewRecorder()
			handler := ApplicationHandler(mockUserAuthReviewFailed, lsc, ApplicationTypeURL)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusInternalServerError))
		})
	})
})
