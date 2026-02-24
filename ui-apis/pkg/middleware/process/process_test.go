// Copyright (c) 2022-2024 Tigera, Inc. All rights reserved.
package process

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	libcalicov3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	lapi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
	"github.com/projectcalico/calico/ui-apis/test/thirdpartymock"
)

// requests from manager to ui-apis
//
//go:embed testdata/process_request_from_manager.json
var processRequest string

// The user authentication review mock struct implementing the authentication review interface.
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

var _ = Describe("Service middleware tests", func() {
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
			// Build mock response from Linseed.
			procs := []lapi.ProcessInfo{
				{Name: "/src/checkoutservice", Endpoint: "checkoutservice-69c8ff664b-*", Count: 4},
				{Name: "/src/server", Endpoint: "frontend-99684f7f8-*", Count: 3},
				{Name: "/usr/local/openjdk-8/bin/java", Endpoint: "adservice-77d5cd745d-*", Count: 3},
				{Name: "/usr/local/bin/python", Endpoint: "loadgenerator-555fbdc87d-*", Count: 2},
				{Name: "/usr/local/bin/locust", Endpoint: "loadgenerator-555fbdc87d-*", Count: 1},
				{Name: "wget", Endpoint: "loadgenerator-555fbdc87d-*", Count: 1},
				{Name: "python", Endpoint: "recommendationservice-5f8c456796-*", Count: 2},
				{Name: "/usr/local/bin/python", Endpoint: "recommendationservice-5f8c456796-*", Count: 2},
				{Name: "/app/cartservice", Endpoint: "cartservice-74f56fd4b-*", Count: 3},
			}

			results := []rest.MockResult{}
			results = append(results, rest.MockResult{
				Body: lapi.List[lapi.ProcessInfo]{
					Items: procs,
				},
			})

			// mock linseed client
			lsc := client.NewMockClient("", results...)

			// validate responses
			req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader([]byte(processRequest)))
			Expect(err).NotTo(HaveOccurred())

			rr := httptest.NewRecorder()
			handler := ProcessHandler(userAuthReview, lsc)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusOK))

			var resp v1.ProcessResponse
			err = json.Unmarshal(rr.Body.Bytes(), &resp)
			Expect(err).NotTo(HaveOccurred())

			Expect(resp.Processes).To(HaveLen(9))

			// sort process slice as the order isn't guaranteed when translated from map.
			sort.Slice(resp.Processes, func(i, j int) bool {
				return resp.Processes[i].Name < resp.Processes[j].Name
			})

			Expect(resp.Processes[0].Name).To(Equal("/app/cartservice"))
			Expect(resp.Processes[0].Endpoint).To(Equal("cartservice-74f56fd4b-*"))
			Expect(resp.Processes[0].Count).To(Equal(3))
			Expect(resp.Processes[1].Name).To(Equal("/src/checkoutservice"))
			Expect(resp.Processes[1].Endpoint).To(Equal("checkoutservice-69c8ff664b-*"))
			Expect(resp.Processes[1].Count).To(Equal(4))
			Expect(resp.Processes[2].Name).To(Equal("/src/server"))
			Expect(resp.Processes[2].Endpoint).To(Equal("frontend-99684f7f8-*"))
			Expect(resp.Processes[2].Count).To(Equal(3))
			Expect(resp.Processes[3].Name).To(Equal("/usr/local/bin/locust"))
			Expect(resp.Processes[3].Endpoint).To(Equal("loadgenerator-555fbdc87d-*"))
			Expect(resp.Processes[3].Count).To(Equal(1))
			Expect(resp.Processes[4].Name).To(Equal("/usr/local/bin/python"))
			Expect(resp.Processes[4].Endpoint).To(Equal("loadgenerator-555fbdc87d-*"))
			Expect(resp.Processes[4].Count).To(Equal(2))
			Expect(resp.Processes[5].Name).To(Equal("/usr/local/bin/python"))
			Expect(resp.Processes[5].Endpoint).To(Equal("recommendationservice-5f8c456796-*"))
			Expect(resp.Processes[5].Count).To(Equal(2))
			Expect(resp.Processes[6].Name).To(Equal("/usr/local/openjdk-8/bin/java"))
			Expect(resp.Processes[6].Endpoint).To(Equal("adservice-77d5cd745d-*"))
			Expect(resp.Processes[6].Count).To(Equal(3))
			Expect(resp.Processes[7].Name).To(Equal("python"))
			Expect(resp.Processes[7].Endpoint).To(Equal("recommendationservice-5f8c456796-*"))
			Expect(resp.Processes[7].Count).To(Equal(2))
			Expect(resp.Processes[8].Name).To(Equal("wget"))
			Expect(resp.Processes[8].Endpoint).To(Equal("loadgenerator-555fbdc87d-*"))
			Expect(resp.Processes[8].Count).To(Equal(1))
		})

		It("should return error when request is not POST", func() {
			req, err := http.NewRequest(http.MethodGet, "", bytes.NewReader([]byte("any")))
			Expect(err).NotTo(HaveOccurred())

			rr := httptest.NewRecorder()
			handler := ProcessHandler(userAuthReview, nil)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusMethodNotAllowed))
		})

		It("should return error when request body is not valid", func() {
			req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader([]byte("invalid-json-body")))
			Expect(err).NotTo(HaveOccurred())

			rr := httptest.NewRecorder()
			handler := ProcessHandler(userAuthReview, nil)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusBadRequest))
		})

		It("should return error when response from linseed is an error", func() {
			// mock linseed client
			lsc := client.NewMockClient("", []rest.MockResult{{Err: fmt.Errorf("mock error")}}...)

			// validate responses
			req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader([]byte(processRequest)))
			Expect(err).NotTo(HaveOccurred())

			rr := httptest.NewRecorder()
			handler := ProcessHandler(userAuthReview, lsc)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusInternalServerError))
		})

		It("should return error when failed to perform AuthorizationReview", func() {
			req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader([]byte(processRequest)))
			Expect(err).NotTo(HaveOccurred())

			// mock auth review returns error
			mockUserAuthReviewFailed := userAuthorizationReviewMock{
				verbs: []libcalicov3.AuthorizedResourceVerbs{},
				err:   fmt.Errorf("PerformReview failed"),
			}

			rr := httptest.NewRecorder()
			handler := ProcessHandler(mockUserAuthReviewFailed, nil)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusInternalServerError))
		})
	})
})
