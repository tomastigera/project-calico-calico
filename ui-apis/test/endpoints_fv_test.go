// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

package fv_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apiserver/pkg/authentication/user"

	lapi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	v1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	"github.com/projectcalico/calico/lma/pkg/httputils"
	querycacheclient "github.com/projectcalico/calico/queryserver/pkg/querycache/client"
	"github.com/projectcalico/calico/queryserver/queryserver/client"
	"github.com/projectcalico/calico/ui-apis/pkg/middleware"
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

type mockAuthorizationReview struct {
	isAuthorized bool
	err          error
}

func (az mockAuthorizationReview) Authorize(user.Info, *authzv1.ResourceAttributes, *authzv1.NonResourceAttributes) (bool, error) {
	return az.isAuthorized, az.err
}

var _ = Describe("Test EndpointsAggregation handler", func() {
	var (
		server       *httptest.Server
		qsconfig     *client.QueryServerConfig
		req          *http.Request
		mocklsclient lsclient.MockClient
		CAFilePath   = "ca"

		authz mockAuthorizationReview
	)

	BeforeEach(func() {
		// initiliaze queryserver config
		qsconfig = &client.QueryServerConfig{
			QueryServerTunnelURL: "",
			QueryServerURL:       "",
			QueryServerCA:        CAFilePath,
		}

		// Create mock client certificate
		CA_file, err := os.Create(CAFilePath)
		Expect(err).ShouldNot(HaveOccurred())
		defer func() { _ = CA_file.Close() }()
	})

	AfterEach(func() {
		// Delete mock client certificate and auth token files
		Expect(os.Remove(CAFilePath)).Error().ShouldNot(HaveOccurred())
	})

	Context("when there are denied flowlogs", func() {
		var authReview userAuthorizationReviewMock
		BeforeEach(func() {
			// prepare mock authreview
			authReview = userAuthorizationReviewMock{
				verbs: []v3.AuthorizedResourceVerbs{
					{
						APIGroup: "lma.tigera.io",
						Resource: "flows",
						Verbs: []v3.AuthorizedResourceVerb{
							{
								Verb:           "get",
								ResourceGroups: nil,
							},
						},
					},
				},
				err: nil,
			}

			// prepare mock linseed client
			linseedResults := []rest.MockResult{
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
			mocklsclient = lsclient.NewMockClient("", linseedResults...)
		})

		It("return denied endpoints", func() {
			By("preparing the server")
			deniedEndPointsResponse := querycacheclient.QueryEndpointsResp{
				Count: 2,
				Items: []querycacheclient.Endpoint{
					{
						Namespace: "ns-src",
						Pod:       "ep-src-1234",
						Name:      "node--1-orchestrator-ep--src--1234-eth0",
					},
					{
						Namespace: "ns-dst",
						Pod:       "ep-dst-1234",
						Name:      "node--1-orchestrator-ep--dst--1234-eth0",
					},
				},
			}
			server = createFakeQueryServer(&deniedEndPointsResponse, func(requestBody *querycacheclient.QueryEndpointsReqBody) {
				// If showDeniedEndpointsOnly is true, the endpoints aggregation handler will generate
				// an endpoint list based on the result of the linseedResults.
				Expect(requestBody.EndpointsList).Should(ConsistOf([]string{
					"(.*?ns-src/.*?-ep--src--*)",
					"(.*?ns-dst/.*?-ep--dst--*)",
				}))
			})
			defer server.Close()

			// update queryserver url
			qsconfig.QueryServerURL = server.URL

			// prepare request
			endpointReq := &middleware.EndpointsAggregationRequest{
				ShowDeniedEndpoints: true,
				TimeRange: &v1.TimeRange{
					From: time.Now(),
					To:   time.Now(),
				},
			}

			reqBodyBytes, err := json.Marshal(endpointReq)
			Expect(err).ShouldNot(HaveOccurred())

			req, err = http.NewRequest("POST", server.URL, bytes.NewBuffer(reqBodyBytes))
			req.Header.Set("Authorization", "Bearer tokentoken")
			Expect(err).ShouldNot(HaveOccurred())

			// prepare response recorder
			rr := httptest.NewRecorder()

			By("calling EndpointsAggregationHandler")

			// set mock authorizer
			authz.isAuthorized = true
			authz.err = nil

			handler := middleware.EndpointsAggregationHandler(authz, authReview, qsconfig, mocklsclient)
			handler.ServeHTTP(rr, req)

			By("validating server response")
			Expect(rr.Code).To(Equal(http.StatusOK))

			response := &middleware.EndpointsAggregationResponse{}
			err = json.Unmarshal(rr.Body.Bytes(), response)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(response.Count).To(Equal(2))
			Expect(response.Item).To(HaveLen(2))
			for _, item := range response.Item {
				Expect(item.HasFlowAccess).To(BeTrue())
				Expect(*item.HasDeniedTraffic).To(BeTrue())
			}
		})

		It("return all endpoints", func() {
			By("preparing the server")
			allEndPointsResponse := querycacheclient.QueryEndpointsResp{
				Count: 3,
				Items: []querycacheclient.Endpoint{
					{
						Namespace: "ns-src",
						Pod:       "ep-src-1234",
						Name:      "node--1-orchestrator-ep--src--1234-eth0",
					},
					{
						Namespace: "ns-dst",
						Pod:       "ep-dst-1234",
						Name:      "node-1-orchestrator-ep--dst--1234-eth0",
					},
					{
						Namespace: "ns-allow",
						Pod:       "ep-allow-1234",
						Name:      "node-1-orchestrator-ep--allow--1234-eth0",
					},
				},
			}
			server = createFakeQueryServer(&allEndPointsResponse, func(requestBody *querycacheclient.QueryEndpointsReqBody) {
				// If showDeniedEndpointsOnly is false, the endpoints aggregation handler will NOT generate
				// an endpoint list and will return all endpoints as a result.
				Expect(requestBody.EndpointsList).Should(ConsistOf([]string{}))
			})
			defer server.Close()

			// update queryserver url
			qsconfig.QueryServerURL = server.URL

			// prepare request
			endpointReq := &middleware.EndpointsAggregationRequest{
				ShowDeniedEndpoints: false,
				TimeRange: &v1.TimeRange{
					From: time.Now(),
					To:   time.Now(),
				},
			}

			reqBodyBytes, err := json.Marshal(endpointReq)
			Expect(err).ShouldNot(HaveOccurred())

			req, err = http.NewRequest("POST", server.URL, bytes.NewBuffer(reqBodyBytes))
			req.Header.Set("Authorization", "Bearer tokentoken")
			Expect(err).ShouldNot(HaveOccurred())

			// prepare response recorder
			rr := httptest.NewRecorder()

			By("calling EndpointsAggregationHandler")
			// set mock authz
			authz.isAuthorized = true
			authz.err = nil
			handler := middleware.EndpointsAggregationHandler(authz, authReview, qsconfig, mocklsclient)
			handler.ServeHTTP(rr, req)

			By("validating server response")
			Expect(rr.Code).To(Equal(http.StatusOK))

			response := &middleware.EndpointsAggregationResponse{}
			err = json.Unmarshal(rr.Body.Bytes(), response)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(response.Count).To(Equal(3))
			Expect(response.Item).To(HaveLen(3))
			for _, item := range response.Item {
				Expect(item.HasFlowAccess).To(BeTrue())
				if item.Namespace == "ns-allow" {
					Expect(*item.HasDeniedTraffic).To(BeFalse())
				} else {
					Expect(*item.HasDeniedTraffic).To(BeTrue())
				}
			}
		})

		It("return all endpoints names", func() {
			By("preparing the server")
			serverResponseJson := `{
				"count": 3,
				"items": [{
					"kind": "WorkloadEndpoint",
					"name": "colmkenefick--bz--eghn--kadm--infra--0-k8s-compliance--benchmarker--t8nbs-eth0",
					"namespace": "tigera-compliance",
					"node": "colmkenefick-bz-eghn-kadm-infra-0",
					"workload": "",
					"orchestrator": "k8s",
					"pod": "compliance-benchmarker-t8nbs",
					"interfaceName": "cali57001ef7b96",
					"ipNetworks": [
						"192.168.170.201/32"
					],
					"labels": {
						"app.kubernetes.io/name": "compliance-benchmarker",
						"controller-revision-hash": "f84cb4cf6",
						"k8s-app": "compliance-benchmarker",
						"pod-template-generation": "1",
						"projectcalico.org/namespace": "tigera-compliance",
						"projectcalico.org/orchestrator": "k8s",
						"projectcalico.org/serviceaccount": "tigera-compliance-benchmarker"
					},
					"numGlobalNetworkPolicies": 0,
					"numNetworkPolicies": 2
					},
					{
					"kind": "WorkloadEndpoint",
					"name": "colmkenefick--bz--eghn--kadm--infra--0-k8s-csi--node--driver--r8vvn-eth0",
					"namespace": "calico-system",
					"node": "colmkenefick-bz-eghn-kadm-infra-0",
					"workload": "",
					"orchestrator": "k8s",
					"pod": "csi-node-driver-r8vvn",
					"interfaceName": "cali948dd367640",
					"ipNetworks": [
						"192.168.170.194/32"
					],
					"labels": {
						"app.kubernetes.io/name": "csi-node-driver",
						"controller-revision-hash": "788499ff8d",
						"k8s-app": "csi-node-driver",
						"name": "csi-node-driver",
						"pod-template-generation": "1",
						"projectcalico.org/namespace": "calico-system",
						"projectcalico.org/orchestrator": "k8s",
						"projectcalico.org/serviceaccount": "csi-node-driver"
					},
					"numGlobalNetworkPolicies": 0,
					"numNetworkPolicies": 1
					},
					{
					"kind": "WorkloadEndpoint",
					"name": "colmkenefick--bz--eghn--kadm--infra--0-k8s-fluentd--node--2nb55-eth0",
					"namespace": "tigera-fluentd",
					"node": "colmkenefick-bz-eghn-kadm-infra-0",
					"workload": "",
					"orchestrator": "k8s",
					"pod": "fluentd-node-2nb55",
					"interfaceName": "cali392a095478c",
					"ipNetworks": [
						"192.168.170.197/32"
					],
					"labels": {
						"app.kubernetes.io/name": "fluentd-node",
						"controller-revision-hash": "ffb846565",
						"k8s-app": "fluentd-node",
						"pod-template-generation": "1",
						"projectcalico.org/namespace": "tigera-fluentd",
						"projectcalico.org/orchestrator": "k8s",
						"projectcalico.org/serviceaccount": "fluentd-node"
					},
					"numGlobalNetworkPolicies": 0,
					"numNetworkPolicies": 1
				}]
			}`
			var serverResponse querycacheclient.QueryEndpointsResp
			err := json.Unmarshal([]byte(serverResponseJson), &serverResponse)
			Expect(err).NotTo(HaveOccurred())

			server = createFakeQueryServer(&serverResponse, nil)
			defer server.Close()

			// update queryserver url
			qsconfig.QueryServerURL = server.URL

			// prepare request
			req, err = http.NewRequest("POST", server.URL, bytes.NewBufferString("{}"))
			req.Header.Set("Authorization", "Bearer tokentoken")
			Expect(err).ShouldNot(HaveOccurred())

			// prepare response recorder
			rr := httptest.NewRecorder()

			By("calling EndpointsNamesHandler")
			handler := middleware.EndpointsNamesHandler(authReview, qsconfig)
			handler.ServeHTTP(rr, req)

			By("validating server response")
			Expect(rr.Code).To(Equal(http.StatusOK))

			var response []middleware.EndPointName
			err = json.Unmarshal(rr.Body.Bytes(), &response)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(response).To(Equal([]middleware.EndPointName{
				{
					Pod:       "compliance-benchmarker-t8nbs",
					Namespace: "tigera-compliance",
				},
				{
					Pod:       "csi-node-driver-r8vvn",
					Namespace: "calico-system",
				},
				{
					Pod:       "fluentd-node-2nb55",
					Namespace: "tigera-fluentd",
				},
			}))
		})
	})
})

// createFakeQueryServer sets up a fake Query Server instance for tests.
func createFakeQueryServer(response *querycacheclient.QueryEndpointsResp, test func(requestBody *querycacheclient.QueryEndpointsReqBody)) *httptest.Server {

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/json" {
			http.Error(w, "bad accept header", http.StatusBadRequest)
			return
		}
		if r.Method != "POST" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)

		// Make sure we get a valid request
		var requestBody querycacheclient.QueryEndpointsReqBody
		err := httputils.Decode(w, r, &requestBody)
		Expect(err).ShouldNot(HaveOccurred())

		// Run any extra test supplied as a parameter
		if test != nil {
			test(&requestBody)
		}

		bytes, err := json.Marshal(response)
		Expect(err).ShouldNot(HaveOccurred())

		_, err = w.Write(bytes)
		Expect(err).ShouldNot(HaveOccurred())
	}))

}
