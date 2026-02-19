package middleware

import (
	"fmt"
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	lapi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	"github.com/projectcalico/calico/lma/pkg/rbac"
)

// Default results for most tests. Consists of two returned flows.
var defaultResults = []rest.MockResult{
	{
		Body: lapi.List[lapi.L3Flow]{
			TotalHits: 2,
			Items: []lapi.L3Flow{
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Namespace:      "tigera-manager",
							AggregatedName: "tigera-manager-778447894c-*",
							Type:           lapi.WEP,
						},
						Destination: lapi.Endpoint{
							Namespace:      "tigera-elasticsearch",
							AggregatedName: "tigera-secure-es-xg2jxdtnqn",
							Type:           lapi.WEP,
						},
					},
					LogStats: &lapi.LogStats{FlowLogCount: 4370},
				},
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Namespace:      "default",
							AggregatedName: "test-app-83958379dc",
							Type:           lapi.WEP,
						},
						Destination: lapi.Endpoint{
							Namespace:      "tigera-elasticsearch",
							AggregatedName: "tigera-secure-es-xg2jxdtnqn",
							Type:           lapi.WEP,
						},
					},
					LogStats: &lapi.LogStats{FlowLogCount: 3698},
				},
			},
		},
	},
}

// Response simulating no flows returned from Linseed
var emptyFlowResponse = []rest.MockResult{
	{
		Body: lapi.List[lapi.L3Flow]{
			TotalHits: 0,
			Items:     []lapi.L3Flow{},
		},
	},
}

// Flow response from linseed that includes flows both to and from the same set of endpoints.
var duplicateFlowResponse = []rest.MockResult{
	{
		Body: lapi.List[lapi.L3Flow]{
			TotalHits: 7,
			Items: []lapi.L3Flow{
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Namespace:      "tigera-compliance",
							AggregatedName: "compliance-benchmarker-*",
							Type:           lapi.WEP,
						},
						Destination: lapi.Endpoint{
							Namespace:      "tigera-compliance",
							AggregatedName: "compliance-controller-c7f4b94dd-*",
							Type:           lapi.WEP,
						},
					},
					LogStats: &lapi.LogStats{FlowLogCount: 10930},
				},
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Namespace:      "tigera-compliance",
							AggregatedName: "compliance-benchmarker-*",
							Type:           lapi.WEP,
						},
						Destination: lapi.Endpoint{
							Namespace:      "tigera-compliance",
							AggregatedName: "compliance-server-69c97dffcf-*",
							Type:           lapi.WEP,
						},
					},
					LogStats: &lapi.LogStats{FlowLogCount: 4393},
				},
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Namespace:      "tigera-compliance",
							AggregatedName: "compliance-controller-c7f4b94dd-*",
							Type:           lapi.WEP,
						},
						Destination: lapi.Endpoint{
							Namespace:      "tigera-compliance",
							AggregatedName: "compliance-server-69c97dffcf-*",
							Type:           lapi.WEP,
						},
					},
					LogStats: &lapi.LogStats{FlowLogCount: 10930},
				},
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Namespace:      "tigera-compliance",
							AggregatedName: "compliance-server-69c97dffcf-*",
							Type:           lapi.WEP,
						},
						Destination: lapi.Endpoint{
							Namespace:      "tigera-manager",
							AggregatedName: "tigera-manager-778447894c-*",
							Type:           lapi.WEP,
						},
					},
					LogStats: &lapi.LogStats{FlowLogCount: 4372},
				},
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Namespace:      "tigera-compliance",
							AggregatedName: "compliance-server-69c97dffcf-*",
							Type:           lapi.WEP,
						},
						Destination: lapi.Endpoint{
							Namespace:      "tigera-compliance",
							AggregatedName: "compliance-controller-c7f4b94dd-*",
							Type:           lapi.WEP,
						},
					},
					LogStats: &lapi.LogStats{FlowLogCount: 4372},
				},
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Namespace:      "tigera-elasticsearch",
							AggregatedName: "tigera-secure-es-xg2jxdtnqn",
							Type:           lapi.WEP,
						},
						Destination: lapi.Endpoint{
							Namespace:      "tigera-manager",
							AggregatedName: "tigera-manager-778447894c-*",
							Type:           lapi.WEP,
						},
					},
					LogStats: &lapi.LogStats{FlowLogCount: 4372},
				},

				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Namespace:      "tigera-compliance",
							AggregatedName: "compliance-benchmarker-*",
							Type:           lapi.WEP,
						},
						Destination: lapi.Endpoint{
							Namespace:      "default",
							AggregatedName: "default/kse.kubernetes",
							Type:           lapi.WEP,
						},
					},
					LogStats: &lapi.LogStats{FlowLogCount: 2185},
				},
			},
		},
	},
}

// Mock an error response from Linseed.
var httpStatusErrorResponse = []rest.MockResult{{Err: fmt.Errorf("mock test error from Linseed")}}

// Includes a flow between global resources - HEP and GlobalNetworkSet.
var globalResponse = []rest.MockResult{
	{
		Body: lapi.List[lapi.L3Flow]{
			TotalHits: 2,
			Items: []lapi.L3Flow{
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Namespace:      "",
							AggregatedName: "tigera-cluster-*",
							Type:           lapi.HEP,
						},
						Destination: lapi.Endpoint{
							Namespace:      "",
							AggregatedName: "tigera-global-networkset",
							Type:           lapi.NetworkSet,
						},
					},
					LogStats: &lapi.LogStats{FlowLogCount: 4370},
				},
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Namespace:      "default",
							AggregatedName: "test-app-83958379dc",
							Type:           lapi.NetworkSet,
						},
						Destination: lapi.Endpoint{
							Namespace:      "tigera-elasticsearch",
							AggregatedName: "tigera-secure-es-xg2jxdtnqn",
							Type:           lapi.WEP,
						},
					},
					LogStats: &lapi.LogStats{FlowLogCount: 3698},
				},
			},
		},
	},
}

var _ = Describe("Test /flowLogNames endpoint functions", func() {
	Context("Test that the validateFlowLogNamesRequest function behaves as expected", func() {
		It("should return an ErrInvalidMethod when passed a request with an http method other than GET", func() {
			By("Creating a request with a POST method")
			req, err := newTestRequest(http.MethodPost)
			Expect(err).NotTo(HaveOccurred())

			params, err := validateFlowLogNamesRequest(req)
			Expect(err).To(BeEquivalentTo(ErrInvalidMethod))
			Expect(params).To(BeNil())

			By("Creating a request with a DELETE method")
			req, err = newTestRequest(http.MethodDelete)
			Expect(err).NotTo(HaveOccurred())

			params, err = validateFlowLogNamesRequest(req)
			Expect(err).To(BeEquivalentTo(ErrInvalidMethod))
			Expect(params).To(BeNil())
		})

		It("should return a valid params object with the limit set to 1000 when passed an empty limit", func() {
			req, err := newTestRequest(http.MethodGet)
			Expect(err).NotTo(HaveOccurred())
			q := req.URL.Query()
			q.Add("limit", "")
			req.URL.RawQuery = q.Encode()

			params, err := validateFlowLogNamesRequest(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(params.Limit).To(BeNumerically("==", 1000))
		})

		It("should return a valid params object with the limit set to 1000 when passed a 0 limit", func() {
			req, err := newTestRequest(http.MethodGet)
			Expect(err).NotTo(HaveOccurred())
			q := req.URL.Query()
			q.Add("limit", "0")
			req.URL.RawQuery = q.Encode()

			params, err := validateFlowLogNamesRequest(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(params.Limit).To(BeNumerically("==", 1000))
		})

		It("should return an ErrParseRequest when passed a request with a negative limit parameter", func() {
			req, err := newTestRequest(http.MethodGet)
			Expect(err).NotTo(HaveOccurred())
			q := req.URL.Query()
			q.Add("limit", "-100")
			req.URL.RawQuery = q.Encode()

			params, err := validateFlowLogNamesRequest(req)
			Expect(err).To(BeEquivalentTo(ErrParseRequest))
			Expect(params).To(BeNil())
		})

		It("should return an ErrParseRequest when passed a request with word as the limit parameter", func() {
			req, err := newTestRequest(http.MethodGet)
			Expect(err).NotTo(HaveOccurred())
			q := req.URL.Query()
			q.Add("limit", "ten")
			req.URL.RawQuery = q.Encode()

			params, err := validateFlowLogNamesRequest(req)
			Expect(err).To(BeEquivalentTo(ErrParseRequest))
			Expect(params).To(BeNil())
		})

		It("should return an ErrParseRequest when passed a request with a floating number as the limit parameter", func() {
			req, err := newTestRequest(http.MethodGet)
			Expect(err).NotTo(HaveOccurred())
			q := req.URL.Query()
			q.Add("limit", "3.14")
			req.URL.RawQuery = q.Encode()

			params, err := validateFlowLogNamesRequest(req)
			Expect(err).To(BeEquivalentTo(ErrParseRequest))
			Expect(params).To(BeNil())
		})

		It("should return an ErrParseRequest when passed a request with a max int32 + 1 number as the limit parameter", func() {
			req, err := newTestRequest(http.MethodGet)
			Expect(err).NotTo(HaveOccurred())
			q := req.URL.Query()
			q.Add("limit", "2147483648")
			req.URL.RawQuery = q.Encode()

			params, err := validateFlowLogNamesRequest(req)
			Expect(err).To(BeEquivalentTo(ErrParseRequest))
			Expect(params).To(BeNil())
		})

		It("should return an ErrParseRequest when passed a request with a min int32 - 1 number as the limit parameter", func() {
			req, err := newTestRequest(http.MethodGet)
			Expect(err).NotTo(HaveOccurred())
			q := req.URL.Query()
			q.Add("limit", "-2147483648")
			req.URL.RawQuery = q.Encode()

			params, err := validateFlowLogNamesRequest(req)
			Expect(err).To(BeEquivalentTo(ErrParseRequest))
			Expect(params).To(BeNil())
		})

		It("should return an ErrParseRequest when passed a request with an invalid unprotected param", func() {
			req, err := newTestRequest(http.MethodGet)
			Expect(err).NotTo(HaveOccurred())
			q := req.URL.Query()
			q.Add("unprotected", "xvz")
			req.URL.RawQuery = q.Encode()

			params, err := validateFlowLogNamesRequest(req)
			Expect(err).To(BeEquivalentTo(ErrParseRequest))
			Expect(params).To(BeNil())
		})

		It("should return an ErrParseRequest when passed a request with an invalid combination of actions and unprotected param", func() {
			req, err := newTestRequest(http.MethodGet)
			Expect(err).NotTo(HaveOccurred())
			q := req.URL.Query()
			q.Add("actions", "allow")
			q.Add("actions", "deny")
			q.Add("unprotected", "true")
			req.URL.RawQuery = q.Encode()

			params, err := validateFlowLogNamesRequest(req)
			Expect(err).To(BeEquivalentTo(errInvalidActionUnprotected))
			Expect(params).To(BeNil())
		})

		It("should return an errInvalidAction when passed a request with an unacceptable actions parameter", func() {
			By("Forming a request with an invalid actions value")
			req, err := newTestRequest(http.MethodGet)
			Expect(err).NotTo(HaveOccurred())
			q := req.URL.Query()
			q.Add("actions", "alloow")
			req.URL.RawQuery = q.Encode()

			params, err := validateFlowLogNamesRequest(req)
			Expect(err).To(BeEquivalentTo(errInvalidAction))
			Expect(params).To(BeNil())

			By("Forming a request with a few valid actions and one invalid")
			req, err = newTestRequest(http.MethodGet)
			Expect(err).NotTo(HaveOccurred())
			q = req.URL.Query()
			q.Add("actions", "allow")
			q.Add("actions", "deny")
			q.Add("actions", "invalid")
			req.URL.RawQuery = q.Encode()

			params, err = validateFlowLogNamesRequest(req)
			Expect(err).To(BeEquivalentTo(errInvalidAction))
			Expect(params).To(BeNil())
		})

		It("should return a valid FlowLogNamesParams object with the Actions and Namespace from the request", func() {
			req, err := newTestRequest(http.MethodGet)
			Expect(err).NotTo(HaveOccurred())
			q := req.URL.Query()
			q.Add("actions", "allow")
			q.Add("actions", "deny")
			q.Add("actions", "unknown")
			q.Add("namespace", "tigera-elasticsearch")
			req.URL.RawQuery = q.Encode()

			params, err := validateFlowLogNamesRequest(req)
			Expect(err).To(Not(HaveOccurred()))
			Expect(params.Actions[0]).To(BeEquivalentTo("allow"))
			Expect(params.Actions[1]).To(BeEquivalentTo("deny"))
			Expect(params.Actions[2]).To(BeEquivalentTo("unknown"))
			Expect(params.Namespace).To(BeEquivalentTo("tigera-elasticsearch"))
		})

		It("should return a valid FlowLogNamesParams object when passed upper case parameters", func() {
			req, err := newTestRequest(http.MethodGet)
			Expect(err).NotTo(HaveOccurred())
			q := req.URL.Query()
			q.Add("actions", "ALLOW")
			q.Add("cluster", "CLUSTER")
			q.Add("namespace", "TIGERA-ELASTICSEARCH")
			req.URL.RawQuery = q.Encode()

			params, err := validateFlowLogNamesRequest(req)
			Expect(err).To(Not(HaveOccurred()))
			Expect(params.Actions[0]).To(BeEquivalentTo("allow"))
			Expect(params.ClusterName).To(BeEquivalentTo("cluster"))
			Expect(params.Namespace).To(BeEquivalentTo("tigera-elasticsearch"))
		})

		It("should return a valid FlowLogNamespaceParams when passed a request with valid start/end time", func() {
			req, err := newTestRequest(http.MethodGet)
			Expect(err).NotTo(HaveOccurred())
			q := req.URL.Query()
			q.Add("actions", "ALLOW")
			q.Add("cluster", "CLUSTER")
			q.Add("namespace", "TIGERA-ELASTICSEARCH")
			startTimeObject, endTimeObject := getTestStartAndEndTime()
			Expect(err).To(Not(HaveOccurred()))
			q.Add("startDateTime", startTimeTest)
			q.Add("endDateTime", endTimeTest)

			Expect(err).To(Not(HaveOccurred()))
			req.URL.RawQuery = q.Encode()

			params, err := validateFlowLogNamesRequest(req)
			Expect(err).To(Not(HaveOccurred()))
			Expect(params.Actions[0]).To(BeEquivalentTo("allow"))
			Expect(params.ClusterName).To(BeEquivalentTo("cluster"))
			Expect(params.Namespace).To(BeEquivalentTo("tigera-elasticsearch"))
			Expect(params.StartDateTime).To(BeEquivalentTo(startTimeObject))
			Expect(params.EndDateTime).To(BeEquivalentTo(endTimeObject))
		})
	})

	Context("Test that the getNamesFromLinseed function behaves as expected", func() {
		It("should retrieve all names with prefix tigera", func() {
			lsc := client.NewMockClient("", defaultResults...)
			params := &FlowLogNamesParams{
				Limit:       1000,
				Actions:     []string{"allow", "deny", "unknown"},
				Prefix:      "tigera",
				ClusterName: "cluster",
				Namespace:   "",
			}
			names, err := getNamesFromLinseed(params, lsc, rbac.NewAlwaysAllowFlowHelper())
			Expect(err).To(Not(HaveOccurred()))
			Expect(names).To(HaveLen(2))
			Expect(names[0]).To(Equal("tigera-manager-778447894c-*"))
			Expect(names[1]).To(Equal("tigera-secure-es-xg2jxdtnqn"))
		})

		It("should handle an empty array of names returned from elasticsearch", func() {
			lsc := client.NewMockClient("", emptyFlowResponse...)
			params := &FlowLogNamesParams{
				Limit:       1000,
				Actions:     []string{"allow", "deny", "unknown"},
				Prefix:      "tigera",
				ClusterName: "cluster",
				Namespace:   "",
			}

			names, err := getNamesFromLinseed(params, lsc, rbac.NewAlwaysAllowFlowHelper())
			Expect(err).To(Not(HaveOccurred()))
			Expect(names).To(HaveLen(0))
		})

		It("should retrieve an empty array of names when the prefix filters them out", func() {
			lsc := client.NewMockClient("", emptyFlowResponse...)
			params := &FlowLogNamesParams{
				Limit:       2000,
				Actions:     []string{"allow", "deny", "unknown"},
				Prefix:      "tigera-elasticccccccc.*",
				ClusterName: "cluster",
				Namespace:   "tigera-compliance",
			}
			names, err := getNamesFromLinseed(params, lsc, rbac.NewAlwaysAllowFlowHelper())
			Expect(err).To(Not(HaveOccurred()))
			Expect(names).To(HaveLen(0))
		})

		It("should retrieve an array of names with no duplicates", func() {
			lsc := client.NewMockClient("", duplicateFlowResponse...)
			params := &FlowLogNamesParams{
				Limit:       2000,
				Actions:     []string{"allow", "deny", "unknown"},
				Prefix:      "",
				ClusterName: "cluster",
				Namespace:   "",
			}
			names, err := getNamesFromLinseed(params, lsc, rbac.NewAlwaysAllowFlowHelper())
			Expect(err).To(Not(HaveOccurred()))
			Expect(names).To(HaveLen(6))
			Expect(names[0]).To(Equal("compliance-benchmarker-*"))
			Expect(names[1]).To(Equal("compliance-controller-c7f4b94dd-*"))
			Expect(names[2]).To(Equal("compliance-server-69c97dffcf-*"))
			Expect(names[3]).To(Equal("default/kse.kubernetes"))
			Expect(names[4]).To(Equal("tigera-manager-778447894c-*"))
			Expect(names[5]).To(Equal("tigera-secure-es-xg2jxdtnqn"))
		})

		It("should retrieve an array of names with no duplicates and only up to the limit", func() {
			lsc := client.NewMockClient("", duplicateFlowResponse...)
			params := &FlowLogNamesParams{
				Limit:       3,
				Actions:     []string{"allow", "deny", "unknown"},
				Prefix:      "",
				ClusterName: "cluster",
				Namespace:   "tigera-compliance",
			}
			names, err := getNamesFromLinseed(params, lsc, rbac.NewAlwaysAllowFlowHelper())
			Expect(err).To(Not(HaveOccurred()))
			Expect(len(names)).To(BeNumerically("==", 3))
			Expect(names[0]).To(Equal("compliance-benchmarker-*"))
			Expect(names[1]).To(Equal("compliance-controller-c7f4b94dd-*"))
			Expect(names[2]).To(Equal("compliance-server-69c97dffcf-*"))
		})

		It("should return an error when the query fails", func() {
			lsc := client.NewMockClient("", httpStatusErrorResponse...)
			params := &FlowLogNamesParams{
				Limit:       2000,
				Actions:     []string{"allow", "deny", "unknown"},
				Prefix:      "",
				ClusterName: "",
				Namespace:   "tigera-compliance",
			}

			names, err := getNamesFromLinseed(params, lsc, rbac.NewAlwaysAllowFlowHelper())
			Expect(err).To(HaveOccurred())
			Expect(names).To(HaveLen(0))
		})

		It("should only return the endpoints for the specified namespace when the namespace is specified", func() {
			lsc := client.NewMockClient("", duplicateFlowResponse...)
			params := &FlowLogNamesParams{
				Limit:       2000,
				Actions:     []string{"allow", "deny", "unknown"},
				Prefix:      "",
				ClusterName: "",
				Namespace:   "tigera-compliance",
			}

			names, err := getNamesFromLinseed(params, lsc, rbac.NewAlwaysAllowFlowHelper())
			Expect(err).To(Not(HaveOccurred()))
			Expect(len(names)).To(BeNumerically("==", 3))
			Expect(names[0]).To(Equal("compliance-benchmarker-*"))
			Expect(names[1]).To(Equal("compliance-controller-c7f4b94dd-*"))
			Expect(names[2]).To(Equal("compliance-server-69c97dffcf-*"))
		})

		It("should return all endpoints and global endpoints with permissive RBAC", func() {
			lsc := client.NewMockClient("", globalResponse...)
			params := &FlowLogNamesParams{
				Limit:       2000,
				Actions:     []string{"allow", "deny", "unknown"},
				Prefix:      "",
				ClusterName: "",
				Namespace:   "",
			}

			names, err := getNamesFromLinseed(params, lsc, rbac.NewAlwaysAllowFlowHelper())
			Expect(err).To(Not(HaveOccurred()))
			Expect(len(names)).To(BeNumerically("==", 4))
			Expect(names[0]).To(Equal("test-app-83958379dc"))
			Expect(names[1]).To(Equal("tigera-cluster-*"))
			Expect(names[2]).To(Equal("tigera-global-networkset"))
			Expect(names[3]).To(Equal("tigera-secure-es-xg2jxdtnqn"))
		})

		Context("getNamesFromLinseed RBAC filtering", func() {
			var mockFlowHelper *rbac.MockFlowHelper
			BeforeEach(func() {
				mockFlowHelper = new(rbac.MockFlowHelper)
			})

			AfterEach(func() {
				mockFlowHelper.AssertExpectations(GinkgoT())
			})

			It("should only return endpoints when global endpoints are not allowed due to RBAC", func() {
				lsc := client.NewMockClient("", globalResponse...)

				mockFlowHelper.On("CanListHostEndpoints").Return(false, nil)
				mockFlowHelper.On("CanListGlobalNetworkSets").Return(false, nil)
				mockFlowHelper.On("CanListNetworkSets", "").Return(true, nil)
				mockFlowHelper.On("CanListPods", "").Return(true, nil)

				params := &FlowLogNamesParams{
					Limit:       2000,
					Actions:     []string{"allow", "deny", "unknown"},
					Prefix:      "",
					ClusterName: "",
					Namespace:   "",
					Strict:      true,
				}

				names, err := getNamesFromLinseed(params, lsc, mockFlowHelper)
				Expect(err).To(Not(HaveOccurred()))
				Expect(names).To(HaveLen(2))
				Expect(names[0]).To(Equal("test-app-83958379dc"))
				Expect(names[1]).To(Equal("tigera-secure-es-xg2jxdtnqn"))
			})

			It("should properly filter endpoints based on allowed namespaces", func() {
				lsc := client.NewMockClient("", globalResponse...)

				mockFlowHelper.On("CanListHostEndpoints").Return(false, nil)
				mockFlowHelper.On("CanListGlobalNetworkSets").Return(false, nil)
				mockFlowHelper.On("CanListNetworkSets", "").Return(false, nil)
				mockFlowHelper.On("CanListNetworkSets", "default").Return(false, nil)
				mockFlowHelper.On("CanListPods", "").Return(false, nil)
				mockFlowHelper.On("CanListPods", "tigera-elasticsearch").Return(true, nil)

				params := &FlowLogNamesParams{
					Limit:       2000,
					Actions:     []string{"allow", "deny", "unknown"},
					Prefix:      "",
					ClusterName: "",
					Namespace:   "",
					Strict:      true,
				}

				names, err := getNamesFromLinseed(params, lsc, mockFlowHelper)
				Expect(err).To(Not(HaveOccurred()))
				Expect(names).To(HaveLen(1))
				Expect(names[0]).To(Equal("tigera-secure-es-xg2jxdtnqn"))
			})

			It("should properly filter out endpoints based on the endpoint type per namespace", func() {
				lsc := client.NewMockClient("", globalResponse...)

				mockFlowHelper.On("CanListHostEndpoints").Return(false, nil)
				mockFlowHelper.On("CanListGlobalNetworkSets").Return(false, nil)
				mockFlowHelper.On("CanListNetworkSets", "").Return(false, nil)
				mockFlowHelper.On("CanListNetworkSets", "default").Return(true, nil)
				mockFlowHelper.On("CanListPods", "").Return(false, nil)
				mockFlowHelper.On("CanListPods", "tigera-elasticsearch").Return(false, nil)

				params := &FlowLogNamesParams{
					Limit:       2000,
					Actions:     []string{"allow", "deny", "unknown"},
					Prefix:      "",
					ClusterName: "",
					Namespace:   "",
					Strict:      true,
				}

				names, err := getNamesFromLinseed(params, lsc, mockFlowHelper)
				Expect(err).To(Not(HaveOccurred()))
				Expect(names).To(HaveLen(1))
				Expect(names[0]).To(Equal("test-app-83958379dc"))
			})

			It("should properly filter out endpoints based on the endpoint type globally", func() {
				lsc := client.NewMockClient("", globalResponse...)

				mockFlowHelper.On("CanListHostEndpoints").Return(true, nil)
				mockFlowHelper.On("CanListGlobalNetworkSets").Return(false, nil)
				mockFlowHelper.On("CanListNetworkSets", "").Return(false, nil)
				mockFlowHelper.On("CanListNetworkSets", "default").Return(false, nil)
				mockFlowHelper.On("CanListPods", "").Return(false, nil)
				mockFlowHelper.On("CanListPods", "tigera-elasticsearch").Return(false, nil)

				params := &FlowLogNamesParams{
					Limit:       2000,
					Actions:     []string{"allow", "deny", "unknown"},
					Prefix:      "",
					ClusterName: "",
					Namespace:   "",
					Strict:      true,
				}

				names, err := getNamesFromLinseed(params, lsc, mockFlowHelper)
				Expect(err).To(Not(HaveOccurred()))
				Expect(names).To(HaveLen(1))
				Expect(names[0]).To(Equal("tigera-cluster-*"))
			})

			It("should return all endpoints as long as RBAC permissions exist for one endpoint in the flow", func() {
				By("Creating a mock ES client with a mocked out search results")
				lsc := client.NewMockClient("", duplicateFlowResponse...)
				mockFlowHelper := new(rbac.MockFlowHelper)

				mockFlowHelper.On("CanListHostEndpoints").Return(false, nil)
				mockFlowHelper.On("CanListGlobalNetworkSets").Return(false, nil)
				mockFlowHelper.On("CanListNetworkSets", "").Return(false, nil)
				mockFlowHelper.On("CanListNetworkSets", "default").Return(false, nil)
				mockFlowHelper.On("CanListPods", "").Return(false, nil)
				mockFlowHelper.On("CanListPods", "tigera-manager").Return(false, nil)
				mockFlowHelper.On("CanListPods", "tigera-elasticsearch").Return(false, nil)
				mockFlowHelper.On("CanListPods", "tigera-compliance").Return(true, nil)

				By("Creating params without strict RBAC enforcement")
				params := &FlowLogNamesParams{
					Limit:       2000,
					Actions:     []string{"allow", "deny", "unknown"},
					Prefix:      "",
					ClusterName: "",
					Namespace:   "",
				}

				names, err := getNamesFromLinseed(params, lsc, mockFlowHelper)
				Expect(err).To(Not(HaveOccurred()))
				Expect(names).To(HaveLen(5))
				Expect(names[0]).To(Equal("compliance-benchmarker-*"))
				Expect(names[1]).To(Equal("compliance-controller-c7f4b94dd-*"))
				Expect(names[2]).To(Equal("compliance-server-69c97dffcf-*"))
				Expect(names[3]).To(Equal("default/kse.kubernetes"))
				Expect(names[4]).To(Equal("tigera-manager-778447894c-*"))
			})
		})
	})

	Context("Test that the buildNamesQuery function applies filters only when necessary", func() {
		It("should return a query without filters", func() {
			By("Creating params with no actions")
			params := &FlowLogNamesParams{
				Limit:       2000,
				Prefix:      "",
				ClusterName: "",
				Namespace:   "tigera-compliance",
			}

			query := buildNamesQuery(params)
			Expect(query.NamespaceMatches).To(HaveLen(1))
		})

		It("should return a query with filters", func() {
			By("Creating params with actions")
			params := &FlowLogNamesParams{
				Limit:       2000,
				Actions:     []string{"allow", "deny", "unknown"},
				Prefix:      "",
				ClusterName: "",
				Namespace:   "tigera-compliance",
			}

			query := buildNamesQuery(params)
			Expect(query.Actions).To(HaveLen(3))
			Expect(query.NamespaceMatches).To(HaveLen(1))
		})

		It("should return a query with endpoint filters", func() {
			By("Creating params with type filters")
			params := &FlowLogNamesParams{
				Limit:       2000,
				Prefix:      "",
				ClusterName: "",
				Namespace:   "",
				SourceType:  []string{"net"},
				DestType:    []string{"wep"},
			}

			query := buildNamesQuery(params)
			Expect(query.SourceTypes).To(HaveLen(1))
			Expect(query.DestinationTypes).To(HaveLen(1))
		})

		It("should return a query with label filters", func() {
			By("Creating params with type filters")
			params := &FlowLogNamesParams{
				Limit:       2000,
				Prefix:      "",
				ClusterName: "",
				Namespace:   "",
				SourceLabels: []LabelSelector{
					{
						Key:      "app",
						Operator: "=",
						Values:   []string{"test-app"},
					},
				},
				DestLabels: []LabelSelector{
					{
						Key:      "otherapp",
						Operator: "=",
						Values:   []string{"not-test-app"},
					},
				},
			}

			query := buildNamesQuery(params)
			Expect(query.SourceSelectors).To(HaveLen(1))
			Expect(query.DestinationSelectors).To(HaveLen(1))
		})
	})
})
