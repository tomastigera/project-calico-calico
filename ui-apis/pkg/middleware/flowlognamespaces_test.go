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

var prefixResponse = []rest.MockResult{
	{
		Body: lapi.List[lapi.L3Flow]{
			TotalHits: 1,
			Items: []lapi.L3Flow{
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Namespace: "tigera-eck-operator",
						},
						Destination: lapi.Endpoint{
							Namespace: "tigera-elasticsearch",
						},
					},
					LogStats: &lapi.LogStats{FlowLogCount: 4370},
				},
			},
		},
	},
}

var duplicateNamespaceResponse = []rest.MockResult{
	{
		Body: lapi.List[lapi.L3Flow]{
			TotalHits: 7,
			Items: []lapi.L3Flow{
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Namespace: "tigera-prometheus",
						},
						Destination: lapi.Endpoint{
							Namespace: "tigera-elasticsearch",
						},
					},
				},
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Namespace: "tigera-compliance",
						},
						Destination: lapi.Endpoint{
							Namespace: "kube-system",
						},
					},
				},
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Namespace: "tigera-fluentd",
						},
						Destination: lapi.Endpoint{
							Namespace: "tigera-compliance",
						},
					},
				},
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Namespace: "tigera-manager",
						},
						Destination: lapi.Endpoint{
							Namespace: "calico-system",
						},
					},
				},
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Namespace: "tigera-eck-operator",
						},
						Destination: lapi.Endpoint{
							Namespace: "tigera-kibana",
						},
					},
				},
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Namespace: "tigera-manager",
						},
						Destination: lapi.Endpoint{
							Namespace: "tigera-intrusion-detection",
						},
					},
				},
			},
		},
	},
}

var globalNamespaceResponse = []rest.MockResult{
	{
		Body: lapi.List[lapi.L3Flow]{
			TotalHits: 1,
			Items: []lapi.L3Flow{
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							// Source is a global, non-namespaced object.
							Namespace: "",
						},
						Destination: lapi.Endpoint{
							Namespace: "tigera-elasticsearch",
						},
					},
				},
			},
		},
	},
}

var errorResponse = []rest.MockResult{{Err: fmt.Errorf("linseed error")}}

var _ = Describe("Test /flowLogNamespaces endpoint functions", func() {
	Context("Test that the validateFlowLogNamespacesRequest function behaves as expected", func() {
		It("should return an ErrInvalidMethod when passed a request with an http method other than GET", func() {
			By("Creating a request with a POST method")
			req, err := newTestRequest(http.MethodPost)
			Expect(err).NotTo(HaveOccurred())

			params, err := validateFlowLogNamespacesRequest(req)
			Expect(err).To(BeEquivalentTo(ErrInvalidMethod))
			Expect(params).To(BeNil())

			By("Creating a request with a DELETE method")
			req, err = newTestRequest(http.MethodDelete)
			Expect(err).NotTo(HaveOccurred())

			params, err = validateFlowLogNamespacesRequest(req)
			Expect(err).To(BeEquivalentTo(ErrInvalidMethod))
			Expect(params).To(BeNil())
		})

		It("should return a valid params object with the limit set to 1000 when passed an empty limit", func() {
			req, err := newTestRequest(http.MethodGet)
			Expect(err).NotTo(HaveOccurred())
			q := req.URL.Query()
			q.Add("limit", "")
			req.URL.RawQuery = q.Encode()

			params, err := validateFlowLogNamespacesRequest(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(params.Limit).To(BeNumerically("==", 1000))
		})

		It("should return a valid params object with the limit set to 1000 when passed a 0 limit", func() {
			req, err := newTestRequest(http.MethodGet)
			Expect(err).NotTo(HaveOccurred())
			q := req.URL.Query()
			q.Add("limit", "0")
			req.URL.RawQuery = q.Encode()

			params, err := validateFlowLogNamespacesRequest(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(params.Limit).To(BeNumerically("==", 1000))
		})

		It("should return an ErrParseRequest when passed a request with a negative limit parameter", func() {
			req, err := newTestRequest(http.MethodGet)
			Expect(err).NotTo(HaveOccurred())
			q := req.URL.Query()
			q.Add("limit", "-100")
			req.URL.RawQuery = q.Encode()

			params, err := validateFlowLogNamespacesRequest(req)
			Expect(err).To(BeEquivalentTo(ErrParseRequest))
			Expect(params).To(BeNil())
		})

		It("should return an ErrParseRequest when passed a request with a word as the limit parameter", func() {
			req, err := newTestRequest(http.MethodGet)
			Expect(err).NotTo(HaveOccurred())
			q := req.URL.Query()
			q.Add("limit", "ten")
			req.URL.RawQuery = q.Encode()

			params, err := validateFlowLogNamespacesRequest(req)
			Expect(err).To(BeEquivalentTo(ErrParseRequest))
			Expect(params).To(BeNil())
		})

		It("should return an ErrParseRequest when passed a request with a floating number as the limit parameter", func() {
			req, err := newTestRequest(http.MethodGet)
			Expect(err).NotTo(HaveOccurred())
			q := req.URL.Query()
			q.Add("limit", "3.14")
			req.URL.RawQuery = q.Encode()

			params, err := validateFlowLogNamespacesRequest(req)
			Expect(err).To(BeEquivalentTo(ErrParseRequest))
			Expect(params).To(BeNil())
		})

		It("should return an ErrParseRequest when passed a request with a max int32 + 1 number as the limit parameter", func() {
			req, err := newTestRequest(http.MethodGet)
			Expect(err).NotTo(HaveOccurred())
			q := req.URL.Query()
			q.Add("limit", "2147483648")
			req.URL.RawQuery = q.Encode()

			params, err := validateFlowLogNamespacesRequest(req)
			Expect(err).To(BeEquivalentTo(ErrParseRequest))
			Expect(params).To(BeNil())
		})

		It("should return an ErrParseRequest when passed a request with a min int32 - 1 number as the limit parameter", func() {
			req, err := newTestRequest(http.MethodGet)
			Expect(err).NotTo(HaveOccurred())
			q := req.URL.Query()
			q.Add("limit", "-2147483648")
			req.URL.RawQuery = q.Encode()

			params, err := validateFlowLogNamespacesRequest(req)
			Expect(err).To(BeEquivalentTo(ErrParseRequest))
			Expect(params).To(BeNil())
		})

		It("should return an ErrParseRequest when passed a request with an invalid unprotected param", func() {
			req, err := newTestRequest(http.MethodGet)
			Expect(err).NotTo(HaveOccurred())
			q := req.URL.Query()
			q.Add("unprotected", "xvz")
			req.URL.RawQuery = q.Encode()

			params, err := validateFlowLogNamespacesRequest(req)
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

			params, err := validateFlowLogNamespacesRequest(req)
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

			params, err = validateFlowLogNamespacesRequest(req)
			Expect(err).To(BeEquivalentTo(errInvalidAction))
			Expect(params).To(BeNil())
		})

		It("should return a valid FlowLogNamespaceParams object with the Actions from the request", func() {
			req, err := newTestRequest(http.MethodGet)
			Expect(err).NotTo(HaveOccurred())
			q := req.URL.Query()
			q.Add("actions", "allow")
			q.Add("actions", "deny")
			q.Add("actions", "unknown")
			req.URL.RawQuery = q.Encode()

			params, err := validateFlowLogNamespacesRequest(req)
			Expect(err).To(Not(HaveOccurred()))
			Expect(params.Actions[0]).To(BeEquivalentTo("allow"))
			Expect(params.Actions[1]).To(BeEquivalentTo("deny"))
			Expect(params.Actions[2]).To(BeEquivalentTo("unknown"))
		})

		It("should return a valid FlowLogNamespaceParams object when passed upper case parameters", func() {
			req, err := newTestRequest(http.MethodGet)
			Expect(err).NotTo(HaveOccurred())
			q := req.URL.Query()
			q.Add("actions", "ALLOW")
			q.Add("cluster", "CLUSTER")
			req.URL.RawQuery = q.Encode()

			params, err := validateFlowLogNamespacesRequest(req)
			Expect(err).To(Not(HaveOccurred()))
			Expect(params.Actions[0]).To(BeEquivalentTo("allow"))
			Expect(params.ClusterName).To(BeEquivalentTo("cluster"))
		})

		It("should return a valid FlowLogNamespaceParams when passed a request with valid start/end time", func() {
			req, err := newTestRequest(http.MethodGet)
			Expect(err).NotTo(HaveOccurred())
			q := req.URL.Query()
			q.Add("actions", "allow")
			q.Add("actions", "deny")
			startTimeObject, endTimeObject := getTestStartAndEndTime()
			q.Add("startDateTime", startTimeTest)
			q.Add("endDateTime", endTimeTest)

			Expect(err).To(Not(HaveOccurred()))
			req.URL.RawQuery = q.Encode()

			params, err := validateFlowLogNamesRequest(req)
			Expect(err).To(Not(HaveOccurred()))
			Expect(params.StartDateTime).To(BeEquivalentTo(startTimeObject))
			Expect(params.EndDateTime).To(BeEquivalentTo(endTimeObject))
		})
	})

	Context("Test that the getNamespacesFromElastic function behaves as expected", func() {
		It("should retrieve all namespaces with prefix tigera-e", func() {
			lsc := client.NewMockClient("", prefixResponse...)
			params := &FlowLogNamespaceParams{
				Limit:       2000,
				Actions:     []string{"allow", "deny", "unknown"},
				Prefix:      "tigera-e",
				ClusterName: "cluster",
			}

			namespaces, err := getNamespacesFromLinseed(params, lsc, rbac.NewAlwaysAllowFlowHelper())
			Expect(err).To(Not(HaveOccurred()))
			Expect(len(namespaces)).To(BeNumerically("==", 2))
			Expect(namespaces[0].Name).To(Equal("tigera-eck-operator"))
			Expect(namespaces[1].Name).To(Equal("tigera-elasticsearch"))
		})

		It("should retrieve an empty array of namespace objects", func() {
			lsc := client.NewMockClient("", emptyFlowResponse...)
			params := &FlowLogNamespaceParams{
				Limit:       2000,
				Actions:     []string{"allow", "deny", "unknown"},
				Prefix:      "",
				ClusterName: "cluster",
			}

			namespaces, err := getNamespacesFromLinseed(params, lsc, rbac.NewAlwaysAllowFlowHelper())
			Expect(err).To(Not(HaveOccurred()))
			Expect(len(namespaces)).To(BeNumerically("==", 0))
		})

		It("should retrieve an array of namespace objects with no duplicates", func() {
			lsc := client.NewMockClient("", duplicateNamespaceResponse...)
			params := &FlowLogNamespaceParams{
				Limit:       2000,
				Actions:     []string{"allow", "deny", "unknown"},
				Prefix:      "",
				ClusterName: "cluster",
			}

			namespaces, err := getNamespacesFromLinseed(params, lsc, rbac.NewAlwaysAllowFlowHelper())
			Expect(err).To(Not(HaveOccurred()))
			Expect(len(namespaces)).To(BeNumerically("==", 10))
			Expect(namespaces[0].Name).To(Equal("calico-system"))
			Expect(namespaces[1].Name).To(Equal("kube-system"))
			Expect(namespaces[2].Name).To(Equal("tigera-compliance"))
			Expect(namespaces[3].Name).To(Equal("tigera-eck-operator"))
			Expect(namespaces[4].Name).To(Equal("tigera-elasticsearch"))
			Expect(namespaces[5].Name).To(Equal("tigera-fluentd"))
			Expect(namespaces[6].Name).To(Equal("tigera-intrusion-detection"))
			Expect(namespaces[7].Name).To(Equal("tigera-kibana"))
			Expect(namespaces[8].Name).To(Equal("tigera-manager"))
			Expect(namespaces[9].Name).To(Equal("tigera-prometheus"))
		})

		It("should retrieve an array of namespace objects with no duplicates and only up to the limit", func() {
			lsc := client.NewMockClient("", duplicateNamespaceResponse...)
			params := &FlowLogNamespaceParams{
				Limit:       3,
				Actions:     []string{"allow", "deny", "unknown"},
				Prefix:      "",
				ClusterName: "cluster",
			}
			possibilities := []string{"kube-system", "tigera-compliance", "tigera-elasticsearch", "tigera-prometheus", "tigera-eck-operator"}
			namespaces, err := getNamespacesFromLinseed(params, lsc, rbac.NewAlwaysAllowFlowHelper())
			Expect(err).To(Not(HaveOccurred()))
			Expect(len(namespaces)).To(BeNumerically("==", 3))
			Expect(possibilities).To(ContainElement(namespaces[0].Name))
			Expect(possibilities).To(ContainElement(namespaces[1].Name))
			Expect(possibilities).To(ContainElement(namespaces[2].Name))
		})

		It("should return an error when the query fails", func() {
			lsc := client.NewMockClient("", errorResponse...)
			params := &FlowLogNamespaceParams{
				Limit:       2000,
				Actions:     []string{"allow", "deny", "unknown"},
				Prefix:      "",
				ClusterName: "",
			}
			namespaces, err := getNamespacesFromLinseed(params, lsc, rbac.NewAlwaysAllowFlowHelper())
			Expect(err).To(HaveOccurred())
			Expect(namespaces).To(HaveLen(0))
		})

		Context("getNamespacesFromElastic RBAC filtering", func() {
			var mockFlowHelper *rbac.MockFlowHelper
			BeforeEach(func() {
				mockFlowHelper = new(rbac.MockFlowHelper)
			})

			AfterEach(func() {
				mockFlowHelper.AssertExpectations(GinkgoT())
			})

			It("should filter out namespaces it does not have RBAC permissions to access", func() {
				lsc := client.NewMockClient("", prefixResponse...)

				mockFlowHelper.On("IncludeNamespace", "").Return(false, nil)
				mockFlowHelper.On("IncludeNamespace", "tigera-eck-operator").Return(false, nil)
				mockFlowHelper.On("IncludeNamespace", "tigera-elasticsearch").Return(true, nil)

				By("Creating params with strict RBAC enforcement")
				params := &FlowLogNamespaceParams{
					Limit:       2000,
					Actions:     []string{"allow", "deny", "unknown"},
					Prefix:      "",
					ClusterName: "cluster",
					Strict:      true,
				}

				namespaces, err := getNamespacesFromLinseed(params, lsc, mockFlowHelper)
				Expect(err).To(Not(HaveOccurred()))
				Expect(namespaces).To(HaveLen(1))
				Expect(namespaces[0].Name).To(Equal("tigera-elasticsearch"))
			})

			It("should return all namespaces as long as RBAC permissions exist for one side of each flow", func() {
				lsc := client.NewMockClient("", duplicateNamespaceResponse...)

				for _, namespace := range []string{
					"", "tigera-fluentd", "tigera-elasticsearch", "tigera-prometheus", "tigera-manager",
					"calico-system", "tigera-eck-operator", "tigera-kibana", "tigera-intrusion-detection",
				} {
					mockFlowHelper.On("IncludeNamespace", namespace).Return(false, nil)
				}

				mockFlowHelper.On("IncludeNamespace", "tigera-compliance").Return(true, nil)

				By("Creating params without strict RBAC enforcement")
				params := &FlowLogNamespaceParams{
					Limit:       2000,
					Actions:     []string{"allow", "deny", "unknown"},
					Prefix:      "",
					ClusterName: "cluster",
				}

				namespaces, err := getNamespacesFromLinseed(params, lsc, mockFlowHelper)
				Expect(err).To(Not(HaveOccurred()))
				Expect(namespaces).To(HaveLen(3))
				Expect(namespaces[0].Name).To(Equal("kube-system"))
				Expect(namespaces[1].Name).To(Equal("tigera-compliance"))
				Expect(namespaces[2].Name).To(Equal("tigera-fluentd"))
			})

			It("should return the global namespace if allowed", func() {
				lsc := client.NewMockClient("", globalNamespaceResponse...)

				mockFlowHelper.On("IncludeGlobalNamespace").Return(true, nil)
				mockFlowHelper.On("IncludeNamespace", "").Return(false, nil)
				mockFlowHelper.On("IncludeNamespace", "tigera-elasticsearch").Return(true, nil)

				By("Creating params with strict RBAC enforcement")
				params := &FlowLogNamespaceParams{
					Limit:       2000,
					Actions:     []string{"allow", "deny", "unknown"},
					Prefix:      "",
					ClusterName: "cluster",
					Strict:      true,
				}

				namespaces, err := getNamespacesFromLinseed(params, lsc, mockFlowHelper)
				Expect(err).To(Not(HaveOccurred()))
				Expect(namespaces).To(HaveLen(2))
				Expect(namespaces[0].Name).To(Equal("-"))
				Expect(namespaces[1].Name).To(Equal("tigera-elasticsearch"))
			})

			It("should omit the global namespace if not allowed", func() {
				lsc := client.NewMockClient("", globalNamespaceResponse...)

				mockFlowHelper.On("IncludeGlobalNamespace").Return(false, nil)
				mockFlowHelper.On("IncludeNamespace", "").Return(false, nil)
				mockFlowHelper.On("IncludeNamespace", "tigera-elasticsearch").Return(true, nil)

				By("Creating params with strict RBAC enforcement")
				params := &FlowLogNamespaceParams{
					Limit:       2000,
					Actions:     []string{"allow", "deny", "unknown"},
					Prefix:      "",
					ClusterName: "cluster",
					Strict:      true,
				}

				namespaces, err := getNamespacesFromLinseed(params, lsc, mockFlowHelper)
				Expect(err).To(Not(HaveOccurred()))
				Expect(namespaces).To(HaveLen(1))
				Expect(namespaces[0].Name).To(Equal("tigera-elasticsearch"))
			})
		})
	})

	Context("Test that the buildESQuery function applies filters only when necessary", func() {
		It("should return a query with filters", func() {
			By("Creating params with actions")
			params := &FlowLogNamespaceParams{
				Limit:       2000,
				Actions:     []string{"allow", "deny", "unknown"},
				Prefix:      "",
				ClusterName: "",
			}

			query := buildFlowNamespaceParams(params)
			Expect(query.Actions).To(HaveLen(3))
		})
	})
})
