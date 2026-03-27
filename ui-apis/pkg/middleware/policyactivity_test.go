// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/utils/ptr"

	linseedv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	uiapi "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
)

func newPolicyActivityPOST(req uiapi.PolicyActivityRequest) *http.Request {
	body, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "/policies/activities", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

// emptyPolicyActivityResult is a convenience for mock results that return no items.
var emptyPolicyActivityResult = rest.MockResult{Body: linseedv1.PolicyActivityResponse{Items: []linseedv1.PolicyActivityResult{}}}

// expectedResponseJSON marshals a uiapi.PolicyActivityResponse to JSON for use with MatchJSON.
func expectedResponseJSON(items []uiapi.PolicyActivityItem) []byte {
	b, err := json.Marshal(uiapi.PolicyActivityResponse{Items: items})
	Expect(err).NotTo(HaveOccurred())
	return b
}

var _ = Describe("PolicyActivity handler", func() {
	Describe("validatePolicyActivityRequest", func() {
		It("rejects empty policies", func() {
			req := &uiapi.PolicyActivityRequest{}
			err := validatePolicyActivityRequest(req)
			Expect(err).NotTo(BeNil())
			Expect(err.Msg).To(ContainSubstring("Policies"))
			Expect(err.Status).To(Equal(http.StatusBadRequest))
		})

		It("rejects missing kind", func() {
			req := &uiapi.PolicyActivityRequest{Policies: []uiapi.PolicyActivityQuery{{Name: "foo", Generation: 1}}}
			err := validatePolicyActivityRequest(req)
			Expect(err).NotTo(BeNil())
			Expect(err.Msg).To(ContainSubstring("Kind"))
			Expect(err.Status).To(Equal(http.StatusBadRequest))
		})

		It("rejects invalid kind", func() {
			req := &uiapi.PolicyActivityRequest{Policies: []uiapi.PolicyActivityQuery{{Kind: "BGPPeer", Name: "foo", Generation: 1}}}
			err := validatePolicyActivityRequest(req)
			Expect(err).NotTo(BeNil())
			Expect(err.Msg).To(ContainSubstring("Kind"))
			Expect(err.Status).To(Equal(http.StatusBadRequest))
		})

		It("rejects missing name", func() {
			req := &uiapi.PolicyActivityRequest{Policies: []uiapi.PolicyActivityQuery{{Kind: "GlobalNetworkPolicy", Generation: 1}}}
			err := validatePolicyActivityRequest(req)
			Expect(err).NotTo(BeNil())
			Expect(err.Msg).To(ContainSubstring("Name"))
			Expect(err.Status).To(Equal(http.StatusBadRequest))
		})

		It("rejects zero generation", func() {
			req := &uiapi.PolicyActivityRequest{Policies: []uiapi.PolicyActivityQuery{{Kind: "GlobalNetworkPolicy", Name: "foo", Generation: 0}}}
			err := validatePolicyActivityRequest(req)
			Expect(err).NotTo(BeNil())
			Expect(err.Msg).To(ContainSubstring("Generation"))
			Expect(err.Status).To(Equal(http.StatusBadRequest))
		})

		It("rejects negative generation", func() {
			req := &uiapi.PolicyActivityRequest{Policies: []uiapi.PolicyActivityQuery{{Kind: "GlobalNetworkPolicy", Name: "foo", Generation: -1}}}
			err := validatePolicyActivityRequest(req)
			Expect(err).NotTo(BeNil())
			Expect(err.Msg).To(ContainSubstring("Generation"))
			Expect(err.Status).To(Equal(http.StatusBadRequest))
		})

		It("accepts generation greater than 1", func() {
			req := &uiapi.PolicyActivityRequest{Policies: []uiapi.PolicyActivityQuery{{Kind: "GlobalNetworkPolicy", Name: "foo", Generation: 5}}}
			Expect(validatePolicyActivityRequest(req)).To(BeNil())
		})

		It("rejects missing namespace for namespaced kind", func() {
			req := &uiapi.PolicyActivityRequest{Policies: []uiapi.PolicyActivityQuery{{Kind: "NetworkPolicy", Name: "foo", Generation: 1}}}
			err := validatePolicyActivityRequest(req)
			Expect(err).NotTo(BeNil())
			Expect(err.Msg).To(ContainSubstring("missing required field: namespace"))
			Expect(err.Status).To(Equal(http.StatusBadRequest))
		})

		It("rejects missing namespace for StagedNetworkPolicy", func() {
			req := &uiapi.PolicyActivityRequest{Policies: []uiapi.PolicyActivityQuery{{Kind: "StagedNetworkPolicy", Name: "foo", Generation: 1}}}
			err := validatePolicyActivityRequest(req)
			Expect(err).NotTo(BeNil())
			Expect(err.Msg).To(ContainSubstring("missing required field: namespace"))
			Expect(err.Status).To(Equal(http.StatusBadRequest))
		})

		It("accepts namespace for namespaced kind", func() {
			req := &uiapi.PolicyActivityRequest{Policies: []uiapi.PolicyActivityQuery{{Kind: "NetworkPolicy", Name: "foo", Namespace: "prod", Generation: 1}}}
			Expect(validatePolicyActivityRequest(req)).To(BeNil())
		})

		It("rejects namespace for cluster-scoped kind GlobalNetworkPolicy", func() {
			req := &uiapi.PolicyActivityRequest{Policies: []uiapi.PolicyActivityQuery{{Kind: "GlobalNetworkPolicy", Name: "foo", Namespace: "oops", Generation: 1}}}
			err := validatePolicyActivityRequest(req)
			Expect(err).NotTo(BeNil())
			Expect(err.Msg).To(ContainSubstring("namespace must not be set"))
			Expect(err.Status).To(Equal(http.StatusBadRequest))
		})

		It("rejects namespace for cluster-scoped kind StagedGlobalNetworkPolicy", func() {
			req := &uiapi.PolicyActivityRequest{Policies: []uiapi.PolicyActivityQuery{{Kind: "StagedGlobalNetworkPolicy", Name: "foo", Namespace: "oops", Generation: 1}}}
			err := validatePolicyActivityRequest(req)
			Expect(err).NotTo(BeNil())
			Expect(err.Msg).To(ContainSubstring("namespace must not be set"))
			Expect(err.Status).To(Equal(http.StatusBadRequest))
		})

		It("accepts cluster-scoped kind without namespace", func() {
			req := &uiapi.PolicyActivityRequest{Policies: []uiapi.PolicyActivityQuery{{Kind: "GlobalNetworkPolicy", Name: "foo", Generation: 1}}}
			Expect(validatePolicyActivityRequest(req)).To(BeNil())
		})

		It("validates each policy independently", func() {
			req := &uiapi.PolicyActivityRequest{Policies: []uiapi.PolicyActivityQuery{
				{Kind: "GlobalNetworkPolicy", Name: "gnp1", Generation: 1},
				{Kind: "NetworkPolicy", Name: "np1", Namespace: "prod", Generation: 2},
			}}
			Expect(validatePolicyActivityRequest(req)).To(BeNil())
		})

		It("rejects when any policy in the list is invalid", func() {
			req := &uiapi.PolicyActivityRequest{Policies: []uiapi.PolicyActivityQuery{
				{Kind: "GlobalNetworkPolicy", Name: "gnp1", Generation: 1},
				{Kind: "NetworkPolicy", Name: "np1", Generation: 1}, // missing namespace
			}}
			err := validatePolicyActivityRequest(req)
			Expect(err).NotTo(BeNil())
			Expect(err.Msg).To(ContainSubstring("missing required field: namespace"))
			Expect(err.Status).To(Equal(http.StatusBadRequest))
		})
	})

	Describe("ServeHTTP", func() {
		var (
			mockLinseed lsclient.MockClient
			handler     http.Handler
		)

		BeforeEach(func() {
			mockLinseed = lsclient.NewMockClient("")
			handler = NewPolicyActivityHandler(mockLinseed)
		})

		When("the request is invalid", func() {
			It("rejects non-POST methods with 405", func() {
				for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
					req := httptest.NewRequest(method, "/policies/activities", nil)
					w := httptest.NewRecorder()
					handler.ServeHTTP(w, req)
					Expect(w.Code).To(Equal(http.StatusMethodNotAllowed), "method %s should be rejected", method)
				}
			})

			It("rejects malformed JSON body", func() {
				req := httptest.NewRequest(http.MethodPost, "/policies/activities", bytes.NewReader([]byte("{invalid")))
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})

			It("rejects empty body", func() {
				req := httptest.NewRequest(http.MethodPost, "/policies/activities", nil)
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})

			It("rejects missing policies field", func() {
				req := newPolicyActivityPOST(uiapi.PolicyActivityRequest{})
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
				Expect(w.Body.String()).To(ContainSubstring("Policies"))
			})

			It("rejects zero generation", func() {
				req := newPolicyActivityPOST(uiapi.PolicyActivityRequest{
					Policies: []uiapi.PolicyActivityQuery{
						{Kind: "GlobalNetworkPolicy", Name: "foo", Generation: 0},
					},
				})
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
				Expect(w.Body.String()).To(ContainSubstring("Generation"))
			})

			It("rejects missing namespace for namespaced kind", func() {
				req := newPolicyActivityPOST(uiapi.PolicyActivityRequest{
					Policies: []uiapi.PolicyActivityQuery{
						{Kind: "NetworkPolicy", Name: "foo", Generation: 1},
					},
				})
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
				Expect(w.Body.String()).To(ContainSubstring("missing required field: namespace"))
			})

			It("rejects namespace for cluster-scoped kind", func() {
				req := newPolicyActivityPOST(uiapi.PolicyActivityRequest{
					Policies: []uiapi.PolicyActivityQuery{
						{Kind: "GlobalNetworkPolicy", Name: "foo", Namespace: "oops", Generation: 1},
					},
				})
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
				Expect(w.Body.String()).To(ContainSubstring("namespace must not be set"))
			})
		})

		When("the requested generation is the newest with activity", func() {
			It("returns lastEvaluated", func() {
				now := time.Now()
				mockLinseed.SetResults(
					rest.MockResult{Body: linseedv1.PolicyActivityResponse{
						Items: []linseedv1.PolicyActivityResult{
							{
								Policy:        linseedv1.PolicyInfo{Kind: "GlobalNetworkPolicy", Name: "allow-dns"},
								LastEvaluated: &now,
								Rules: []linseedv1.PolicyActivityRuleResult{
									{Direction: "ingress", Index: "0", Generation: 1, LastEvaluated: now},
								},
							},
						},
					}},
				)

				req := newPolicyActivityPOST(uiapi.PolicyActivityRequest{
					Policies: []uiapi.PolicyActivityQuery{
						{Kind: "GlobalNetworkPolicy", Name: "allow-dns", Generation: 1},
					},
				})
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)

				Expect(w.Code).To(Equal(http.StatusOK))
				Expect(w.Header().Get("Content-Type")).To(Equal("application/json"))
				Expect(w.Body.Bytes()).To(MatchJSON(expectedResponseJSON([]uiapi.PolicyActivityItem{
					{
						PolicyKey: uiapi.PolicyKey{Kind: "GlobalNetworkPolicy", Name: "allow-dns"},
						PolicyActivity: uiapi.PolicyActivity{
							LastEvaluated:           &now,
							LastEvaluatedGeneration: ptr.To(int64(1)),
						},
					},
				})))

				reqs := mockLinseed.Requests()
				Expect(reqs).To(HaveLen(1))
				Expect(reqs[0].GetParams()).To(Equal(&linseedv1.PolicyActivityParams{
					Policies: []linseedv1.PolicyActivityQueryPolicy{
						{Kind: "GlobalNetworkPolicy", Name: "allow-dns"},
					},
				}))
			})
		})

		When("activity exists only at an older generation", func() {
			It("returns lastEvaluatedAnyGeneration", func() {
				earlier := time.Now().Add(-10 * time.Minute)
				mockLinseed.SetResults(
					rest.MockResult{Body: linseedv1.PolicyActivityResponse{
						Items: []linseedv1.PolicyActivityResult{
							{
								Policy:        linseedv1.PolicyInfo{Kind: "GlobalNetworkPolicy", Name: "allow-dns"},
								LastEvaluated: &earlier,
								Rules: []linseedv1.PolicyActivityRuleResult{
									{Direction: "ingress", Index: "0", Generation: 1, LastEvaluated: earlier},
								},
							},
						},
					}},
				)

				req := newPolicyActivityPOST(uiapi.PolicyActivityRequest{
					Policies: []uiapi.PolicyActivityQuery{
						{Kind: "GlobalNetworkPolicy", Name: "allow-dns", Generation: 2},
					},
				})
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)

				Expect(w.Code).To(Equal(http.StatusOK))
				Expect(w.Body.Bytes()).To(MatchJSON(expectedResponseJSON([]uiapi.PolicyActivityItem{
					{
						PolicyKey: uiapi.PolicyKey{Kind: "GlobalNetworkPolicy", Name: "allow-dns"},
						PolicyActivity: uiapi.PolicyActivity{
							LastEvaluatedAnyGeneration: &earlier,
							LastEvaluatedGeneration:    ptr.To(int64(1)),
						},
					},
				})))
			})
		})

		When("the policy has never been evaluated", func() {
			It("returns all nil timestamps", func() {
				mockLinseed.SetResults(emptyPolicyActivityResult)

				req := newPolicyActivityPOST(uiapi.PolicyActivityRequest{
					Policies: []uiapi.PolicyActivityQuery{
						{Kind: "GlobalNetworkPolicy", Name: "deny-all", Generation: 1},
					},
				})
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)

				Expect(w.Code).To(Equal(http.StatusOK))
				Expect(w.Body.Bytes()).To(MatchJSON(expectedResponseJSON([]uiapi.PolicyActivityItem{
					{PolicyKey: uiapi.PolicyKey{Kind: "GlobalNetworkPolicy", Name: "deny-all"}},
				})))
			})
		})

		When("activity exists at a newer generation than requested", func() {
			It("uses newer generation timestamp when requested generation also has activity", func() {
				now := time.Now()
				older := now.Add(-1 * time.Hour)
				mockLinseed.SetResults(
					rest.MockResult{Body: linseedv1.PolicyActivityResponse{
						Items: []linseedv1.PolicyActivityResult{
							{
								Policy:        linseedv1.PolicyInfo{Kind: "GlobalNetworkPolicy", Name: "test-pol"},
								LastEvaluated: &now,
								Rules: []linseedv1.PolicyActivityRuleResult{
									{Direction: "ingress", Index: "0", Generation: 1, LastEvaluated: older},
									{Direction: "egress", Index: "0", Generation: 2, LastEvaluated: now},
								},
							},
						},
					}},
				)

				req := newPolicyActivityPOST(uiapi.PolicyActivityRequest{
					Policies: []uiapi.PolicyActivityQuery{
						{Kind: "GlobalNetworkPolicy", Name: "test-pol", Generation: 1},
					},
				})
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)

				Expect(w.Code).To(Equal(http.StatusOK))
				Expect(w.Body.Bytes()).To(MatchJSON(expectedResponseJSON([]uiapi.PolicyActivityItem{
					{
						PolicyKey: uiapi.PolicyKey{Kind: "GlobalNetworkPolicy", Name: "test-pol"},
						PolicyActivity: uiapi.PolicyActivity{
							LastEvaluated:           &now,
							LastEvaluatedGeneration: ptr.To(int64(2)),
						},
					},
				})))
			})

			It("uses newer generation timestamp when requested generation has no activity", func() {
				now := time.Now()
				mockLinseed.SetResults(
					rest.MockResult{Body: linseedv1.PolicyActivityResponse{
						Items: []linseedv1.PolicyActivityResult{
							{
								Policy:        linseedv1.PolicyInfo{Kind: "GlobalNetworkPolicy", Name: "test-pol"},
								LastEvaluated: &now,
								Rules: []linseedv1.PolicyActivityRuleResult{
									{Direction: "ingress", Index: "0", Generation: 3, LastEvaluated: now},
								},
							},
						},
					}},
				)

				req := newPolicyActivityPOST(uiapi.PolicyActivityRequest{
					Policies: []uiapi.PolicyActivityQuery{
						{Kind: "GlobalNetworkPolicy", Name: "test-pol", Generation: 2},
					},
				})
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)

				Expect(w.Code).To(Equal(http.StatusOK))
				Expect(w.Body.Bytes()).To(MatchJSON(expectedResponseJSON([]uiapi.PolicyActivityItem{
					{
						PolicyKey: uiapi.PolicyKey{Kind: "GlobalNetworkPolicy", Name: "test-pol"},
						PolicyActivity: uiapi.PolicyActivity{
							LastEvaluated:           &now,
							LastEvaluatedGeneration: ptr.To(int64(3)),
						},
					},
				})))
			})
		})

		When("querying multiple policies", func() {
			It("returns mixed activity states in request order", func() {
				now := time.Now()
				earlier := now.Add(-5 * time.Minute)
				anyGenTime := now.Add(-30 * time.Minute)

				mockLinseed.SetResults(
					rest.MockResult{Body: linseedv1.PolicyActivityResponse{
						Items: []linseedv1.PolicyActivityResult{
							{
								Policy:        linseedv1.PolicyInfo{Kind: "GlobalNetworkPolicy", Name: "pol-a"},
								LastEvaluated: &now,
								Rules: []linseedv1.PolicyActivityRuleResult{
									{Direction: "ingress", Index: "0", Generation: 3, LastEvaluated: now},
								},
							},
							{
								Policy:        linseedv1.PolicyInfo{Kind: "NetworkPolicy", Namespace: "prod", Name: "pol-b"},
								LastEvaluated: &earlier,
								Rules: []linseedv1.PolicyActivityRuleResult{
									{Direction: "egress", Index: "0", Generation: 1, LastEvaluated: earlier},
								},
							},
							{
								Policy:        linseedv1.PolicyInfo{Kind: "GlobalNetworkPolicy", Name: "pol-c"},
								LastEvaluated: &anyGenTime,
								Rules: []linseedv1.PolicyActivityRuleResult{
									{Direction: "ingress", Index: "0", Generation: 1, LastEvaluated: anyGenTime},
								},
							},
						},
					}},
				)

				req := newPolicyActivityPOST(uiapi.PolicyActivityRequest{
					Policies: []uiapi.PolicyActivityQuery{
						{Kind: "GlobalNetworkPolicy", Name: "pol-a", Generation: 3},
						{Kind: "NetworkPolicy", Name: "pol-b", Namespace: "prod", Generation: 1},
						{Kind: "GlobalNetworkPolicy", Name: "pol-c", Generation: 2},
					},
				})
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)

				Expect(w.Code).To(Equal(http.StatusOK))
				Expect(w.Body.Bytes()).To(MatchJSON(expectedResponseJSON([]uiapi.PolicyActivityItem{
					{
						PolicyKey: uiapi.PolicyKey{Kind: "GlobalNetworkPolicy", Name: "pol-a"},
						PolicyActivity: uiapi.PolicyActivity{
							LastEvaluated:           &now,
							LastEvaluatedGeneration: ptr.To(int64(3)),
						},
					},
					{
						PolicyKey: uiapi.PolicyKey{Kind: "NetworkPolicy", Name: "pol-b", Namespace: "prod"},
						PolicyActivity: uiapi.PolicyActivity{
							LastEvaluated:           &earlier,
							LastEvaluatedGeneration: ptr.To(int64(1)),
						},
					},
					{
						PolicyKey: uiapi.PolicyKey{Kind: "GlobalNetworkPolicy", Name: "pol-c"},
						PolicyActivity: uiapi.PolicyActivity{
							LastEvaluatedAnyGeneration: &anyGenTime,
							LastEvaluatedGeneration:    ptr.To(int64(1)),
						},
					},
				})))
			})
		})

		When("interacting with Linseed", func() {
			It("sends a single query with Generation nil", func() {
				mockLinseed.SetResults(emptyPolicyActivityResult)

				req := newPolicyActivityPOST(uiapi.PolicyActivityRequest{
					Policies: []uiapi.PolicyActivityQuery{
						{Kind: "NetworkPolicy", Name: "allow-web", Namespace: "production", Generation: 3},
						{Kind: "GlobalNetworkPolicy", Name: "deny-all", Generation: 7},
					},
				})
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)

				Expect(w.Code).To(Equal(http.StatusOK))

				reqs := mockLinseed.Requests()
				Expect(reqs).To(HaveLen(1))
				Expect(reqs[0].GetParams()).To(Equal(&linseedv1.PolicyActivityParams{
					Policies: []linseedv1.PolicyActivityQueryPolicy{
						{Kind: "NetworkPolicy", Namespace: "production", Name: "allow-web"},
						{Kind: "GlobalNetworkPolicy", Name: "deny-all"},
					},
				}))
			})

			It("forwards x-cluster-id header", func() {
				mockLinseed.SetResults(emptyPolicyActivityResult)

				req := newPolicyActivityPOST(uiapi.PolicyActivityRequest{
					Policies: []uiapi.PolicyActivityQuery{
						{Kind: "GlobalNetworkPolicy", Name: "test-pol", Generation: 1},
					},
				})
				req.Header.Set(lmak8s.XClusterIDHeader, "managed-cluster-1")
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)

				Expect(w.Code).To(Equal(http.StatusOK))

				reqs := mockLinseed.Requests()
				Expect(reqs).To(HaveLen(1))
				Expect(reqs[0].GetParams()).To(Equal(&linseedv1.PolicyActivityParams{
					Policies: []linseedv1.PolicyActivityQueryPolicy{
						{Kind: "GlobalNetworkPolicy", Name: "test-pol"},
					},
				}))
			})

			It("returns items with nil timestamps when no results", func() {
				mockLinseed.SetResults(emptyPolicyActivityResult)

				req := newPolicyActivityPOST(uiapi.PolicyActivityRequest{
					Policies: []uiapi.PolicyActivityQuery{
						{Kind: "GlobalNetworkPolicy", Name: "nonexistent-policy", Generation: 1},
					},
				})
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)

				Expect(w.Code).To(Equal(http.StatusOK))
				Expect(w.Body.Bytes()).To(MatchJSON(expectedResponseJSON([]uiapi.PolicyActivityItem{
					{PolicyKey: uiapi.PolicyKey{Kind: "GlobalNetworkPolicy", Name: "nonexistent-policy"}},
				})))
			})
		})
	})
})
