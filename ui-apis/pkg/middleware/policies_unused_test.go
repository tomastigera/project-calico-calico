// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package middleware

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	querycacheclient "github.com/projectcalico/calico/queryserver/pkg/querycache/client"
	queryserverclient "github.com/projectcalico/calico/queryserver/queryserver/client"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
)

// mockPoliciesSearcher is a test double for policiesSearcher.
type mockPoliciesSearcher struct {
	resp *querycacheclient.QueryPoliciesResp
	err  error

	capturedFrom      *time.Time
	capturedTo        *time.Time
	capturedClusterID string
}

func (m *mockPoliciesSearcher) SearchPolicies(cfg *queryserverclient.QueryServerConfig, from, to *time.Time, clusterID string) (*querycacheclient.QueryPoliciesResp, error) {
	m.capturedFrom = from
	m.capturedTo = to
	m.capturedClusterID = clusterID
	if m.err != nil {
		return nil, m.err
	}
	return m.resp, nil
}

func newTestUnusedHandler(mock *mockPoliciesSearcher) http.Handler {
	cfg := &queryserverclient.QueryServerConfig{}
	return unusedPoliciesHandler(cfg, mock)
}

var _ = Describe("classifyUnusedPolicies", func() {
	now := time.Now()

	It("returns empty lists when no policies", func() {
		resp := classifyUnusedPolicies(nil)
		Expect(resp.Policies).To(BeEmpty())
		Expect(resp.Rules).To(BeEmpty())
	})

	It("classifies a policy with nil lastEvaluated as entirely unused", func() {
		createdAt := &metav1.Time{Time: now.Add(-48 * time.Hour)}
		resp := classifyUnusedPolicies([]querycacheclient.Policy{
			{
				Kind:          "NetworkPolicy",
				Namespace:     "default",
				Name:          "deny-all",
				Generation:    3,
				CreationTime:  createdAt,
				LastEvaluated: nil,
			},
		})
		Expect(resp.Policies).To(HaveLen(1))
		Expect(resp.Rules).To(BeEmpty())

		p := resp.Policies[0]
		Expect(p.Kind).To(Equal("NetworkPolicy"))
		Expect(p.Namespace).To(Equal("default"))
		Expect(p.Name).To(Equal("deny-all"))
		Expect(p.Generation).To(Equal(int64(3)))
		Expect(p.CreationTime).To(Equal(createdAt))
	})

	It("ignores a fully-evaluated policy (all rules have lastEvaluated)", func() {
		ingTime := now.Add(-1 * time.Hour)
		egrTime := now.Add(-2 * time.Hour)
		resp := classifyUnusedPolicies([]querycacheclient.Policy{
			{
				Kind:          "NetworkPolicy",
				Namespace:     "ns",
				Name:          "allow-web",
				LastEvaluated: &now,
				IngressRules:  []querycacheclient.RuleInfo{{LastEvaluated: &ingTime}},
				EgressRules:   []querycacheclient.RuleInfo{{LastEvaluated: &egrTime}},
			},
		})
		Expect(resp.Policies).To(BeEmpty())
		Expect(resp.Rules).To(BeEmpty())
	})

	It("classifies a policy with some nil rule timestamps as partially unused", func() {
		ingTime := now.Add(-1 * time.Hour)
		resp := classifyUnusedPolicies([]querycacheclient.Policy{
			{
				Kind:          "NetworkPolicy",
				Namespace:     "ns",
				Name:          "partial",
				Generation:    2,
				LastEvaluated: &now,
				IngressRules: []querycacheclient.RuleInfo{
					{LastEvaluated: &ingTime}, // used
					{LastEvaluated: nil},      // unused
				},
				EgressRules: []querycacheclient.RuleInfo{
					{LastEvaluated: nil},      // unused
					{LastEvaluated: &ingTime}, // used
				},
			},
		})
		Expect(resp.Policies).To(BeEmpty())
		Expect(resp.Rules).To(HaveLen(1))

		r := resp.Rules[0]
		Expect(r.Kind).To(Equal("NetworkPolicy"))
		Expect(r.Namespace).To(Equal("ns"))
		Expect(r.Name).To(Equal("partial"))
		Expect(r.Generation).To(Equal(int64(2)))
		Expect(r.UnusedRules).To(ConsistOf(
			v1.UnusedRule{Direction: "ingress", Index: "1"},
			v1.UnusedRule{Direction: "egress", Index: "0"},
		))
	})

	It("handles a mix of unused, partially-unused, and fully-used policies", func() {
		ingTime := now.Add(-1 * time.Hour)
		policies := []querycacheclient.Policy{
			// entirely unused
			{Kind: "NetworkPolicy", Namespace: "ns", Name: "unused", LastEvaluated: nil},
			// all rules evaluated
			{
				Kind:          "NetworkPolicy",
				Namespace:     "ns",
				Name:          "fully-used",
				LastEvaluated: &now,
				IngressRules:  []querycacheclient.RuleInfo{{LastEvaluated: &ingTime}},
			},
			// partial: ingress[0] used, egress[0] unused
			{
				Kind:          "GlobalNetworkPolicy",
				Namespace:     "",
				Name:          "gnp-partial",
				LastEvaluated: &now,
				IngressRules:  []querycacheclient.RuleInfo{{LastEvaluated: &ingTime}},
				EgressRules:   []querycacheclient.RuleInfo{{LastEvaluated: nil}},
			},
		}
		resp := classifyUnusedPolicies(policies)

		Expect(resp.Policies).To(HaveLen(1))
		Expect(resp.Policies[0].Name).To(Equal("unused"))

		Expect(resp.Rules).To(HaveLen(1))
		Expect(resp.Rules[0].Name).To(Equal("gnp-partial"))
		Expect(resp.Rules[0].UnusedRules).To(ConsistOf(
			v1.UnusedRule{Direction: "egress", Index: "0"},
		))
	})

	It("does not add to rules list when all rules are evaluated even if policy has lastEvaluated", func() {
		ingTime := now.Add(-1 * time.Hour)
		resp := classifyUnusedPolicies([]querycacheclient.Policy{
			{
				Kind:          "NetworkPolicy",
				Namespace:     "ns",
				Name:          "all-rules-used",
				LastEvaluated: &now,
				IngressRules:  []querycacheclient.RuleInfo{{LastEvaluated: &ingTime}},
				EgressRules:   []querycacheclient.RuleInfo{{LastEvaluated: &ingTime}},
			},
		})
		Expect(resp.Policies).To(BeEmpty())
		Expect(resp.Rules).To(BeEmpty())
	})

	It("handles a policy with no rules as fully used when lastEvaluated is set", func() {
		resp := classifyUnusedPolicies([]querycacheclient.Policy{
			{Kind: "NetworkPolicy", Name: "no-rules", LastEvaluated: &now},
		})
		Expect(resp.Policies).To(BeEmpty())
		Expect(resp.Rules).To(BeEmpty())
	})
})

var _ = Describe("parseUnusedTimeRange", func() {
	It("returns nil, nil when no query params", func() {
		r, _ := http.NewRequest("GET", "/policies/unused", nil)
		from, to, err := parseUnusedTimeRange(r)
		Expect(err).NotTo(HaveOccurred())
		Expect(from).To(BeNil())
		Expect(to).To(BeNil())
	})

	It("parses valid RFC3339 from and to", func() {
		fromStr := "2024-01-01T00:00:00Z"
		toStr := "2024-06-01T12:00:00Z"
		r, _ := http.NewRequest("GET", "/policies/unused?from="+fromStr+"&to="+toStr, nil)
		from, to, err := parseUnusedTimeRange(r)

		Expect(err).NotTo(HaveOccurred())
		Expect(from).NotTo(BeNil())
		Expect(to).NotTo(BeNil())
		Expect(from.UTC().Format(time.RFC3339)).To(Equal(fromStr))
		Expect(to.UTC().Format(time.RFC3339)).To(Equal(toStr))
	})

	It("parses only from when to is absent", func() {
		r, _ := http.NewRequest("GET", "/policies/unused?from=2024-01-01T00:00:00Z", nil)
		from, to, err := parseUnusedTimeRange(r)
		Expect(err).NotTo(HaveOccurred())
		Expect(from).NotTo(BeNil())
		Expect(to).To(BeNil())
	})

	It("parses relative time formats", func() {
		r, _ := http.NewRequest("GET", "/policies/unused?from=now-90d&to=now", nil)
		from, to, err := parseUnusedTimeRange(r)
		Expect(err).NotTo(HaveOccurred())
		Expect(from).NotTo(BeNil())
		Expect(to).NotTo(BeNil())
	})

	It("returns error for an unparseable from value", func() {
		r, _ := http.NewRequest("GET", "/policies/unused?from=not-a-date", nil)
		_, _, err := parseUnusedTimeRange(r)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid 'from'"))
	})

	It("returns error for an unparseable to value", func() {
		r, _ := http.NewRequest("GET", "/policies/unused?to=garbage", nil)
		_, _, err := parseUnusedTimeRange(r)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid 'to'"))
	})
})

var _ = Describe("UnusedPoliciesHandler", func() {
	It("returns 405 for non-GET requests", func() {
		handler := newTestUnusedHandler(&mockPoliciesSearcher{})
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			r, _ := http.NewRequest(method, "/policies/unused", nil)
			r.Header.Set("Authorization", "Bearer token")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			Expect(w.Code).To(Equal(http.StatusMethodNotAllowed), "expected 405 for method %s", method)
		}
	})

	It("returns 401 when Authorization header is missing", func() {
		handler := newTestUnusedHandler(&mockPoliciesSearcher{})
		r, _ := http.NewRequest("GET", "/policies/unused", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		Expect(w.Code).To(Equal(http.StatusUnauthorized))
	})

	It("returns 401 when Authorization header is too short", func() {
		handler := newTestUnusedHandler(&mockPoliciesSearcher{})
		r, _ := http.NewRequest("GET", "/policies/unused", nil)
		r.Header.Set("Authorization", "short")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		Expect(w.Code).To(Equal(http.StatusUnauthorized))
	})

	It("returns 500 when queryserver SearchPolicies fails", func() {
		mock := &mockPoliciesSearcher{err: errors.New("queryserver unavailable")}
		handler := newTestUnusedHandler(mock)
		r, _ := http.NewRequest("GET", "/policies/unused", nil)
		r.Header.Set("Authorization", "Bearer mytoken")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		Expect(w.Code).To(Equal(http.StatusInternalServerError))
	})

	It("returns classified policies on success", func() {
		now := time.Now()
		mock := &mockPoliciesSearcher{
			resp: &querycacheclient.QueryPoliciesResp{
				Count: 2,
				Items: []querycacheclient.Policy{
					{Kind: "NetworkPolicy", Namespace: "ns", Name: "unused", LastEvaluated: nil},
					{
						Kind:          "NetworkPolicy",
						Namespace:     "ns",
						Name:          "partial",
						LastEvaluated: &now,
						EgressRules:   []querycacheclient.RuleInfo{{LastEvaluated: nil}},
					},
				},
			},
		}
		handler := newTestUnusedHandler(mock)
		r, _ := http.NewRequest("GET", "/policies/unused", nil)
		r.Header.Set("Authorization", "Bearer mytoken")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)

		Expect(w.Code).To(Equal(http.StatusOK))

		var resp v1.UnusedPoliciesResponse
		Expect(json.Unmarshal(w.Body.Bytes(), &resp)).To(Succeed())
		Expect(resp.Policies).To(HaveLen(1))
		Expect(resp.Policies[0].Name).To(Equal("unused"))
		Expect(resp.Rules).To(HaveLen(1))
		Expect(resp.Rules[0].Name).To(Equal("partial"))
		Expect(resp.Rules[0].UnusedRules).To(ConsistOf(v1.UnusedRule{Direction: "egress", Index: "0"}))
	})

	It("passes from/to query params to queryserver", func() {
		mock := &mockPoliciesSearcher{
			resp: &querycacheclient.QueryPoliciesResp{Items: []querycacheclient.Policy{}},
		}
		handler := newTestUnusedHandler(mock)
		r, _ := http.NewRequest("GET", "/policies/unused?from=2024-01-01T00:00:00Z&to=2024-06-01T00:00:00Z", nil)
		r.Header.Set("Authorization", "Bearer mytoken")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)

		Expect(w.Code).To(Equal(http.StatusOK))
		Expect(mock.capturedFrom).NotTo(BeNil())
		Expect(mock.capturedTo).NotTo(BeNil())
		Expect(mock.capturedFrom.UTC().Format(time.RFC3339)).To(Equal("2024-01-01T00:00:00Z"))
		Expect(mock.capturedTo.UTC().Format(time.RFC3339)).To(Equal("2024-06-01T00:00:00Z"))
	})

	It("passes x-cluster-id header to queryserver", func() {
		mock := &mockPoliciesSearcher{
			resp: &querycacheclient.QueryPoliciesResp{Items: []querycacheclient.Policy{}},
		}
		handler := newTestUnusedHandler(mock)
		r, _ := http.NewRequest("GET", "/policies/unused", nil)
		r.Header.Set("Authorization", "Bearer mytoken")
		r.Header.Set("x-cluster-id", "my-cluster")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)

		Expect(w.Code).To(Equal(http.StatusOK))
		Expect(mock.capturedClusterID).To(Equal("my-cluster"))
	})
})
