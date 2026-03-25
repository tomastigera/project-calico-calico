// Copyright (c) 2026 Tigera, Inc. All rights reserved.
package client

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

// mockLinseedPolicyClient is a test mock for lsclient.PolicyActivityInterface.
type mockLinseedPolicyClient struct {
	resp *lsv1.PolicyActivityResponse
	err  error
	reqs []*lsv1.PolicyActivityParams
}

func (m *mockLinseedPolicyClient) Create(_ context.Context, _ []lsv1.PolicyActivity) (*lsv1.BulkResponse, error) {
	return nil, nil
}

func (m *mockLinseedPolicyClient) GetPolicyActivities(_ context.Context, req *lsv1.PolicyActivityParams) (*lsv1.PolicyActivityResponse, error) {
	m.reqs = append(m.reqs, req)
	if m.err != nil {
		return nil, m.err
	}
	return m.resp, nil
}

var _ = Describe("enrichPoliciesWithActivity", func() {
	It("merges activity data into policy items and rules", func() {
		now := time.Now()
		ingressTime := now.Add(-1 * time.Hour)
		egressTime := now.Add(-2 * time.Hour)

		mockClient := &mockLinseedPolicyClient{
			resp: &lsv1.PolicyActivityResponse{
				Items: []lsv1.PolicyActivityResult{
					{
						Policy:        lsv1.PolicyInfo{Kind: "NetworkPolicy", Namespace: "default", Name: "p1"},
						LastEvaluated: &now,
						Rules: []lsv1.PolicyActivityRuleResult{
							{Direction: "ingress", Index: "0", Generation: 5, LastEvaluated: ingressTime},
							{Direction: "egress", Index: "0", Generation: 5, LastEvaluated: egressTime},
						},
					},
				},
			},
		}

		cq := &cachedQuery{linseedPolicyActivity: mockClient}

		items := []Policy{
			{
				Kind:       "NetworkPolicy",
				Namespace:  "default",
				Name:       "p1",
				Generation: 5,
				IngressRules: []RuleInfo{
					{Source: RuleEntity{NumWorkloadEndpoints: 1}},
				},
				EgressRules: []RuleInfo{
					{Source: RuleEntity{NumWorkloadEndpoints: 2}},
				},
			},
		}

		err := cq.enrichPoliciesWithActivity(context.Background(), nil, nil, items)
		Expect(err).NotTo(HaveOccurred())

		Expect(items[0].LastEvaluated).To(HaveValue(BeTemporally("~", ingressTime, time.Second)))
		Expect(items[0].LastEvaluatedAnyGeneration).To(Equal(&now))
		Expect(items[0].IngressRules[0].LastEvaluated).To(Equal(&ingressTime))
		Expect(items[0].EgressRules[0].LastEvaluated).To(Equal(&egressTime))

		// Single request (all-generation query).
		Expect(mockClient.reqs).To(HaveLen(1))
		Expect(mockClient.reqs[0].Policies[0].Generation).To(BeNil())
	})

	It("returns error when linseed fails", func() {
		mockClient := &mockLinseedPolicyClient{
			err: fmt.Errorf("linseed unavailable"),
		}

		cq := &cachedQuery{linseedPolicyActivity: mockClient}

		items := []Policy{
			{Kind: "NetworkPolicy", Namespace: "default", Name: "p1", Generation: 1},
		}

		err := cq.enrichPoliciesWithActivity(context.Background(), nil, nil, items)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("linseed unavailable"))
	})

	It("enriches multiple policies where only some have activity data", func() {
		now := time.Now()
		earlier := now.Add(-3 * time.Hour)

		mockClient := &mockLinseedPolicyClient{
			resp: &lsv1.PolicyActivityResponse{
				Items: []lsv1.PolicyActivityResult{
					{
						Policy:        lsv1.PolicyInfo{Kind: "NetworkPolicy", Namespace: "default", Name: "p1"},
						LastEvaluated: &now,
						Rules: []lsv1.PolicyActivityRuleResult{
							{Direction: "ingress", Index: "0", Generation: 1, LastEvaluated: now},
						},
					},
					// p2 has no activity data — not in response
					{
						Policy:        lsv1.PolicyInfo{Kind: "GlobalNetworkPolicy", Namespace: "", Name: "gp1"},
						LastEvaluated: &earlier,
						Rules: []lsv1.PolicyActivityRuleResult{
							{Direction: "ingress", Index: "0", Generation: 3, LastEvaluated: earlier},
						},
					},
				},
			},
		}

		cq := &cachedQuery{linseedPolicyActivity: mockClient}

		items := []Policy{
			{Kind: "NetworkPolicy", Namespace: "default", Name: "p1", Generation: 1},
			{Kind: "NetworkPolicy", Namespace: "default", Name: "p2", Generation: 2},
			{Kind: "GlobalNetworkPolicy", Namespace: "", Name: "gp1", Generation: 3},
		}

		err := cq.enrichPoliciesWithActivity(context.Background(), nil, nil, items)
		Expect(err).NotTo(HaveOccurred())

		Expect(items[0].LastEvaluated).NotTo(BeNil())
		Expect(items[1].LastEvaluated).To(BeNil()) // no activity data
		Expect(items[2].LastEvaluated).NotTo(BeNil())
	})

	It("enriches multiple ingress and egress rules independently", func() {
		now := time.Now()
		ing0 := now.Add(-1 * time.Hour)
		ing1 := now.Add(-2 * time.Hour)
		egr0 := now.Add(-3 * time.Hour)

		mockClient := &mockLinseedPolicyClient{
			resp: &lsv1.PolicyActivityResponse{
				Items: []lsv1.PolicyActivityResult{
					{
						Policy:        lsv1.PolicyInfo{Kind: "NetworkPolicy", Namespace: "ns", Name: "multi-rule"},
						LastEvaluated: &now,
						Rules: []lsv1.PolicyActivityRuleResult{
							{Direction: "ingress", Index: "0", Generation: 1, LastEvaluated: ing0},
							{Direction: "ingress", Index: "1", Generation: 1, LastEvaluated: ing1},
							{Direction: "egress", Index: "0", Generation: 1, LastEvaluated: egr0},
							// egress/1 has no activity
						},
					},
				},
			},
		}

		cq := &cachedQuery{linseedPolicyActivity: mockClient}

		items := []Policy{
			{
				Kind: "NetworkPolicy", Namespace: "ns", Name: "multi-rule",
				Generation: 1,
				IngressRules: []RuleInfo{
					{Source: RuleEntity{NumWorkloadEndpoints: 1}},
					{Source: RuleEntity{NumWorkloadEndpoints: 2}},
				},
				EgressRules: []RuleInfo{
					{Source: RuleEntity{NumWorkloadEndpoints: 3}},
					{Source: RuleEntity{NumWorkloadEndpoints: 4}},
				},
			},
		}

		err := cq.enrichPoliciesWithActivity(context.Background(), nil, nil, items)
		Expect(err).NotTo(HaveOccurred())

		Expect(items[0].LastEvaluated).NotTo(BeNil())
		Expect(items[0].IngressRules[0].LastEvaluated).To(Equal(&ing0))
		Expect(items[0].IngressRules[1].LastEvaluated).To(Equal(&ing1))
		Expect(items[0].EgressRules[0].LastEvaluated).To(Equal(&egr0))
		Expect(items[0].EgressRules[1].LastEvaluated).To(BeNil()) // no activity for this rule
	})

	It("populates implicit deny timestamps from non-integer rule indices", func() {
		now := time.Now()
		implicitTime := now.Add(-30 * time.Minute)

		mockClient := &mockLinseedPolicyClient{
			resp: &lsv1.PolicyActivityResponse{
				Items: []lsv1.PolicyActivityResult{
					{
						Policy:        lsv1.PolicyInfo{Kind: "NetworkPolicy", Namespace: "default", Name: "p1"},
						LastEvaluated: &now,
						Rules: []lsv1.PolicyActivityRuleResult{
							{Direction: "ingress", Index: "0", Generation: 1, LastEvaluated: now},
							{Direction: "ingress", Index: "implicit_deny", Generation: 1, LastEvaluated: implicitTime},
							{Direction: "egress", Index: "implicit_deny", Generation: 1, LastEvaluated: implicitTime},
						},
					},
				},
			},
		}

		cq := &cachedQuery{linseedPolicyActivity: mockClient}

		items := []Policy{
			{
				Kind: "NetworkPolicy", Namespace: "default", Name: "p1",
				Generation: 1,
				IngressRules: []RuleInfo{
					{Source: RuleEntity{NumWorkloadEndpoints: 1}},
				},
			},
		}

		err := cq.enrichPoliciesWithActivity(context.Background(), nil, nil, items)
		Expect(err).NotTo(HaveOccurred())

		Expect(items[0].IngressRules[0].LastEvaluated).To(Equal(&now))
		Expect(items[0].IngressRules[0].ImplicitDenyLastEvaluated).To(Equal(&implicitTime))
		// No egress rules defined, so egress implicit deny has nowhere to surface.
		Expect(items[0].EgressRules).To(BeEmpty())
	})

	It("populates LastEvaluatedAnyGeneration when only a previous generation has activity", func() {
		oldTime := time.Now().Add(-24 * time.Hour)

		// Linseed returns activity from gen 1 but the policy is at gen 3.
		// The single all-gen query returns rules tagged with generation.
		mockClient := &mockLinseedPolicyClient{
			resp: &lsv1.PolicyActivityResponse{
				Items: []lsv1.PolicyActivityResult{
					{
						Policy:        lsv1.PolicyInfo{Kind: "NetworkPolicy", Namespace: "default", Name: "p1"},
						LastEvaluated: &oldTime,
						Rules: []lsv1.PolicyActivityRuleResult{
							// Only generation 1 activity — no gen 3 rules.
							{Direction: "ingress", Index: "0", Generation: 1, LastEvaluated: oldTime},
						},
					},
				},
			},
		}
		cq := &cachedQuery{linseedPolicyActivity: mockClient}

		items := []Policy{{Kind: "NetworkPolicy", Namespace: "default", Name: "p1", Generation: 3}}

		err := cq.enrichPoliciesWithActivity(context.Background(), nil, nil, items)
		Expect(err).NotTo(HaveOccurred())
		// Current generation (3) has no activity.
		Expect(items[0].LastEvaluated).To(BeNil())
		// But a previous generation does.
		Expect(items[0].LastEvaluatedAnyGeneration).To(Equal(&oldTime))
	})

	It("skips enrichment when items list is empty", func() {
		mockClient := &mockLinseedPolicyClient{
			resp: &lsv1.PolicyActivityResponse{Items: []lsv1.PolicyActivityResult{}},
		}

		cq := &cachedQuery{linseedPolicyActivity: mockClient}
		err := cq.enrichPoliciesWithActivity(context.Background(), nil, nil, []Policy{})
		Expect(err).NotTo(HaveOccurred())

		// Should not have called linseed at all.
		Expect(mockClient.reqs).To(BeEmpty())
	})
})

var _ = Describe("needsPolicyActivity", func() {
	It("returns true when no field selector (all fields)", func() {
		cq := &cachedQuery{linseedPolicyActivity: &mockLinseedPolicyClient{}}
		Expect(cq.needsPolicyActivity(nil)).To(BeTrue())
	})

	It("returns true when lastEvaluated is in field selector", func() {
		cq := &cachedQuery{linseedPolicyActivity: &mockLinseedPolicyClient{}}
		Expect(cq.needsPolicyActivity(map[string]bool{"lastevaluated": true, "name": true})).To(BeTrue())
	})

	It("returns false when lastEvaluated is not in field selector", func() {
		cq := &cachedQuery{linseedPolicyActivity: &mockLinseedPolicyClient{}}
		Expect(cq.needsPolicyActivity(map[string]bool{"name": true, "kind": true})).To(BeFalse())
	})

	It("returns false when field selector is empty map", func() {
		cq := &cachedQuery{linseedPolicyActivity: &mockLinseedPolicyClient{}}
		Expect(cq.needsPolicyActivity(map[string]bool{})).To(BeFalse())
	})
})
