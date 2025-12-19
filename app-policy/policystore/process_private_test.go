// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package policystore

import (
	"testing"

	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
)

func TestPolicyHeaderMerging(t *testing.T) {
	RegisterTestingT(t)

	store := NewPolicyStore()

	// Create a policy with duplicate content-type headers
	policy := &proto.Policy{
		Tier: "default",
		InboundRules: []*proto.Rule{
			{
				Action: "allow",
				HttpMatch: &proto.HTTPMatch{
					Headers: []*proto.HTTPMatch_HeadersMatch{
						{
							Header:   "content-type",
							Operator: "In",
							Values:   []string{"text/plain"},
						},
						{
							Header:   "content-type",
							Operator: "In",
							Values:   []string{"application/json"},
						},
					},
				},
			},
		},
	}

	update := &proto.ActivePolicyUpdate{
		Id: &proto.PolicyID{
			Name: "test-policy",
			Kind: v3.KindGlobalNetworkPolicy,
		},
		Policy: policy,
	}

	// Process the policy update through our merging logic
	store.processActivePolicyUpdate(update)

	// Verify the policy was stored and merged correctly
	policyID := types.PolicyID{Name: "test-policy", Kind: v3.KindGlobalNetworkPolicy}
	storedPolicy := store.PolicyByID[policyID]

	Expect(storedPolicy).ToNot(BeNil())
	Expect(storedPolicy.InboundRules).To(HaveLen(1))

	rule := storedPolicy.InboundRules[0]
	Expect(rule.HttpMatch).ToNot(BeNil())

	// Should have only 1 content-type header after merging
	Expect(rule.HttpMatch.Headers).To(HaveLen(1))

	header := rule.HttpMatch.Headers[0]
	Expect(header.Header).To(Equal("content-type"))
	Expect(header.Operator).To(Equal("In"))

	// Should have merged values
	Expect(header.Values).To(HaveLen(2))
	Expect(header.Values).To(ConsistOf("text/plain", "application/json"))
}

func TestPolicyHeaderMergingWithDifferentOperators(t *testing.T) {
	RegisterTestingT(t)

	store := NewPolicyStore()

	// Create a policy with same header name but different operators
	policy := &proto.Policy{
		Tier: "default",
		InboundRules: []*proto.Rule{
			{
				Action: "allow",
				HttpMatch: &proto.HTTPMatch{
					Headers: []*proto.HTTPMatch_HeadersMatch{
						{
							Header:   "content-type",
							Operator: "exact",
							Values:   []string{"text/plain"},
						},
						{
							Header:   "content-type",
							Operator: "regex",
							Values:   []string{"application/.*"},
						},
					},
				},
			},
		},
	}

	update := &proto.ActivePolicyUpdate{
		Id: &proto.PolicyID{
			Name: "test-policy-2",
			Kind: v3.KindGlobalNetworkPolicy,
		},
		Policy: policy,
	}

	store.processActivePolicyUpdate(update)

	policyID := types.PolicyID{Name: "test-policy-2", Kind: v3.KindGlobalNetworkPolicy}
	storedPolicy := store.PolicyByID[policyID]

	Expect(storedPolicy).ToNot(BeNil())
	Expect(storedPolicy.InboundRules).To(HaveLen(1))

	rule := storedPolicy.InboundRules[0]
	Expect(rule.HttpMatch).ToNot(BeNil())

	// Should have 2 headers (different operators are not merged)
	Expect(rule.HttpMatch.Headers).To(HaveLen(2))
}
