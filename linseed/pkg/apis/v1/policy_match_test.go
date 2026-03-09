// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package v1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/utils/ptr"

	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
)

// TestPolicyMatchValidation_NameWithDots verifies that PolicyMatch.Name accepts policy names
// containing dots. After the policy naming changes (PR #10337), policy names are opaque strings
// that may contain dots (e.g., "platform.loadgenerator" in tier "platform"). The validation
// should not reject these names.
func TestPolicyMatchValidation_NameWithDots(t *testing.T) {
	tests := []struct {
		name        string
		policyMatch PolicyMatch
		expectValid bool
	}{
		{
			name: "simple name without dots should be valid",
			policyMatch: PolicyMatch{
				Tier:      "platform",
				Name:      ptr.To("loadgenerator"),
				Namespace: ptr.To("vote"),
			},
			expectValid: true,
		},
		{
			name: "name with dot (tier prefix style) should be valid",
			policyMatch: PolicyMatch{
				Tier:      "platform",
				Name:      ptr.To("platform.loadgenerator"),
				Namespace: ptr.To("vote"),
			},
			expectValid: true,
		},
		{
			name: "name with dot (non-tier prefix) should be valid",
			policyMatch: PolicyMatch{
				Tier:      "platform",
				Name:      ptr.To("foo.bar"),
				Namespace: ptr.To("vote"),
			},
			expectValid: true,
		},
		{
			name: "name with multiple dots should be valid",
			policyMatch: PolicyMatch{
				Tier:      "default",
				Name:      ptr.To("my.policy.name"),
				Namespace: ptr.To("default"),
			},
			expectValid: true,
		},
		{
			name: "calico-system tier policy with dot prefix should be valid",
			policyMatch: PolicyMatch{
				Tier: "calico-system",
				Name: ptr.To("calico-system.some-policy"),
			},
			expectValid: true,
		},
		{
			name: "name with colon should be invalid",
			policyMatch: PolicyMatch{
				Tier: "default",
				Name: ptr.To("bad:name"),
			},
			expectValid: false,
		},
		{
			name: "name with slash should be invalid",
			policyMatch: PolicyMatch{
				Tier: "default",
				Name: ptr.To("bad/name"),
			},
			expectValid: false,
		},
		{
			name: "tier with dot should be invalid",
			policyMatch: PolicyMatch{
				Tier: "bad.tier",
			},
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.Validate(&tt.policyMatch)
			if tt.expectValid {
				assert.NoError(t, err, "PolicyMatch should be valid but got error: %v", err)
			} else {
				assert.Error(t, err, "PolicyMatch should be invalid but passed validation")
			}
		})
	}
}
