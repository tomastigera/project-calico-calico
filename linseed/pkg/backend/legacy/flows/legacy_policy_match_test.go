// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package flows

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

func TestAllPolicyQueryLegacy(t *testing.T) {
	t.Run("Enforced (Default)", func(t *testing.T) {
		// Define a simple policy match (Staged=false by default)
		pm := v1.PolicyMatch{
			Tier: "default",
		}

		// Generate the query
		q, err := allPolicyQueryLegacy(pm)
		require.NoError(t, err)
		require.NotNil(t, q)

		// Convert to source map to inspect structure
		src, err := q.Source()
		require.NoError(t, err)

		// Marshal to JSON string to make string containment checks easy
		jsonBytes, err := json.Marshal(src)
		require.NoError(t, err)
		jsonStr := string(jsonBytes)

		// Assertions
		// 1. Must be a bool query
		assert.Contains(t, jsonStr, `"bool"`)
		// 2. Must have minimum_should_match set to 1
		assert.Contains(t, jsonStr, `"minimum_should_match":"1"`)
		// 3. Must search in all_policies and enforced_policies
		assert.Contains(t, jsonStr, `"policies.all_policies"`)
		assert.Contains(t, jsonStr, `"policies.enforced_policies"`)
		// 4. Must NOT search in pending_policies
		assert.NotContains(t, jsonStr, `"policies.pending_policies"`)
	})

	t.Run("Pending (Staged=true)", func(t *testing.T) {
		// Define a policy match with Staged=true
		pm := v1.PolicyMatch{
			Tier:   "default",
			Staged: ptr.To(true),
		}

		// Generate the query
		q, err := allPolicyQueryLegacy(pm)
		require.NoError(t, err)
		require.NotNil(t, q)

		// Convert to source map to inspect structure
		src, err := q.Source()
		require.NoError(t, err)

		// Marshal to JSON string to make string containment checks easy
		jsonBytes, err := json.Marshal(src)
		require.NoError(t, err)
		jsonStr := string(jsonBytes)

		// Assertions
		// 1. Must be a bool query
		assert.Contains(t, jsonStr, `"bool"`)
		// 2. Must have minimum_should_match set to 1
		assert.Contains(t, jsonStr, `"minimum_should_match":"1"`)
		// 3. Must search in all_policies and pending_policies
		assert.Contains(t, jsonStr, `"policies.all_policies"`)
		assert.Contains(t, jsonStr, `"policies.pending_policies"`)
		// 4. Must NOT search in enforced_policies
		assert.NotContains(t, jsonStr, `"policies.enforced_policies"`)
	})
}
