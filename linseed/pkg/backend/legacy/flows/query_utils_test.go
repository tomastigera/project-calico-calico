// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.

package flows_test

import (
	"encoding/json"
	"testing"

	"github.com/olivere/elastic/v7"
	"github.com/stretchr/testify/assert"
	"k8s.io/utils/ptr"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/flows"
	"github.com/projectcalico/calico/linseed/pkg/testutils"
)

func TestPolicyMatchQueryBuilder(t *testing.T) {
	type testResult struct {
		error     bool
		errorMsg  string
		boolQuery *elastic.BoolQuery
	}

	testcases := []struct {
		name          string
		policyMatches []v1.PolicyMatch
		testResult    testResult
	}{
		{
			name:          "error when there is an empty PolicyMatch",
			policyMatches: []v1.PolicyMatch{{}},
			testResult: testResult{
				error:     true,
				errorMsg:  "PolicyMatch passed to BuildPolicyMatchQuery cannot be empty",
				boolQuery: nil,
			},
		},
		{
			name:          "should not return error when the PolicyMatch slice is empty",
			policyMatches: []v1.PolicyMatch{},
			testResult: testResult{
				error:     false,
				errorMsg:  "",
				boolQuery: nil,
			},
		},
		{
			name: "return non-nil BoolQuery when valid PolicyMatch is passed",
			policyMatches: []v1.PolicyMatch{{
				Tier:   "default",
				Action: ActionPtr(v1.FlowActionDeny),
			}},
			testResult: testResult{
				error:     false,
				errorMsg:  "",
				boolQuery: elastic.NewBoolQuery(),
			},
		},
		{},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			bq, err := flows.BuildAllPolicyMatchQuery(tt.policyMatches)

			if tt.testResult.error {
				assert.Error(t, err)
				assert.Equal(t, tt.testResult.errorMsg, err.Error())
				assert.Nil(t, bq)
			} else {
				assert.NoError(t, err)
				if tt.testResult.boolQuery == nil {
					assert.Nil(t, bq)
				} else {
					assert.NotNil(t, bq)
					// If it's a valid match (not empty/special case), check if it has the Should clauses for fallback
					if len(tt.policyMatches) > 0 {
						source, err := bq.Source()
						assert.NoError(t, err)

						// Verify query structure: Bool -> Should -> [Nested Bool Query]
						sourceMap, ok := source.(map[string]any)
						assert.True(t, ok, "Query source should be a map")
						boolMap, ok := sourceMap["bool"].(map[string]any)
						assert.True(t, ok, "Top level query should be a bool query")
						shouldSlice, ok := boolMap["should"].([]any)
						assert.True(t, ok, "Bool query should have 'should' clause")
						assert.NotEmpty(t, shouldSlice)
						assert.EqualValues(t, "1", boolMap["minimum_should_match"], "Top level bool query should have minimum_should_match=1")

						// Check for nested bool query with expected fields
						foundNested := false
						for _, clause := range shouldSlice {
							if clauseMap, ok := clause.(map[string]any); ok {
								if subBool, ok := clauseMap["bool"].(map[string]any); ok {
									// This sub-query should contain should clauses for polices fields
									if subShould, ok := subBool["should"].([]any); ok {
										foundNested = true
										assert.EqualValues(t, "1", subBool["minimum_should_match"], "Nested bool query should have minimum_should_match=1")
										subJSON, _ := json.Marshal(subShould)
										assert.Contains(t, string(subJSON), "policies.all_policies")
										assert.Contains(t, string(subJSON), "policies.enforced_policies")
									}
								}
							}
						}
						assert.True(t, foundNested, "Did not find nested bool query with policy fields")
					}
				}
			}
		})
	}
}

// TestPolicyMatchStagedFalseNotEmpty verifies that PolicyMatch{Staged: ptr.To(false)}
// is not treated as an empty struct (regression test for the bug where Staged was a
// plain bool, making {Staged: false} indistinguishable from the zero-value PolicyMatch{}).
func TestPolicyMatchStagedFalseNotEmpty(t *testing.T) {
	// With Staged as *bool, {Staged: ptr.To(false)} should NOT be considered empty
	// and should build a valid query.
	policyMatches := []v1.PolicyMatch{{Staged: ptr.To(false)}}
	bq, err := flows.BuildAllPolicyMatchQuery(policyMatches)
	assert.NoError(t, err)
	assert.NotNil(t, bq, "PolicyMatch{Staged: ptr.To(false)} should not be rejected as empty")

	// Also verify it works for enforced and pending query builders
	bq, err = flows.BuildEnforcedPolicyMatchQuery(policyMatches)
	assert.NoError(t, err)
	assert.NotNil(t, bq, "PolicyMatch{Staged: ptr.To(false)} should not be rejected as empty for enforced query")

	bq, err = flows.BuildPendingPolicyMatchQuery(policyMatches)
	assert.NoError(t, err)
	assert.NotNil(t, bq, "PolicyMatch{Staged: ptr.To(false)} should not be rejected as empty for pending query")

	// Verify that a truly empty PolicyMatch{} is still rejected
	emptyMatches := []v1.PolicyMatch{{}}
	bq, err = flows.BuildAllPolicyMatchQuery(emptyMatches)
	assert.Error(t, err)
	assert.Nil(t, bq)
	assert.Contains(t, err.Error(), "PolicyMatch passed to BuildPolicyMatchQuery cannot be empty")
}

func TestEnforcedPolicyMatchQueryBuilder(t *testing.T) {
	type testResult struct {
		error     bool
		errorMsg  string
		boolQuery *elastic.BoolQuery
	}

	testcases := []struct {
		name                  string
		enforcedPolicyMatches []v1.PolicyMatch
		testResult            testResult
	}{
		{
			name:                  "error when there is an empty PolicyMatch",
			enforcedPolicyMatches: []v1.PolicyMatch{{}},
			testResult: testResult{
				error:     true,
				errorMsg:  "PolicyMatch passed to BuildPolicyMatchQuery cannot be empty",
				boolQuery: nil,
			},
		},
		{
			name:                  "should not return error when the PolicyMatch slice is empty",
			enforcedPolicyMatches: []v1.PolicyMatch{},
			testResult: testResult{
				error:     false,
				errorMsg:  "",
				boolQuery: nil,
			},
		},
		{
			name: "return non-nil BoolQuery when valid PolicyMatch is passed",
			enforcedPolicyMatches: []v1.PolicyMatch{{
				Tier:   "default",
				Action: ActionPtr(v1.FlowActionDeny),
			}},
			testResult: testResult{
				error:     false,
				errorMsg:  "",
				boolQuery: elastic.NewBoolQuery(),
			},
		},
		{},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			bq, err := flows.BuildEnforcedPolicyMatchQuery(tt.enforcedPolicyMatches)

			if tt.testResult.error {
				assert.Error(t, err)
				assert.Equal(t, tt.testResult.errorMsg, err.Error())
				assert.Nil(t, bq)
			} else {
				assert.NoError(t, err)
				if tt.testResult.boolQuery == nil {
					assert.Nil(t, bq)
				} else {
					assert.NotNil(t, bq)
				}
			}
		})
	}
}

func TestPendingPolicyMatchQueryBuilder(t *testing.T) {
	type testResult struct {
		error     bool
		errorMsg  string
		boolQuery *elastic.BoolQuery
	}

	testcases := []struct {
		name                 string
		pendingPolicyMatches []v1.PolicyMatch
		testResult           testResult
	}{
		{
			name:                 "error when there is an empty PolicyMatch",
			pendingPolicyMatches: []v1.PolicyMatch{{}},
			testResult: testResult{
				error:     true,
				errorMsg:  "PolicyMatch passed to BuildPolicyMatchQuery cannot be empty",
				boolQuery: nil,
			},
		},
		{
			name:                 "should not return error when the PolicyMatch slice is empty",
			pendingPolicyMatches: []v1.PolicyMatch{},
			testResult: testResult{
				error:     false,
				errorMsg:  "",
				boolQuery: nil,
			},
		},
		{
			name: "return non-nil BoolQuery when valid PolicyMatch is passed",
			pendingPolicyMatches: []v1.PolicyMatch{{
				Tier:   "default",
				Action: ActionPtr(v1.FlowActionDeny),
			}},
			testResult: testResult{
				error:     false,
				errorMsg:  "",
				boolQuery: elastic.NewBoolQuery(),
			},
		},
		{},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			bq, err := flows.BuildPendingPolicyMatchQuery(tt.pendingPolicyMatches)

			if tt.testResult.error {
				assert.Error(t, err)
				assert.Equal(t, tt.testResult.errorMsg, err.Error())
				assert.Nil(t, bq)
			} else {
				assert.NoError(t, err)
				if tt.testResult.boolQuery == nil {
					assert.Nil(t, bq)
				} else {
					assert.NotNil(t, bq)
				}
			}
		})
	}
}

// TestPolicyNameWithDots verifies that both CompileStringMatch (new format) and
// CompileLegacyStringMatch correctly handle policy names containing dots. After the
// policy naming changes (PR #10337), policy names are opaque strings that may contain
// dots (e.g., "platform.loadgenerator" in tier "platform").
//
// New format: uses the name as-is.
// Legacy format: policies were always stored as <tier>.<name>, so:
//   - If the name's dot-prefix matches the tier, the legacy match is valid.
//   - If the name's dot-prefix does NOT match the tier, this combination was impossible
//     in older Calico versions, so the legacy match should return empty (no match possible).
func TestPolicyNameWithDots(t *testing.T) {
	testcases := []struct {
		name           string
		policyMatch    v1.PolicyMatch
		expected       string
		legacyExpected string
	}{
		{
			// Bug report scenario: policy named "platform.loadgenerator" in tier
			// "platform", namespace "vote". The dot-prefix matches the tier, so
			// the legacy match is valid and both formats produce the same result.
			name: "namespaced policy with tier-matching dot prefix",
			policyMatch: v1.PolicyMatch{
				Tier:      "platform",
				Name:      testutils.StringPtr("platform.loadgenerator"),
				Namespace: testutils.StringPtr("vote"),
			},
			expected:       "*|platform|np:vote/platform.loadgenerator|*|*",
			legacyExpected: "*|platform|vote/platform.loadgenerator|*|*",
		},
		{
			// Policy name with a dot prefix that does NOT match the tier.
			// New format uses the name as-is. Legacy format can't match because
			// older Calico never generated flow logs for this naming pattern.
			name: "namespaced policy with non-tier dot prefix",
			policyMatch: v1.PolicyMatch{
				Tier:      "platform",
				Name:      testutils.StringPtr("foo.bar"),
				Namespace: testutils.StringPtr("vote"),
			},
			expected:       "*|platform|np:vote/foo.bar|*|*",
			legacyExpected: "",
		},
		{
			// Global policy with a dot-prefix that does NOT match the tier.
			name: "global policy with non-tier dot prefix",
			policyMatch: v1.PolicyMatch{
				Tier: "platform",
				Name: testutils.StringPtr("foo.bar"),
			},
			expected:       "*|platform|*:foo.bar|*|*",
			legacyExpected: "",
		},
		{
			// Simple name without dots — both formats should work.
			name: "namespaced policy without dots",
			policyMatch: v1.PolicyMatch{
				Tier:      "platform",
				Name:      testutils.StringPtr("loadgenerator"),
				Namespace: testutils.StringPtr("vote"),
			},
			expected:       "*|platform|np:vote/loadgenerator|*|*",
			legacyExpected: "*|platform|vote/platform.loadgenerator|*|*",
		},
		{
			// Multiple dots in the name.
			name: "namespaced policy with multiple dots",
			policyMatch: v1.PolicyMatch{
				Tier:      "default",
				Name:      testutils.StringPtr("my.policy.name"),
				Namespace: testutils.StringPtr("ns"),
			},
			expected:       "*|default|np:ns/my.policy.name|*|*",
			legacyExpected: "",
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			result, err := flows.CompileStringMatch(tt.policyMatch)
			assert.NoError(t, err, "CompileStringMatch should not error")
			assert.Equal(t, tt.expected, result, "new format mismatch")

			legacyResult, err := flows.CompileLegacyStringMatch(tt.policyMatch)
			assert.NoError(t, err, "CompileLegacyStringMatch should not error")
			assert.Equal(t, tt.legacyExpected, legacyResult, "legacy format mismatch")
		})
	}
}

func TestCompileStringMatch(t *testing.T) {
	type testResult struct {
		error       bool
		errorMsg    string
		stringMatch string
	}
	testcases := []struct {
		name        string
		policyMatch v1.PolicyMatch
		testResult  testResult
	}{
		{
			name: "kubernetes network policy with name",
			policyMatch: v1.PolicyMatch{
				Type: "knp",
				Name: testutils.StringPtr("test"),
			},
			testResult: testResult{
				error:       true,
				errorMsg:    "namespace cannot be empty for kubernetes network policy",
				stringMatch: "",
			},
		},
		{
			name: "kubernetes network policy with namespace",
			policyMatch: v1.PolicyMatch{
				Type:      "knp",
				Namespace: testutils.StringPtr("ns"),
			},
			testResult: testResult{
				error:       false,
				errorMsg:    "",
				stringMatch: "*|default|ns/knp.default.*|*|*",
			},
		},
		{
			name: "staged kubernetes network policy with namespace",
			policyMatch: v1.PolicyMatch{
				Type:      "knp",
				Staged:    ptr.To(true),
				Namespace: testutils.StringPtr("ns"),
			},
			testResult: testResult{
				error:       false,
				errorMsg:    "",
				stringMatch: "*|default|ns/staged:knp.default.*|*|*",
			},
		},
		{
			name: "kubernetes network policy with incorrect tier",
			policyMatch: v1.PolicyMatch{
				Type:      "knp",
				Namespace: testutils.StringPtr("ns"),
				Tier:      "tier1",
			},
			testResult: testResult{
				error:       true,
				errorMsg:    "tier cannot be set to tier1 for kubernetes network policy",
				stringMatch: "",
			},
		},
		{
			name: "admin network policy with name",
			policyMatch: v1.PolicyMatch{
				Type: "kanp",
				Name: testutils.StringPtr("test"),
			},
			testResult: testResult{
				error:       false,
				errorMsg:    "",
				stringMatch: "*|adminnetworkpolicy|adminnetworkpolicy.kanp.adminnetworkpolicy.test|*|*",
			},
		},
		{
			name: "global calico network policy in adminnetworkpolicy tier",
			policyMatch: v1.PolicyMatch{
				Type: "",
				Name: testutils.StringPtr("test"),
				Tier: "adminnetworkpolicy",
			},
			testResult: testResult{
				error:       false,
				errorMsg:    "",
				stringMatch: "*|adminnetworkpolicy|adminnetworkpolicy.test|*|*",
			},
		},
		{
			name: "admin network policy with namespace",
			policyMatch: v1.PolicyMatch{
				Type:      "kanp",
				Namespace: testutils.StringPtr("ns"),
			},
			testResult: testResult{
				error:       true,
				errorMsg:    "namespace cannot be set for adminnetworkpolicy",
				stringMatch: "",
			},
		},
		{
			name: "staged admin network policy",
			policyMatch: v1.PolicyMatch{
				Type:   "kanp",
				Staged: ptr.To(true),
			},
			testResult: testResult{
				error:       true,
				errorMsg:    "staged is not supported for adminnetworkpolicy",
				stringMatch: "",
			},
		},
		{
			name: "admin network policy with incorrect tier",
			policyMatch: v1.PolicyMatch{
				Type: "kanp",
				Tier: "tier1",
			},
			testResult: testResult{
				error:       true,
				errorMsg:    "tier cannot be set to tier1 for adminnetworkpolicy",
				stringMatch: "",
			},
		},
		{
			name: "baseline admin network policy with name",
			policyMatch: v1.PolicyMatch{
				Type: "kbanp",
				Name: testutils.StringPtr("test"),
			},
			testResult: testResult{
				error:       false,
				errorMsg:    "",
				stringMatch: "*|baselineadminnetworkpolicy|baselineadminnetworkpolicy.kbanp.baselineadminnetworkpolicy.test|*|*",
			},
		},
		{
			name: "global calico network policy in baselineadminnetworkpolicy tier",
			policyMatch: v1.PolicyMatch{
				Type: "",
				Name: testutils.StringPtr("test"),
				Tier: "baselineadminnetworkpolicy",
			},
			testResult: testResult{
				error:       false,
				errorMsg:    "",
				stringMatch: "*|baselineadminnetworkpolicy|baselineadminnetworkpolicy.test|*|*",
			},
		},
		{
			name: "baseline admin network policy with namespace",
			policyMatch: v1.PolicyMatch{
				Type:      "kbanp",
				Namespace: testutils.StringPtr("ns"),
			},
			testResult: testResult{
				error:       true,
				errorMsg:    "namespace cannot be set for baselineadminnetworkpolicy",
				stringMatch: "",
			},
		},
		{
			name: "staged baseline admin network policy not supported",
			policyMatch: v1.PolicyMatch{
				Type:   "kbanp",
				Staged: ptr.To(true),
			},
			testResult: testResult{
				error:       true,
				errorMsg:    "staged is not supported for baselineadminnetworkpolicy",
				stringMatch: "",
			},
		},
		{
			name: "baseline admin network policy with incorrect tier",
			policyMatch: v1.PolicyMatch{
				Type: "kbanp",
				Tier: "tier1",
			},
			testResult: testResult{
				error:       true,
				errorMsg:    "tier cannot be set to tier1 for baselineadminnetworkpolicy",
				stringMatch: "",
			},
		},
		{
			name: "calico network policy with name (global)",
			policyMatch: v1.PolicyMatch{
				Name: testutils.StringPtr("test"),
			},
			testResult: testResult{
				error:       false,
				errorMsg:    "",
				stringMatch: "*|*|*.test|*|*",
			},
		},
		{
			name: "calico network policy with name & namespaces",
			policyMatch: v1.PolicyMatch{
				Name:      testutils.StringPtr("test"),
				Namespace: testutils.StringPtr("ns"),
			},
			testResult: testResult{
				error:       false,
				errorMsg:    "",
				stringMatch: "*|*|ns/*.test|*|*",
			},
		},
		{
			name: "calico network policy with name & tier (global)",
			policyMatch: v1.PolicyMatch{
				Name: testutils.StringPtr("test"),
				Tier: "tier1",
			},
			testResult: testResult{
				error:       false,
				errorMsg:    "",
				stringMatch: "*|tier1|tier1.test|*|*",
			},
		},
		{
			name: "calico network policy with name, namespace, & tier",
			policyMatch: v1.PolicyMatch{
				Name:      testutils.StringPtr("test"),
				Namespace: testutils.StringPtr("ns"),
				Tier:      "tier1",
			},
			testResult: testResult{
				error:       false,
				errorMsg:    "",
				stringMatch: "*|tier1|ns/tier1.test|*|*",
			},
		},
		{
			name: "calico network policy with name, namespace = \"*\", & tier",
			policyMatch: v1.PolicyMatch{
				Name:      testutils.StringPtr("test"),
				Namespace: testutils.StringPtr("*"),
				Tier:      "tier1",
			},
			testResult: testResult{
				error:       false,
				errorMsg:    "",
				stringMatch: "*|tier1|*/tier1.test|*|*",
			},
		},
		{
			name: "calico network policy with staged & namespace",
			policyMatch: v1.PolicyMatch{
				Staged:    ptr.To(true),
				Namespace: testutils.StringPtr("ns"),
			},
			testResult: testResult{
				error:       false,
				errorMsg:    "",
				stringMatch: "*|*|ns/*.staged:*|*|*",
			},
		},
		{
			name: "calico network policy with staged & global",
			policyMatch: v1.PolicyMatch{
				Staged: ptr.To(true),
			},
			testResult: testResult{
				error:       false,
				errorMsg:    "",
				stringMatch: "*|*|*.staged:*|*|*",
			},
		},
		{
			name: "calico network policy with __PROFILE__",
			policyMatch: v1.PolicyMatch{
				Tier: "__PROFILE__",
			},
			testResult: testResult{
				error:       false,
				errorMsg:    "",
				stringMatch: "*|__PROFILE__|__PROFILE__.*|*|*",
			},
		},
	}

	for _, tt := range testcases {
		stringMatch, err := flows.CompileLegacyStringMatch(tt.policyMatch)
		if tt.testResult.error {
			assert.Error(t, err)
			assert.Equal(t, tt.testResult.errorMsg, err.Error())
		} else {
			assert.NoError(t, err)
			assert.Equal(t, tt.testResult.stringMatch, stringMatch)
		}
	}
}
