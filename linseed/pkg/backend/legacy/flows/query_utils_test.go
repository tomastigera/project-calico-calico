// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package flows_test

import (
	"testing"

	"github.com/olivere/elastic/v7"
	"github.com/stretchr/testify/assert"

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
				}
			}
		})
	}
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
				Staged:    true,
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
				Staged: true,
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
				Staged: true,
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
				Staged:    true,
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
				Staged: true,
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
		stringMatch, err := flows.CompileStringMatch(tt.policyMatch)
		if tt.testResult.error {
			assert.Error(t, err)
			assert.Equal(t, tt.testResult.errorMsg, err.Error())
		} else {
			assert.NoError(t, err)
			assert.Equal(t, tt.testResult.stringMatch, stringMatch)
		}
	}
}
