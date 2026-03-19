// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package linseed

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tigera/tds-apiserver/lib/slices"
	"k8s.io/utils/ptr"

	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/collections"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/filters"
	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/flows"
)

// policyTypeField returns the CollectionField for the policy.type enum in the flows collection.
func policyTypeField(t *testing.T) collections.CollectionField {
	t.Helper()
	collectionsMap := slices.AssociateBy(collections.Collections(nil), func(c collections.Collection) collections.CollectionName {
		return c.Name()
	})
	field, ok := collectionsMap[collections.CollectionNameFlows].Field(collections.FieldNamePolicyType)
	require.True(t, ok, "policy.type field must exist in the flows collection")
	return field
}

// TestContractPolicyTypeFilterRoundTrip verifies that policy type filters produced by the dashboard
// survive JSON serialization and are accepted by linseed's query builders. This catches bugs like
// PR #10802 where omitempty on bool zero-values silently dropped data.
func TestContractPolicyTypeFilterRoundTrip(t *testing.T) {
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	ptField := policyTypeField(t)

	testCases := []struct {
		name                      string
		criteria                  filters.Criteria
		expectEnforcedMatches     []lsv1.PolicyMatch
		expectPendingMatches      []lsv1.PolicyMatch
		enforcedQueryShouldAccept bool
		pendingQueryShouldAccept  bool
	}{
		{
			name:                      "enforced equals",
			criteria:                  filters.Criteria{filters.NewEquals(ptField, "enforced", false)},
			expectEnforcedMatches:     []lsv1.PolicyMatch{{Staged: ptr.To(false)}},
			expectPendingMatches:      nil,
			enforcedQueryShouldAccept: true,
			pendingQueryShouldAccept:  false,
		},
		{
			name:                      "staged equals",
			criteria:                  filters.Criteria{filters.NewEquals(ptField, "staged", false)},
			expectEnforcedMatches:     nil,
			expectPendingMatches:      []lsv1.PolicyMatch{{Staged: ptr.To(true)}},
			enforcedQueryShouldAccept: false,
			pendingQueryShouldAccept:  true,
		},
		{
			name:                      "enforced negated",
			criteria:                  filters.Criteria{filters.NewEquals(ptField, "enforced", true)},
			expectEnforcedMatches:     nil,
			expectPendingMatches:      []lsv1.PolicyMatch{{Staged: ptr.To(true)}},
			enforcedQueryShouldAccept: false,
			pendingQueryShouldAccept:  true,
		},
		{
			name:                      "staged negated",
			criteria:                  filters.Criteria{filters.NewEquals(ptField, "staged", true)},
			expectEnforcedMatches:     []lsv1.PolicyMatch{{Staged: ptr.To(false)}},
			expectPendingMatches:      nil,
			enforcedQueryShouldAccept: true,
			pendingQueryShouldAccept:  false,
		},
		{
			name:                      "both via IN",
			criteria:                  filters.Criteria{filters.NewIn(ptField, []string{"staged", "enforced"}, false)},
			expectEnforcedMatches:     []lsv1.PolicyMatch{{Staged: ptr.To(false)}},
			expectPendingMatches:      []lsv1.PolicyMatch{{Staged: ptr.To(true)}},
			enforcedQueryShouldAccept: true,
			pendingQueryShouldAccept:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Stage 1: Build params the way the dashboard does.
			qp, err := newQueryParams(0, 0, "start_time", []string{"cluster"}, nil)
			require.NoError(t, err)
			err = qp.setCriteria(tc.criteria, now)
			require.NoError(t, err)

			// Build FlowLogParams the same way collectionClientFlows.Params does.
			original := &lsv1.FlowLogParams{
				QueryParams:           qp.linseedQueryParams,
				QuerySortParams:       qp.linseedQuerySortParams,
				LogSelectionParams:    qp.linseedLogSelectionParams,
				EnforcedPolicyMatches: qp.enforcedPolicyMatches,
				PendingPolicyMatches:  qp.pendingPolicyMatches,
			}

			// Stage 2: JSON round-trip — simulates the HTTP boundary between dashboard and linseed.
			data, err := json.Marshal(original)
			require.NoError(t, err)

			var roundTripped lsv1.FlowLogParams
			err = json.Unmarshal(data, &roundTripped)
			require.NoError(t, err)

			// Verify policy match slices survived the round-trip.
			require.Equal(t, tc.expectEnforcedMatches, roundTripped.EnforcedPolicyMatches,
				"EnforcedPolicyMatches mismatch after JSON round-trip")
			require.Equal(t, tc.expectPendingMatches, roundTripped.PendingPolicyMatches,
				"PendingPolicyMatches mismatch after JSON round-trip")

			// Stage 3: Feed round-tripped PolicyMatch slices into linseed's query builders.
			if tc.enforcedQueryShouldAccept {
				q, err := flows.BuildEnforcedPolicyMatchQuery(roundTripped.EnforcedPolicyMatches)
				require.NoError(t, err, "linseed rejected enforced policy matches")
				require.NotNil(t, q, "enforced query should not be nil")
			}
			if tc.pendingQueryShouldAccept {
				q, err := flows.BuildPendingPolicyMatchQuery(roundTripped.PendingPolicyMatches)
				require.NoError(t, err, "linseed rejected pending policy matches")
				require.NotNil(t, q, "pending query should not be nil")
			}
		})
	}
}

// TestContractPolicyMatchJSONPreservation directly tests that key PolicyMatch field combinations
// survive JSON round-trips. This catches any future omitempty issues on new or changed fields.
func TestContractPolicyMatchJSONPreservation(t *testing.T) {
	actionAllow := lsv1.FlowActionAllow

	cases := []struct {
		name  string
		match lsv1.PolicyMatch
	}{
		{name: "staged false (the exact bug case)", match: lsv1.PolicyMatch{Staged: ptr.To(false)}},
		{name: "staged true", match: lsv1.PolicyMatch{Staged: ptr.To(true)}},
		{name: "tier only", match: lsv1.PolicyMatch{Tier: "default"}},
		{name: "tier and staged false", match: lsv1.PolicyMatch{Tier: "default", Staged: ptr.To(false)}},
		{name: "tier and action", match: lsv1.PolicyMatch{Tier: "default", Action: &actionAllow}},
		{name: "tier staged and name", match: lsv1.PolicyMatch{Tier: "default", Staged: ptr.To(true), Name: ptr.To("my-policy")}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.match)
			require.NoError(t, err)

			var roundTripped lsv1.PolicyMatch
			err = json.Unmarshal(data, &roundTripped)
			require.NoError(t, err)

			require.True(t, reflect.DeepEqual(tc.match, roundTripped),
				"PolicyMatch did not survive JSON round-trip:\n  original:     %+v\n  round-tripped: %+v\n  json: %s",
				tc.match, roundTripped, string(data))
		})
	}
}

// TestContractEmptyPolicyMatchStillRejected is a sanity check that a truly empty PolicyMatch{}
// is still rejected by linseed's query builders. This prevents someone from "fixing" the empty
// check in a way that accepts everything.
func TestContractEmptyPolicyMatchStillRejected(t *testing.T) {
	emptyMatches := []lsv1.PolicyMatch{{}}

	_, err := flows.BuildAllPolicyMatchQuery(emptyMatches)
	require.Error(t, err, "BuildAllPolicyMatchQuery should reject empty PolicyMatch")

	_, err = flows.BuildEnforcedPolicyMatchQuery(emptyMatches)
	require.Error(t, err, "BuildEnforcedPolicyMatchQuery should reject empty PolicyMatch")

	_, err = flows.BuildPendingPolicyMatchQuery(emptyMatches)
	require.Error(t, err, "BuildPendingPolicyMatchQuery should reject empty PolicyMatch")
}
