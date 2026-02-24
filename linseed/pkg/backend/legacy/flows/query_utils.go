// Copyright (c) 2021-2023 Tigera, Inc. All rights reserved.

package flows

import (
	"fmt"

	"github.com/olivere/elastic/v7"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

func BuildAllPolicyMatchQuery(policyMatches []v1.PolicyMatch) (*elastic.BoolQuery, error) {
	return buildPolicyMatchQuery(policyMatches, allPolicyQuery, allPolicyQueryLegacy)
}

func BuildEnforcedPolicyMatchQuery(policyMatches []v1.PolicyMatch) (*elastic.BoolQuery, error) {
	return buildPolicyMatchQuery(policyMatches, enforcedPolicyQuery, enforcedPolicyQueryLegacy)
}

func BuildPendingPolicyMatchQuery(policyMatches []v1.PolicyMatch) (*elastic.BoolQuery, error) {
	return buildPolicyMatchQuery(policyMatches, pendingPolicyQuery, pendingPolicyQueryLegacy)
}

func BuildTransitPolicyMatchQuery(policyMatches []v1.PolicyMatch) (*elastic.BoolQuery, error) {
	return buildPolicyMatchQuery(policyMatches, transitPolicyQuery, transitPolicyQueryLegacy)
}

func buildPolicyMatchQuery(policyMatches []v1.PolicyMatch, builders ...func(v1.PolicyMatch) (elastic.Query, error)) (*elastic.BoolQuery, error) {
	if len(policyMatches) == 0 {
		return nil, nil
	}

	// Filter-in any flow logs that match any of the given policy matches.
	b := elastic.NewBoolQuery()
	for _, m := range policyMatches {
		// only build query for non-empty PolicyMatch. Return error if there is an empty PolicyMatch.
		if (m == v1.PolicyMatch{}) {
			return nil, fmt.Errorf("PolicyMatch passed to BuildPolicyMatchQuery cannot be empty")
		}
		for _, build := range builders {
			query, err := build(m)
			if err != nil {
				return nil, err
			}
			b.Should(query)
		}
	}
	b.MinimumNumberShouldMatch(1)
	return b, nil
}

func allPolicyQuery(m v1.PolicyMatch) (elastic.Query, error) {
	matchString, err := CompileStringMatch(m)
	if err != nil {
		return nil, err
	}

	b := elastic.NewBoolQuery()

	// To support querying across both legacy data (all_policies) and new data
	// (enforced/pending_policies), we search in all relevant fields.
	b.Should(elastic.NewWildcardQuery("policies.all_policies", matchString))

	if m.Staged != nil && *m.Staged {
		b.Should(elastic.NewWildcardQuery("policies.pending_policies", matchString))
	} else {
		b.Should(elastic.NewWildcardQuery("policies.enforced_policies", matchString))
	}
	b.MinimumNumberShouldMatch(1)

	return b, nil
}

func enforcedPolicyQuery(m v1.PolicyMatch) (elastic.Query, error) {
	matchString, err := CompileStringMatch(m)
	if err != nil {
		return nil, err
	}

	wildcard := elastic.NewWildcardQuery("policies.enforced_policies", matchString)
	return wildcard, nil
}

func pendingPolicyQuery(m v1.PolicyMatch) (elastic.Query, error) {
	matchString, err := CompileStringMatch(m)
	if err != nil {
		return nil, err
	}

	wildcard := elastic.NewWildcardQuery("policies.pending_policies", matchString)
	return wildcard, nil
}

func transitPolicyQuery(m v1.PolicyMatch) (elastic.Query, error) {
	matchString, err := CompileStringMatch(m)
	if err != nil {
		return nil, err
	}

	wildcard := elastic.NewWildcardQuery("policies.transit_policies", matchString)
	return wildcard, nil
}

func CompileStringMatch(m v1.PolicyMatch) (string, error) {
	actionMatch := "*"
	if m.Action != nil && *m.Action != "" {
		actionMatch = string(*m.Action)
	}

	// Calculate the tier match string.
	kind := getKindMatch(m)
	tier := getTierMatch(m)
	name := getNameMatch(m)

	// Construct the final match string.
	// Format is "<id>|<tier>|<kind>:[namespace/]:name|<action>|<ruleID>"
	matchString := fmt.Sprintf("*|%s|%s:%s|%s|*", tier, kind, name, actionMatch)
	logrus.WithField("match", matchString).Debugf("Matching on policy string")
	return matchString, nil
}

func getKindMatch(m v1.PolicyMatch) string {
	if m.Type == "" && m.Tier != calc.ProfileTierStr && (m.Staged == nil || !*m.Staged) && m.Namespace == nil {
		// No type, tier, staged, or namespace specified; match all kinds.
		return "*"
	}

	// Handle any explicitly set types first.
	switch m.Type {
	case v1.KNP:
		if m.Staged != nil && *m.Staged {
			return types.ShortKindStagedKubernetesNetworkPolicy
		}
		return types.ShortKindKubernetesNetworkPolicy
	case v1.KANP:
		// Legacy Admin Network Policy type - no short kind const defined.
		return "kanp"
	case v1.KBANP:
		// Legacy Baseline Admin Network Policy type - no short kind const defined.
		return "kbanp"
	}

	// Handle special profile case.
	if m.Tier == calc.ProfileTierStr {
		return types.ShortKindProfile
	}

	// Derive kind from staged /namespace fields.
	ns := ""
	if m.Namespace != nil {
		ns = *m.Namespace
	}
	kind := v1.KindFromHints(false, false, m.Staged != nil && *m.Staged, ns)

	// Convert the kind to its short form as used in flow logs.
	return types.PolicyID{Kind: kind}.KindShortName()
}

func getNameMatch(m v1.PolicyMatch) string {
	nameMatch := "*"
	if m.Name != nil && *m.Name != "" {
		nameMatch = *m.Name
	}

	// Set namespace
	if m.Namespace != nil && *m.Namespace != "" {
		nameMatch = fmt.Sprintf("%s/%s", *m.Namespace, nameMatch)
	}

	return nameMatch
}

func getTierMatch(m v1.PolicyMatch) string {
	if m.Tier != "" {
		return m.Tier
	}

	switch m.Type {
	case v1.KNP:
		return names.DefaultTierName
	case v1.KANP:
		return names.AdminNetworkPolicyTierName
	case v1.KBANP:
		return names.BaselineAdminNetworkPolicyTierName
	default:
		return "*"
	}
}
