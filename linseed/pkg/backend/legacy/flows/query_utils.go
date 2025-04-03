// Copyright (c) 2021-2023 Tigera, Inc. All rights reserved.

package flows

import (
	"errors"
	"fmt"

	"github.com/olivere/elastic/v7"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/names"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

func BuildAllPolicyMatchQuery(policyMatches []v1.PolicyMatch) (*elastic.BoolQuery, error) {
	return buildPolicyMatchQuery(policyMatches, allPolicyQuery)
}

func BuildEnforcedPolicyMatchQuery(policyMatches []v1.PolicyMatch) (*elastic.BoolQuery, error) {
	return buildPolicyMatchQuery(policyMatches, enforcedPolicyQuery)
}

func BuildPendingPolicyMatchQuery(policyMatches []v1.PolicyMatch) (*elastic.BoolQuery, error) {
	return buildPolicyMatchQuery(policyMatches, pendingPolicyQuery)
}

func buildPolicyMatchQuery(policyMatches []v1.PolicyMatch, policyQuery func(v1.PolicyMatch) (elastic.Query, error)) (*elastic.BoolQuery, error) {
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
		query, err := policyQuery(m)
		if err != nil {
			return nil, err
		}
		b.Should(query)
	}
	b.MinimumNumberShouldMatch(1)
	return b, nil
}

func allPolicyQuery(m v1.PolicyMatch) (elastic.Query, error) {
	matchString, err := CompileStringMatch(m)
	if err != nil {
		return nil, err
	}

	wildcard := elastic.NewWildcardQuery("policies.all_policies", matchString)
	return elastic.NewNestedQuery("policies", wildcard), nil
}

func enforcedPolicyQuery(m v1.PolicyMatch) (elastic.Query, error) {
	matchString, err := CompileStringMatch(m)
	if err != nil {
		return nil, err
	}

	wildcard := elastic.NewWildcardQuery("policies.enforced_policies", matchString)
	return elastic.NewNestedQuery("policies", wildcard), nil
}

func pendingPolicyQuery(m v1.PolicyMatch) (elastic.Query, error) {
	matchString, err := CompileStringMatch(m)
	if err != nil {
		return nil, err
	}

	wildcard := elastic.NewWildcardQuery("policies.pending_policies", matchString)
	return elastic.NewNestedQuery("policies", wildcard), nil
}

func CompileStringMatch(m v1.PolicyMatch) (string, error) {
	// replace nil values with empty string "" since they have same meaning.
	name, namespace := "", ""
	if m.Name != nil {
		name = *m.Name
	}
	if m.Namespace != nil {
		namespace = *m.Namespace
	}
	tier, nameMatch, err := calculateTierAndNameMatch(m.Type, name, namespace, m.Tier, m.Staged)
	if err != nil {
		return "", err
	}

	// Set the action if an action is provided, otherwise action should be set to `*` to match against all actions
	actionMatch := "*"
	if m.Action != nil && *m.Action != "" {
		actionMatch = string(*m.Action)
	}

	// Policy strings are formatted like so:
	// <index> | <tier> | <nameMatch> | <action> | <ruleID>
	matchString := fmt.Sprintf("*|%s|%s|%s|*", tier, nameMatch, actionMatch)
	logrus.WithField("match", matchString).Debugf("Matching on policy string")

	return matchString, nil
}

// calculateTierAndNameMatch calculates the string match for policy based on the values provided for PolicyType, name,
// namespace, tier, and staged flag.
// return tier, nameMatch, and err
func calculateTierAndNameMatch(policyType v1.PolicyType, name, namespace, tier string, staged bool) (string, string, error) {
	nameMatch := "*"

	// Set policy name if it is provided, otherwise name should be set to `*` to match against all names
	if name != "" {
		nameMatch = name
	}

	// Policy combined-name in flowlogs is constructed differently depending on the type of hit.
	// The formatting can be found in: https://github.com/tigera/calico-private/blob/master/felix/calc/policy_lookup_cache.go
	// - non-k8s namespaced policy: <namespace>/<tier>.<name>
	// - non-k8s global / profile policy: <tier>.<name>
	// - kubernetes policy (namespaced): <namespace>/knp.default.<name>
	// - kubernetes admin policy (global): kanp.adminnetworkpolicy.<name>
	// m.Type defines how the name should be constructed
	var err error
	switch policyType {
	case v1.KNP:
		tier, nameMatch, err = calculateKNPTierAndName(staged, nameMatch, namespace, tier)
	case v1.KANP:
		tier, nameMatch, err = calculateKANPTierAndName(staged, nameMatch, namespace, tier)
	case v1.KBANP:
		tier, nameMatch, err = calculateKBANPTierAndName(staged, nameMatch, namespace, tier)
	default:
		tier, nameMatch, err = calculateCalicoPolicyTierAndName(staged, nameMatch, namespace, tier)
	}
	if err != nil {
		return "", "", err
	}

	return tier, nameMatch, nil
}

// calculateTierAndNameMatch calculates the string match for calico policies
// returns tier, nameMatch, err
func calculateCalicoPolicyTierAndName(staged bool, name, namespace, tier string) (string, string, error) {
	if tier == "" {
		// Match against all tiers if m.Tier is empty
		tier = "*"
	}

	nameMatch := name

	// Calico staged policy:
	// staged namespaced policies: <namespace>/<tier>.<staged:><name>
	// staged global policies: <tier>.staged:<name>
	if staged {
		nameMatch = fmt.Sprintf("staged:%s", nameMatch)
	}
	nameMatch = fmt.Sprintf("%s.%s", tier, nameMatch)

	// Set namespace
	if namespace != "" {
		if tier == "__PROFILE__" {
			return "", "", errors.New("namespace cannot be set when tier==__PROFILE__")
		}

		nameMatch = fmt.Sprintf("%s/%s", namespace, nameMatch)
	}
	return tier, nameMatch, nil
}

// CalculateKANPTierAndName calculates the string match for admin network policies
// returns tier, nameMatch, err
func calculateKANPTierAndName(staged bool, name, namespace, tier string) (string, string, error) {
	if tier != "" && tier != names.AdminNetworkPolicyTierName {
		return "", "", fmt.Errorf("tier cannot be set to %s for adminnetworkpolicy", tier)
	}
	tier = names.AdminNetworkPolicyTierName

	if namespace != "" {
		return "", "", errors.New("namespace cannot be set for adminnetworkpolicy")
	}

	nameMatch := name

	// staged  is not supported for kubernetes admin network policies:
	// "<index>|adminnetworkpolicy|adminnetworkpolicy.<name>|<action>|<rule>"
	if staged {
		return "", "", errors.New("staged is not supported for adminnetworkpolicy")
	}
	nameMatch = fmt.Sprintf("%s.%s%s", tier, names.K8sAdminNetworkPolicyNamePrefix, nameMatch)

	return tier, nameMatch, nil
}

// CalculateKANPTierAndName calculates the string match for admin network policies
// returns tier, nameMatch, err
func calculateKBANPTierAndName(staged bool, name, namespace, tier string) (string, string, error) {
	if tier != "" && tier != names.BaselineAdminNetworkPolicyTierName {
		return "", "", fmt.Errorf("tier cannot be set to %s for baselineadminnetworkpolicy", tier)
	}
	tier = names.BaselineAdminNetworkPolicyTierName

	if namespace != "" {
		return "", "", errors.New("namespace cannot be set for baselineadminnetworkpolicy")
	}

	nameMatch := name

	// staged is not supported for kubernetes admin network policies:
	// "<index>|baselineadminnetworkpolicy|baselineadminnetworkpolicy.<name>|<action>|<rule>"
	if staged {
		return "", "", errors.New("staged is not supported for baselineadminnetworkpolicy")
	}
	nameMatch = fmt.Sprintf("%s.%s%s", tier, names.K8sBaselineAdminNetworkPolicyNamePrefix, nameMatch)

	return tier, nameMatch, nil
}

// calculateKNPTierAndName calculates the string match for admin network policies
// returns tier, nameMatch, err
func calculateKNPTierAndName(staged bool, name, namespace, tier string) (string, string, error) {
	if tier != "" && tier != names.DefaultTierName {
		return "", "", fmt.Errorf("tier cannot be set to %s for kubernetes network policy", tier)
	}
	tier = names.DefaultTierName

	nameMatch := fmt.Sprintf("%s%s", names.K8sNetworkPolicyNamePrefix, name)

	// staged kubernetes network policy format:
	// "<index>|<namespace>|<namespace>/<staged:>knp.default.<name>|<action>|<rule>"
	if staged {
		nameMatch = fmt.Sprintf("staged:%s", nameMatch)
	}

	// Set namespace
	if namespace == "" {
		return "", "", errors.New("namespace cannot be empty for kubernetes network policy")
	} else {
		nameMatch = fmt.Sprintf("%s/%s", namespace, nameMatch)
	}

	return tier, nameMatch, nil
}
