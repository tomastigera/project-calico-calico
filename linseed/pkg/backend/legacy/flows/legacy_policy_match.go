// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

package flows

import (
	"errors"
	"fmt"
	"strings"

	"github.com/olivere/elastic/v7"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

func allPolicyQueryLegacy(m v1.PolicyMatch) (elastic.Query, error) {
	matchString, err := CompileLegacyStringMatch(m)
	if err != nil {
		return nil, err
	}
	if matchString == "" {
		return nil, nil
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

func enforcedPolicyQueryLegacy(m v1.PolicyMatch) (elastic.Query, error) {
	matchString, err := CompileLegacyStringMatch(m)
	if err != nil {
		return nil, err
	}
	if matchString == "" {
		return nil, nil
	}

	return elastic.NewWildcardQuery("policies.enforced_policies", matchString), nil
}

func pendingPolicyQueryLegacy(m v1.PolicyMatch) (elastic.Query, error) {
	matchString, err := CompileLegacyStringMatch(m)
	if err != nil {
		return nil, err
	}
	if matchString == "" {
		return nil, nil
	}

	return elastic.NewWildcardQuery("policies.pending_policies", matchString), nil
}

func transitPolicyQueryLegacy(m v1.PolicyMatch) (elastic.Query, error) {
	matchString, err := CompileLegacyStringMatch(m)
	if err != nil {
		return nil, err
	}
	if matchString == "" {
		return nil, nil
	}

	return elastic.NewWildcardQuery("policies.transit_policies", matchString), nil
}

// CompileLegacyStringMatch compiles a PolicyMatch into a legacy policy string match used in flow logs.
// The legacy policy string matches policies from before Calico Enterprise v3.23 EP2, which is when we
// removed tier prefixing from policy names, thus treating policy names as opaque strings instead of structured data.
func CompileLegacyStringMatch(m v1.PolicyMatch) (string, error) {
	// replace nil values with empty string "" since they have same meaning.
	name, namespace := "", ""
	if m.Name != nil {
		name = *m.Name
	}
	if m.Namespace != nil {
		namespace = *m.Namespace
	}
	tier, nameMatch, err := calculateTierAndNameMatch(m.Type, name, namespace, m.Tier, m.Staged != nil && *m.Staged)
	if err != nil {
		return "", err
	}
	if tier == "" && nameMatch == "" {
		// No possible match in the legacy format (e.g., policy name contains a dot
		// prefix that doesn't match the tier — this pattern never existed in older
		// versions of Calico).
		return "", nil
	}

	// Set the action if an action is provided, otherwise action should be set to `*` to match against all actions
	actionMatch := "*"
	if m.Action != nil && *m.Action != "" {
		actionMatch = string(*m.Action)
	}

	// Policy strings are formatted like so:
	// <index> | <tier> | <nameMatch> | <action> | <ruleID>
	matchString := fmt.Sprintf("*|%s|%s|%s|*", tier, nameMatch, actionMatch)
	logrus.WithField("match", matchString).Debugf("Matching on legacy policy string")

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
	nameMatch := name
	if tier == "" {
		// Match against all tiers if m.Tier is empty
		tier = "*"
	}
	if name != "*" {
		// In older versions of Calico, policy names were always prefixed with the tier
		// (e.g., "platform.loadgenerator" in tier "platform"). Newer versions treat the
		// name as opaque, so a request might include the tier prefix or not.
		//
		// If the name contains a dot and the prefix matches the tier, strip it so we can
		// reconstruct the legacy format below. If the prefix does NOT match the tier, this
		// policy could never have existed in the legacy format, so there's nothing to match.
		splits := strings.SplitN(nameMatch, ".", 2)
		if len(splits) == 2 {
			if tier != "*" && splits[0] != tier {
				// The dot-prefix doesn't match the tier — impossible in legacy flow logs.
				return "", "", nil
			}
			nameMatch = splits[1]
		}
	}

	// At this point, namematch is either "*", or the name without the tier prefix.
	// Now construct the full nameMatch based on whether it's staged or not.
	if staged {
		// Calico staged policy:
		// staged namespaced policies: <namespace>/<tier>.<staged:><name>
		// staged global policies: <tier>.staged:<name>
		nameMatch = fmt.Sprintf("staged:%s", nameMatch)
	}

	// Older versions of Calico required policy names be prefixed with the tier.
	nameMatch = fmt.Sprintf("%s.%s", tier, nameMatch)

	// Set namespace
	if namespace != "" {
		if tier == calc.ProfileTierStr {
			return "", "", fmt.Errorf("namespace cannot be set when tier==%s", calc.ProfileTierStr)
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
	nameMatch = fmt.Sprintf("%s.kanp.adminnetworkpolicy.%s", tier, nameMatch)

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
	nameMatch = fmt.Sprintf("%s.kbanp.baselineadminnetworkpolicy.%s", tier, nameMatch)

	return tier, nameMatch, nil
}

// calculateKNPTierAndName calculates the string match for admin network policies
// returns tier, nameMatch, err
func calculateKNPTierAndName(staged bool, name, namespace, tier string) (string, string, error) {
	if tier != "" && tier != names.DefaultTierName {
		return "", "", fmt.Errorf("tier cannot be set to %s for kubernetes network policy", tier)
	}
	tier = names.DefaultTierName

	nameMatch := fmt.Sprintf("knp.default.%s", name)

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
