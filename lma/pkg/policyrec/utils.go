// Copyright (c) 2022 Tigera, Inc. All rights reserved.
package policyrec

import (
	"fmt"
	"reflect"
	"strings"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// Test Utilities

// MatchPolicy is a convenience function that returns a policyMatcher for matching
// policies in a Gomega assertion.
func MatchPolicy(expected interface{}) *policyMatcher {
	log.Debugf("Creating policy matcher")
	return &policyMatcher{expected: expected}
}

// policyMatcher implements the GomegaMatcher interface to match policies.
type policyMatcher struct {
	expected interface{}
}

func (pm *policyMatcher) Match(actual interface{}) (success bool, err error) {
	// We expect to only handle pointer to TSEE NetworkPolicy for now.
	// TODO(doublek): Support for other policy resources should be added here.
	switch actualPolicy := actual.(type) {
	case *v3.StagedNetworkPolicy:
		expectedPolicy := pm.expected.(*v3.StagedNetworkPolicy)
		success = expectedPolicy.GroupVersionKind().Kind == actualPolicy.GroupVersionKind().Kind &&
			expectedPolicy.GroupVersionKind().Version == actualPolicy.GroupVersionKind().Version &&
			expectedPolicy.GetName() == actualPolicy.GetName() &&
			expectedPolicy.GetNamespace() == actualPolicy.GetNamespace() &&
			expectedPolicy.Spec.Tier == actualPolicy.Spec.Tier &&
			expectedPolicy.Spec.Order == actualPolicy.Spec.Order &&
			reflect.DeepEqual(expectedPolicy.Spec.Types, actualPolicy.Spec.Types) &&
			matchSelector(expectedPolicy.Spec.Selector, actualPolicy.Spec.Selector) &&
			matchRules(expectedPolicy.Spec.Ingress, actualPolicy.Spec.Ingress) &&
			matchRules(expectedPolicy.Spec.Egress, actualPolicy.Spec.Egress)
	default:
		// TODO(doublek): Remove this after testing the test.
		log.Debugf("Default case")

	}
	return
}

func matchSelector(actual, expected string) bool {
	// Currently only matches &&-ed selectors.
	// TODO(doublek): Add support for ||-ed selectors as well.
	actualSelectors := strings.Split(actual, " && ")
	expectedSelectors := strings.Split(expected, " && ")
	as := set.FromArray(actualSelectors)
	es := set.FromArray(expectedSelectors)
	for item := range es.All() {
		if as.Contains(item) {
			as.Discard(item)
			es.Discard(item)
		}
	}
	log.Debugf("\nActual %+v\nExpected %+v\n", actual, expected)
	if es.Len() != 0 || as.Len() != 0 {
		return false
	}
	return true
}

func matchRules(actual, expected []v3.Rule) bool {
	// TODO(doublek): Make sure there aren't any extra rules left over in either params.
NEXTRULE:
	for _, actualRule := range actual {
		for i, expectedRule := range expected {
			if matchSingleRule(actualRule, expectedRule) {
				expected = append(expected[:i], expected[i+1:]...)
				continue NEXTRULE
			}
		}
		log.Debugf("\nDidn't find a match for rule\n\t%+v", actualRule)
		return false
	}
	if len(expected) != 0 {
		log.Debugf("\nDidn't find matching actual rules\n\t%+v for  expected rules\n\t%+v\n", actual, expected)
		return false
	}
	return true
}

func matchSingleRule(actual, expected v3.Rule) bool {
	return matchEntityRule(actual.Source, expected.Source) &&
		matchEntityRule(actual.Destination, expected.Destination) &&
		actual.Protocol.String() == expected.Protocol.String()
}

func matchEntityRule(actual, expected v3.EntityRule) bool {
	match := set.FromArray(actual.Nets).ContainsAll(set.FromArray(expected.Nets)) &&
		set.FromArray(actual.Ports).ContainsAll(set.FromArray(expected.Ports)) &&
		matchSelector(actual.Selector, expected.Selector) &&
		matchSelector(actual.NamespaceSelector, expected.NamespaceSelector) &&
		set.FromArray(actual.NotNets).ContainsAll(set.FromArray(expected.NotNets))
	if actual.ServiceAccounts != nil && expected.ServiceAccounts != nil {
		return match &&
			set.FromArray(actual.ServiceAccounts.Names).ContainsAll(set.FromArray(expected.ServiceAccounts.Names)) &&
			matchSelector(actual.ServiceAccounts.Selector, expected.ServiceAccounts.Selector)
	}
	return match
}

func (pm *policyMatcher) FailureMessage(actual interface{}) (message string) {
	message = fmt.Sprintf("Expected\n\t%#v\nto match\n\t%#v", actual, pm.expected)
	return
}

func (pm *policyMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	message = fmt.Sprintf("Expected\n\t%#v\nnot to match\n\t%#v", actual, pm.expected)
	return
}
