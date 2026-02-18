// Copyright 2020-2021 Tigera Inc. All rights reserved.
package fortimanager_test

import (
	"fmt"
	"reflect"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/firewall-integration/pkg/controllers/fortimanager"
	fortilib "github.com/projectcalico/calico/firewall-integration/pkg/fortimanager"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var (
	protoTCP  = numorstring.ProtocolFromString(numorstring.ProtocolTCP)
	protoUDP  = numorstring.ProtocolFromString(numorstring.ProtocolUDP)
	protoICMP = numorstring.ProtocolFromString(numorstring.ProtocolICMP)
)

const (
	testPolicyPackageNamge = "test"
	testTierName           = "tigera-firewall-controller"
)

var (
	TCPFortimanagerPolicy = fortilib.FortiFWPolicy{
		SrcAddr: []string{"frontend"},
		DstAddr: []string{"backend"},
		Service: []string{"HTTP", "HTTPS"},
		Name:    "web",
		Action:  0, //deny
	}

	TCPConvertedPolicy = []apiv3.GlobalNetworkPolicy{
		apiv3.GlobalNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: policyName(testTierName, "web", "ingress"),
				Annotations: map[string]string{
					"FortiManagerPackageName": testPolicyPackageNamge,
					"FWRuleName":              "web",
					"Comments":                "",
				},
			},
			Spec: apiv3.GlobalNetworkPolicySpec{
				Tier:     testTierName,
				Selector: "tigera.io/address-group == \"backend\"",
				Types:    []apiv3.PolicyType{apiv3.PolicyTypeIngress},
				Ingress: []apiv3.Rule{
					apiv3.Rule{
						Protocol: &protoTCP,
						Action:   apiv3.Deny,
						Source: apiv3.EntityRule{
							Selector: "tigera.io/address-group == \"frontend\"",
						},
						Destination: apiv3.EntityRule{
							Ports: []numorstring.Port{
								numorstring.SinglePort(80),
								numorstring.SinglePort(443),
							},
						},
					},
				},
			},
		},
		apiv3.GlobalNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: policyName(testTierName, "web", "ing", "deny"),
				Annotations: map[string]string{
					"FortiManagerPackageName": testPolicyPackageNamge,
					"FWRuleName":              "web",
					"Comments":                "",
				},
			},
			Spec: apiv3.GlobalNetworkPolicySpec{
				Tier:     testTierName,
				Selector: "tigera.io/address-group == \"backend\"",
				Types:    []apiv3.PolicyType{apiv3.PolicyTypeIngress, apiv3.PolicyTypeEgress},
			},
		},
		apiv3.GlobalNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: policyName(testTierName, "web", "egress"),
				Annotations: map[string]string{
					"FortiManagerPackageName": testPolicyPackageNamge,
					"FWRuleName":              "web",
					"Comments":                "",
				},
			},
			Spec: apiv3.GlobalNetworkPolicySpec{
				Tier:     testTierName,
				Selector: "tigera.io/address-group == \"frontend\"",
				Types:    []apiv3.PolicyType{apiv3.PolicyTypeEgress},
				Egress: []apiv3.Rule{
					apiv3.Rule{
						Protocol: &protoTCP,
						Action:   apiv3.Deny,
						Destination: apiv3.EntityRule{
							Selector: "tigera.io/address-group == \"backend\"",
							Ports: []numorstring.Port{
								numorstring.SinglePort(80),
								numorstring.SinglePort(443),
							},
						},
					},
				},
			},
		},
		apiv3.GlobalNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: policyName(testTierName, "web", "egr", "deny"),
				Annotations: map[string]string{
					"FortiManagerPackageName": testPolicyPackageNamge,
					"FWRuleName":              "web",
					"Comments":                "",
				},
			},
			Spec: apiv3.GlobalNetworkPolicySpec{
				Tier:     testTierName,
				Selector: "tigera.io/address-group == \"frontend\"",
				Types:    []apiv3.PolicyType{apiv3.PolicyTypeIngress, apiv3.PolicyTypeEgress},
			},
		},
	}
)

var (
	UDPFortimanagerPolicy = fortilib.FortiFWPolicy{
		SrcAddr: []string{"frontend"},
		DstAddr: []string{"backend"},
		Service: []string{"DNS"},
		Name:    "dns-policy",
		Action:  1, //allow
	}

	UDPConvertedPolicy = []apiv3.GlobalNetworkPolicy{
		apiv3.GlobalNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: policyName(testTierName, "dns-policy", "ingress"),
				Annotations: map[string]string{
					"FortiManagerPackageName": testPolicyPackageNamge,
					"FWRuleName":              "dns-policy",
					"Comments":                "",
				},
			},
			Spec: apiv3.GlobalNetworkPolicySpec{
				Tier:     testTierName,
				Selector: "tigera.io/address-group == \"backend\"",
				Types:    []apiv3.PolicyType{apiv3.PolicyTypeIngress},
				Ingress: []apiv3.Rule{
					// FortiManager defines DNS in both TCP and UDP protocols
					apiv3.Rule{
						Protocol: &protoTCP,
						Action:   apiv3.Allow,
						Source: apiv3.EntityRule{
							Selector: "tigera.io/address-group == \"frontend\"",
						},
						Destination: apiv3.EntityRule{
							Ports: []numorstring.Port{
								numorstring.SinglePort(53),
							},
						},
					},
					apiv3.Rule{
						Protocol: &protoUDP,
						Action:   apiv3.Allow,
						Source: apiv3.EntityRule{
							Selector: "tigera.io/address-group == \"frontend\"",
						},
						Destination: apiv3.EntityRule{
							Ports: []numorstring.Port{
								numorstring.SinglePort(53),
							},
						},
					},
				},
			},
		},
		apiv3.GlobalNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: policyName(testTierName, "dns-policy", "ing", "deny"),
				Annotations: map[string]string{
					"FortiManagerPackageName": testPolicyPackageNamge,
					"FWRuleName":              "dns-policy",
					"Comments":                "",
				},
			},
			Spec: apiv3.GlobalNetworkPolicySpec{
				Tier:     testTierName,
				Selector: "tigera.io/address-group == \"backend\"",
				Types:    []apiv3.PolicyType{apiv3.PolicyTypeIngress, apiv3.PolicyTypeEgress},
			},
		},
		apiv3.GlobalNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: policyName(testTierName, "dns-policy", "egress"),
				Annotations: map[string]string{
					"FortiManagerPackageName": testPolicyPackageNamge,
					"FWRuleName":              "dns-policy",
					"Comments":                "",
				},
			},
			Spec: apiv3.GlobalNetworkPolicySpec{
				Tier:     testTierName,
				Selector: "tigera.io/address-group == \"frontend\"",
				Types:    []apiv3.PolicyType{apiv3.PolicyTypeEgress},
				Egress: []apiv3.Rule{
					apiv3.Rule{
						Protocol: &protoTCP,
						Action:   apiv3.Allow,
						Destination: apiv3.EntityRule{
							Selector: "tigera.io/address-group == \"backend\"",
							Ports: []numorstring.Port{
								numorstring.SinglePort(53),
							},
						},
					},
					apiv3.Rule{
						Protocol: &protoUDP,
						Action:   apiv3.Allow,
						Destination: apiv3.EntityRule{
							Selector: "tigera.io/address-group == \"backend\"",
							Ports: []numorstring.Port{
								numorstring.SinglePort(53),
							},
						},
					},
				},
			},
		},
		apiv3.GlobalNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: policyName(testTierName, "dns-policy", "egr", "deny"),
				Annotations: map[string]string{
					"FortiManagerPackageName": testPolicyPackageNamge,
					"FWRuleName":              "dns-policy",
					"Comments":                "",
				},
			},
			Spec: apiv3.GlobalNetworkPolicySpec{
				Tier:     testTierName,
				Selector: "tigera.io/address-group == \"frontend\"",
				Types:    []apiv3.PolicyType{apiv3.PolicyTypeIngress, apiv3.PolicyTypeEgress},
			},
		},
	}
)

var (
	ICMPFortimanagerPolicy = fortilib.FortiFWPolicy{
		SrcAddr: []string{"svc1", "pinger"},
		DstAddr: []string{"svc2", "pinger"},
		Service: []string{"PING"},
		Name:    "pingables",
		Action:  1, //allow
	}

	ICMPConvertedPolicy = []apiv3.GlobalNetworkPolicy{
		apiv3.GlobalNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: policyName(testTierName, "pingables", "ingress"),
				Annotations: map[string]string{
					"FortiManagerPackageName": testPolicyPackageNamge,
					"FWRuleName":              "pingables",
					"Comments":                "",
				},
			},
			Spec: apiv3.GlobalNetworkPolicySpec{
				Tier:     testTierName,
				Selector: "tigera.io/address-group == \"svc2\" && tigera.io/address-group == \"pinger\"",
				Types:    []apiv3.PolicyType{apiv3.PolicyTypeIngress},
				Ingress: []apiv3.Rule{
					apiv3.Rule{
						Protocol: &protoICMP,
						Action:   apiv3.Allow,
						Source: apiv3.EntityRule{
							Selector: "tigera.io/address-group == \"svc1\" && tigera.io/address-group == \"pinger\"",
						},
					},
				},
			},
		},
		apiv3.GlobalNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: policyName(testTierName, "pingables", "ing", "deny"),
				Annotations: map[string]string{
					"FortiManagerPackageName": testPolicyPackageNamge,
					"FWRuleName":              "pingables",
					"Comments":                "",
				},
			},
			Spec: apiv3.GlobalNetworkPolicySpec{
				Tier:     testTierName,
				Selector: "tigera.io/address-group == \"svc2\" && tigera.io/address-group == \"pinger\"",
				Types:    []apiv3.PolicyType{apiv3.PolicyTypeIngress, apiv3.PolicyTypeEgress},
			},
		},
		apiv3.GlobalNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: policyName(testTierName, "pingables", "egress"),
				Annotations: map[string]string{
					"FortiManagerPackageName": testPolicyPackageNamge,
					"FWRuleName":              "pingables",
					"Comments":                "",
				},
			},
			Spec: apiv3.GlobalNetworkPolicySpec{
				Tier:     testTierName,
				Selector: "tigera.io/address-group == \"svc1\" && tigera.io/address-group == \"pinger\"",
				Types:    []apiv3.PolicyType{apiv3.PolicyTypeEgress},
				Egress: []apiv3.Rule{
					apiv3.Rule{
						Protocol: &protoICMP,
						Action:   apiv3.Allow,
						Destination: apiv3.EntityRule{
							Selector: "tigera.io/address-group == \"svc2\" && tigera.io/address-group == \"pinger\"",
						},
					},
				},
			},
		},
		apiv3.GlobalNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: policyName(testTierName, "pingables", "egr", "deny"),
				Annotations: map[string]string{
					"FortiManagerPackageName": testPolicyPackageNamge,
					"FWRuleName":              "pingables",
					"Comments":                "",
				},
			},
			Spec: apiv3.GlobalNetworkPolicySpec{
				Tier:     testTierName,
				Selector: "tigera.io/address-group == \"svc1\" && tigera.io/address-group == \"pinger\"",
				Types:    []apiv3.PolicyType{apiv3.PolicyTypeIngress, apiv3.PolicyTypeEgress},
			},
		},
	}
)

func policyName(tier string, parts ...string) string {
	part := strings.Join(parts, "-")
	return fmt.Sprintf("%s.%s", tier, part)
}

var _ = Describe("Policy conversion tests", func() {
	DescribeTable("Converted policies",
		func(fwPolicy fortilib.FortiFWPolicy, expectedGNPs []apiv3.GlobalNetworkPolicy) {
			actualGNPs, err := fortimanager.ConvertFWRuleToGNPs(testTierName, testPolicyPackageNamge, fwPolicy)
			Expect(err).To(BeNil())
			for _, expectedGNP := range expectedGNPs {
				Expect(actualGNPs).To(ContainElement(MatchPolicy(expectedGNP)))
			}
		},
		Entry("Convert TCP rule", TCPFortimanagerPolicy, TCPConvertedPolicy),
		Entry("Convert UDP rule", UDPFortimanagerPolicy, UDPConvertedPolicy),
		Entry("Convert ICMP rule", ICMPFortimanagerPolicy, ICMPConvertedPolicy),
	)
})

// MatchPolicy is a convenience function that returns a policyMatcher for matching
// policies in a Gomega assertion.
// TODO(doublek): This is based on the matcher defined in policy recommendation testing.
// Needs to be commonized at some point.
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
	case apiv3.GlobalNetworkPolicy:
		expectedPolicy := pm.expected.(apiv3.GlobalNetworkPolicy)
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

func matchRules(actual, expected []apiv3.Rule) bool {
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

func matchSingleRule(actual, expected apiv3.Rule) bool {
	return matchEntityRule(actual.Source, expected.Source) &&
		matchEntityRule(actual.Destination, expected.Destination) &&
		actual.Protocol.String() == expected.Protocol.String()
}

func matchEntityRule(actual, expected apiv3.EntityRule) bool {
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
