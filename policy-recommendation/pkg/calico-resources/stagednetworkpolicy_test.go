// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package calicoresources

import (
	"fmt"
	"reflect"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/policy-recommendation/pkg/types"
	"github.com/projectcalico/calico/policy-recommendation/utils"
)

const (
	domainNamespace  = "test-domainset-namespace"
	name             = "test-name"
	longName         = "this-is-a-very-long-networkset-name-that-exceeds-the-sixty-three-character-limit"
	namespace        = "test-namespace"
	tier             = "test-policy-tier"
	selector         = "namespace1 AND namespace2"
	service          = "test-service-name"
	serviceNamespace = "test-service-namespace"

	rfc3339Time = "2002-10-02T10:00:00-05:00"
)

var (
	protocolTCP  = numorstring.ProtocolFromString("TCP")
	protocolUDP  = numorstring.ProtocolFromString("UDP")
	protocolICMP = numorstring.ProtocolFromString("ICMP")
)

var _ = Describe("NewStagedNetworkPolicy", func() {
	It("valid staged network policy", func() {
		expectedStagedNetworkPolicy := &v3.StagedNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("%s.%s-%s", tier, name, mockSuffixGenerator()),
				Namespace: namespace,
			},

			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionLearn,
				Tier:         tier,
				Selector:     selector,
			},
		}

		snp := NewStagedNetworkPolicy(utils.GenerateRecommendationName(tier, name, mockSuffixGenerator), namespace, tier, "orikr-9df4d-0k43m")
		Expect(snp).ToNot(BeNil())

		testStagedNetworkPolicyEquality(snp, expectedStagedNetworkPolicy)
	})
})

var _ = Describe("Policy Recommendation Rules", func() {
	var (
		domains      []string
		orderedPorts []numorstring.Port
		ports        []numorstring.Port
	)

	BeforeEach(func() {
		domains = []string{
			"kubernetes.io",
			"tigera.io",
			"calico.org",
		}
		ports = []numorstring.Port{
			{
				MinPort: 55,
				MaxPort: 55,
			},
			{
				MinPort: 75,
				MaxPort: 75,
			},
			{
				MinPort: 74,
				MaxPort: 88,
			},
			{
				MinPort: 1,
				MaxPort: 10,
			},
		}

		orderedPorts = []numorstring.Port{
			{
				MinPort: 1,
				MaxPort: 10,
			},
			{
				MinPort: 55,
				MaxPort: 55,
			},
			{
				MinPort: 74,
				MaxPort: 88,
			},
			{
				MinPort: 75,
				MaxPort: 75,
			},
		}
	})

	It("returns a valid GetEgressToDomainSetV3Rule", func() {
		expectedRule := &v3.Rule{
			Metadata: &v3.RuleMetadata{
				Annotations: map[string]string{
					"policyrecommendation.tigera.io/lastUpdated": time.Now().Format(policyRecommendationTimeFormat),
					"policyrecommendation.tigera.io/name":        "test-domainset-namespace-egress-domains",
					"policyrecommendation.tigera.io/namespace":   "test-domainset-namespace",
					"policyrecommendation.tigera.io/scope":       "DomainSet",
				},
			},
			Action:   v3.Allow,
			Protocol: &protocolTCP,
			Destination: v3.EntityRule{
				Ports:    orderedPorts,
				Selector: "policyrecommendation.tigera.io/scope == 'Domains'",
			},
		}

		data := types.FlowLogData{
			Action:    v3.Allow,
			Namespace: domainNamespace,
			Ports:     ports,
			Protocol:  protocolTCP,
			Timestamp: rfc3339Time,
		}

		rule := GetEgressToDomainSetV3Rule(data, EgressTraffic)
		testRuleEquality(rule, expectedRule)
	})

	It("returns a valid GetEgressToDomainSetV3Rule with ICMP protocol", func() {
		expectedRule := &v3.Rule{
			Metadata: &v3.RuleMetadata{
				Annotations: map[string]string{
					"policyrecommendation.tigera.io/lastUpdated": time.Now().Format(policyRecommendationTimeFormat),
					"policyrecommendation.tigera.io/name":        "test-domainset-namespace-egress-domains",
					"policyrecommendation.tigera.io/namespace":   "test-domainset-namespace",
					"policyrecommendation.tigera.io/scope":       "DomainSet",
				},
			},
			Action:   v3.Allow,
			Protocol: &protocolICMP,
			Destination: v3.EntityRule{
				Selector: "policyrecommendation.tigera.io/scope == 'Domains'",
			},
		}

		data := types.FlowLogData{
			Action:    v3.Allow,
			Namespace: domainNamespace,
			Ports:     []numorstring.Port{},
			Protocol:  protocolICMP,
			Timestamp: rfc3339Time,
		}

		rule := GetEgressToDomainSetV3Rule(data, EgressTraffic)
		testRuleEquality(rule, expectedRule)
	})

	It("returns a valid GetEgressToDomainV3Rule", func() {
		expectedRule := &v3.Rule{
			Metadata: &v3.RuleMetadata{
				Annotations: map[string]string{
					"policyrecommendation.tigera.io/lastUpdated": time.Now().Format(policyRecommendationTimeFormat),
					"policyrecommendation.tigera.io/scope":       "Domains",
				},
			},
			Action:   v3.Allow,
			Protocol: &protocolTCP,
			Destination: v3.EntityRule{
				Ports:   []numorstring.Port{{MinPort: 55, MaxPort: 55, PortName: ""}},
				Domains: []string{"calico.org", "kubernetes.io", "tigera.io"},
			},
		}

		data := types.FlowLogData{
			Action:    v3.Allow,
			Domains:   domains,
			Ports:     []numorstring.Port{{MinPort: 55, MaxPort: 55, PortName: ""}},
			Protocol:  protocolTCP,
			Timestamp: rfc3339Time,
		}

		rule := GetEgressToDomainV3Rule(data, EgressTraffic)
		testRuleEquality(rule, expectedRule)
	})

	It("returns a valid GetEgressToDomainV3Rule with ICMP protocol", func() {
		expectedRule := &v3.Rule{
			Metadata: &v3.RuleMetadata{
				Annotations: map[string]string{
					"policyrecommendation.tigera.io/lastUpdated": time.Now().Format(policyRecommendationTimeFormat),
					"policyrecommendation.tigera.io/scope":       "Domains",
				},
			},
			Action:   v3.Allow,
			Protocol: &protocolICMP,
			Destination: v3.EntityRule{
				Domains: []string{"calico.org", "kubernetes.io", "tigera.io"},
			},
		}

		data := types.FlowLogData{
			Action:    v3.Allow,
			Domains:   domains,
			Ports:     []numorstring.Port{},
			Protocol:  protocolICMP,
			Timestamp: rfc3339Time,
		}

		rule := GetEgressToDomainV3Rule(data, EgressTraffic)
		testRuleEquality(rule, expectedRule)
	})

	It("returns a valid GetEgressToServiceSetV3Rule", func() {
		expectedRule := &v3.Rule{
			Metadata: &v3.RuleMetadata{
				Annotations: map[string]string{
					"policyrecommendation.tigera.io/lastUpdated": time.Now().Format(policyRecommendationTimeFormat),
					"policyrecommendation.tigera.io/name":        "test-service-name",
					"policyrecommendation.tigera.io/namespace":   "test-service-namespace",
					"policyrecommendation.tigera.io/scope":       "Service",
				},
			},
			Action:   v3.Allow,
			Protocol: &protocolTCP,
			Destination: v3.EntityRule{
				Ports: orderedPorts,
				Services: &v3.ServiceMatch{
					Name:      "test-service-name",
					Namespace: "test-service-namespace",
				},
			},
		}

		data := types.FlowLogData{
			Action:    v3.Allow,
			Name:      service,
			Namespace: serviceNamespace,
			Ports:     ports,
			Protocol:  protocolTCP,
			Timestamp: rfc3339Time,
		}

		rule := GetEgressToServiceV3Rule(data, EgressTraffic)
		testRuleEquality(rule, expectedRule)
	})

	It("returns a valid GetEgressToServiceSetV3Rule with ICMP protocol", func() {
		expectedRule := &v3.Rule{
			Metadata: &v3.RuleMetadata{
				Annotations: map[string]string{
					"policyrecommendation.tigera.io/lastUpdated": time.Now().Format(policyRecommendationTimeFormat),
					"policyrecommendation.tigera.io/name":        "test-service-name",
					"policyrecommendation.tigera.io/namespace":   "test-service-namespace",
					"policyrecommendation.tigera.io/scope":       "Service",
				},
			},
			Action:   v3.Allow,
			Protocol: &protocolICMP,
			Destination: v3.EntityRule{
				Services: &v3.ServiceMatch{
					Name:      "test-service-name",
					Namespace: "test-service-namespace",
				},
			},
		}

		data := types.FlowLogData{
			Action:    v3.Allow,
			Name:      service,
			Namespace: serviceNamespace,
			Ports:     []numorstring.Port{},
			Protocol:  protocolICMP,
			Timestamp: rfc3339Time,
		}

		rule := GetEgressToServiceV3Rule(data, EgressTraffic)
		testRuleEquality(rule, expectedRule)
	})

	It("returns a valid GetNamespaceV3Rule", func() {
		expectedRule := &v3.Rule{
			Metadata: &v3.RuleMetadata{
				Annotations: map[string]string{
					"policyrecommendation.tigera.io/lastUpdated": time.Now().Format(policyRecommendationTimeFormat),
					"policyrecommendation.tigera.io/namespace":   "test-namespace",
					"policyrecommendation.tigera.io/scope":       "Namespace",
				},
			},
			Action:   v3.Allow,
			Protocol: &protocolTCP,
			Source: v3.EntityRule{
				NamespaceSelector: "projectcalico.org/name == 'test-namespace'",
			},
			Destination: v3.EntityRule{
				Ports: orderedPorts,
			},
		}

		data := types.FlowLogData{
			Action:    v3.Allow,
			Namespace: namespace,
			Ports:     ports,
			Protocol:  protocolTCP,
			Timestamp: rfc3339Time,
		}

		rule := GetNamespaceV3Rule(data, IngressTraffic)
		testRuleEquality(rule, expectedRule)
	})

	It("returns a valid GetNamespaceV3Rule with ICMP protocol", func() {
		expectedRule := &v3.Rule{
			Metadata: &v3.RuleMetadata{
				Annotations: map[string]string{
					"policyrecommendation.tigera.io/lastUpdated": time.Now().Format(policyRecommendationTimeFormat),
					"policyrecommendation.tigera.io/namespace":   "test-namespace",
					"policyrecommendation.tigera.io/scope":       "Namespace",
				},
			},
			Action:   v3.Allow,
			Protocol: &protocolICMP,
			Source: v3.EntityRule{
				NamespaceSelector: "projectcalico.org/name == 'test-namespace'",
			},
			Destination: v3.EntityRule{},
		}

		data := types.FlowLogData{
			Action:    v3.Allow,
			Namespace: namespace,
			Ports:     []numorstring.Port{},
			Protocol:  protocolICMP,
			Timestamp: rfc3339Time,
		}

		rule := GetNamespaceV3Rule(data, IngressTraffic)
		testRuleEquality(rule, expectedRule)
	})

	It("returns a valid GetNetworkSetV3Rule", func() {
		expectedRule := &v3.Rule{
			Metadata: &v3.RuleMetadata{
				Annotations: map[string]string{
					"policyrecommendation.tigera.io/lastUpdated": time.Now().Format(policyRecommendationTimeFormat),
					"policyrecommendation.tigera.io/name":        "test-name",
					"policyrecommendation.tigera.io/namespace":   "test-namespace",
					"policyrecommendation.tigera.io/scope":       "NetworkSet",
				},
			},
			Action:   v3.Allow,
			Protocol: &protocolTCP,
			Source: v3.EntityRule{
				Selector:          "projectcalico.org/name == 'test-name' && projectcalico.org/kind == 'NetworkSet'",
				NamespaceSelector: "global()",
			},
			Destination: v3.EntityRule{
				Ports: orderedPorts,
			},
		}

		data := types.FlowLogData{
			Action:    v3.Allow,
			Global:    true,
			Name:      name,
			Namespace: namespace,
			Ports:     ports,
			Protocol:  protocolTCP,
			Timestamp: rfc3339Time,
		}

		rule := GetNetworkSetV3Rule(data, IngressTraffic)
		fmt.Print(rule.Destination.Ports)
		fmt.Print(expectedRule.Destination.Ports)
		testRuleEquality(rule, expectedRule)
	})

	It("returns a valid GetNetworkSetV3Rule with a network set name larger than 63 characters", func() {
		expectedRule := &v3.Rule{
			Metadata: &v3.RuleMetadata{
				Annotations: map[string]string{
					"policyrecommendation.tigera.io/lastUpdated": time.Now().Format(policyRecommendationTimeFormat),
					"policyrecommendation.tigera.io/name":        "this-is-a-very-long-networkset-name-that-exceeds-the-sixty-three-character-limit",
					"policyrecommendation.tigera.io/namespace":   "test-namespace",
					"policyrecommendation.tigera.io/scope":       "NetworkSet",
				},
			},
			Action:   v3.Allow,
			Protocol: &protocolTCP,
			Source: v3.EntityRule{
				Selector:          "projectcalico.org/name == 'this-is-a-very-long-networkset-name-that-exceeds-the-si-04iv1q2' && projectcalico.org/kind == 'NetworkSet'",
				NamespaceSelector: "global()",
			},
			Destination: v3.EntityRule{
				Ports: orderedPorts,
			},
		}

		data := types.FlowLogData{
			Action:    v3.Allow,
			Global:    true,
			Name:      longName,
			Namespace: namespace,
			Ports:     ports,
			Protocol:  protocolTCP,
			Timestamp: rfc3339Time,
		}

		rule := GetNetworkSetV3Rule(data, IngressTraffic)
		fmt.Print(rule.Destination.Ports)
		fmt.Print(expectedRule.Destination.Ports)
		testRuleEquality(rule, expectedRule)
	})

	It("returns a valid GetNetworkSetV3Rule with ICMP protocol", func() {
		expectedRule := &v3.Rule{
			Metadata: &v3.RuleMetadata{
				Annotations: map[string]string{
					"policyrecommendation.tigera.io/lastUpdated": time.Now().Format(policyRecommendationTimeFormat),
					"policyrecommendation.tigera.io/name":        "test-name",
					"policyrecommendation.tigera.io/namespace":   "test-namespace",
					"policyrecommendation.tigera.io/scope":       "NetworkSet",
				},
			},
			Action:   v3.Allow,
			Protocol: &protocolICMP,
			Source: v3.EntityRule{
				Selector:          "projectcalico.org/name == 'test-name' && projectcalico.org/kind == 'NetworkSet'",
				NamespaceSelector: "global()",
			},
			Destination: v3.EntityRule{},
		}

		data := types.FlowLogData{
			Action:    v3.Allow,
			Global:    true,
			Name:      name,
			Namespace: namespace,
			Ports:     []numorstring.Port{},
			Protocol:  protocolICMP,
			Timestamp: rfc3339Time,
		}

		rule := GetNetworkSetV3Rule(data, IngressTraffic)
		testRuleEquality(rule, expectedRule)
	})

	It("returns a valid Ingress GetPrivateNetworkV3Rule with TCP protocol", func() {
		expectedRule := &v3.Rule{
			Metadata: &v3.RuleMetadata{
				Annotations: map[string]string{
					"policyrecommendation.tigera.io/lastUpdated": time.Now().Format(policyRecommendationTimeFormat),
					"policyrecommendation.tigera.io/scope":       "Private",
				},
			},
			Action:   v3.Allow,
			Protocol: &protocolTCP,
			Source: v3.EntityRule{
				Nets: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			},
			Destination: v3.EntityRule{
				Ports: []numorstring.Port{{MinPort: 80, MaxPort: 80}},
			},
		}

		data := types.FlowLogData{
			Action:    v3.Allow,
			Ports:     []numorstring.Port{{MinPort: 80, MaxPort: 80}},
			Protocol:  protocolTCP,
			Timestamp: rfc3339Time,
		}

		rule := GetPrivateNetworkV3Rule(data, IngressTraffic)
		testRuleEquality(rule, expectedRule)
	})

	It("returns a valid Ingress GetPrivateNetworkV3Rule with UDP protocol", func() {
		expectedRule := &v3.Rule{
			Metadata: &v3.RuleMetadata{
				Annotations: map[string]string{
					"policyrecommendation.tigera.io/lastUpdated": time.Now().Format(policyRecommendationTimeFormat),
					"policyrecommendation.tigera.io/scope":       "Private",
				},
			},
			Action:   v3.Allow,
			Protocol: &protocolUDP,
			Source: v3.EntityRule{
				Nets: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			},
			Destination: v3.EntityRule{
				Ports: []numorstring.Port{{MinPort: 53, MaxPort: 53}},
			},
		}

		data := types.FlowLogData{
			Action:    v3.Allow,
			Ports:     []numorstring.Port{{MinPort: 53, MaxPort: 53}},
			Protocol:  protocolUDP,
			Timestamp: rfc3339Time,
		}

		rule := GetPrivateNetworkV3Rule(data, IngressTraffic)
		testRuleEquality(rule, expectedRule)
	})

	It("returns a valid Ingress GetPrivateNetworkV3Rule with ICMP protocol", func() {

		expectedRule := &v3.Rule{
			Metadata: &v3.RuleMetadata{
				Annotations: map[string]string{
					"policyrecommendation.tigera.io/lastUpdated": time.Now().Format(policyRecommendationTimeFormat),
					"policyrecommendation.tigera.io/scope":       "Private",
				},
			},
			Action:   v3.Allow,
			Protocol: &protocolICMP,
			Source: v3.EntityRule{
				Nets: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			},
			Destination: v3.EntityRule{},
		}

		data := types.FlowLogData{
			Action:    v3.Allow,
			Ports:     []numorstring.Port{},
			Protocol:  protocolICMP,
			Timestamp: rfc3339Time,
		}

		rule := GetPrivateNetworkV3Rule(data, IngressTraffic)
		testRuleEquality(rule, expectedRule)
	})

	It("returns a valid Egress GetPrivateNetworkV3Rule with TCP protocol", func() {

		expectedRule := &v3.Rule{
			Metadata: &v3.RuleMetadata{
				Annotations: map[string]string{
					"policyrecommendation.tigera.io/lastUpdated": time.Now().Format(policyRecommendationTimeFormat),
					"policyrecommendation.tigera.io/scope":       "Private",
				},
			},
			Action:   v3.Allow,
			Protocol: &protocolTCP,
			Source:   v3.EntityRule{},
			Destination: v3.EntityRule{
				Nets:  []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
				Ports: []numorstring.Port{{MinPort: 80, MaxPort: 80}},
			},
		}

		data := types.FlowLogData{
			Action:    v3.Allow,
			Ports:     []numorstring.Port{{MinPort: 80, MaxPort: 80}},
			Protocol:  protocolTCP,
			Timestamp: rfc3339Time,
		}

		rule := GetPrivateNetworkV3Rule(data, EgressTraffic)
		testRuleEquality(rule, expectedRule)
	})

	It("returns a valid Egress GetPrivateNetworkV3Rule with UDP protocol", func() {
		expectedRule := &v3.Rule{
			Metadata: &v3.RuleMetadata{
				Annotations: map[string]string{
					"policyrecommendation.tigera.io/lastUpdated": time.Now().Format(policyRecommendationTimeFormat),
					"policyrecommendation.tigera.io/scope":       "Private",
				},
			},
			Action:   v3.Allow,
			Protocol: &protocolUDP,
			Source:   v3.EntityRule{},
			Destination: v3.EntityRule{
				Nets:  []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
				Ports: []numorstring.Port{{MinPort: 53, MaxPort: 53}},
			},
		}

		data := types.FlowLogData{
			Action:    v3.Allow,
			Ports:     []numorstring.Port{{MinPort: 53, MaxPort: 53}},
			Protocol:  protocolUDP,
			Timestamp: rfc3339Time,
		}

		rule := GetPrivateNetworkV3Rule(data, EgressTraffic)
		testRuleEquality(rule, expectedRule)
	})

	It("returns a valid Egress GetPrivateNetworkV3Rule with ICMP protocol", func() {

		expectedRule := &v3.Rule{
			Metadata: &v3.RuleMetadata{
				Annotations: map[string]string{
					"policyrecommendation.tigera.io/lastUpdated": time.Now().Format(policyRecommendationTimeFormat),
					"policyrecommendation.tigera.io/scope":       "Private",
				},
			},
			Action:   v3.Allow,
			Protocol: &protocolICMP,
			Source:   v3.EntityRule{},
			Destination: v3.EntityRule{
				Nets: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			},
		}

		data := types.FlowLogData{
			Action:    v3.Allow,
			Ports:     []numorstring.Port{},
			Protocol:  protocolICMP,
			Timestamp: rfc3339Time,
		}

		rule := GetPrivateNetworkV3Rule(data, EgressTraffic)
		testRuleEquality(rule, expectedRule)
	})
})

func testStagedNetworkPolicyEquality(leftSnp, rightSnp *v3.StagedNetworkPolicy) {
	if leftSnp == nil && rightSnp == nil {
		return
	}

	if leftSnp != nil {
		Expect(rightSnp).NotTo(BeNil())
	} else if rightSnp != nil {
		Expect(leftSnp).NotTo(BeNil())
	}

	Expect(leftSnp.Name).To(Equal(rightSnp.Name))
	Expect(leftSnp.Namespace).To(Equal(rightSnp.Namespace))
	Expect(leftSnp.Spec.StagedAction).To(Equal(rightSnp.Spec.StagedAction))
	Expect(reflect.DeepEqual(leftSnp.Spec.Types, rightSnp.Spec.Types)).To(Equal(true))
	Expect(reflect.DeepEqual(leftSnp.Spec.Egress, rightSnp.Spec.Egress)).To(Equal(true))
	Expect(reflect.DeepEqual(leftSnp.Spec.Ingress, rightSnp.Spec.Ingress)).To(Equal(true))
}

func testRuleEquality(leftRule, rightRule *v3.Rule) {
	if leftRule == nil && rightRule == nil {
		return
	}

	if leftRule != nil {
		Expect(rightRule).NotTo(BeNil())
	} else if rightRule != nil {
		Expect(leftRule).NotTo(BeNil())
	}

	Expect(leftRule.Action).To(Equal(rightRule.Action))
	Expect(leftRule.Protocol).To(Equal(rightRule.Protocol))

	leftRuleName := leftRule.Metadata.Annotations[fmt.Sprintf("%s/name", PolicyRecKeyName)]
	rightRuleName := rightRule.Metadata.Annotations[fmt.Sprintf("%s/name", PolicyRecKeyName)]
	Expect(leftRuleName).To(Equal(rightRuleName))

	leftRuleNamespace := leftRule.Metadata.Annotations[fmt.Sprintf("%s/namespace", PolicyRecKeyName)]
	rightRuleNamespace := rightRule.Metadata.Annotations[fmt.Sprintf("%s/namespace", PolicyRecKeyName)]
	Expect(leftRuleNamespace).To(Equal(rightRuleNamespace))

	leftScope := leftRule.Metadata.Annotations[fmt.Sprintf("%s/scope", PolicyRecKeyName)]
	rightScope := rightRule.Metadata.Annotations[fmt.Sprintf("%s/scope", PolicyRecKeyName)]
	Expect(leftScope).To(Equal(rightScope))

	Expect(reflect.DeepEqual(leftRule.Destination.Ports, rightRule.Destination.Ports)).To(Equal(true))

	Expect(leftRule.Destination.Selector).To(Equal(rightRule.Destination.Selector))
	Expect(leftRule.Source.Selector).To(Equal(rightRule.Source.Selector))

	Expect(leftRule.Destination.NamespaceSelector).To(Equal(rightRule.Destination.NamespaceSelector))
	Expect(leftRule.Source.NamespaceSelector).To(Equal(rightRule.Source.NamespaceSelector))

	Expect(reflect.DeepEqual(leftRule.Destination.Domains, rightRule.Destination.Domains)).To(Equal(true))
	Expect(reflect.DeepEqual(leftRule.Destination.Services, rightRule.Destination.Services)).To(Equal(true))
}

func mockSuffixGenerator() string {
	return "xv5fb"
}
