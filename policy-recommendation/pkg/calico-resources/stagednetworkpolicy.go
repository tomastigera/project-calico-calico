// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package calicoresources

import (
	"fmt"
	"sort"
	"time"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"

	"github.com/projectcalico/calico/compliance/pkg/hashutils"
	"github.com/projectcalico/calico/policy-recommendation/pkg/types"
)

type DirectionType string
type ScopeType string

const (
	// Default SNP Spec values
	StagedNetworkPoliciesDefaultOrder = float64(100)
	// The possible directions a flow can take.
	EgressTraffic  DirectionType = "egress"
	IngressTraffic DirectionType = "ingress"

	// Scope annotations the v3 rules can be tagged with.
	EgressToDomainScope    ScopeType = "Domains"
	EgressToDomainSetScope ScopeType = "DomainSet"
	EgressToServiceScope   ScopeType = "Service"
	NamespaceScope         ScopeType = "Namespace"
	NetworkSetScope        ScopeType = "NetworkSet"
	PrivateNetworkScope    ScopeType = "Private"
	PublicNetworkScope     ScopeType = "Public"

	projectCalicoKeyName = "projectcalico.org"
	PolicyRecKeyName     = "policyrecommendation.tigera.io"

	nonServiceTypeWarning          = "NonServicePortsAndProtocol"
	policyRecommendationTimeFormat = time.RFC3339
	namespaceScope                 = "namespace"

	LastUpdatedKey  = PolicyRecKeyName + "/lastUpdated"
	NameKey         = PolicyRecKeyName + "/name"
	NamespaceKey    = PolicyRecKeyName + "/namespace"
	ScopeKey        = PolicyRecKeyName + "/scope"
	StagedActionKey = projectCalicoKeyName + "/spec.stagedAction"
	StatusKey       = PolicyRecKeyName + "/status"
	TierKey         = projectCalicoKeyName + "/tier"

	LearningStatus    = "Learning"
	NoDataStatus      = "NoData"
	StableStatus      = "Stable"
	StabilizingStatus = "Stabilizing"
	StaleStatus       = "Stale"

	policyRecommendationScopeKind = "PolicyRecommendationScope"
)

var (
	// Private RFC 1918 blocks
	// Note: Make sure this list reflects the equivalent list in felix/collector/flowlog_util.go
	privateNetwork24BitBlock = "10.0.0.0/8"
	privateNetwork20BitBlock = "172.16.0.0/12"
	privateNetwork16BitBlock = "192.168.0.0/16"
)

// NewStagedNetworkPolicy returns a pointer to a staged network policy.
func NewStagedNetworkPolicy(name, namespace, tier string, uid ktypes.UID) *v3.StagedNetworkPolicy {
	snp := &v3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindStagedNetworkPolicy,
			APIVersion: v3.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				StatusKey: LearningStatus,
			},
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"projectcalico.org/tier":                tier,
				"projectcalico.org/ownerReference.kind": policyRecommendationScopeKind,
				"policyrecommendation.tigera.io/scope":  namespaceScope,
				"projectcalico.org/spec.stagedAction":   "Learn",
			},
		},

		Spec: v3.StagedNetworkPolicySpec{
			StagedAction: v3.StagedActionLearn,
			Tier:         tier,
			Selector:     fmt.Sprintf("%s/namespace == '%s'", projectCalicoKeyName, namespace),
			Egress:       nil,
			Ingress:      nil,
			Types:        nil,
		},
	}

	if uid != "" {
		snp.ObjectMeta.OwnerReferences = []metav1.OwnerReference{
			{
				APIVersion:         v3.GroupVersionCurrent,
				Kind:               policyRecommendationScopeKind,
				Name:               types.PolicyRecommendationScopeName,
				UID:                uid,
				Controller:         &[]bool{true}[0],
				BlockOwnerDeletion: &[]bool{false}[0],
			},
		}
	}
	return snp
}

// GetEgressToDomainV3Rule returns the egress traffic to domain rule. The destination entity rule
// ports are in sorted order and the domains are in alphabetical order.
//
// Metadata.Annotations:
//
//	policyrecommendation.tigera.io/lastUpdated	=	<RFC3339 formatted timestamp>
//	policyrecommendation.tigera.io/scope 				= 'Domains'
//
// EntityRule.Ports:
//
//	set of ports from flows (always destination rule)
//
// EntityRule.Domains:
//
//	set of domains from flows
func GetEgressToDomainV3Rule(data types.FlowLogData, direction DirectionType) *v3.Rule {
	rule := &v3.Rule{
		Metadata: &v3.RuleMetadata{
			Annotations: map[string]string{
				fmt.Sprintf("%s/lastUpdated", PolicyRecKeyName): data.Timestamp,
				fmt.Sprintf("%s/scope", PolicyRecKeyName):       string(EgressToDomainScope),
			},
		},
		Action:   data.Action,
		Protocol: &data.Protocol,
	}

	if data.Protocol.SupportsPorts() {
		rule.Destination.Ports = data.Ports
	}

	// Retruns a sorted slice of domains in alphabetical order.
	sortDomains := func(domains []string) []string {
		sortedDomains := domains
		sort.SliceStable(sortedDomains, func(i, j int) bool {
			return sortedDomains[i] < sortedDomains[j]
		})

		return sortedDomains
	}

	rule.Destination.Domains = sortDomains(data.Domains)

	return rule
}

// GetEgressToDomainSetV3Rule returns an egress traffic to domain set rule. The destination entity
// rule ports are in sorted order.
//
// Metadata.Annotations
//
//	policyrecommendation.tigera.io/lastUpdated	= <RFC3339 formatted timestamp>
//	policyrecommendation.tigera.io/name 				= ‘<namespace>-egress-domains’
//	policyrecommendation.tigera.io/namespace 		= <namespace>
//	policyrecommendation.tigera.io/scope 				= 'DomainsSet'
//
// EntityRule.Ports:
//
//	set of ports from flows (always destination rule)
//
// EntityRule.Selector
//
//	policyrecommendation.tigera.io/scope == 'Domains'
func GetEgressToDomainSetV3Rule(data types.FlowLogData, direction DirectionType) *v3.Rule {
	rule := &v3.Rule{
		Metadata: &v3.RuleMetadata{
			Annotations: map[string]string{
				fmt.Sprintf("%s/lastUpdated", PolicyRecKeyName): data.Timestamp,
				fmt.Sprintf("%s/name", PolicyRecKeyName):        fmt.Sprintf("%s-egress-domains", data.Namespace),
				fmt.Sprintf("%s/namespace", PolicyRecKeyName):   data.Namespace,
				fmt.Sprintf("%s/scope", PolicyRecKeyName):       string(EgressToDomainSetScope),
			},
		},
		Action:   data.Action,
		Protocol: &data.Protocol,
	}

	if data.Protocol.SupportsPorts() {
		rule.Destination.Ports = sortPorts(data.Ports)
	}
	rule.Destination.Selector = fmt.Sprintf("%s/scope == '%s'", PolicyRecKeyName, string(EgressToDomainScope))

	return rule
}

// GetEgressToServiceV3Rule returns the egress traffic to service rule. The destination entity
// rule ports are in sorted order.
//
// Metadata.Annotations:
//
//	policyrecommendation.tigera.io/lastUpdated 	= <RFC3339 formatted timestamp>
//	policyrecommendation.tigera.io/name 				= '<service_name>'
//	policyrecommendation.tigera.io/namespace 		= '<namespace>'
//	policyrecommendation.tigera.io/scope 				= 'Service'
//
// EntityRule.Ports:
//
//	set of ports from flows (always destination rule)
//
// EntityRule.Name:
//
//	<service_name>
//
// EntityRule.Namespace:
//
//	<service_namespace>
func GetEgressToServiceV3Rule(data types.FlowLogData, direction DirectionType) *v3.Rule {
	rule := &v3.Rule{
		Metadata: &v3.RuleMetadata{
			Annotations: map[string]string{
				fmt.Sprintf("%s/lastUpdated", PolicyRecKeyName): data.Timestamp,
				fmt.Sprintf("%s/name", PolicyRecKeyName):        data.Name,
				fmt.Sprintf("%s/namespace", PolicyRecKeyName):   data.Namespace,
				fmt.Sprintf("%s/scope", PolicyRecKeyName):       string(EgressToServiceScope),
			},
		},
		Action:   data.Action,
		Protocol: &data.Protocol,
	}

	if data.Protocol.SupportsPorts() {
		rule.Destination.Ports = sortPorts(data.Ports)
	}
	rule.Destination.Services = &v3.ServiceMatch{
		Name:      data.Name,
		Namespace: data.Namespace,
	}

	return rule
}

// GetNamespaceV3Rule returns the traffic to namespace rule. The entity rule ports are
// in sorted order.
//
// Metadata.Annotations:
//
//	policyrecommendation.tigera.io/lastUpdated=<RFC3339 formatted timestamp>
//	policyrecommendation.tigera.io/namespace = '<namespace>'
//	policyrecommendation.tigera.io/scope = 'Namespace'
//
// EntityRule.Ports:
//
//	set of ports from flows (always destination rule)
//
// EntityRule.Selector:
//
// EntityRule.NamespaceSelector:
//
//	projectcalico.org/name == '<namespace>'
func GetNamespaceV3Rule(data types.FlowLogData, direction DirectionType) *v3.Rule {
	rule := &v3.Rule{
		Metadata: &v3.RuleMetadata{
			Annotations: map[string]string{
				fmt.Sprintf("%s/lastUpdated", PolicyRecKeyName): data.Timestamp,
				fmt.Sprintf("%s/namespace", PolicyRecKeyName):   data.Namespace,
				fmt.Sprintf("%s/scope", PolicyRecKeyName):       string(NamespaceScope),
				fmt.Sprintf("%s/warnings", PolicyRecKeyName):    nonServiceTypeWarning,
			},
		},
		Action:   data.Action,
		Protocol: &data.Protocol,
	}

	entityRule := getEntityRuleReference(direction, rule)
	entityRule.NamespaceSelector = fmt.Sprintf("%s/name == '%s'", projectCalicoKeyName, data.Namespace)
	if data.Protocol.SupportsPorts() {
		rule.Destination.Ports = sortPorts(data.Ports)
	}

	return rule
}

// GetNetworkSetV3Rule returns the traffic to network set rule. The entity rule ports are in sorted
// order.
//
// Metadata.Annotations
//
//	policyrecommendation.tigera.io/lastUpdated=<RFC3339 formatted timestamp>
//	policyrecommendation.tigera.io/name = <name>
//	policyrecommendation.tigera.io/namespace = <namespace>
//	policyrecommendation.tigera.io/scope = ‘NetworkSet’
//
// EntityRule.Ports:
//
//	set of ports from flows (always destination rule)
//
// EntityRule.Selector:
//
//	projectcalico.org/name == '<name>' && projectcalico.org/kind == 'NetworkSet'
//
// EntityRule.NamespaceSelector:
//
//	projectcalico.org/name == '<namespace>', or global()
func GetNetworkSetV3Rule(data types.FlowLogData, direction DirectionType) *v3.Rule {
	rule := &v3.Rule{
		Metadata: &v3.RuleMetadata{
			Annotations: map[string]string{
				fmt.Sprintf("%s/lastUpdated", PolicyRecKeyName): data.Timestamp,
				fmt.Sprintf("%s/name", PolicyRecKeyName):        data.Name,
				fmt.Sprintf("%s/namespace", PolicyRecKeyName):   data.Namespace,
				fmt.Sprintf("%s/scope", PolicyRecKeyName):       string(NetworkSetScope),
			},
		},
		Action:   data.Action,
		Protocol: &data.Protocol,
	}

	// The implicit label of every network set (or global network set) uses the
	// "github.com/projectcalico/calico/compliance/pkg/hashutils.GetLengthLimitedName" function to
	// generate a name limited to 63 characters. The rule selector matches that label.
	// The limit was added in: https://github.com/tigera/calico-private/pull/7766.
	name := getNetworkSetLabelLengthLimitedName(data.Name)

	entityRule := getEntityRuleReference(direction, rule)
	entityRule.Selector = fmt.Sprintf("%s/name == '%s' && %s/kind == '%s'",
		projectCalicoKeyName, name, projectCalicoKeyName, string(NetworkSetScope))
	if data.Global {
		entityRule.NamespaceSelector = "global()"
	} else {
		entityRule.NamespaceSelector = fmt.Sprintf("%s/name == '%s'", projectCalicoKeyName, data.Namespace)
	}

	if data.Protocol.SupportsPorts() {
		rule.Destination.Ports = sortPorts(data.Ports)
	}

	return rule
}

// GetPrivateNetworkV3Rule returns the traffic to private network set rule. The entity rule ports
// are in sorted order.
//
// Metadata.Annotations
//
//	policyrecommendation.tigera.io/lastUpdated=<RFC3339 formatted timestamp>
//	policyrecommendation.tigera.io/scope = ‘Private’
//
// Destination.Ports:
//
//	set of ports from flows (always destination rule)
//
// EntityRule.Selector
//
//	policyrecommendation.tigera.io/scope == ‘Private’
//
// EntityRule.Nets:
//
//   - "10.0.0.0/8"
//   - "172.16.0.0/12"
//   - "192.168.0.0/16"
func GetPrivateNetworkV3Rule(data types.FlowLogData, direction DirectionType) *v3.Rule {
	rule := &v3.Rule{
		Metadata: &v3.RuleMetadata{
			Annotations: map[string]string{
				fmt.Sprintf("%s/lastUpdated", PolicyRecKeyName): data.Timestamp,
				fmt.Sprintf("%s/scope", PolicyRecKeyName):       string(PrivateNetworkScope),
			},
		},
		Action:   data.Action,
		Protocol: &data.Protocol,
	}

	entityRule := getEntityRuleReference(direction, rule)
	if data.Protocol.SupportsPorts() {
		rule.Destination.Ports = sortPorts(data.Ports)
	}
	entityRule.Nets = []string{privateNetwork24BitBlock, privateNetwork20BitBlock, privateNetwork16BitBlock}

	return rule
}

// GetPublicNetworkV3Rule returns the traffic to public network set rule. The entity rule ports are in
// sorted order.
//
// Metadata.Annotations:
//
//	policyrecommendation.tigera.io/lastUpdated = <RFC3339 formatted timestamp>
//	policyrecommendation.tigera.io/scope = ‘Public’
//
// EntityRule.Ports:
//
//	set of ports from flows (always destination rule)
func GetPublicNetworkV3Rule(data types.FlowLogData, direction DirectionType) *v3.Rule {
	rule := &v3.Rule{
		Metadata: &v3.RuleMetadata{
			Annotations: map[string]string{
				fmt.Sprintf("%s/lastUpdated", PolicyRecKeyName): data.Timestamp,
				fmt.Sprintf("%s/scope", PolicyRecKeyName):       string(PublicNetworkScope),
			},
		},
		Action:   data.Action,
		Protocol: &data.Protocol,
	}

	if data.Protocol.SupportsPorts() {
		rule.Destination.Ports = sortPorts(data.Ports)
	}

	return rule
}

// getEntityRuleReference returns the entity rule pointer, given the traffic direction.
func getEntityRuleReference(direction DirectionType, rule *v3.Rule) *v3.EntityRule {
	var entityRule *v3.EntityRule
	if direction == EgressTraffic {
		entityRule = &rule.Destination
	} else if direction == IngressTraffic {
		entityRule = &rule.Source
	}

	return entityRule
}

// getNetworkSetLabelLengthLimitedName returns a label length limited to 63 characters name for the
// network set.
func getNetworkSetLabelLengthLimitedName(name string) string {
	return hashutils.GetLengthLimitedName(name, k8svalidation.DNS1123LabelMaxLength)
}

// sortPorts returns a sorted list of ports, sorted by min port.
func sortPorts(ports []numorstring.Port) []numorstring.Port {
	sortedPorts := ports
	sort.SliceStable(sortedPorts, func(i, j int) bool {
		if sortedPorts[i].MinPort != sortedPorts[j].MinPort {
			return sortedPorts[i].MinPort < sortedPorts[j].MinPort
		}
		if sortedPorts[i].MaxPort != sortedPorts[j].MaxPort {
			return sortedPorts[i].MaxPort < sortedPorts[j].MaxPort
		}
		return sortedPorts[i].PortName < sortedPorts[j].PortName
	})

	return sortedPorts
}
