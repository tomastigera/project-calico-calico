// Copyright (c) 2018-2014 Tigera, Inc. All rights reserved.
package api

import v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

type Policy interface {
	Kind() string
	GetAnnotations() map[string]string
	GetResource() Resource
	GetTier() string
	GetEndpointCounts() EndpointCounts
	GetRuleEndpointCounts() Rule
	IsUnmatched() bool
	GetOrder() *float64
	GetStagedAction() *v3.StagedAction
	GetSelector() *string
	GetNamespaceSelector() *string
	GetServiceAccountSelector() *string
	IsKubernetesType() (bool, error)
}

type PolicyCounts struct {
	NumGlobalNetworkPolicies int
	NumNetworkPolicies       int
}

type PolicySummary struct {
	Total        int
	NumUnmatched int
}

type Rule struct {
	Ingress []RuleDirection
	Egress  []RuleDirection
}

type RuleDirection struct {
	Source      EndpointCounts
	Destination EndpointCounts
}
