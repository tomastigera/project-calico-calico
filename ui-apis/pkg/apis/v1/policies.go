// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package v1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// PolicyKey uniquely identifies a Calico policy by kind, namespace, and name.
type PolicyKey struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// UnusedPoliciesResponse is the response body for GET /policies/unused.
type UnusedPoliciesResponse struct {
	// Policies contains policies with no activity in the requested time window.
	Policies []UnusedPolicyEntry `json:"policies"`
	// Rules contains policies that have activity but have one or more rules
	// with no activity in the requested time window.
	Rules []UnusedRuleEntry `json:"rules"`
}

// UnusedPolicyEntry identifies an entirely-unused policy.
type UnusedPolicyEntry struct {
	PolicyKey                     `json:",inline"`
	Generation                    int64        `json:"generation,omitempty"`
	CreationTime                  *metav1.Time `json:"creationTimestamp,omitempty"`
	EvaluatedAtPreviousGeneration bool         `json:"evaluatedAtPreviousGeneration,omitempty"`
}

// UnusedRuleEntry identifies a policy that has some unused rules.
type UnusedRuleEntry struct {
	Kind         string       `json:"policyKind"`
	Namespace    string       `json:"policyNamespace,omitempty"`
	Name         string       `json:"policyName"`
	Generation   int64        `json:"policyGeneration,omitempty"`
	CreationTime *metav1.Time `json:"creationTimestamp,omitempty"`
	UnusedRules  []UnusedRule `json:"unusedRules"`
}

// UnusedRule identifies a single rule within a policy that had no activity.
type UnusedRule struct {
	Direction string `json:"direction"` // "ingress" or "egress"
	Index     string `json:"index"`
}
