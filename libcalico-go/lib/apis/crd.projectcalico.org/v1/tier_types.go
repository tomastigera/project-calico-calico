// Copyright (c) 2020 Tigera, Inc. All rights reserved.

package v1

import (
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// +k8s:openapi-gen=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'kube-admin' ? self.spec.defaultAction == 'Pass' : true", message="The 'kube-admin' tier must have default action 'Pass'"
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'kube-baseline' ? self.spec.defaultAction == 'Pass' : true", message="The 'kube-baseline' tier must have default action 'Pass'"
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'default' ? self.spec.defaultAction == 'Deny' : true", message="The 'default' tier must have default action 'Deny'"
type Tier struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              v3.TierSpec `json:"spec"`
}
