// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package flowlogs

import (
	"fmt"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/projectcalico/calico/lma/pkg/api"
)

// kindFromObject derives the Calico API kind from the Go struct type. This is needed because
// controller-runtime clears TypeMeta GVK after Create(), making GetObjectKind().GroupVersionKind().Kind
// return "" on in-memory objects.
func kindFromObject(obj runtime.Object) string {
	switch obj.(type) {
	case *v3.NetworkPolicy:
		return v3.KindNetworkPolicy
	case *v3.GlobalNetworkPolicy:
		return v3.KindGlobalNetworkPolicy
	case *v3.StagedNetworkPolicy:
		return v3.KindStagedNetworkPolicy
	case *v3.StagedGlobalNetworkPolicy:
		return v3.KindStagedGlobalNetworkPolicy
	case *v3.StagedKubernetesNetworkPolicy:
		return v3.KindStagedKubernetesNetworkPolicy
	default:
		return ""
	}
}

// FindPolicyInFlowLogs parses each flow log policy string and returns the PolicyHit that matches
// the expected policy object by name, namespace, and kind. Fails the test if no match is found.
func FindPolicyInFlowLogs(policyStrings []string, expected runtime.Object) api.PolicyHit {
	ns := expected.(metav1.Object).GetNamespace()
	name := expected.(metav1.Object).GetName()
	kind := kindFromObject(expected)

	for _, s := range policyStrings {
		hit, err := api.PolicyHitFromFlowLogPolicyString(s)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to parse policy string %s", s))
		if hit.Name() == name && hit.Namespace() == ns && (kind == "" || hit.Kind() == kind) {
			return hit
		}
	}

	msg := fmt.Sprintf(
		"Expected to find policy %s/%s (kind %s) in flow logs but did not. Got policies: %v",
		ns, name, kind, policyStrings,
	)
	ExpectWithOffset(1, false).To(BeTrue(), msg)
	return nil
}

// ExpectPolicyInFlowLogs asserts that the given policy object appears in the flow log policy strings.
func ExpectPolicyInFlowLogs(policyStrings []string, expected runtime.Object) {
	FindPolicyInFlowLogs(policyStrings, expected)
}

// ExpectProfileInFlowLogs asserts that a profile for the given namespace appears in the flow log
// policy strings. Kubernetes namespace profiles are named "kns.<namespace>" in the flow log.
func ExpectProfileInFlowLogs(policyStrings []string, namespace string) {
	expectedName := "kns." + namespace
	for _, s := range policyStrings {
		hit, err := api.PolicyHitFromFlowLogPolicyString(s)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to parse policy string %s", s))
		if hit.Name() == expectedName && hit.Kind() == "Profile" {
			return
		}
	}

	msg := fmt.Sprintf(
		"Expected to find profile for namespace %s (kns.%s) in flow logs but did not. Got policies: %v",
		namespace, namespace, policyStrings,
	)
	ExpectWithOffset(1, false).To(BeTrue(), msg)
}

// FindPolicyHitByName parses each flow log policy string and returns the PolicyHit whose name
// matches the given name. Fails the test if no match is found.
func FindPolicyHitByName(policyStrings []string, name string) api.PolicyHit {
	for _, s := range policyStrings {
		hit, err := api.PolicyHitFromFlowLogPolicyString(s)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to parse policy string %s", s))
		if hit.Name() == name {
			return hit
		}
	}

	msg := fmt.Sprintf(
		"Expected to find policy with name %q in flow logs but did not. Got policies: %v",
		name, policyStrings,
	)
	ExpectWithOffset(1, false).To(BeTrue(), msg)
	return nil
}
