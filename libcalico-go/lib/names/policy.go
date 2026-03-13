// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

package names

import "reflect"

const (
	DefaultTierName                    = "default"
	KubeAdminTierName                  = "kube-admin"
	KubeBaselineTierName               = "kube-baseline"
	AdminNetworkPolicyTierName         = "adminnetworkpolicy"
	BaselineAdminNetworkPolicyTierName = "baselineadminnetworkpolicy"

	// OpenStackNetworkPolicyNamePrefix is the prefix for OpenStack security groups.
	OpenStackNetworkPolicyNamePrefix = "ossg."
)

// TierOrDefault returns the tier name, or the default if blank.
func TierOrDefault(tier string) string {
	if len(tier) == 0 {
		return DefaultTierName
	} else {
		return tier
	}
}

// TierFromPolicy extracts the tier name from a policy object using reflection.
// It looks for a Spec.Tier string field, which most Calico policy types have
// (GlobalNetworkPolicy, NetworkPolicy, StagedGlobalNetworkPolicy,
// StagedNetworkPolicy). Returns the tier name and true if found, or empty
// string and false if the object doesn't have a Spec.Tier field (e.g.,
// StagedKubernetesNetworkPolicy).
func TierFromPolicy(obj any) (string, bool) {
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	spec := v.FieldByName("Spec")
	if !spec.IsValid() {
		return "", false
	}
	tier := spec.FieldByName("Tier")
	if !tier.IsValid() || tier.Kind() != reflect.String {
		return "", false
	}
	return TierOrDefault(tier.String()), true
}

func TierIsStatic(name string) bool {
	return name == DefaultTierName || name == KubeAdminTierName || name == KubeBaselineTierName ||
		name == AdminNetworkPolicyTierName || name == BaselineAdminNetworkPolicyTierName
}
