// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

package names

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

func TierIsStatic(name string) bool {
	return name == DefaultTierName || name == KubeAdminTierName || name == KubeBaselineTierName ||
		name == AdminNetworkPolicyTierName || name == BaselineAdminNetworkPolicyTierName
}
