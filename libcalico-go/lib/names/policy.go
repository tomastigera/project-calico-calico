// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

package names

const (
	DefaultTierName                    = "default"
	KubeAdminTierName                  = "kube-admin"
	KubeBaselineTierName               = "kube-baseline"
	AdminNetworkPolicyTierName         = "adminnetworkpolicy"
	BaselineAdminNetworkPolicyTierName = "baselineadminnetworkpolicy"

	// K8sNetworkPolicyNamePrefix is the prefix used when translating a
	// Kubernetes network policy into a Calico one.
	K8sNetworkPolicyNamePrefix = "knp.default."
	// K8sAdminNetworkPolicyNamePrefix is the prefix for a Kubernetes
	// AdminNetworkPolicy resources, which are cluster-scoped and live in a
	// tier ahead of the default tier.
	K8sAdminNetworkPolicyNamePrefix = "kanp.adminnetworkpolicy."
	// K8sBaselineAdminNetworkPolicyNamePrefix is the prefix for the singleton
	// BaselineAdminNetworkPolicy resource, which is cluster-scoped and lives
	// in a tier after the default tier.
	K8sBaselineAdminNetworkPolicyNamePrefix = "kbanp.baselineadminnetworkpolicy."
	K8sCNPAdminTierNamePrefix               = "kcnp.kube-admin."
	K8sCNPBaselineTierNamePrefix            = "kcnp.kube-baseline."

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
