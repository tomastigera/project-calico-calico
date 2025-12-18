// Copyright (c) 2018-2020 Tigera, Inc. All rights reserved.
package utils

import (
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
)

// DoExcludeStagedPolicy return true if staged policy should be filtered out
// Staged policies with StagedAction set to Delete are filtered out.
func DoExcludeStagedPolicy(uv3 *api.Update) bool {
	p3Key := uv3.Key.(model.ResourceKey)

	switch p3Key.Kind {
	case v3.KindStagedNetworkPolicy:
		if p3Value, ok := uv3.Value.(*v3.StagedNetworkPolicy); ok {
			if p3Value.Spec.StagedAction == v3.StagedActionDelete {
				return true
			}
		}
	case v3.KindStagedKubernetesNetworkPolicy:
		if p3Value, ok := uv3.Value.(*v3.StagedKubernetesNetworkPolicy); ok {
			if p3Value.Spec.StagedAction == v3.StagedActionDelete {
				return true
			}
		}
	case v3.KindStagedGlobalNetworkPolicy:
		if p3Value, ok := uv3.Value.(*v3.StagedGlobalNetworkPolicy); ok {
			if p3Value.Spec.StagedAction == v3.StagedActionDelete {
				return true
			}
		}
	}

	return false
}

func StagedToEnforcedConversion(uv1 *api.Update, uv3 *api.Update) {
	p1Key := uv1.Key.(model.PolicyKey)
	p3Key := uv3.Key.(model.ResourceKey)

	// TODO: queryserver currently uses two caches - one for NetworkPolicy and one for
	// GlobalNetworkPolicy. When we receive StagedNetworkPolicy or StagedGlobalNetworkPolicy,
	// we convert them to enforced NetworkPolicy or GlobalNetworkPolicy respectively, using this prefix
	// to disambiguate them from normal enforced policies.
	// In future, we should refactor queryserver to use a single cache for all policy types
	// and remove the need for this prefix, using the native Kind field on the Key instead.
	const stagedPrefix = "staged:"

	switch p3Key.Kind {
	case v3.KindStagedNetworkPolicy:
		p3Key.Kind = v3.KindNetworkPolicy
		p3Key.Name = stagedPrefix + p3Key.Name
		if p3Value, ok := uv3.Value.(*v3.StagedNetworkPolicy); ok {
			// Preserve the original UID from the staged policy
			originalUID := p3Value.UID
			_, cp3Value := v3.ConvertStagedPolicyToEnforced(p3Value)
			cp3Value.Name = stagedPrefix + cp3Value.Name
			// Restore the UID so it appears in the API response
			cp3Value.UID = originalUID
			uv3.Value = cp3Value
			// Add back the staged prefix to the name in the v1 key if not present
		}
	case v3.KindStagedKubernetesNetworkPolicy:
		p3Key.Kind = v3.KindNetworkPolicy
		p3Key.Name = stagedPrefix + names.K8sNetworkPolicyNamePrefix + p3Key.Name
		if p3Value, ok := uv3.Value.(*v3.StagedKubernetesNetworkPolicy); ok {
			// Preserve the original UID from the staged policy
			originalUID := p3Value.UID
			// From StagedKubernetesNetworkPolicy to networkingv1 NetworkPolicy
			_, v1NetworkPolicy := v3.ConvertStagedKubernetesPolicyToK8SEnforced(p3Value)
			c := conversion.NewConverter()
			// From networkingv1 NetworkkPolicy to calico model.KVPair
			kvPair, err := c.K8sNetworkPolicyToCalico(v1NetworkPolicy)
			if err == nil {
				if cp3Value, ok := kvPair.Value.(*v3.NetworkPolicy); ok {
					cp3Value.Name = stagedPrefix + cp3Value.Name
					// Restore the UID so it appears in the API response
					cp3Value.UID = originalUID
					uv3.Value = cp3Value
				}
			}
		}
	case v3.KindStagedGlobalNetworkPolicy:
		p3Key.Kind = v3.KindGlobalNetworkPolicy
		p3Key.Name = stagedPrefix + p3Key.Name
		if p3Value, ok := uv3.Value.(*v3.StagedGlobalNetworkPolicy); ok {
			// Preserve the original UID from the staged policy
			originalUID := p3Value.UID
			_, cp3Value := v3.ConvertStagedGlobalPolicyToEnforced(p3Value)
			cp3Value.Name = stagedPrefix + cp3Value.Name
			// Restore the UID so it appears in the API response
			cp3Value.UID = originalUID
			uv3.Value = cp3Value
		}
	}

	uv1.Key = p1Key
	uv3.Key = p3Key
}
