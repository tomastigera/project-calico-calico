// Copyright (c) 2018-2020 Tigera, Inc. All rights reserved.
package utils

import (
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
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
