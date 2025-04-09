// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package recommendation_scope_controller

import (
	"context"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	recengine "github.com/projectcalico/calico/policy-recommendation/pkg/engine"
	rectypes "github.com/projectcalico/calico/policy-recommendation/pkg/types"
)

type tierReconciler struct {
	*reconcilerBase
}

// newTierReconciler constructs our tierReconciler.
func newTierReconciler(
	ctx context.Context,
	clusterID string,
	clientSet lmak8s.ClientSet,
	linseed lsclient.Client,
	minPollInterval metav1.Duration,
	clog *log.Entry,
) *tierReconciler {
	base := &reconcilerBase{
		ctx:             ctx,
		clusterID:       clusterID,
		clientSet:       clientSet,
		linseed:         linseed,
		enabled:         v3.PolicyRecommendationScopeDisabled,
		minPollInterval: minPollInterval,
		clog:            clog,
	}

	return &tierReconciler{reconcilerBase: base}
}

func (r *tierReconciler) Reconcile(key types.NamespacedName) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if !isTargetTier(key) {
		r.clog.Infof("Ignoring Tier %s", key.Name)
		return nil
	}
	var err error
	tier, err := r.clientSet.ProjectcalicoV3().Tiers().Get(r.ctx, key.Name, metav1.GetOptions{})
	if err != nil || tier == nil {
		return nil
	}

	scope := newDefaultRecommendationScope()
	return r.reconcilerBase.reconcile(scope)
}

func isTargetTier(key types.NamespacedName) bool {
	return key.Name == rectypes.PolicyRecommendationTierName && key.Namespace == v1.NamespaceAll
}

func newDefaultRecommendationScope() *v3.PolicyRecommendationScope {
	return &v3.PolicyRecommendationScope{
		Spec: v3.PolicyRecommendationScopeSpec{
			NamespaceSpec: v3.PolicyRecommendationScopeNamespaceSpec{
				RecStatus: v3.PolicyRecommendationScopeEnabled,
				Selector:  recengine.DefaultSelector,
			},
		},
	}
}
