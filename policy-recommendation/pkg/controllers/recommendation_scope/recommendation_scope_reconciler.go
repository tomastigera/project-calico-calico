// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

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
	rectypes "github.com/projectcalico/calico/policy-recommendation/pkg/types"
)

const (
	// kindRecommendations is the kind of the recommendations resource.
	kindRecommendations = "recommendations"
)

type recommendationScopeReconciler struct {
	*reconcilerBase
}

func newRecommendationScopeReconciler(
	ctx context.Context, clusterID string, clientSet lmak8s.ClientSet, linseed lsclient.Client, minPollInterval metav1.Duration, clog *log.Entry,
) *recommendationScopeReconciler {

	base := &reconcilerBase{
		clog:            clog,
		ctx:             ctx,
		clusterID:       clusterID,
		clientSet:       clientSet,
		linseed:         linseed,
		enabled:         v3.PolicyRecommendationScopeDisabled,
		minPollInterval: minPollInterval,
	}
	return &recommendationScopeReconciler{
		reconcilerBase: base,
	}
}

// Reconcile will be triggered by any changes performed on the PolicyRecommendation resource.
func (r *recommendationScopeReconciler) Reconcile(key types.NamespacedName) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// TODO(dimitrin): Remove this check once https://tigera.atlassian.net/browse/EV-4647 has been
	// merged in recommendation_scope_controller.go.
	if !isTargetScope(key) {
		r.clog.Infof("Ignoring PolicyRecommendationScope %s", key.Name)
		return nil
	}
	var err error
	scope, err := r.clientSet.ProjectcalicoV3().PolicyRecommendationScopes().Get(r.ctx, key.Name, metav1.GetOptions{})
	if err != nil || scope == nil {
		return nil
	}

	return r.reconcilerBase.reconcile(scope)
}

func isTargetScope(key types.NamespacedName) bool {
	return key.Name == rectypes.PolicyRecommendationScopeName && key.Namespace == v1.NamespaceAll
}
