// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package recommendation_scope_controller

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	rcache "github.com/projectcalico/calico/kube-controllers/pkg/cache"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	"github.com/projectcalico/calico/policy-recommendation/pkg/controllers/controller"
	reccontroller "github.com/projectcalico/calico/policy-recommendation/pkg/controllers/recommendation"
	recengine "github.com/projectcalico/calico/policy-recommendation/pkg/engine"
	"github.com/projectcalico/calico/policy-recommendation/pkg/flows"
	rectypes "github.com/projectcalico/calico/policy-recommendation/pkg/types"
)

// reconcilerBase defines the common fields and logic shared by reconcilers.
type reconcilerBase struct {
	ctx             context.Context
	clusterID       string
	clientSet       lmak8s.ClientSet
	linseed         lsclient.Client
	ctrl            controller.Controller
	enabled         v3.PolicyRecommendationNamespaceStatus
	engine          recengine.RecommendationEngine
	stopChan        chan struct{}
	minPollInterval metav1.Duration
	clog            *log.Entry
	mutex           sync.Mutex

	// Each reconciler can provide its own factory for creating the controller/engine.
	ctrlFactory func(*v3.PolicyRecommendationScope) (controller.Controller, recengine.RecommendationEngine, error)
}

// reconcile is the shared logic for enabling/disabling the recommendation engine.
func (r *reconcilerBase) reconcile(scope *v3.PolicyRecommendationScope) error {
	status := scope.Spec.NamespaceSpec.RecStatus
	if r.enabled != status {
		if status == v3.PolicyRecommendationScopeEnabled {
			if r.ctrl == nil {
				var err error
				if r.ctrlFactory != nil {
					r.ctrl, r.engine, err = r.ctrlFactory(scope)
				} else {
					r.ctrl, r.engine, err = r.defaultFactory(scope)
				}
				if err != nil {
					return nil
				}
			}
			r.stopChan = make(chan struct{})
			go r.ctrl.Run(r.stopChan)

			r.enabled = v3.PolicyRecommendationScopeEnabled
			r.clog.Info("Recommendation engine enabled")
		} else {
			close(r.stopChan)
			r.ctrl = nil
			r.enabled = v3.PolicyRecommendationScopeDisabled
			r.clog.Info("Recommendation engine disabled")
		}
	}
	if r.enabled == v3.PolicyRecommendationScopeEnabled {
		r.clog.Info("Updating PolicyRecommendation settings")
		if r.engine != nil {
			r.engine.ReceiveScopeUpdate(*scope)
		}
	}

	return nil
}

// defaultFactory is a fallback if ctrlFactory is not provided.
func (r *reconcilerBase) defaultFactory(scope *v3.PolicyRecommendationScope) (controller.Controller, recengine.RecommendationEngine, error) {
	cache := r.newRecommendationResourceCache()
	engine := recengine.NewRecommendationEngine(
		r.ctx,
		r.clusterID,
		r.clientSet.ProjectcalicoV3(),
		r.linseed,
		flows.NewRecommendationFlowLogQuery(r.ctx, r.linseed, r.clusterID),
		cache,
		scope,
		r.minPollInterval,
		realClock{},
	)
	ctrl, err := reccontroller.NewRecommendationController(r.ctx, r.clusterID, r.clientSet, engine, cache)
	if err != nil {
		r.clog.WithError(err).Error("failed to create recommendation controller")
		return nil, nil, err
	}
	return ctrl, engine, nil
}

// newRecommendationResourceCache creates a new recommendation resource cache.
func (r *reconcilerBase) newRecommendationResourceCache() rcache.ResourceCache {
	// Define the list of items handled by the policy recommendation cache.
	listFunc := func() (map[string]interface{}, error) {
		r.clog.Debug("Listing recommendations")

		snps, err := r.clientSet.ProjectcalicoV3().StagedNetworkPolicies(v1.NamespaceAll).List(r.ctx, metav1.ListOptions{
			LabelSelector: fmt.Sprintf("%s=%s", v3.LabelTier, rectypes.PolicyRecommendationTierName),
		})
		if err != nil {
			r.clog.WithError(err).Error("unexpected error querying staged network policies")
			return nil, err
		}

		snpMap := make(map[string]interface{})
		for _, snp := range snps.Items {
			r.clog.WithField("name", snp.Name).Debug("Cache recommendation")
			snpMap[snp.Namespace] = snp
		}

		return snpMap, nil
	}

	// Create a cache to store recommendations in.
	cacheArgs := rcache.ResourceCacheArgs{
		ListFunc:    listFunc,
		ObjectType:  reflect.TypeOf(v3.StagedNetworkPolicy{}),
		LogTypeDesc: kindRecommendations,
		ReconcilerConfig: rcache.ReconcilerConfig{
			DisableUpdateOnChange: true,
			DisableMissingInCache: true,
		},
	}

	return rcache.NewResourceCache(cacheArgs)
}

// stop stops the reconciler.
func (r *reconcilerBase) stop() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.ctrl != nil {
		close(r.stopChan)
	}
}

type realClock struct{}

func (c realClock) NowRFC3339() string {
	return time.Now().Format(time.RFC3339)
}
