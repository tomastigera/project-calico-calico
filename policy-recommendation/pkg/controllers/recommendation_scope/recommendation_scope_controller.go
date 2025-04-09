// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

package recommendation_scope_controller

import (
	"context"
	"errors"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	k8swatch "k8s.io/apimachinery/pkg/watch"
	k8scache "k8s.io/client-go/tools/cache"

	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	"github.com/projectcalico/calico/policy-recommendation/pkg/controllers/controller"
	"github.com/projectcalico/calico/policy-recommendation/pkg/controllers/watcher"
	"github.com/projectcalico/calico/policy-recommendation/pkg/types"
	"github.com/projectcalico/calico/policy-recommendation/utils"
)

type WatcherConfig struct {
	WatchScope bool
	WatchTier  bool
}

type recommendationScopeController struct {
	// The context for the controller.
	ctx context.Context

	// The cluster ID.
	clusterID string

	// The clientSet used to access the Calico or Kubernetes API.
	clientSet lmak8s.ClientSet

	// The linseed client.
	linseed lsclient.Client

	// The enabled flag is used keep track of the engine status.
	enabled v3.PolicyRecommendationNamespaceStatus

	// The reconciler is used to reconcile the recommendation scope resource or the alternative tier resource.
	scopeReconciler *recommendationScopeReconciler

	// The recommendationScopeWatcher is used to watch for updates to the PolicyRecommendationScope resource.
	recommendationScopeWatcher watcher.Watcher

	// The tierReconciler is used to reconcile the Tier resource.
	tierReconciler *tierReconciler

	// The tierWatcher is used to watch for updates to the Tier resource, which is an alternative to the
	// PolicyRecommendationScope resource.
	tierWatcher watcher.Watcher

	stopScopeWatcherChan chan struct{}
	stopTierWatcherChan  chan struct{}

	// clog is the logger for the controller. This has been added for convenience of testing.
	clog *log.Entry
}

// NewRecommendationScopeController returns a controller which manages updates for the
// PolicyRecommendationScope resource. The resource is responsible for enabling/disabling the
// recommendation engine, and for defining the scope of the engine.
func NewRecommendationScopeController(
	ctx context.Context,
	clusterID string,
	clientSet lmak8s.ClientSet,
	linseed lsclient.Client,
	minPollInterval metav1.Duration,
	watcherCfg WatcherConfig,
) (controller.Controller, error) {
	logEntry := log.WithField("clusterID", utils.GetLogClusterID(clusterID))

	ctrl := &recommendationScopeController{
		clog:      logEntry,
		ctx:       ctx,
		clientSet: clientSet,
		clusterID: clusterID,
		linseed:   linseed,
		enabled:   v3.PolicyRecommendationScopeDisabled,
	}

	if !watcherCfg.WatchScope && !watcherCfg.WatchTier {
		return nil, errors.New("no watcher enabled")
	}
	if watcherCfg.WatchScope {
		reconciler := newRecommendationScopeReconciler(ctx, clusterID, clientSet, linseed, minPollInterval, logEntry)
		if reconciler == nil {
			return nil, errors.New("failed to create recommendation scope reconciler")
		}
		ctrl.recommendationScopeWatcher = watcher.NewWatcher(
			reconciler,
			// The FieldSelector does not work, reported as a known issue (https://tigera.atlassian.net/browse/EV-4647).
			// The reconciler ignores all recommendation scope resources except the default one.
			&k8scache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					options.FieldSelector = fields.OneTermEqualSelector("metadata.name", types.PolicyRecommendationScopeName).String() // defaultNameFieldLabel
					return clientSet.ProjectcalicoV3().PolicyRecommendationScopes().List(context.Background(), options)
				},
				WatchFunc: func(options metav1.ListOptions) (k8swatch.Interface, error) {
					options.FieldSelector = fields.OneTermEqualSelector("metadata.name", types.PolicyRecommendationScopeName).String() // defaultNameFieldLabel
					return clientSet.ProjectcalicoV3().PolicyRecommendationScopes().Watch(context.Background(), options)
				},
			},
			&v3.PolicyRecommendationScope{},
		)
		ctrl.stopScopeWatcherChan = make(chan struct{})
		ctrl.scopeReconciler = reconciler
	}

	if watcherCfg.WatchTier {
		reconciler := newTierReconciler(ctx, clusterID, clientSet, linseed, minPollInterval, logEntry)
		if reconciler == nil {
			return nil, errors.New("failed to create tier reconciler")
		}
		ctrl.tierWatcher = watcher.NewWatcher(
			reconciler,
			&k8scache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					// We only care about tier named "namespace-isolation" within the calico-system namespace.
					options.FieldSelector = fields.OneTermEqualSelector("metadata.name", types.PolicyRecommendationTierName).String()
					return clientSet.ProjectcalicoV3().Tiers().List(context.Background(), options)
				},
				WatchFunc: func(options metav1.ListOptions) (k8swatch.Interface, error) {
					// We only care about tier named "namespace-isolation" within the calico-system namespace.
					options.FieldSelector = fields.OneTermEqualSelector("metadata.name", types.PolicyRecommendationTierName).String()
					return clientSet.ProjectcalicoV3().Tiers().Watch(context.Background(), options)
				},
			},
			&v3.Tier{},
		)
		ctrl.stopTierWatcherChan = make(chan struct{})
		ctrl.tierReconciler = reconciler
	}

	return ctrl, nil
}

// Run starts the PolicyRecommendationScope controller. This blocks until we've been asked to stop.
func (c *recommendationScopeController) Run(stopChan chan struct{}) {
	defer uruntime.HandleCrash()

	if c.recommendationScopeWatcher != nil {
		go c.recommendationScopeWatcher.Run(c.stopScopeWatcherChan)
	}
	if c.tierWatcher != nil {
		go c.tierWatcher.Run(c.stopTierWatcherChan)
	}

	c.clog.Info("Started RecommendationScope controller")

	// Listen for the stop signal. Blocks until we receive a stop signal.
	<-stopChan

	if c.recommendationScopeWatcher != nil {
		close(c.stopScopeWatcherChan)
	}
	if c.tierWatcher != nil {
		close(c.stopTierWatcherChan)
	}

	if c.scopeReconciler != nil {
		c.scopeReconciler.stop()
	}
	if c.tierReconciler != nil {
		c.tierReconciler.stop()
	}

	c.clog.Info("Stopped RecommendationScope controller")
}
