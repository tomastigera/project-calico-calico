// Copyright (c) 2025 Tigera, Inc. All rights reserved.
package managed_cluster_controller

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	"github.com/projectcalico/calico/policy-recommendation/pkg/controllers/controller"
	rscope "github.com/projectcalico/calico/policy-recommendation/pkg/controllers/recommendation_scope"
	"github.com/projectcalico/calico/policy-recommendation/pkg/controllers/watcher"
)

type managedClusterController struct {
	// ctx is the context for the controller.
	ctx context.Context

	// managedClusters is a map of PolicyRecommendationScope controllers for each managed cluster.
	managedClusters map[string]*managedClusterCtrlContext

	// watcher is the watcher that is used to watch for updates to the managed cluster resource.
	watcher watcher.Watcher

	// recScopeWatcherCfg is the watcher configuration for the recommendation scope controller.
	recScopeWatcherCfg rscope.WatcherConfig

	// mutex protects the controller.
	mutex sync.Mutex
}

type managedClusterCtrlContext struct {
	// ctrl is the PolicyRecommendationScope controller
	ctrl controller.Controller

	// stopChan is the channel used to stop the PolicyRecommendationScope controller.
	stopChan chan struct{}
}

// NewManagedClusterController returns a controller which manages managed clusters.
func NewManagedClusterController(
	ctx context.Context,
	client ctrlclient.WithWatch,
	clientFactory lmak8s.ClientSetFactory,
	linseed lsclient.Client,
	tenantNamespace string,
	minPollInterval metav1.Duration,
	recScopeWatcherCfg rscope.WatcherConfig,
) (controller.Controller, error) {
	// The mapping of managed cluster names to PolicyRecommendationScope controllers.
	managedClusters := make(map[string]*managedClusterCtrlContext)

	return &managedClusterController{
		ctx:                ctx,
		managedClusters:    managedClusters,
		recScopeWatcherCfg: recScopeWatcherCfg,
		watcher: watcher.NewWatcher(
			newManagedClusterReconciler(
				ctx, client, clientFactory, linseed, managedClusters,
				rscope.NewRecommendationScopeController, tenantNamespace, minPollInterval, recScopeWatcherCfg),
			newManagedClusterListWatcher(ctx, client, tenantNamespace),
			&v3.ManagedCluster{},
		),
	}, nil
}

// Run starts the ManagedCluster controller.
func (c *managedClusterController) Run(stopChan chan struct{}) {
	defer uruntime.HandleCrash()

	// Run the ManagedCluster watcher. New managed clusters will trigger a new
	// PolicyRecommendationScope controller per cluster.
	go c.watcher.Run(stopChan)

	log.Info("Started ManagedCluster controller")

	// Listen for the stop signal. Blocks until we receive a stop signal.
	<-stopChan

	// Stop the ManagedCluster recommendation scope controllers.
	c.stopControllers()

	log.Info("Stopped ManagedCluster controller")
}

// stopControllers stops the recommendation scope controllers for every managed cluster.
func (c *managedClusterController) stopControllers() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	log.Debug("Stopping all managed cluster PolicyRecommendationScope controllers.")
	for key, mc := range c.managedClusters {
		close(mc.stopChan)
		delete(c.managedClusters, key)
	}
}

// newManagedClusterListWatcher returns an implementation of the ListWatch interface capable of being used to
// build an informer based on a controller-runtime client. Using the controller-runtime client allows us to build
// an Informer that works for both namespaced and cluster-scoped ManagedCluster resources regardless of whether
// it is a multi-tenant cluster or not.
func newManagedClusterListWatcher(ctx context.Context, c ctrlclient.WithWatch, namespace string) *cache.ListWatch {
	return &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			list := &v3.ManagedClusterList{}
			err := c.List(ctx, list, &ctrlclient.ListOptions{Raw: &options, Namespace: namespace})
			return list, err
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			list := &v3.ManagedClusterList{}
			return c.Watch(ctx, list, &ctrlclient.ListOptions{Raw: &options, Namespace: namespace})
		},
	}
}
