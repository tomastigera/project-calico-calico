// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.
package recommendation_controller

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/google/go-cmp/cmp"
	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	k8swatch "k8s.io/apimachinery/pkg/watch"
	k8scache "k8s.io/client-go/tools/cache"

	rcache "github.com/projectcalico/calico/kube-controllers/pkg/cache"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	calres "github.com/projectcalico/calico/policy-recommendation/pkg/calico-resources"
	"github.com/projectcalico/calico/policy-recommendation/pkg/controllers/controller"
	"github.com/projectcalico/calico/policy-recommendation/pkg/controllers/watcher"
	recengine "github.com/projectcalico/calico/policy-recommendation/pkg/engine"
	rectypes "github.com/projectcalico/calico/policy-recommendation/pkg/types"
	"github.com/projectcalico/calico/policy-recommendation/utils"
)

const (
	// namespaceIsolationTierLabel is the label used to identify the namespace-isolation tier.
	namespaceIsolationTierLabel = v3.LabelTier + "=" + rectypes.PolicyRecommendationTierName

	// The number of workers threads used to read the queue for the recommendation cache.
	numberOfWorkers = 5

	// retries is the number of times to retry a datastore operation.
	retries = 5

	// The duration between synching of the datastore.
	synchingInterval = time.Second * 10

	// The tier order for the recommendation tier.
	tierOrder = 10000
)

type recommendationController struct {
	// ctx is the context.
	ctx context.Context

	// clusterID is the ID of the cluster that the controller is running on.
	clusterID string

	// clientSet is the client-set that is used to interact with the Calico API.
	clientSet lmak8s.ClientSet

	// cache is the cache that is used to store the recommendations.
	cache rcache.ResourceCache

	// engine is the recommendation engine.
	engine recengine.RecommendationEngine

	// The number of workers threads used to read the queue for the recommendation cache.
	numberOfWorkers int

	// watchers is the list of watchers that are used to watch for updates to the resources.
	watchers []watcher.Watcher

	// clog is the logger used by the controller.
	clog *log.Entry

	// mutex is used to synchronize to the datastore and cache.
	mutex sync.Mutex
}

func NewRecommendationController(
	ctx context.Context, clusterID string, clientSet lmak8s.ClientSet, engine recengine.RecommendationEngine, cache rcache.ResourceCache,
) (controller.Controller, error) {
	clog := log.WithField("clusterID", utils.GetLogClusterID(clusterID))

	return &recommendationController{
		ctx:       ctx,
		clusterID: clusterID,
		clientSet: clientSet,
		cache:     cache,
		engine:    engine,
		watchers: []watcher.Watcher{
			watcher.NewWatcher(
				newNamespaceReconciler(ctx, clientSet, cache, engine, clog),
				&k8scache.ListWatch{
					ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
						return clientSet.CoreV1().Namespaces().List(context.Background(), options)
					},
					WatchFunc: func(options metav1.ListOptions) (k8swatch.Interface, error) {
						return clientSet.CoreV1().Namespaces().Watch(context.Background(), options)
					},
				},
				&v1.Namespace{},
			),
			watcher.NewWatcher(
				newNetworkPolicyReconciler(ctx, clientSet, cache, clog),
				&k8scache.ListWatch{
					ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
						// We only care about policies within the namespace-isolation tier.
						options.LabelSelector = namespaceIsolationTierLabel
						return clientSet.ProjectcalicoV3().NetworkPolicies(v3.AllNamespaces).List(context.Background(), options)
					},
					WatchFunc: func(options metav1.ListOptions) (k8swatch.Interface, error) {
						// We only care about policies within the namespace-isolation tier.
						options.LabelSelector = namespaceIsolationTierLabel
						return clientSet.ProjectcalicoV3().NetworkPolicies(v3.AllNamespaces).Watch(context.Background(), options)
					},
				},
				&v3.NetworkPolicy{},
			),
			watcher.NewWatcher(
				newStagedNetworkPolicyReconciler(ctx, clientSet, cache, clog),
				&k8scache.ListWatch{
					ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
						// We only care about policies within the namespace-isolation tier.
						options.LabelSelector = namespaceIsolationTierLabel
						return clientSet.ProjectcalicoV3().StagedNetworkPolicies(v3.AllNamespaces).List(context.Background(), options)
					},
					WatchFunc: func(options metav1.ListOptions) (k8swatch.Interface, error) {
						// We only care about policies within the namespace-isolation tier.
						options.LabelSelector = namespaceIsolationTierLabel
						return clientSet.ProjectcalicoV3().StagedNetworkPolicies(v3.AllNamespaces).Watch(context.Background(), options)
					},
				},
				&v3.StagedNetworkPolicy{},
			),
		},
		numberOfWorkers: numberOfWorkers,
		clog:            clog,
	}, nil
}

// Run starts warms up and runs the cache, starts the engine, and watchers. This blocks until we've
// been asked to stop.
func (c *recommendationController) Run(stopChan chan struct{}) {
	defer uruntime.HandleCrash()

	// Warms up the cache with the existing recommendations in the datastore. Adds the namespaces to
	// the engine for processing.
	c.warmupCacheAndEngine()

	// Start the engine.
	go c.engine.Run(stopChan)
	c.clog.Info("Running engine")

	// Watchers will trigger events that will ultimately add new namespaces for processing or update
	// the recommendation cache.
	for _, w := range c.watchers {
		go w.Run(stopChan)
	}

	// Start the Kubernetes reconciler cache to fix up any differences between the required and
	// configured data.
	c.cache.Run(synchingInterval.String())

	// Start a number of worker threads to read from the queue.
	for i := 0; i < c.numberOfWorkers; i++ {
		go wait.Until(c.runWorker, time.Second, c.ctx.Done())
	}

	c.clog.Info("Started Recommendation controller")

	<-stopChan

	c.cache.Stop()
	c.clog.Info("Stopped Recommendation cache and controller")
}

// GetEngine returns the recommendation engine.
func (c *recommendationController) GetEngine() recengine.RecommendationEngine {
	return c.engine
}

// runWorker processes the list of the cache queued items.
func (c *recommendationController) runWorker() {
	for c.processNextItem() {
	}
}

// processNextItem waits for an event on the output queue from the recommendation resource
// cache and syncs any received keys to the kubernetes datastore.
func (c *recommendationController) processNextItem() bool {
	// Wait until there is a new item in the work queue.
	workqueue := c.cache.GetQueue()
	key, quit := workqueue.Get()
	if quit {
		return false
	}

	// Sync the object to the Calico datastore.
	if err := c.syncToDatastore(key.(string)); err != nil {
		c.handleErr(err, key.(string))
	}

	// Indicate that we're done processing this key, allowing for safe parallel processing such that
	// two objects with the same key are never processed in parallel.
	workqueue.Done(key)
	return true
}

// syncToDatastore syncs the recommendation (SNP) with the datastore.
func (c *recommendationController) syncToDatastore(key string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.cache.GetQueue().ShuttingDown() {
		c.clog.WithField("namespace", key).Debug("Cache queue is shutting down, do not sync recommendation to datastore.")
		return nil
	}

	c.clog.WithField("key", key).Debug("SyncToDatastore")

	// Get the cached recommendation for the key.
	item, ok := c.cache.Get(key)
	if !ok {
		// The item is no longer in the cache, delete it from the store.
		return c.deleteStoreItem(key)
	}
	cacheItem := item.(v3.StagedNetworkPolicy)

	// Get the store recommendation for the key.
	storeItem, err := c.getStoreItem(key)
	if err != nil {
		return err
	}

	// Create a new recommendation (StagedNetworkPolicy) if the store item doesn't yet exist.
	if storeItem == nil {
		// Create a new recommendation tier, if that doesn't yet exist.
		if err := calres.MaybeCreateTier(c.ctx, c.clientSet.ProjectcalicoV3(), rectypes.PolicyRecommendationTierName, tierOrder, c.clog); err != nil {
			c.clog.WithError(err).WithField("name", rectypes.PolicyRecommendationTierName).Error("failed creating Tier")
			return err
		}
		if err := c.createStoreItem(key, &cacheItem); err != nil {
			return err
		}
		c.clog.WithField("name", cacheItem.Name).Info("Created recommendation")

		return nil
	}

	// Update the store value, if the cache differs from the store.
	if !reflect.DeepEqual(cacheItem, *storeItem) {
		c.clog.Debugf("Cache and store differ: %s", cmp.Diff(cacheItem, *storeItem))

		// If the names differ, replace the store item.
		// When the status becomes stable, the cache item is replaced with a new SNP. Subsequently,
		// the cache diff will trigger a recommendation replacement in the datastore.
		if cacheItem.Name != storeItem.Name {
			err := c.clientSet.ProjectcalicoV3().StagedNetworkPolicies(key).Delete(c.ctx, storeItem.Name, metav1.DeleteOptions{})
			if err != nil {
				c.clog.WithError(err).WithField("name", cacheItem.Name).Error("failed to delete recommendation")
				return err
			}
			if err := c.createStoreItem(key, &cacheItem); err != nil {
				return err
			}
			c.clog.Infof("Replaced recommendation %s with %s", storeItem.Name, cacheItem.Name)

			return nil
		}

		// A value within the cache item has changed, triggering an update to the datastore.
		updatedItem, err := c.clientSet.ProjectcalicoV3().StagedNetworkPolicies(key).Update(c.ctx, &cacheItem, metav1.UpdateOptions{})
		if err != nil || updatedItem == nil {
			c.clog.WithError(err).WithField("name", cacheItem.Name).Error("failed to update recommendation")
			return err
		}
		c.setCacheItem(key, updatedItem)
	}

	return nil
}

// handleErr handles errors which occur while processing a key received from the resource cache.
// For a given error, we will re-queue the key in order to retry the datastore sync up to 5 times,
// at which point the update is dropped.
func (c *recommendationController) handleErr(err error, key string) {
	workqueue := c.cache.GetQueue()
	if err == nil {
		// Forget about the #AddRateLimited history of the key on every successful synchronization.
		// This ensures that future processing of updates for this key is not delayed because of
		// an outdated error history.
		workqueue.Forget(key)
		return
	}

	// This controller retries 5 times if something goes wrong. After that, it stops trying.
	if workqueue.NumRequeues(key) < retries {
		// Re-enqueue the key rate limited. Based on the rate limiter on the queue and the re-enqueue
		// history, the key will be processed later again.
		c.clog.WithError(err).Infof("failed to sync Profile %v: %v", key, err)
		workqueue.AddRateLimited(key)
		return
	}
	workqueue.Forget(key)

	// Report to an external entity that, even after several retries, we could not successfully
	// process this key
	uruntime.HandleError(err)
	c.clog.WithError(err).Errorf("dropping profile %q out of the queue: %v", key, err)
}

// createStoreItem creates a recommendation in the datastore and and brings parity to the cache
// item.
func (c *recommendationController) createStoreItem(namespace string, snp *v3.StagedNetworkPolicy) error {
	// The resource version should be automatically generated.
	snp.ResourceVersion = ""

	createdItem, err := c.clientSet.ProjectcalicoV3().StagedNetworkPolicies(namespace).Create(c.ctx, snp, metav1.CreateOptions{})
	if err != nil || createdItem == nil {
		c.clog.WithError(err).WithField("name", snp.Name).Error("failed creating recommendation")
		return err
	}
	c.setCacheItem(namespace, createdItem)

	return nil
}

// deleteStoreItem deletes a recommendation from the datastore.
func (c *recommendationController) deleteStoreItem(namespace string) error {
	storeItem, err := c.getStoreItem(namespace)
	if err != nil {
		c.clog.WithError(err).WithField("name", namespace).Info("failed to get recommendation")
		return nil
	}
	if storeItem != nil {
		// The item is no longer in the cache, delete it from the store.
		err := c.clientSet.ProjectcalicoV3().StagedNetworkPolicies(namespace).Delete(c.ctx, storeItem.Name, metav1.DeleteOptions{})
		if err != nil {
			c.clog.WithError(err).WithField("name", namespace).Info("failed to delete recommendation")
			return err
		}
		c.clog.WithField("name", storeItem.Name).Info("Deleted recommendation from store")
	}

	return nil
}

// getStoreItem gets the recommendation from the datastore. We cannot use the necessary label to get
// the item from the datastore. Therefore, we get the first item from the list of recommendations in
// the namespace, as there should only be one recommendation per namespace.
func (c *recommendationController) getStoreItem(namespace string) (*v3.StagedNetworkPolicy, error) {
	list, err := c.clientSet.ProjectcalicoV3().StagedNetworkPolicies(namespace).List(c.ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", v3.LabelTier, rectypes.PolicyRecommendationTierName),
	})
	if err != nil {
		c.clog.WithError(err).WithField("namespace", namespace).Errorf("failed getting recommendation")
		return nil, err
	} else if len(list.Items) == 0 {
		c.clog.WithField("namespace", namespace).Debug("No recommendation found")
		return nil, nil
	}
	return &list.Items[0], nil
}

// setCacheItem sets the cache item and adds missing context to the StagedNetworkPolicy.
func (c *recommendationController) setCacheItem(namespace string, snp *v3.StagedNetworkPolicy) {
	// The TypeMeta is not copied over to the StagedNetworkPolicy in the call to Create()
	snp.APIVersion = v3.GroupVersionCurrent
	snp.Kind = v3.KindStagedNetworkPolicy
	// Reconcile the cache value with the value added to the store
	c.cache.Set(namespace, *snp)
	c.clog.WithField("name", snp.Name).Debug("Set cache item")
}

// warmupCacheAndEngine warms up the cache with the existing recommendations in the datastore. Adds
// the namespaces to the engine for processing.
func (c *recommendationController) warmupCacheAndEngine() {
	snps, err := c.clientSet.ProjectcalicoV3().StagedNetworkPolicies(v1.NamespaceAll).List(c.ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", v3.LabelTier, rectypes.PolicyRecommendationTierName),
	})
	if err != nil {
		c.clog.WithError(err).Error("unexpected error querying staged network policies")
	}
	// Add the staged network policies to the cache.
	for _, snp := range snps.Items {
		c.clog.WithField("key", snp.Namespace).WithField("name", snp.Name).Info("Load recommendation into cache and setup the namespace for processing")
		c.cache.Set(snp.Namespace, snp)
	}

	// Add the namespaces tracking.
	namespaces, err := c.clientSet.CoreV1().Namespaces().List(c.ctx, metav1.ListOptions{})
	if err != nil {
		c.clog.WithError(err).Error("unexpected error querying namespaces")
	}
	for _, ns := range namespaces.Items {
		c.engine.AddNamespace(ns.Name)
		c.clog.WithField("namespace", ns.Name).Debug("Added namespace for tracking")
	}
}
