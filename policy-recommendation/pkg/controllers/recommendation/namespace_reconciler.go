// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package recommendation_controller

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	rcache "github.com/projectcalico/calico/kube-controllers/pkg/cache"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	"github.com/projectcalico/calico/policy-recommendation/pkg/controllers/controller"
	recengine "github.com/projectcalico/calico/policy-recommendation/pkg/engine"
)

type namespaceReconciler struct {
	// ctx is the context.
	ctx context.Context

	// cache is the cache that is used to store the recommendations.
	cache rcache.ResourceCache

	// clientSet is the client set that is used to interact with the Calico or Kubernetes API.
	clientSet lmak8s.ClientSet

	// engine is the recommendation engine.
	engine recengine.RecommendationEngine

	// clog is the logger for the controller.
	clog *log.Entry

	// mutex is used to synchronize access to the cache.
	mutex sync.Mutex
}

func newNamespaceReconciler(
	ctx context.Context, clientSet lmak8s.ClientSet, cache rcache.ResourceCache, engine recengine.RecommendationEngine, clog *log.Entry,
) controller.Reconciler {
	return &namespaceReconciler{
		ctx:       ctx,
		cache:     cache,
		clientSet: clientSet,
		engine:    engine,
		clog:      clog,
	}
}

// Reconcile will be triggered by any changes performed on the designated namespace.
func (r *namespaceReconciler) Reconcile(key types.NamespacedName) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	namespace := key.Name
	r.clog.WithField("namespace", namespace).Debug("Reconciling namespace.")

	// isDelete returns true if the namespace was deleted from the datastore.
	isDelete := func(ns string) bool {
		_, err := r.clientSet.CoreV1().Namespaces().Get(r.ctx, ns, metav1.GetOptions{})
		if err != nil && kerrors.IsNotFound(err) {
			r.clog.WithField("namespace", ns).Debug("Namespace not found or was deleted.")
			return true
		}
		r.clog.WithField("namespace", ns).Debug("Namespace found.")
		return false
	}

	if !isDelete(namespace) {
		// Add the namespace to the engine for processing. The engine holds a set of namespaces.
		r.engine.AddNamespace(namespace)
	} else {
		// Remove the namespace from the engine processing items, and the cache.
		r.engine.RemoveNamespace(namespace)
	}

	return nil
}
