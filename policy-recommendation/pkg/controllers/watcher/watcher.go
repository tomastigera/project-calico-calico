// Copyright (c) 2024-2025 Tigera Inc. All rights reserved.

package watcher

import (
	"reflect"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	ctrl "github.com/projectcalico/calico/policy-recommendation/pkg/controllers/controller"
)

const (
	// maxRequeueAttempts is the maximum number of times a resource will be requeued before it is
	maxRequeueAttempts = 5

	// resyncPeriod is the period at which the resource will be resynced.
	resyncPeriod = 0
)

type Watcher interface {
	// Run starts the watcher and blocks until the passed in stop channel is closed.
	Run(stopChan chan struct{})
}

type watcher struct {
	// workqueue.TypedRateLimitingInterface is an interface that defines a rate limited work queue.
	workqueue.TypedRateLimitingInterface[any]

	// reconciler is the interface that is used to react to changes to watched resources.
	reconciler ctrl.Reconciler

	// resource is the resource that the watcher is watching.
	resource watchedObj

	// maxRequeueAttempts is the maximum number of times a resource will be requeued before it is
	// dropped from the queue.
	maxRequeueAttempts int
}

type watchedObj struct {
	// listWatcher is the interface that is used to watch a resource.
	listWatcher cache.ListerWatcher

	// obj is the resource that the watcher is watching.
	obj runtime.Object
}

func NewWatcher(reconciler ctrl.Reconciler, listWatcher cache.ListerWatcher, obj runtime.Object) Watcher {
	return &watcher{
		TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[any]()),
		reconciler:                 reconciler,
		resource: watchedObj{
			listWatcher: listWatcher,
			obj:         obj,
		},
		maxRequeueAttempts: maxRequeueAttempts,
	}
}

func (w *watcher) Run(stopChan chan struct{}) {
	defer uruntime.HandleCrash()
	defer w.ShutDown()

	_, informer := cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: w.resource.listWatcher,
		ObjectType:    w.resource.obj,
		ResyncPeriod:  resyncPeriod,
		Handler:       w.resourceEventHandlerFuncs(),
		Indexers:      cache.Indexers{},
	})

	go informer.Run(stopChan)

	if !cache.WaitForNamedCacheSync(reflect.TypeOf(w.resource.obj).String(), stopChan, informer.HasSynced) {
		log.Infof("Failed to sync resource %T which may have received signal for controller to shut down.", w.resource.obj)

		return
	}

	go wait.Until(w.startWatch, time.Second, stopChan)

	<-stopChan

	log.Infof("Stopped watching resource %T", w.resource.obj)
}

func (w *watcher) resourceEventHandlerFuncs() cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err == nil {
				w.Add(key)
			}
			log.Debugf("Create event received for resource %s", key)
		},
		UpdateFunc: func(_ any, new any) {
			key, err := cache.MetaNamespaceKeyFunc(new)
			if err == nil {
				w.Add(key)
			}
			log.Debugf("Update event received for resource %s", key)
		},
		DeleteFunc: func(obj any) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err == nil {
				w.Add(key)
			}
			log.Debugf("Delete event received for resource %s", key)
		},
	}
}

func (w *watcher) startWatch() {
	for w.processNextItem() {
	}
}

func (w *watcher) processNextItem() bool {
	key, shutdown := w.Get()
	if shutdown {
		return false
	}
	defer w.Done(key)

	log.Debugf("Received '%v', and type: %s", key, reflect.TypeOf(w.resource.obj).String())
	reqLogger := log.WithField("key", key)
	reqLogger.Debug("Processing next key")

	keyStr, ok := key.(string)
	if !ok {
		log.Errorf("incorrect key type %+v", key)
		return false
	}

	namespace, name, err := cache.SplitMetaNamespaceKey(keyStr)
	if err != nil {
		log.WithError(err).Errorf("unable to process key: %s", keyStr)
		return false
	}

	if err = w.reconciler.Reconcile(types.NamespacedName{
		Namespace: namespace,
		Name:      name,
	}); err != nil {
		log.WithError(err).Errorf("failed to reconcile %s", keyStr)

		if w.NumRequeues(key) > w.maxRequeueAttempts {
			reqLogger.Debug("Max number or retries for key reached, forgetting key")
			w.Forget(key)
			uruntime.HandleError(err)
		} else {
			w.AddRateLimited(key)
		}
	}

	return true
}
