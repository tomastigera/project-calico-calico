// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

package worker

// package worker contains code to watch k8s resources and react based on changes to those resources.
// All that's needed to create a new controllers is declaring what
// resources you want to watch for and what to do when they're updated.

import (
	"fmt"
	"reflect"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/health"
)

const (
	DefaultMaxRequeueAttempts = 5
)

// Reconciler is the interface that is used to react to changes to the resources that the worker is watching. When a change
// to a resource is detected, the Reconcile function of the passed in reconciler is used
type Reconciler interface {
	Reconcile(name types.NamespacedName) error
	Close()
}

// Worker is the interface used to watch k8s resources and react to changes to those resources
type Worker interface {
	AddWatch(listWatcher cache.ListerWatcher, obj runtime.Object) health.Pinger
	Run(stop <-chan struct{})
	Close()
}

type worker struct {
	workqueue.TypedRateLimitingInterface[any]

	reconciler         Reconciler
	watches            []watch
	maxRequeueAttempts int
}

// watch contains the information needed to create a resource watch
type watch struct {
	listWatcher cache.ListerWatcher
	obj         runtime.Object
	ponger      health.PingPonger
}

// New creates a new Worker implementation
func New(reconciler Reconciler) Worker {
	return &worker{
		TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[any]()),
		reconciler:                 reconciler,
		maxRequeueAttempts:         DefaultMaxRequeueAttempts,
	}
}

// AddWatch registers a resource to watch and run the reconciler on changes to that resource,
// creates and returns a health.PingPonger object that is used by health check endpoint to verify
// if controller queue can process incoming items.
func (w *worker) AddWatch(listWatcher cache.ListerWatcher, obj runtime.Object) health.Pinger {
	ponger := health.NewPingPonger()
	w.watches = append(w.watches, watch{
		listWatcher: listWatcher,
		obj:         obj,
		ponger:      ponger,
	})
	return ponger
}

// Close in turn calls close on the reconciler to close all goroutines and make a call to close the Ping channel.
func (w *worker) Close() {
	log.Infof("closing worker %+v", w)
	for _, watch := range w.watches {
		watch.ponger.Close()
	}
	w.reconciler.Close()
}

func (w *worker) resourceEventHandlerFuncs() cache.ResourceEventHandlerFuncs {
	r := cache.ResourceEventHandlerFuncs{}

	r.AddFunc = func(obj any) {
		key, err := cache.MetaNamespaceKeyFunc(obj)
		if err == nil {
			w.Add(key)
		}
		log.Debugf("Create event received for resource %s", key)
	}

	r.UpdateFunc = func(oldObj any, newObj any) {
		key, err := cache.MetaNamespaceKeyFunc(newObj)
		if err == nil {
			w.Add(key)
		}
		log.Debugf("Update event received for resource %s", key)
	}

	r.DeleteFunc = func(obj any) {
		key, err := cache.MetaNamespaceKeyFunc(obj)
		if err == nil {
			w.Add(key)
		}
		log.Debugf("Delete event received for resource %s", key)
	}

	return r
}

// Run creates the resource watches then starts the worker. The worker will be started in a go routine.
// Start a routine that will listen for health pings after controller has finished sync and is
// ready to process ponger added to the queue.
func (w *worker) Run(stop <-chan struct{}) {
	defer uruntime.HandleCrash()
	defer w.ShutDown()

	for _, watch := range w.watches {
		_, ctrl := cache.NewInformerWithOptions(cache.InformerOptions{
			ListerWatcher: watch.listWatcher,
			ObjectType:    watch.obj,
			ResyncPeriod:  0,
			Handler:       w.resourceEventHandlerFuncs(),
			Indexers:      cache.Indexers{},
		})

		go ctrl.Run(stop)

		if !cache.WaitForNamedCacheSync(reflect.TypeOf(watch.obj).String(), stop, ctrl.HasSynced) {
			log.Errorf("Failed to sync resource %T", watch.obj)
			return
		}

		go w.listenForPings(watch.ponger, stop)
	}

	go wait.Until(w.startWorker, time.Second, stop)

	<-stop
}

// startWorker starts processing items off the queue
func (w *worker) startWorker() {
	for w.processNextItem() {
	}
}

// processNextItem gets the next item off the queue and runs the Reconciler with that item
// If the item in the queue is a health check Ponger, sends a value via pongChan.
func (w *worker) processNextItem() bool {
	key, shutdown := w.Get()
	if shutdown {
		return false
	}
	defer w.Done(key)

	if p, ok := key.(health.Ponger); ok {
		p.Pong()
		return true
	}

	log.Debugf("Received %v", key)
	reqLogger := log.WithField("key", key)
	reqLogger.Debug("Processing next item")

	var namespacedName types.NamespacedName
	var err error

	namespacedName.Namespace, namespacedName.Name, err = cache.SplitMetaNamespaceKey(fmt.Sprintf("%s", key))
	if err != nil {
		return false
	}
	if err := w.reconciler.Reconcile(namespacedName); err != nil {
		reqLogger.WithError(err).Error("An error occurred while processing the next item")
		if w.NumRequeues(key) < w.maxRequeueAttempts {
			reqLogger.Debug("Rate limiting requeue of key")
			w.AddRateLimited(key)
			return true
		}

		reqLogger.Debug("Max number or retries for key reached, forgetting key")
		w.Forget(key)
		uruntime.HandleError(err)
	}

	reqLogger.Debug("Finished processing next item")

	return true
}

// listenForPings starts listening to the Pings. It adds the received Ponger to worker queue for processing.
func (w *worker) listenForPings(ponger health.PingPonger, stop <-chan struct{}) {
	for {
		select {
		case pong := <-ponger.ListenForPings():
			w.Add(pong)
		case <-stop:
			return
		}
	}
}
