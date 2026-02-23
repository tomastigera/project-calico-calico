// Copyright 2019-2021 Tigera Inc. All rights reserved.

package globalnetworksets

import (
	"context"
	"reflect"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v3client "github.com/tigera/api/pkg/client/clientset_generated/clientset/typed/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/cacher"
	feedutils "github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/utils"
)

const DefaultClientRetries = 5
const DefaultResyncPeriod = time.Hour
const LabelKey = "tigera.io/creator"
const LabelValue = "intrusion-detection-controller"

type Controller interface {
	// Add, Delete, and GC alter the desired state the controller will attempt to
	// maintain, by syncing with the Kubernetes API server.

	// Add or update a new GlobalNetworkSet including the spec
	Add(*v3.GlobalNetworkSet, func(error), cacher.GlobalThreatFeedCacher)

	// Delete removes a GlobalNetworkSet from the desired state.
	Delete(*v3.GlobalNetworkSet)

	// NoGC marks a GlobalNetworkSet as not eligible for garbage collection
	// until deleted. This is useful when we don't know the contents of a
	// GlobalNetworkSet, but know it should not be deleted.
	NoGC(*v3.GlobalNetworkSet)

	// Run starts synching GlobalNetworkSets.  All required sets should be added
	// or marked NoGC() before calling run, as any extra will be deleted by the
	// controller.
	Run(context.Context)
}

type controller struct {
	once     sync.Once
	client   v3client.GlobalNetworkSetInterface
	local    cache.Store
	remote   cache.Store
	informer cache.Controller
	queue    workqueue.TypedRateLimitingInterface[any]

	noGC    map[string]struct{}
	gcMutex sync.RWMutex

	failFuncs   map[string]func(error)
	feedCachers map[string]cacher.GlobalThreatFeedCacher
	fsMutex     sync.RWMutex
}

// Wrapper for clientset errors, used in retry processing.
type clientsetError struct {
	e  error
	op clientSetOp
}

type clientSetOp int

const (
	opCreate clientSetOp = iota
	opUpdate
	opDelete
)

func NewController(client v3client.GlobalNetworkSetInterface) Controller {
	lw := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			// We only care about GlobalNetworkSets created by this controller
			options.LabelSelector = LabelKey + " = " + LabelValue
			return client.List(context.Background(), options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			options.LabelSelector = LabelKey + " = " + LabelValue
			return client.Watch(context.Background(), options)
		},
	}
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[any]())

	remote, informer := cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: lw,
		ObjectType:    &v3.GlobalNetworkSet{},
		ResyncPeriod:  DefaultResyncPeriod,
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) {
				key, err := cache.MetaNamespaceKeyFunc(obj)
				if err == nil {
					queue.Add(key)
				}
			},
			UpdateFunc: func(old any, new any) {
				key, err := cache.MetaNamespaceKeyFunc(new)
				if err == nil {
					queue.Add(key)
				}
			},
			DeleteFunc: func(obj any) {
				// IndexerInformer uses a delta queue, therefore for deletes we have to use this
				// key function.
				key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
				if err == nil {
					queue.Add(key)
				}
			},
		},
		Indexers: cache.Indexers{},
	})

	local := cache.NewStore(cache.MetaNamespaceKeyFunc)
	return &controller{
		client:      client,
		local:       local,
		queue:       queue,
		remote:      remote,
		informer:    informer,
		noGC:        make(map[string]struct{}),
		failFuncs:   make(map[string]func(error)),
		feedCachers: make(map[string]cacher.GlobalThreatFeedCacher),
	}
}

func (c *controller) Add(s *v3.GlobalNetworkSet, fail func(error), feedCacher cacher.GlobalThreatFeedCacher) {
	ss := s.DeepCopy()

	// The "creator" key ensures this object will be watched/listed by
	if ss.Labels == nil {
		ss.Labels = make(map[string]string)
	}
	ss.Labels[LabelKey] = LabelValue
	err := c.local.Add(ss)
	if err != nil {
		// Add to local cache only returns error if we fail to extract a key,
		// which is a bug if it ever happens.
		panic(err)
	}
	key, err := cache.MetaNamespaceKeyFunc(ss)
	if err != nil {
		panic(err)
	}
	c.queue.Add(key)

	c.fsMutex.Lock()
	defer c.fsMutex.Unlock()
	c.failFuncs[s.Name] = fail
	c.feedCachers[s.Name] = feedCacher
}

func (c *controller) Delete(s *v3.GlobalNetworkSet) {
	// don't bother copying, since we won't keep a reference to the Set
	err := c.local.Delete(s)
	if err != nil {
		// Delete from local cache only returns error if we fail to extract a key,
		// which is a bug if it ever happens.
		panic(err)
	}

	// Mark as safe to garbage collect
	c.gcMutex.Lock()
	delete(c.noGC, s.Name)
	c.gcMutex.Unlock()

	// Don't notify puller of failures any more, since the GNS is no longer
	// needed.
	c.fsMutex.Lock()
	delete(c.failFuncs, s.Name)
	delete(c.feedCachers, s.Name)
	c.fsMutex.Unlock()

	c.queue.Add(s.Name)
}

func (c *controller) NoGC(s *v3.GlobalNetworkSet) {
	// don't bother copying, since we're only going to extract a key.
	key, err := cache.MetaNamespaceKeyFunc(s)
	if err != nil {
		panic(err)
	}
	c.gcMutex.Lock()
	defer c.gcMutex.Unlock()
	c.noGC[key] = struct{}{}
	// don't add the Set to the queue.  NoGC just prevents garbage collection,
	// but doesn't trigger any direct action.
}

func (c *controller) Run(ctx context.Context) {
	c.once.Do(func() {
		go c.run(ctx)
	})
}

func (c *controller) run(ctx context.Context) {

	// Let the workers stop when we are done
	defer c.queue.ShutDown()
	log.Info("[Global Threat Feeds] Starting GlobalNetworkSet controller")

	go c.informer.Run(ctx.Done())

	// Wait for all involved caches to be synced, before processing items from the queue is started
	if !cache.WaitForCacheSync(ctx.Done(), c.informer.HasSynced) {
		// WaitForCacheSync returns false if the context expires before sync is successful.
		// If that happens, the controller is no longer needed, so just log the error.
		log.Error("[Global Threat Feeds] Failed to sync GlobalNetworkSet controller")
		return
	}

	for {
		select {
		case <-ctx.Done():
			log.Info("[Global Threat Feeds] Stopping GlobalNetworkSet controller")
			return
		default:
			c.processNextItem(ctx)
		}
	}
}

func (c *controller) processNextItem(ctx context.Context) {
	item, shutdown := c.queue.Get()
	if shutdown {
		log.Info("[Global Threat Feeds] GlobalNetworkSet workqueue shut down")
		return
	}
	defer c.queue.Done(item)
	key := item.(string)
	logCtx := log.WithField("name", key)
	logCtx.Debug("[Global Threat Feeds] processing GlobalNetworkSet")

	il, okl, err := c.local.GetByKey(key)
	if err != nil {
		// Local cache should never error.
		panic(err)
	}
	ir, okr, err := c.remote.GetByKey(key)
	if err != nil {
		// Remote is a cache and should never error.
		panic(err)
	}
	defer c.handleErr(key)
	switch {
	case okl && okr:
		// Local and remote copies exist.  Are they identical?
		sl := il.(*v3.GlobalNetworkSet)
		sr := ir.(*v3.GlobalNetworkSet)
		logCtx.Debug("[Global Threat Feeds] local & remote GNS exist")
		if setIdentical(sl, sr) {
			logCtx.Debug("[Global Threat Feeds] local & remote identical, no update")
			return
		} else {
			logCtx.Debug("[Global Threat Feeds] updating GNS")
			c.update(ctx, sl, sr)
		}
	case okl && !okr:
		// Local exists, but remote does not.
		sl := il.(*v3.GlobalNetworkSet)
		logCtx.Debug("[Global Threat Feeds] local GNS exists")
		c.create(ctx, sl)
	case !okl && okr:
		// Local does not exist, but remote does.
		logCtx.Debug("[Global Threat Feeds] remote GNS exists")
		if c.okToGC(key) {
			sr := ir.(*v3.GlobalNetworkSet)
			logCtx.Debug("[Global Threat Feeds] garbage collect GNS")
			c.delete(ctx, sr)
		} else {
			logCtx.Debug("[Global Threat Feeds] skip GC of GNS")
		}
	case !okl && !okr:
		// Neither local nor remote exist
		logCtx.Debug("[Global Threat Feeds] neither local nor remote GNS exist")
		return
	}
}

// handleErr recovers from panics adding, deleting, or updating resources on
// the remote API Server.
func (c *controller) handleErr(key string) {
	e := recover()
	if e == nil {
		log.WithField("name", key).Debug("[Global Threat Feeds] successfully processed GNS")

		// Forget any rate limiting history for this key.
		c.queue.Forget(key)

		// If we are tracking status for the key, clear any errors.
		c.fsMutex.RLock()
		feedCacher, ok := c.feedCachers[key]
		c.fsMutex.RUnlock()
		if ok {
			feedutils.ClearErrorFromFeedStatus(feedCacher, cacher.GlobalNetworkSetSyncFailed)
		}
		return
	}
	// Re-raise if not our "exception" type
	f, ok := e.(clientsetError)
	if !ok {
		panic(e)
	}

	// Try to requeue and reprocess.  But, if we try and fail too many times,
	// give up.  The hourly full resync will try again later.
	if c.queue.NumRequeues(key) < DefaultClientRetries {
		log.WithError(f.e).Errorf("[Global Threat Feeds] Error handling %v, will retry", key)
		c.queue.AddRateLimited(key)
		return
	}
	// Give up
	c.queue.Forget(key)
	log.WithError(f.e).Errorf("[Global Threat Feeds] Dropping key %q out of the work queue", key)

	// Inform Puller of failure, if it has registered to be notified.
	if f.op == opDelete {
		// Don't inform on deletes --- these are garbage collection.
		return
	}
	c.fsMutex.RLock()
	fn, fok := c.failFuncs[key]
	feedCacher, sok := c.feedCachers[key]
	c.fsMutex.RUnlock()
	if fok {
		fn(f.e)
	}
	if sok {
		feedutils.AddErrorToFeedStatus(feedCacher, cacher.GlobalNetworkSetSyncFailed, f.e)
	}
}

func (c *controller) okToGC(key string) bool {
	c.gcMutex.RLock()
	defer c.gcMutex.RUnlock()
	_, ok := c.noGC[key]
	return !ok
}

func (c *controller) update(ctx context.Context, new, old *v3.GlobalNetworkSet) {
	newMeta := old.ObjectMeta.DeepCopy()
	newMeta.Labels = new.Labels
	newMeta.DeepCopyInto(&new.ObjectMeta)
	_, err := c.client.Update(ctx, new, metav1.UpdateOptions{})
	if err != nil {
		panic(clientsetError{err, opUpdate})
	}
}

func (c *controller) create(ctx context.Context, s *v3.GlobalNetworkSet) {
	_, err := c.client.Create(ctx, s, metav1.CreateOptions{})
	if err != nil {
		panic(clientsetError{err, opCreate})
	}
}

func (c *controller) delete(ctx context.Context, s *v3.GlobalNetworkSet) {
	err := c.client.Delete(ctx, s.Name, metav1.DeleteOptions{})
	if err != nil {
		panic(clientsetError{err, opDelete})
	}
}

func setIdentical(s1, s2 *v3.GlobalNetworkSet) bool {
	// We only care about labels and spec in this comparison.  This makes sure
	// resource versions, create times, etc don't enter into the comparison.
	if !reflect.DeepEqual(s1.Labels, s2.Labels) {
		return false
	}
	if !reflect.DeepEqual(s1.Spec, s2.Spec) {
		return false
	}
	return true
}
