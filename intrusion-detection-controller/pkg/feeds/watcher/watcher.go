// Copyright 2019-2020 Tigera Inc. All rights reserved.

package watcher

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v32 "github.com/tigera/api/pkg/client/clientset_generated/clientset/typed/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/cacher"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/controller"
	geodb "github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/geodb"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/puller"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/searcher"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/sync/globalnetworksets"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/health"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/storage"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/util"
)

const DefaultResyncPeriod = 0

// Watcher accepts updates from threat pullers and synchronizes them to the
// database
type Watcher interface {
	health.Pinger

	// Run starts the feed synchronization.
	Run(ctx context.Context)
	Close()
}

type watcher struct {
	configMapClient        v1.ConfigMapInterface
	secretsClient          v1.SecretInterface
	globalThreatFeedClient v32.GlobalThreatFeedInterface
	gnsController          globalnetworksets.Controller
	ipsController          controller.Controller
	dnsController          controller.Controller
	httpClient             *http.Client
	ipSet                  storage.IPSet
	dnSet                  storage.DomainNameSet
	suspiciousIP           storage.SuspiciousSet
	suspiciousDomains      storage.SuspiciousSet
	events                 storage.Events
	feedWatchers           map[string]*feedWatcher
	feedWatchersMutex      sync.RWMutex
	cancel                 context.CancelFunc
	geoDB                  geodb.GeoDatabase
	maxLinseedTimeSkew     time.Duration

	// Unfortunately, cache.Controller callbacks can't accept
	// a context, so we need to store this on the watcher so we can pass it
	// to Pullers & Searchers we create.
	ctx context.Context

	once       sync.Once
	ping       chan struct{}
	watching   bool
	controller cache.Controller
	fifo       *cache.DeltaFIFO
	feeds      cache.Store
}

type feedWatcher struct {
	feed       *v3.GlobalThreatFeed
	puller     puller.Puller
	searcher   searcher.Searcher
	feedCacher cacher.GlobalThreatFeedCacher
}

func NewWatcher(
	configMapClient v1.ConfigMapInterface,
	secretsClient v1.SecretInterface,
	globalThreatFeedInterface v32.GlobalThreatFeedInterface,
	globalNetworkSetController globalnetworksets.Controller,
	ipsController controller.Controller,
	dnsController controller.Controller,
	httpClient *http.Client,
	ipSet storage.IPSet,
	dnSet storage.DomainNameSet,
	suspiciousIP storage.SuspiciousSet,
	suspiciousDomains storage.SuspiciousSet,
	events storage.Events,
	geodb geodb.GeoDatabase,
	maxLinseedTimeSkew time.Duration,
) Watcher {
	feedWatchers := map[string]*feedWatcher{}

	lw := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return globalThreatFeedInterface.List(context.Background(), options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return globalThreatFeedInterface.Watch(context.Background(), options)
		},
	}
	w := &watcher{
		configMapClient:        configMapClient,
		secretsClient:          secretsClient,
		globalThreatFeedClient: globalThreatFeedInterface,
		gnsController:          globalNetworkSetController,
		ipsController:          ipsController,
		dnsController:          dnsController,
		httpClient:             httpClient,
		ipSet:                  ipSet,
		dnSet:                  dnSet,
		suspiciousIP:           suspiciousIP,
		suspiciousDomains:      suspiciousDomains,
		events:                 events,
		feedWatchers:           feedWatchers,
		ping:                   make(chan struct{}),
		geoDB:                  geodb,
		maxLinseedTimeSkew:     maxLinseedTimeSkew,
	}

	w.fifo, w.feeds = util.NewPingableFifo()

	cfg := &cache.Config{
		Queue:            w.fifo,
		ListerWatcher:    lw,
		ObjectType:       &v3.GlobalThreatFeed{},
		FullResyncPeriod: DefaultResyncPeriod,
		Process:          w.processQueue,
	}
	w.controller = cache.New(cfg)

	return w
}

func (s *watcher) Run(ctx context.Context) {
	s.once.Do(func() {
		log.Info("[Global Threat Feeds] Start Feeds controller")

		s.ctx, s.cancel = context.WithCancel(ctx)

		go func() {
			// s.watching should only be true while this function is running.  Don't
			// bother with a lock because updates to booleans are always atomic.
			s.watching = true
			defer func() { s.watching = false }()
			s.controller.Run(s.ctx.Done())
		}()

		// The ipsController/dnsController can start running right away. It waits for
		// StartGC() before it does reconciliation. Note that the gnsController
		// should *not* be started before everything is synced, since it will
		// start reconciliation as soon as we call Run() on it.
		s.ipsController.Run(s.ctx)
		s.dnsController.Run(s.ctx)

		// We need to wait until we sync all GlobalThreatFeeds before starting
		// the GlobalNetworkSet controller. This is because the GlobalNetworkSet
		// controller does garbage collection---if we started garbage collecting
		// before syncing all threat feeds, we might delete state associated
		// with an active threat feed.
		go func() {
			if !cache.WaitForCacheSync(s.ctx.Done(), s.controller.HasSynced) {
				// WaitForCacheSync returns false if the context expires before sync is successful.
				// If that happens, the controller is no longer needed, so just log the error.
				log.Error("[Global Threat Feeds] Failed to sync GlobalThreatFeed controller")
				return
			}
			log.Debug("[Global Threat Feeds] GlobalThreatFeed controller synced")
			s.gnsController.Run(s.ctx)
			s.ipsController.StartReconciliation(s.ctx)
			s.dnsController.StartReconciliation(s.ctx)
		}()
	})
}

func (s *watcher) processQueue(obj any, isInInitialList bool) error {
	// In general, this function only operates on local caches and FIFOs, so
	// will never return an error.  We panic on any errors since these indicate
	// programming bugs.

	// from oldest to newest
	for _, d := range obj.(cache.Deltas) {
		// Pings also come as cache updates
		_, ok := d.Object.(util.Ping)
		if ok {
			// Pong on a go routine so we don't block the main loop
			// if no pinger is listening.
			go s.pong()
			continue
		}
		switch d.Type {
		case cache.Sync, cache.Added, cache.Updated:
			old, exists, err := s.feeds.Get(d.Object)
			if err != nil {
				panic(err)
			}
			if exists {
				if err := s.feeds.Update(d.Object); err != nil {
					panic(err)
				}
				s.updateFeedWatcher(s.ctx, old.(*v3.GlobalThreatFeed), d.Object.(*v3.GlobalThreatFeed))
			} else {
				if err := s.feeds.Add(d.Object); err != nil {
					panic(err)
				}
				s.startFeedWatcher(s.ctx, d.Object.(*v3.GlobalThreatFeed))
			}
		case cache.Deleted:
			if err := s.feeds.Delete(d.Object); err != nil {
				panic(err)
			}
			var name string
			switch f := d.Object.(type) {
			case *v3.GlobalThreatFeed:
				name = f.Name
			case cache.DeletedFinalStateUnknown:
				name = f.Key
			default:
				panic(fmt.Sprintf("[Global Threat Feeds] unknown FIFO delta type %v", d.Object))
			}
			_, exists := s.getFeedWatcher(name)
			if exists {
				s.stopFeedWatcher(s.ctx, name)
			}
		}
	}
	return nil
}

func (s *watcher) startFeedWatcher(ctx context.Context, f *v3.GlobalThreatFeed) {
	switch f.Spec.Content {
	case v3.ThreatFeedContentDomainNameSet:
		s.startFeedWatcherDomains(ctx, f)
	default:
		// Note: ThreatFeedContentIPset is the default
		s.startFeedWatcherIP(ctx, s.geoDB, f)
	}
}

func (s *watcher) startFeedWatcherIP(ctx context.Context, geodb geodb.GeoDatabase, f *v3.GlobalThreatFeed) {
	if _, ok := s.getFeedWatcher(f.Name); ok {
		panic(fmt.Sprintf("[Global Threat Feeds] Feed %s already started", f.Name))
	}

	fCopy := f.DeepCopy()

	feedCacher := cacher.NewGlobalThreatFeedCache(f.Name, s.globalThreatFeedClient)
	feedCacher.Run(ctx)

	fw := feedWatcher{
		feed:       fCopy,
		searcher:   searcher.NewSearcher(fCopy, time.Minute, s.suspiciousIP, s.events, geodb, s.maxLinseedTimeSkew),
		feedCacher: feedCacher,
	}

	s.setFeedWatcher(f.Name, &fw)

	if fCopy.Spec.Pull != nil && fCopy.Spec.Pull.HTTP != nil {
		fw.puller = puller.NewIPSetHTTPPuller(fCopy, s.ipSet, s.configMapClient, s.secretsClient, s.httpClient, s.gnsController, s.ipsController)
		fw.puller.Run(ctx, fw.feedCacher)
	} else {
		fw.puller = nil
	}
	s.ipsController.NoGC(ctx, fCopy.Name)

	if fCopy.Spec.GlobalNetworkSet != nil {
		s.gnsController.NoGC(util.NewGlobalNetworkSet(fCopy.Name))
	}

	fw.searcher.Run(ctx, fw.feedCacher)
}

func (s *watcher) startFeedWatcherDomains(ctx context.Context, f *v3.GlobalThreatFeed) {
	if _, ok := s.getFeedWatcher(f.Name); ok {
		panic(fmt.Sprintf("[Global Threat Feeds] Feed %s already started", f.Name))
	}

	fCopy := f.DeepCopy()

	feedCacher := cacher.NewGlobalThreatFeedCache(f.Name, s.globalThreatFeedClient)
	feedCacher.Run(ctx)

	fw := feedWatcher{
		feed:       fCopy,
		searcher:   searcher.NewSearcher(fCopy, time.Minute, s.suspiciousDomains, s.events, &geodb.GeoDB{}, s.maxLinseedTimeSkew),
		feedCacher: feedCacher,
	}

	s.setFeedWatcher(f.Name, &fw)

	if fCopy.Spec.Pull != nil && fCopy.Spec.Pull.HTTP != nil {
		fw.puller = puller.NewDomainNameSetHTTPPuller(fCopy, s.dnSet, s.configMapClient, s.secretsClient, s.httpClient, s.dnsController)
		fw.puller.Run(ctx, fw.feedCacher)
	} else {
		fw.puller = nil
	}
	s.dnsController.NoGC(ctx, fCopy.Name)

	fw.searcher.Run(ctx, fw.feedCacher)
}

func (s *watcher) updateFeedWatcher(ctx context.Context, oldFeed, newFeed *v3.GlobalThreatFeed) {
	fw, ok := s.getFeedWatcher(newFeed.Name)
	if !ok {
		panic(fmt.Sprintf("[Global Threat Feeds] Feed %s not started", newFeed.Name))
	}

	fw.feed = newFeed.DeepCopy()

	// Has it changed Content?
	oldContent := v3.ThreatFeedContentIPset // the default
	if oldFeed.Spec.Content != "" {
		oldContent = oldFeed.Spec.Content
	}
	newContent := v3.ThreatFeedContentIPset
	if newFeed.Spec.Content != "" {
		newContent = newFeed.Spec.Content
	}
	if oldContent != newContent {
		// It has changed content.  Stop the old and start the new.
		s.stopFeedWatcher(ctx, newFeed.Name)
		s.startFeedWatcher(ctx, newFeed)
		return
	}

	if fw.feed.Spec.Pull != nil && fw.feed.Spec.Pull.HTTP != nil {
		if util.FeedNeedsRestart(oldFeed, fw.feed) {
			s.restartPuller(ctx, newFeed)
		} else {
			fw.puller.SetFeed(fw.feed)
		}
	} else {
		if fw.puller != nil {
			fw.puller.Close()
		}
		fw.puller = nil
	}

	gns := util.NewGlobalNetworkSet(fw.feed.Name)
	if oldFeed.Spec.GlobalNetworkSet == nil && newFeed.Spec.GlobalNetworkSet != nil {
		s.gnsController.NoGC(gns)
	}
	if oldFeed.Spec.GlobalNetworkSet != nil && newFeed.Spec.GlobalNetworkSet == nil {
		s.gnsController.Delete(gns)
	}

	fw.searcher.SetFeed(fw.feed)
}

func (s *watcher) restartPuller(ctx context.Context, f *v3.GlobalThreatFeed) {
	name := f.Name

	fw, ok := s.getFeedWatcher(name)
	if !ok {
		panic(fmt.Sprintf("[Global Threat Feeds] feed %s not running", name))
	}

	fw.feed = f.DeepCopy()
	if fw.puller != nil {
		fw.puller.Close()
	}

	if fw.feed.Spec.Pull != nil && fw.feed.Spec.Pull.HTTP != nil {
		switch fw.feed.Spec.Content {
		case v3.ThreatFeedContentDomainNameSet:
			fw.puller = puller.NewDomainNameSetHTTPPuller(fw.feed, s.dnSet, s.configMapClient, s.secretsClient, s.httpClient, s.dnsController)
		default:
			// Note: ThreatFeedContentIPset is the default
			fw.puller = puller.NewIPSetHTTPPuller(fw.feed, s.ipSet, s.configMapClient, s.secretsClient, s.httpClient, s.gnsController, s.ipsController)
		}
		fw.puller.Run(ctx, fw.feedCacher)
	} else {
		fw.puller = nil
	}
}

func (s *watcher) stopFeedWatcher(ctx context.Context, name string) {
	fw, ok := s.getFeedWatcher(name)
	if !ok {
		panic(fmt.Sprintf("[Global Threat Feeds] feed %s not running", name))
	}

	log.WithField("feed", name).Info("[Global Threat Feeds] Stopping feed")

	if fw.puller != nil {
		fw.puller.Close()
	}
	gns := util.NewGlobalNetworkSet(name)
	s.gnsController.Delete(gns)
	// Feeds have unique names and Delete is idempotent, so just delete from all
	// set controllers.
	s.ipsController.Delete(ctx, name)
	s.dnsController.Delete(ctx, name)

	fw.searcher.Close()
	fw.feedCacher.Close()
	s.deleteFeedWatcher(name)
}

func (s *watcher) Close() {
	s.cancel()
}

func (s *watcher) getFeedWatcher(name string) (fw *feedWatcher, ok bool) {
	s.feedWatchersMutex.RLock()
	defer s.feedWatchersMutex.RUnlock()
	fw, ok = s.feedWatchers[name]
	return
}

func (s *watcher) setFeedWatcher(name string, fw *feedWatcher) {
	s.feedWatchersMutex.Lock()
	defer s.feedWatchersMutex.Unlock()
	s.feedWatchers[name] = fw
}

func (s *watcher) deleteFeedWatcher(name string) {
	s.feedWatchersMutex.Lock()
	defer s.feedWatchersMutex.Unlock()
	delete(s.feedWatchers, name)
}

func (s *watcher) listFeedWatchers() []*feedWatcher {
	s.feedWatchersMutex.RLock()
	defer s.feedWatchersMutex.RUnlock()
	var out []*feedWatcher
	for _, fw := range s.feedWatchers {
		out = append(out, fw)
	}
	return out
}

// Ping is used to ensure the watcher's main loop is running and not blocked.
func (s *watcher) Ping(ctx context.Context) error {
	// Enqueue a ping
	err := s.fifo.Update(util.Ping{})
	if err != nil {
		// Local fifo & cache should never error.
		panic(err)
	}

	// Wait for the ping to be processed, or context to expire.
	select {
	case <-ctx.Done():
		return ctx.Err()

	// Since this channel is unbuffered, this will block if the main loop is not
	// running, or has itself blocked.
	case <-s.ping:
		return nil
	}
}

// pong is called from the main processing loop to reply to a ping.
func (s *watcher) pong() {
	// Nominally, a sync.Cond would work nicely here rather than a channel,
	// which would allow us to wake up all pingers at once. However, sync.Cond
	// doesn't allow timeouts, so we stick with channels and one pong() per ping.
	s.ping <- struct{}{}
}
