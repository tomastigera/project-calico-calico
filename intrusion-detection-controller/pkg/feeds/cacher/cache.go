// Copyright 2021 Tigera Inc. All rights reserved.

package cacher

import (
	"context"
	"net/http"
	"sync"

	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	clientV3 "github.com/tigera/api/pkg/client/clientset_generated/clientset/typed/projectcalico/v3"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type CacheRequestType int

const (
	MaxUpdateRetry = 5
)

const (
	RequestTypeGet = iota
	RequestTypeUpdate
	RequestTypeUpdateStatus
)

const (
	LinseedSyncFailed          = "LinseedSyncFailed"
	GlobalNetworkSetSyncFailed = "GlobalNetworkSetSyncFailed"
	GarbageCollectionFailed    = "GarbageCollectionFailed"
	PullFailed                 = "PullFailed"
	SearchFailed               = "SearchFailed"
)

// cacheRequest is the data structure sent to the requestChannel of globalThreatFeedCacher and will be processed by the
// cacher in a sequential order. The requestType field specifies what operation we want to perform to the cache. The
// responseChannel field is the channel we provide to the cacher to send CacheResponse back to us. The globalThreatFeed
// field is payload of the request, it's only required when trying to update the cache.
type cacheRequest struct {
	requestType      CacheRequestType
	responseChannel  chan CacheResponse
	globalThreatFeed *apiv3.GlobalThreatFeed
}

// CacheResponse is the data structure returned by GlobalThreatFeedCacher when we try to get/update GlobalThreatFeed CR
// through it. The GlobalThreatFeed field is expected to be populated when get/update the cache is successful or when
// updating the cache failed due to a recoverable failure, it would be left nil when any unrecoverable failure happens.
// Err field is populated whenever the get/update the cache failed, and would be populated with the reason of failure.
type CacheResponse struct {
	GlobalThreatFeed *apiv3.GlobalThreatFeed
	Err              error
}

// GlobalThreatFeedCacher caches a particular GlobalThreatFeed CR for the owner of the cacher to get/update it.
// It reduces traffic between IDS controller and the k8s server every time.
type GlobalThreatFeedCacher interface {
	// Run starts the GlobalThreatFeedCacher, makes the cacher listens to CacheRequest sent to it
	Run(ctx context.Context)
	// Close stops the GlobalThreatFeedCacher
	Close()
	// GetGlobalThreatFeed returns a copy of the cached GlobalThreatFeed CR
	GetGlobalThreatFeed() CacheResponse
	// UpdateGlobalThreatFeed updates the cached GlobalThreatFeed CR
	UpdateGlobalThreatFeed(globalThreatFeed *apiv3.GlobalThreatFeed) CacheResponse
	// UpdateGlobalThreatFeedStatus updates the GlobalThreatFeedStatus subresource of the cached GlobalThreatFeed CR
	UpdateGlobalThreatFeedStatus(globalThreatFeed *apiv3.GlobalThreatFeed) CacheResponse
}

// globalThreatFeedCacher is a lazy-loaded cache that implements the GlobalThreatFeedCacher interface, the cached
// GlobalThreatFeed CR won't be loaded until a cacheRequest comes in and will only be updated when an update to the
// cache (either the CR itself or its status subresource) succeeds
type globalThreatFeedCacher struct {
	once                   sync.Once
	feedName               string
	cachedGlobalThreatFeed *apiv3.GlobalThreatFeed
	globalThreatFeedClient clientV3.GlobalThreatFeedInterface
	requestChannel         chan cacheRequest
	stop                   chan struct{}
}

func NewGlobalThreatFeedCache(feedName string, globalThreatFeedClient clientV3.GlobalThreatFeedInterface) GlobalThreatFeedCacher {
	return &globalThreatFeedCacher{
		feedName:               feedName,
		globalThreatFeedClient: globalThreatFeedClient,
		requestChannel:         make(chan cacheRequest),
		stop:                   make(chan struct{}),
	}
}

// Run starts another thread that infinitely listens to incoming cacheRequests and process those requests until a stop
// signal is received
func (c *globalThreatFeedCacher) Run(ctx context.Context) {
	c.once.Do(func() {
		go c.startHandlingCacheRequests(ctx)
	})
}

// Close sends a stop signal to the stop channel to terminate the infinite loop of receiving and processing incoming cacheRequests
func (c *globalThreatFeedCacher) Close() {
	c.stop <- struct{}{}
}

// GetGlobalThreatFeed sends a cacheRequest to the requestChannel and returns a copy of the cached GlobalThreatFeed CR
// when the cache presents or it's successfully loaded, it returns an error when the cache fails to load.
func (c *globalThreatFeedCacher) GetGlobalThreatFeed() CacheResponse {
	responseChannel := make(chan CacheResponse)
	getRequest := cacheRequest{requestType: RequestTypeGet, responseChannel: responseChannel}
	c.requestChannel <- getRequest
	return <-responseChannel
}

// UpdateGlobalThreatFeed wraps the passed-in globalThreatFeed into a cacheRequest and sends the request to the requestChannel.
// It returns an error when the update failed or the cache failed to load in the first place.
func (c *globalThreatFeedCacher) UpdateGlobalThreatFeed(globalThreatFeed *apiv3.GlobalThreatFeed) CacheResponse {
	responseChannel := make(chan CacheResponse)
	c.requestChannel <- cacheRequest{requestType: RequestTypeUpdate, globalThreatFeed: globalThreatFeed, responseChannel: responseChannel}
	return <-responseChannel
}

// UpdateGlobalThreatFeedStatus wraps the passed-in globalThreatFeed into a cacheRequest and sends the request to the requestChannel.
// It returns an error when the update status failed or the cache failed to load in the first place.
func (c *globalThreatFeedCacher) UpdateGlobalThreatFeedStatus(globalThreatFeed *apiv3.GlobalThreatFeed) CacheResponse {
	responseChannel := make(chan CacheResponse)
	c.requestChannel <- cacheRequest{requestType: RequestTypeUpdateStatus, globalThreatFeed: globalThreatFeed, responseChannel: responseChannel}
	return <-responseChannel
}

func (c *globalThreatFeedCacher) startHandlingCacheRequests(ctx context.Context) {
	for {
		select {
		case <-c.stop:
			return
		case req := <-c.requestChannel:
			c.handleCacheRequest(ctx, req)
		}
	}
}

func (c *globalThreatFeedCacher) handleCacheRequest(ctx context.Context, req cacheRequest) {
	if c.cachedGlobalThreatFeed == nil {
		if err := c.reloadCache(ctx); err != nil {
			log.WithError(err).WithField("feedName", c.feedName).
				Error("[Global Threat Feeds] unable to handle cache request because GlobalThreatFeed cache failed to load")
			req.responseChannel <- CacheResponse{GlobalThreatFeed: nil, Err: err}
			return
		}
	}
	switch req.requestType {
	case RequestTypeGet:
		c.handleCacheGetRequest(req)
	case RequestTypeUpdate:
		c.handleCacheUpdateRequest(ctx, req)
	case RequestTypeUpdateStatus:
		c.handleCacheUpdateStatusRequest(ctx, req)
	default:
		log.WithField("feedName", c.feedName).Error("[Global Threat Feeds] unknown cache request type, unable to handle")
	}
}

func (c *globalThreatFeedCacher) handleCacheGetRequest(req cacheRequest) {
	req.responseChannel <- CacheResponse{GlobalThreatFeed: c.cachedGlobalThreatFeed.DeepCopy(), Err: nil}
}

func (c *globalThreatFeedCacher) handleCacheUpdateStatusRequest(ctx context.Context, req cacheRequest) {
	newCachedGlobalThreatFeed, err := c.globalThreatFeedClient.UpdateStatus(ctx, req.globalThreatFeed, v1.UpdateOptions{})
	if err == nil {
		log.WithField("feedName", c.feedName).Debug("[Global Threat Feeds] updating GlobalThreatFeed CR status subresource succeeded")
		c.cachedGlobalThreatFeed = newCachedGlobalThreatFeed
		req.responseChannel <- CacheResponse{GlobalThreatFeed: newCachedGlobalThreatFeed.DeepCopy(), Err: nil}
		return
	}
	log.WithError(err).WithField("feedName", c.feedName).Error("[Global Threat Feeds] failed to update GlobalThreatFeed CR status subresource")
	c.handleUpdateFailure(ctx, req, err)
}

func (c *globalThreatFeedCacher) handleCacheUpdateRequest(ctx context.Context, req cacheRequest) {
	newCachedGlobalThreatFeed, err := c.globalThreatFeedClient.Update(ctx, req.globalThreatFeed, v1.UpdateOptions{})
	if err == nil {
		log.WithField("feedName", c.feedName).Debug("[Global Threat Feeds] updating GlobalThreatFeed CR succeeded")
		c.cachedGlobalThreatFeed = newCachedGlobalThreatFeed
		req.responseChannel <- CacheResponse{GlobalThreatFeed: newCachedGlobalThreatFeed.DeepCopy(), Err: nil}
		return
	}
	log.WithError(err).WithField("feedName", c.feedName).Error("[Global Threat Feeds] failed to update GlobalThreatFeed CR")
	c.handleUpdateFailure(ctx, req, err)
}

func (c *globalThreatFeedCacher) handleUpdateFailure(ctx context.Context, req cacheRequest, err error) {
	statusError, ok := err.(*errors.StatusError)
	if ok && statusError.ErrStatus.Code == http.StatusConflict {
		loadCacheErr := c.reloadCache(ctx)
		if loadCacheErr != nil {
			req.responseChannel <- CacheResponse{GlobalThreatFeed: nil, Err: loadCacheErr}
		} else {
			req.responseChannel <- CacheResponse{GlobalThreatFeed: c.cachedGlobalThreatFeed.DeepCopy(), Err: err}
		}
		return
	}
	req.responseChannel <- CacheResponse{GlobalThreatFeed: nil, Err: err}
}

func (c *globalThreatFeedCacher) reloadCache(ctx context.Context) error {
	cachedGlobalThreatFeed, err := c.globalThreatFeedClient.Get(ctx, c.feedName, v1.GetOptions{})
	if cachedGlobalThreatFeed != nil && err == nil {
		c.cachedGlobalThreatFeed = cachedGlobalThreatFeed
	}
	return err
}
