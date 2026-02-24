// Copyright 2019-2020 Tigera Inc. All rights reserved.

package puller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	retry "github.com/avast/retry-go"
	log "github.com/sirupsen/logrus"
	calico "github.com/tigera/api/pkg/apis/projectcalico/v3"
	apiErrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	core "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/cacher"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/errorcondition"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/utils"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/runloop"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/util"
)

const (
	CommentPrefix = "#"
	retryAttempts = 3
	retryDelay    = 60 * time.Second
)

// httpPuller is a feed that periodically pulls Puller sets from a URL
type httpPuller struct {
	configMapClient  core.ConfigMapInterface
	secretsClient    core.SecretInterface
	client           *http.Client
	feed             *calico.GlobalThreatFeed
	needsUpdate      bool
	url              *url.URL
	header           http.Header
	period           time.Duration
	setHandler       setHandlerinterface
	syncFailFunction SyncFailFunction
	cancel           context.CancelFunc
	once             sync.Once
	lock             sync.RWMutex
}

type setHandlerinterface interface {
	lastModified(ctx context.Context, name string) (time.Time, error)
	updateDataStore(ctx context.Context, name string, snapshot any, f func(error), feedCacher cacher.GlobalThreatFeedCacher)
	snapshot(r io.Reader) (any, error)
	handleSnapshot(ctx context.Context, snapshot any, feedCacher cacher.GlobalThreatFeedCacher, f SyncFailFunction)
	syncFromDB(ctx context.Context, feedCacher cacher.GlobalThreatFeedCacher)
}

func NewHttpPuller(cmClient core.ConfigMapInterface, secClient core.SecretInterface, client *http.Client, tf *calico.GlobalThreatFeed, needsUpdate bool, setHandler setHandlerinterface) *httpPuller {
	return &httpPuller{
		configMapClient: cmClient,
		secretsClient:   secClient,
		client:          client,
		feed:            tf.DeepCopy(),
		needsUpdate:     needsUpdate,
		setHandler:      setHandler,
		period:          util.ParseFeedDuration(tf),
	}
}

func (h *httpPuller) SetFeed(f *calico.GlobalThreatFeed) {
	h.lock.Lock()
	defer h.lock.Unlock()

	h.feed = f.DeepCopy()
	h.needsUpdate = true
}

func (h *httpPuller) Run(ctx context.Context, feedCacher cacher.GlobalThreatFeedCacher) {
	h.once.Do(func() {

		h.lock.RLock()
		log.WithField("feed", h.feed.Name).Debug("[Global Threat Feeds] started HTTP puller")
		h.lock.RUnlock()
		ctx, h.cancel = context.WithCancel(ctx)

		runFunc, rescheduleFunc := runloop.RunLoopWithReschedule()
		h.syncFailFunction = func(error) { _ = rescheduleFunc() }

		go func() {
			defer h.cancel()
			if h.period == 0 {
				return
			}

			// Synchronize the GlobalNetworkSet on startup
			h.setHandler.syncFromDB(ctx, feedCacher)

			delay := h.getStartupDelay(ctx)
			if delay > 0 {
				h.lock.RLock()
				log.WithField("delay", delay).WithField("feed", h.feed.Name).Info("[Global Threat Feeds] Delaying start")
				h.lock.RUnlock()
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
				break
			}
			_ = runFunc(ctx, func() { _ = h.queryURL(ctx, feedCacher, retryAttempts, retryDelay) }, h.period, func() {}, h.period/3)
		}()

	})
}

func (h *httpPuller) Close() {
	h.cancel()
}

func (h *httpPuller) setFeedURIAndHeader(ctx context.Context, f *calico.GlobalThreatFeed) error {
	u, err := url.Parse(f.Spec.Pull.HTTP.URL)
	if err != nil {
		return err
	}

	headers := http.Header{}
	for _, header := range f.Spec.Pull.HTTP.Headers {
		value := header.Value
		if value == "" && header.ValueFrom != nil {
			ok := false
			switch {
			case header.ValueFrom.ConfigMapKeyRef != nil:
				configMap, err := h.configMapClient.Get(ctx, header.ValueFrom.ConfigMapKeyRef.Name, meta.GetOptions{})
				if err != nil {
					if header.ValueFrom.ConfigMapKeyRef.Optional != nil && *header.ValueFrom.ConfigMapKeyRef.Optional {
						log.WithError(err).WithFields(log.Fields{"feed": f.Name, "header": header.Name, "configMapKeyRef": header.ValueFrom.ConfigMapKeyRef.Name, "key": header.ValueFrom.ConfigMapKeyRef.Key}).Debug("[Global Threat Feeds] Skipping header")
						continue
					}
					return FatalError("[Global Threat Feeds] could not get ConfigMap %s, %s", header.ValueFrom.ConfigMapKeyRef.Name, err.Error())
				}
				value, ok = configMap.Data[header.ValueFrom.ConfigMapKeyRef.Key]
				if ok {
					log.WithField("value", value).Debug("[Global Threat Feeds] Loaded config")
				} else if header.ValueFrom.ConfigMapKeyRef.Optional != nil && *header.ValueFrom.ConfigMapKeyRef.Optional {
					log.WithFields(log.Fields{"feed": f.Name, "header": header.Name, "configMapKeyRef": header.ValueFrom.ConfigMapKeyRef.Name, "key": header.ValueFrom.ConfigMapKeyRef.Key}).Debug("[Global Threat Feeds] Skipping header")
					continue
				} else {
					return FatalError("[Global Threat Feeds] configMap %s key %s not found", header.ValueFrom.ConfigMapKeyRef.Name, header.ValueFrom.ConfigMapKeyRef.Key)
				}
			case header.ValueFrom.SecretKeyRef != nil:
				secret, err := h.secretsClient.Get(ctx, header.ValueFrom.SecretKeyRef.Name, meta.GetOptions{})
				if err != nil {
					if header.ValueFrom.SecretKeyRef.Optional != nil && *header.ValueFrom.SecretKeyRef.Optional {
						log.WithError(err).WithFields(log.Fields{"feed": f.Name, "header": header.Name, "secretKeyRef": header.ValueFrom.SecretKeyRef.Name, "key": header.ValueFrom.SecretKeyRef.Key}).Debug("[Global Threat Feeds] Skipping header")
						continue
					}
					return FatalError("[Global Threat Feeds] could not get Secret %s, %s", header.ValueFrom.SecretKeyRef.Name, err.Error())
				}

				var bvalue []byte
				bvalue, ok = secret.Data[header.ValueFrom.SecretKeyRef.Key]
				value = string(bvalue)
				if ok {
					log.Debug("[Global Threat Feeds] Loaded secret")
				} else if header.ValueFrom.SecretKeyRef.Optional != nil && *header.ValueFrom.SecretKeyRef.Optional {
					log.WithFields(log.Fields{"feed": f.Name, "header": header.Name, "secretKeyRef": header.ValueFrom.SecretKeyRef.Name, "key": header.ValueFrom.SecretKeyRef.Key}).Debug("[Global Threat Feeds] Skipping header")
					continue
				} else {
					return FatalError("[Global Threat Feeds] secrets %s key %s not found", header.ValueFrom.SecretKeyRef.Name, header.ValueFrom.SecretKeyRef.Key)
				}
			default:
				return FatalError("[Global Threat Feeds] neither ConfigMap nor SecretKey was set")
			}
		}
		headers.Add(header.Name, value)
	}

	h.url = u
	h.header = headers
	h.needsUpdate = false

	return nil
}

func (h *httpPuller) getStartupDelay(ctx context.Context) time.Duration {
	lastModified, err := h.setHandler.lastModified(ctx, h.feed.Name)
	if err != nil {
		return 0
	}
	since := time.Since(lastModified)
	if since < h.period {
		return h.period - since
	}
	return 0
}

// queryInfo gets the information required for a query in a threadsafe way
func (h *httpPuller) queryInfo(ctx context.Context) (name string, u *url.URL, header http.Header, err error) {
	h.lock.RLock()

	if h.needsUpdate {
		h.lock.RUnlock()
		h.lock.Lock()

		if h.needsUpdate {
			err = h.setFeedURIAndHeader(ctx, h.feed)
			if err != nil {
				h.lock.Unlock()
				return
			}
		}

		name = h.feed.Name
		u = h.url
		header = h.header
		h.lock.Unlock()
	} else {
		name = h.feed.Name
		u = h.url
		header = h.header
		h.lock.RUnlock()
	}
	return
}

func (h *httpPuller) queryURL(ctx context.Context, feedCacher cacher.GlobalThreatFeedCacher, attempts uint, delay time.Duration) error {
	name, u, header, err := h.queryInfo(ctx)
	if err != nil {
		log.WithError(err).Error("[Global Threat Feeds] failed to query")
		utils.AddErrorToFeedStatus(feedCacher, cacher.PullFailed, err)
		return err
	}
	log.WithField("feed", name).Debugf("[Global Threat Feeds] querying HTTP feed for %v", feedCacher.GetGlobalThreatFeed().GlobalThreatFeed.Name)

	req := &http.Request{Method: "GET", Header: header, URL: u}
	req = req.WithContext(ctx)
	var resp *http.Response
	err = retry.Do(
		func() error {
			var err error
			resp, err = h.client.Do(req)
			if err != nil {
				return err
			}
			if resp.StatusCode >= 500 {
				return &url.Error{
					Op:  req.Method,
					URL: u.String(),
					Err: TemporaryError(resp.Status),
				}
			}
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				return &url.Error{
					Op:  req.Method,
					URL: u.String(),
					Err: errors.New(resp.Status),
				}
			}
			return nil
		},
		retry.Attempts(attempts),
		retry.Delay(delay),
		retry.RetryIf(
			func(err error) bool {
				switch err := err.(type) {
				case net.Error:
					return err.Timeout()
				default:
					return false
				}
			},
		),
		retry.OnRetry(
			func(n uint, err error) {
				log.WithError(err).WithFields(log.Fields{
					"n":   n,
					"url": u,
				}).Infof("[Global Threat Feeds] Retrying for feed %v", feedCacher.GetGlobalThreatFeed().GlobalThreatFeed.Name)
			},
		),
	)
	if err != nil {
		log.WithError(err).Errorf("[Global Threat Feeds] failed to query HTTP feed for %v", feedCacher.GetGlobalThreatFeed().GlobalThreatFeed.Name)
		utils.AddErrorToFeedStatus(feedCacher, cacher.PullFailed, err)
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	snapshot, err := h.setHandler.snapshot(resp.Body)
	if err != nil {
		log.WithError(err).Error("[Global Threat Feeds] failed to parse snapshot for feed", feedCacher.GetGlobalThreatFeed().GlobalThreatFeed.Name)
		utils.AddErrorToFeedStatus(feedCacher, cacher.PullFailed, err)
		return err
	}

	h.setHandler.updateDataStore(ctx, name, snapshot, h.syncFailFunction, feedCacher)
	h.setHandler.handleSnapshot(ctx, snapshot, feedCacher, h.syncFailFunction)
	updateFeedStatusAfterSuccessfulPull(feedCacher, time.Now())

	return nil
}

// updateFeedStatusAfterSuccessfulPull is called after a sync to GlobalNetworkSet succeeds.
// It updates the GlobalThreatFeed.Status.LastSuccessfulSync timestamp with a retry mechanism.
// A retry only kicks off when the update failure is caused by a StatusConflict and it will retry at most cacher.MaxUpdateRetry times
func updateFeedStatusAfterSuccessfulPull(feedCacher cacher.GlobalThreatFeedCacher, lastSuccessfulSync time.Time) {
	getCachedFeedResponse := feedCacher.GetGlobalThreatFeed()
	if getCachedFeedResponse.Err != nil {
		log.WithError(getCachedFeedResponse.Err).
			Error("[Global Threat Feeds] abort updating feed status after successful pull because failed to retrieve cached GlobalThreatFeed CR")
		return
	}
	if getCachedFeedResponse.GlobalThreatFeed == nil {
		log.Error("[Global Threat Feeds] abort updating feed status after successful pull because cached GlobalThreatFeed CR cannot be empty")
		return
	}

	toBeUpdated := getCachedFeedResponse.GlobalThreatFeed
	for i := 1; i <= cacher.MaxUpdateRetry; i++ {
		log.Debug(fmt.Sprintf("[Global Threat Feeds] %d/%d attempt to update feed %v status after successful pull", i, cacher.MaxUpdateRetry, feedCacher.GetGlobalThreatFeed().GlobalThreatFeed.Name))
		if toBeUpdated.Status.LastSuccessfulSync == nil || lastSuccessfulSync.After(toBeUpdated.Status.LastSuccessfulSync.Time) {
			toBeUpdated.Status.LastSuccessfulSync = &meta.Time{Time: lastSuccessfulSync}
		} else {
			log.Errorf("[Global Threat Feeds] abort updating feed %v status after successful pull because the current attempt is out of date", feedCacher.GetGlobalThreatFeed().GlobalThreatFeed.Name)
			return
		}
		errorcondition.ClearError(&toBeUpdated.Status, cacher.PullFailed)
		updateResponse := feedCacher.UpdateGlobalThreatFeedStatus(toBeUpdated)
		updateErr := updateResponse.Err
		if updateErr == nil {
			log.Debugf("[Global Threat Feeds] attempt to update feed %v status after successful pull succeeded, exiting the loop", feedCacher.GetGlobalThreatFeed().GlobalThreatFeed.Name)
			return
		}
		statusErr, ok := updateErr.(*apiErrors.StatusError)
		if !ok || statusErr.Status().Code != http.StatusConflict {
			log.WithError(updateErr).Errorf("[Global Threat Feeds] abort updating feed %v status after successful pull due to unrecoverable failure", feedCacher.GetGlobalThreatFeed().GlobalThreatFeed.Name)
			return
		}
		log.WithError(updateErr).Errorf("[Global Threat Feeds] failed updating feed %v status after successful pull", feedCacher.GetGlobalThreatFeed().GlobalThreatFeed.Name)
		toBeUpdated = updateResponse.GlobalThreatFeed
	}
}
