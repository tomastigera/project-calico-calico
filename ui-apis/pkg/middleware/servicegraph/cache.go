// Copyright (c) 2021-2023 Tigera, Inc. All rights reserved.
package servicegraph

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/libcalico-go/lib/jitter"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
	"github.com/projectcalico/calico/ui-apis/pkg/middleware"
)

// This file provides a cache-backed interface for service graph data.
//
// The cache is a warm cache. It keeps a number of data sets cached so that subsequent queries requiring the same
// underlying data will be handled from the cache. The cache contains unfiltered correlated L3 and L7 flows, and events.
// Each set of cached data may be accessed by any user because the raw cached data is post-processed to provide a
// user-specific subset of data.
//
// Data requested using relative times (e.g. now-15m to now) are updated in the background, so that subsequent requests
// using the same relative time interval will return regularly updated cached values for the same relative range.
// The Force Refresh option in the service graph request parameters may be used if the data is not updating fast enough,
// but that will obviously impact response times because the cache would then be cold for that request.
//
// There are a number of different configuration parameters available to configure the size, refresh interval and max
// age of cache entries. See pkg/server/config.go for details.
// TODO(rlb): Future iterations may use runtime stats to determine how the cache grows and ages out, and perhaps control
//            garbage collection.

const (
	// This is the default request time range from Tigera Manager.
	// Update this when Manager changes the default value.
	defaultRequestTimeRange = 15 * time.Minute
)

type ServiceGraphCache interface {
	GetFilteredServiceGraphData(ctx context.Context, rd *RequestData) (*ServiceGraphData, error)
	GetCacheSize() int
}

func NewServiceGraphCache(client ctrlclient.WithWatch, backend ServiceGraphBackend, cfg *Config) ServiceGraphCache {
	ctx := context.Background()
	sgc := &serviceGraphCache{
		ctx:     ctx,
		cache:   make(map[cacheKey]*cacheEntry),
		backend: backend,
		cfg:     cfg,
	}
	go sgc.backgroundCacheUpdateLoop()
	if cfg.ServiceGraphCacheDataPrefetch {
		sgc.prefetchRawData(ctx, client)
	}

	return sgc
}

type TimeSeriesFlow struct {
	Edge                 FlowEdge
	AggregatedProtoPorts *v1.AggregatedProtoPorts
	Stats                []v1.GraphStats
}

type TimeSeriesDNS struct {
	Endpoint FlowEndpoint
	Stats    []v1.GraphStats
}

func (t TimeSeriesFlow) String() string {
	if t.AggregatedProtoPorts == nil {
		return fmt.Sprintf("L3Flow %s", t.Edge)
	}
	return fmt.Sprintf("L3Flow %s (%s)", t.Edge, t.AggregatedProtoPorts)
}

type ServiceGraphData struct {
	TimeIntervals         []lmav1.TimeRange
	FilteredFlows         []TimeSeriesFlow
	FilteredDNSClientLogs []TimeSeriesDNS
	ServiceGroups         ServiceGroups
	NameHelper            NameHelper
	Events                []Event
	ServiceLabels         map[v1.NamespacedName]LabelSelectors
	ResourceLabels        map[v1.NamespacedName]LabelSelectors
	Truncated             bool
}

type serviceGraphCache struct {
	// The process context.
	ctx context.Context

	// The service graph backend.
	backend ServiceGraphBackend

	// The service graph config
	cfg *Config

	// We cache a number of different sets of data.
	lock  sync.Mutex
	cache map[cacheKey]*cacheEntry

	// Cached data queue in the order of most recently accessed first.
	queue cacheEntryQueue
}

// GetCacheSize returns the current number of entries in the cache. Mostly for testing purposes.
func (s *serviceGraphCache) GetCacheSize() int {
	s.lock.Lock()
	defer s.lock.Unlock()
	return len(s.cache)
}

// GetFilteredServiceGraphData returns RBAC filtered service graph data:
// -  correlated (source/dest) flow logs and flow stats
// -  service groups calculated from flows
// -  event IDs correlated to endpoints
// TODO(rlb): The events are not RBAC filtered, instead events are overlaid onto the filtered graph view - so the
//
//	presence of a graph node or not is used to determine whether or not an event is included. This will likely
//	need to be revisited when we refine RBAC control of events.
func (s *serviceGraphCache) GetFilteredServiceGraphData(ctx context.Context, rd *RequestData) (*ServiceGraphData, error) {
	// Run the following queries in parallel.
	// - Get the RBAC filter
	// - Get the host name mapping helper
	// - Get the raw data.
	log.Debugf("GetFilteredServiceGraphData called with time range: %s", rd.ServiceGraphRequest.TimeRange)
	var cacheData *cacheData
	var rbacFilter RBACFilter
	var nameHelper NameHelper
	var errCacheData, errRBACFilter, errNameHelper error
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		rbacFilter, errRBACFilter = s.backend.NewRBACFilter(ctx, rd)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		nameHelper, errNameHelper = s.backend.NewNameHelper(ctx, rd)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		cacheData, errCacheData = s.getRawDataForRequest(ctx, rd)
	}()
	wg.Wait()
	if errRBACFilter != nil {
		log.WithError(errRBACFilter).Error("Failed to load users permissions")
		return nil, errRBACFilter
	} else if errNameHelper != nil {
		log.WithError(errNameHelper).Error("Failed to load name mappings")
		return nil, errNameHelper
	} else if errCacheData != nil {
		log.WithError(errCacheData).Error("Failed to load raw graph data")
		return nil, errCacheData
	}

	// Construct the service graph data by filtering the L3 and L7 data. Return the time range of the actual data
	// rather than the request.
	fd := &ServiceGraphData{
		TimeIntervals: []lmav1.TimeRange{cacheData.timeRange},
		ServiceGroups: NewServiceGroups(),
		NameHelper:    nameHelper,
		Truncated:     cacheData.truncated(),
	}

	// Filter the L3 flows based on RBAC. All other graph content is removed through graph pruning. Note that L3 logs
	// are accessible by the user since this is checked in the chained handler early in the request processing.
	for _, rf := range cacheData.l3 {
		if !rbacFilter.IncludeFlow(rf.Edge) {
			continue
		}

		// Update the names in the flow (if required).
		rf = nameHelper.ConvertL3Flow(rf)

		if rf.Edge.ServicePort != nil {
			fd.ServiceGroups.AddMapping(*rf.Edge.ServicePort, rf.Edge.Dest)
		}
		stats := rf.Stats

		fd.FilteredFlows = append(fd.FilteredFlows, TimeSeriesFlow{
			Edge:                 rf.Edge,
			AggregatedProtoPorts: rf.AggregatedProtoPorts,
			Stats: []v1.GraphStats{{
				L3:        &stats,
				Processes: rf.Processes,
			}},
		})
	}

	// Filter the L7 flows based on RBAC. All other graph content is removed through graph pruning.
	if s.cfg.ServiceGraphCacheFetchL7 && rbacFilter.IncludeL7Logs() {
		for _, rf := range cacheData.l7 {
			if !rbacFilter.IncludeFlow(rf.Edge) {
				continue
			}

			// Update the names in the flow (if required).
			rf = nameHelper.ConvertL7Flow(rf)

			if rf.Edge.ServicePort != nil {
				fd.ServiceGroups.AddMapping(*rf.Edge.ServicePort, rf.Edge.Dest)
			}
			stats := rf.Stats

			fd.FilteredFlows = append(fd.FilteredFlows, TimeSeriesFlow{
				Edge: rf.Edge,
				Stats: []v1.GraphStats{{
					L7: &stats,
				}},
			})
		}
	}

	// We have loaded all L3 and L7 data.  Finish the service group mappings.
	fd.ServiceGroups.FinishMappings()

	// Filter the DNS logs based on RBAC. All other graph content is removed through graph pruning.
	if s.cfg.ServiceGraphCacheFetchDNS && rbacFilter.IncludeDNSLogs() {
		for _, dl := range cacheData.dns {
			if !rbacFilter.IncludeEndpoint(dl.Endpoint) {
				continue
			}

			stats := dl.Stats
			fd.FilteredDNSClientLogs = append(fd.FilteredDNSClientLogs, TimeSeriesDNS{
				Endpoint: dl.Endpoint,
				Stats: []v1.GraphStats{{
					DNS: &stats,
				}},
			})
		}
	}

	// Filter the events.
	if s.cfg.ServiceGraphCacheFetchEvents && rbacFilter.IncludeAlerts() {
		for _, ev := range cacheData.events {
			// Update the names in the events (if required).
			ev = nameHelper.ConvertEvent(ev)
			fd.Events = append(fd.Events, ev)
		}
	}

	fd.ServiceLabels = cacheData.serviceLabels
	fd.ResourceLabels = cacheData.resourceLabels

	return fd, nil
}

// getRawDataForRequest returns the raw data used to fulfill a request.
func (s *serviceGraphCache) getRawDataForRequest(ctx context.Context, rd *RequestData) (cd *cacheData, err error) {
	start := time.Now()
	log.Debug("getRawDataForRequest called")
	defer func() {
		log.WithError(err).Infof("getRawDataForRequest took %s", time.Since(start))
	}()

	// Convert the time range to a key.
	key, kerr := s.calculateKey(rd)
	if kerr != nil {
		return nil, err
	}
	logCxt := log.WithField("key", key)
	logCxt.Debug("Getting raw entry")

	// Lock to access the cache. Grab the current entry or create a new entry and kick off a query. This approach allows
	// multiple concurrent accesses of the same entry - but only one goroutine will create a new entry and kick off a
	// query.
	s.lock.Lock()
	entry := s.getEntry(key)
	var data *cacheData

	if entry == nil {
		// There is no entry, so create a new one - this will kick off async population of the data.
		logCxt.Debug("Creating new cache entry")
		entry = s.newEntry(key)
		data = entry.data
	} else {
		// There is an existing entry.
		logCxt.Debug("Using existing cache entry")
		data = entry.data

		if rd.ServiceGraphRequest.ForceRefresh {
			logCxt.Debug("Forced update requested")

			// A forced refresh has been requested. If there is no update currently in progress then trigger one.
			if entry.update == nil {
				logCxt.Debug("Triggering fresh update")
				s.updateEntry(entry)
			}
			data = entry.update
		}
	}

	// Increment the count of requests.
	entry.requests++

	// Release the lock.
	s.lock.Unlock()

	// When we exit, decrement the requests count again and touch the entry to update access times. We need the lock to
	// do this.
	defer func() {
		s.lock.Lock()
		entry.requests--
		s.touchEntry(entry)
		s.lock.Unlock()
	}()

	select {
	case <-ctx.Done():
		logCxt.Debug("Request context cancelled before request was fulfilled")
		if ctx.Err() == context.DeadlineExceeded {
			// This was a timeout, so return an error indicating the query progress.
			return nil, NewCacheTimeoutError(time.Since(data.created))
		}
		return nil, ctx.Err()
	case <-data.pending:
	}

	// We can still return truncated data provided we at least have L3 data.
	if data.err != nil && (data.err != errDataTruncatedError || len(data.l3) == 0) {
		logCxt.Debug("Request fulfilled with error response")
		return nil, data.err
	}

	logCxt.Debug("Request fulfilled successfully")
	return data, nil
}

// getEntry returns the cached data for the specified key.
//
// Lock is held by caller.
func (s *serviceGraphCache) getEntry(k cacheKey) *cacheEntry {
	return s.cache[k]
}

// newEntry creates a new entry and kicks off the data population.
func (s *serviceGraphCache) newEntry(key cacheKey) *cacheEntry {
	// Create a new entry and add it to the queue.
	ctx, cancel := context.WithCancel(s.ctx)
	entry := &cacheEntry{
		ctx:      ctx,
		cancel:   cancel,
		cacheKey: key,
		accessed: time.Now(),
	}
	s.addEntry(entry)

	// Kick off an update for this entry.
	s.updateEntry(entry)

	// For entry creation, the update and the main data are the same thing - so copy the update pointer across.
	entry.data = entry.update

	return entry
}

// touchEntry updates the accessed time and moves the data to the front of the queue.
//
// Lock is held by caller.
func (s *serviceGraphCache) touchEntry(d *cacheEntry) {
	d.accessed = time.Now()
	s.queue.add(d)
}

// removeEntry removes the data from the cache.
//
// Lock is held by caller.
func (s *serviceGraphCache) removeEntry(d *cacheEntry) {
	delete(s.cache, d.cacheKey)
	s.queue.remove(d)
}

// addEntry adds the data to the cache.
//
// Lock is held by caller.
func (s *serviceGraphCache) addEntry(d *cacheEntry) {
	s.cache[d.cacheKey] = d
	s.queue.add(d)
}

// updateEntry ensures an update is in progress for the entry. On return entry.update is non-nil.
//
// Lock is held by caller.
func (s *serviceGraphCache) updateEntry(e *cacheEntry) {
	if e.update != nil {
		// An update is already in progress so nothing more to do here.
		return
	}
	// Kick off the query on a go routine so we can unlock and unblock other go routines.
	e.update = newCacheData(e.cacheKey)
	go func() {
		s.populateData(e, e.update)

		// If the entry needs discarding then remove it...
		s.lock.Lock()
		defer s.lock.Unlock()

		// Copy across the update to the main data for the entry.
		if e.update.err == nil {
			e.data = e.update
		}
		e.update = nil

		// Discard the entry if it is errored and the error is not a truncated error.  We maintain truncation errors
		// because we don't want the client to keep triggering this query.
		if e.data.err != nil && e.data.err != errDataTruncatedError {
			s.removeEntry(e)
		}

		// Discard the cache entry when flow logs are empty as ServiceGraph nodes and edges are calculated based on flows.
		// It is less likely for a cluster to have no flows. It happens when the cluster is newly installed and logcollector
		// haven't yet send logs to datastore or the entire cluster got stopped and restarted.
		if len(e.data.l3) == 0 {
			s.removeEntry(e)
		}

		// and tidy the cache to maintain cache size and age out old entries.
		s.tidyCache()
	}()
}

// tidyCache is called after adding new entries to the cache, or during the update poll. It removes oldest entries from
// the cache to maintain cache size and removes polled entries that have not been accessed for a long time (to avoid
// continuously polling).
//
// Lock is held by caller.
func (s *serviceGraphCache) tidyCache() {
	// Aged out cutoff time for slow queries that have not completed based on last access.
	cutoff := time.Now().Add(-s.cfg.ServiceGraphCacheSlowQueryEntryAgeOut)

	// Remove any entries that have excessively slow queries and are no longer required by any user.
	entry := s.queue.first
	for entry != nil {
		next := entry.next

		data := entry.data
		select {
		case <-data.pending:
			// The data is already populated, so does not require the slow-query handling.
		default:
			// The data is still pending and may need the slow-query handling.
			if entry.requests == 0 && entry.accessed.Before(cutoff) {
				// There are no requests waiting for this data, it is not yet populated and it was last accessed before
				// the slow-query cut-off time.  Cancel the query and then remove the data.
				log.Infof("Removing aged out unpopulated cache entry and canceling query: %s", entry.cacheKey)
				entry.cancel()
				s.removeEntry(entry)
			}
		}

		entry = next
	}

	// Aged out cutoff time based on last access.
	cutoff = time.Now().Add(-s.cfg.ServiceGraphCachePolledEntryAgeOut)

	// Remove all aged-out relative time entries - this avoids unnecessary polling.
	entry = s.queue.first
	for entry != nil {
		next := entry.next
		if entry.relative && entry.accessed.Before(cutoff) {
			log.Debugf("Removing aged out cache entry: %s", entry.cacheKey)
			s.removeEntry(entry)
		}
		entry = next
	}

	// Remove oldest entries to maintain cache size, but don't remove entries that are actively being requested.
	entry = s.queue.last
	for entry != nil {
		if len(s.cache) <= s.cfg.ServiceGraphCacheMaxEntries {
			// Cache size is within limits, so exit.
			break
		}

		// Remove oldest entries that are not actively being requested.
		prev := entry.prev
		if entry.requests == 0 {
			log.Debugf("Removing cache entry to keep cache size maintained: %s", entry.cacheKey)
			s.removeEntry(entry)
		}
		entry = prev
	}
}

// backgroundCacheUpdateLoop loops until done, updating cache entries every tick.
func (s *serviceGraphCache) backgroundCacheUpdateLoop() {
	loopTicker := jitter.NewTicker(s.cfg.ServiceGraphCachePollLoopInterval, s.cfg.ServiceGraphCachePollLoopInterval/10)
	defer loopTicker.Stop()
	queryTicker := jitter.NewTicker(s.cfg.ServiceGraphCachePollQueryInterval, s.cfg.ServiceGraphCachePollQueryInterval/10)
	defer queryTicker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-loopTicker.C:
			log.Debug("Starting cache update cycle")
		}

		// Grab the lock and construct the set of cache entries that need updating.
		var entriesToUpdate []*cacheEntry
		createdCutoff := time.Now().Add(-s.cfg.ServiceGraphCachePollLoopInterval / 2)
		settleCutoff := time.Now().Add(-s.cfg.ServiceGraphCacheDataSettleTime)

		// Start by tidying the cache and then loop through remaining cache entries to see which need updating.
		s.lock.Lock()
		s.tidyCache()
		for entry := s.queue.last; entry != nil; entry = entry.prev {
			if entry.needsUpdating(createdCutoff, settleCutoff) {
				// This cache entry needs updating.
				entriesToUpdate = append(entriesToUpdate, entry)
			}
		}
		s.lock.Unlock()

		// Process the entries on a ticker to avoid a deluge of requests. Each request kicks off a background goroutine
		// so that slow queries will not block this processing.
		for _, entry := range entriesToUpdate {
			log.Debugf("Checking cache entry: %s", entry.cacheKey)
			select {
			case <-s.ctx.Done():
				return
			case <-queryTicker.C:
				// Hold the lock while we kick off an update.
				s.lock.Lock()
				if entry.needsUpdating(createdCutoff, settleCutoff) {
					s.updateEntry(entry)
				}
				s.lock.Unlock()
			}
		}

		log.Debug("Finished cache update cycle")
	}
}

func (s *serviceGraphCache) prefetchRawData(ctx context.Context, client ctrlclient.WithWatch) {
	log.Info("Prefetch cluster raw data to warm up cache")

	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Start with the default cluster name
	clusterNames := []string{lmak8s.DefaultCluster}

	// Add managed cluster names
	mcs := &v3.ManagedClusterList{}
	if err := client.List(context.Background(), mcs, &ctrlclient.ListOptions{Namespace: s.cfg.TenantNamespace}); err != nil {
		log.WithError(err).Info("failed to list managed clusters. prefetching raw data for managed clusters are skipped")
	} else {
		for _, managedCluster := range mcs.Items {
			clusterNames = append(clusterNames, managedCluster.Name)
		}
	}

	now := time.Now().UTC()
	from := now.Add(-defaultRequestTimeRange)
	for _, clusterName := range clusterNames {
		rd := &RequestData{
			ServiceGraphRequest: &v1.ServiceGraphRequest{
				Cluster: clusterName,
				TimeRange: &lmav1.TimeRange{
					From: from,
					To:   now,
					Now:  &now,
				},
				Timeout: metav1.Duration{
					Duration: middleware.DefaultRequestTimeout,
				},
			},
		}
		if _, err := s.getRawDataForRequest(ctx, rd); err != nil {
			log.WithError(err).WithField("cluster", clusterName).Info("failed to prefetch raw data and skipped")
		} else {
			log.WithField("cluster", clusterName).Info("Prefetch raw data is successful")
		}
	}
}

// calculateKey calculates the cache data key for the request.
func (s *serviceGraphCache) calculateKey(rd *RequestData) (cacheKey, error) {
	var namespaces string
	if rd.ServiceGraphRequest.CacheByFocus {
		namespacesSlice, err := ParseNamespacesFromFocus(rd.ServiceGraphRequest.SelectedView)
		if err != nil {
			return cacheKey{}, err
		}
		namespaces = strings.Join(namespacesSlice, ",")
	}

	if rd.ServiceGraphRequest.TimeRange.Now == nil {
		return cacheKey{
			relative:   false,
			start:      rd.ServiceGraphRequest.TimeRange.From.Unix(),
			end:        rd.ServiceGraphRequest.TimeRange.To.Unix(),
			cluster:    rd.ServiceGraphRequest.Cluster,
			namespaces: namespaces,
		}, nil
	}
	return cacheKey{
		relative:   true,
		start:      int64(rd.ServiceGraphRequest.TimeRange.Now.Sub(rd.ServiceGraphRequest.TimeRange.From) / time.Second),
		end:        int64(rd.ServiceGraphRequest.TimeRange.Now.Sub(rd.ServiceGraphRequest.TimeRange.To) / time.Second),
		cluster:    rd.ServiceGraphRequest.Cluster,
		namespaces: namespaces,
	}, nil
}

// populateData performs the various queries to get raw log data and updates the cacheEntry.
func (s *serviceGraphCache) populateData(e *cacheEntry, d *cacheData) {
	log.Debugf("Populating data from linseed and k8s queries: %s", e.cacheKey)

	// When this finishes, close the pending channel so threads waiting for this to populate can complete.
	defer close(d.pending)

	// At the moment there is no cache and only a single data point in the flow. Kick off the L3 and L7 queries at the
	// same time.
	wg := sync.WaitGroup{}
	var rawL3 []L3Flow
	var rawL7 []L7Flow
	var rawDNS []DNSLog
	var rawEvents []Event
	var serviceLabels map[v1.NamespacedName]LabelSelectors
	var replicaSetsLabels map[v1.NamespacedName]LabelSelectors
	var statefulSetsLabels map[v1.NamespacedName]LabelSelectors
	var daemonSetsLabels map[v1.NamespacedName]LabelSelectors
	var podsLabels map[v1.NamespacedName]LabelSelectors
	var errL3, errL7, errDNS, errEvents error
	var errServiceLabels, errReplicaSetsLabels, errStatefulSetsLabels, errDaemonSetsLabels, errPodsLabels error

	// Determine the flow config - we need this to process the flow data correctly.
	flowConfig, err := s.backend.GetFlowConfig(e.ctx, e.cluster)
	if err != nil {
		log.WithError(err).Error("failed to get felix flow configuration")
		d.err = err
		return
	}

	// Run simultaneous queries to get the L3, L7 and events data.
	wg.Add(1)
	go func() {
		defer wg.Done()
		rawL3, errL3 = s.backend.GetL3FlowData(e.ctx, e.cluster, e.namespaces, d.timeRange, flowConfig)
	}()
	if s.cfg.ServiceGraphCacheFetchL7 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rawL7, errL7 = s.backend.GetL7FlowData(e.ctx, e.cluster, d.timeRange)
		}()
	}
	if s.cfg.ServiceGraphCacheFetchDNS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rawDNS, errDNS = s.backend.GetDNSData(e.ctx, e.cluster, d.timeRange)
		}()
	}
	if s.cfg.ServiceGraphCacheFetchEvents {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rawEvents, errEvents = s.backend.GetEvents(e.ctx, e.cluster, d.timeRange)
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		serviceLabels, errServiceLabels = s.backend.GetServiceLabels(e.ctx, e.cluster)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		replicaSetsLabels, errReplicaSetsLabels = s.backend.GetReplicaSetLabels(e.ctx, e.cluster)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		statefulSetsLabels, errStatefulSetsLabels = s.backend.GetStatefulSetLabels(e.ctx, e.cluster)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		daemonSetsLabels, errDaemonSetsLabels = s.backend.GetDaemonSetLabels(e.ctx, e.cluster)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		podsLabels, errPodsLabels = s.backend.GetPodsLabels(e.ctx, e.cluster)
	}()
	wg.Wait()
	if errL3 != nil {
		log.WithError(errL3).Error("failed to get l3 logs")
		d.err = errL3
	} else if errL7 != nil {
		log.WithError(errL7).Error("failed to get l7 logs")
		d.err = errL7
	} else if errDNS != nil {
		log.WithError(errDNS).Error("failed to get DNS logs")
		d.err = errDNS
	} else if errEvents != nil {
		log.WithError(errEvents).Error("failed to get event logs")
		d.err = errEvents
	} else if errServiceLabels != nil {
		log.WithError(errServiceLabels).Error("failed to get service labels")
		d.err = errServiceLabels
	} else if errReplicaSetsLabels != nil {
		log.WithError(errReplicaSetsLabels).Error("failed to get replica sets labels")
		d.err = errReplicaSetsLabels
	} else if errStatefulSetsLabels != nil {
		log.WithError(errStatefulSetsLabels).Error("failed to get stateful sets labels")
		d.err = errStatefulSetsLabels
	} else if errDaemonSetsLabels != nil {
		log.WithError(errDaemonSetsLabels).Error("failed to get daemon sets labels")
		d.err = errDaemonSetsLabels
	} else if errPodsLabels != nil {
		log.WithError(errPodsLabels).Error("failed to get pods labels")
		d.err = errPodsLabels
	}

	// Store results - even if an error was returned, some results may have still been returned as well.
	d.l3 = rawL3
	d.l7 = rawL7
	d.dns = rawDNS
	d.events = rawEvents
	d.serviceLabels = serviceLabels
	d.resourceLabels = addValues(d.resourceLabels, replicaSetsLabels)
	d.resourceLabels = addValues(d.resourceLabels, statefulSetsLabels)
	d.resourceLabels = addValues(d.resourceLabels, daemonSetsLabels)
	d.resourceLabels = addValues(d.resourceLabels, podsLabels)

	if log.IsLevelEnabled(log.DebugLevel) {
		log.Debug(" ========= Tracing output from raw queries ========= ")
		if b, err := json.Marshal(d.l3); err == nil {
			log.Debugf("RawL3: %s", b)
		}
		if b, err := json.Marshal(d.l7); err == nil {
			log.Debugf("RawL7: %s", b)
		}
		if b, err := json.Marshal(d.dns); err == nil {
			log.Debugf("RawDNS: %s", b)
		}
		if b, err := json.Marshal(d.events); err == nil {
			log.Debugf("RawEvents: %s", b)
		}
		log.Debugf("ServiceLabels: %s", d.serviceLabels)
		log.Debugf("ResourceLabels: %s", d.resourceLabels)
		log.Debug(" ========= End of tracing ========= ")
	}

	log.Debugf("Updated data: %s", e.cacheKey)
}

func addValues(source map[v1.NamespacedName]LabelSelectors, newValues map[v1.NamespacedName]LabelSelectors) map[v1.NamespacedName]LabelSelectors {
	if source == nil {
		source = make(map[v1.NamespacedName]LabelSelectors)
	}

	for k, v := range newValues {
		source[k] = v
	}

	return source
}

// cacheEntry contains entry for a requested window.
type cacheEntry struct {
	cacheKey

	// Context and cancel. The parent context is the main process context rather than the request context since the
	// cache population is handled by the cache and not by the request. The request triggers the cache to populate.
	// The cache needs to cancel long running requests that are no longer explicitly required by any clients.
	ctx    context.Context
	cancel context.CancelFunc

	// ==== lock required for accessing the following data ====

	// The previous and next most recently accessed entries. A nil entry indicates the end of the queue (see
	// cacheEntryQueue below).
	prev *cacheEntry
	next *cacheEntry

	// Requests waiting for this data. Incremented upon request and decremented when the request is fulfilled.
	requests int

	// The time this entry was last accessed and is updated upon returning the response. This is used to maintain the
	// cache entries based on time, in particular the tidyCache processing ages out the following:
	// - relative time entries that have not been accessed for some amount of time are removed so that we don't just
	//   keep querying forever (*)
	// - long-running queries that are no longer being requested by the client to avoid queries that the user has
	//   effectively aborted.
	//
	// (*) Note that only relative time entries (e.g. now-1hr->now) are continuously updated in the background. Fixed
	//     time entries (e.g. 1p->3:30p) are not updated indefinitely and therefore can remain in the cache until they
	//     are removed due to cache size limits.
	accessed time.Time

	// Active data associated with this cache entry. This is always non-nil.
	data *cacheData

	// Pending update.  There can only be one pending update for each cache entry - this avoids the situation where we
	// have a background update happening at the same time as a forced update request.
	update *cacheData
}

// cacheData contains the queried data and is part of the cacheEntry.
type cacheData struct {
	// Channel is closed once data has been fetched.
	pending chan struct{}

	// The time this entry was created.
	created time.Time

	// ==== cached data:  This is read safe without any locks once the pending channel is closed ====

	// Error obtained attempting to fetch the data.
	err error

	// The time range for this data.
	timeRange lmav1.TimeRange

	// The queried data.
	l3             []L3Flow
	l7             []L7Flow
	dns            []DNSLog
	events         []Event
	serviceLabels  map[v1.NamespacedName]LabelSelectors
	resourceLabels map[v1.NamespacedName]LabelSelectors
}

func (d *cacheData) truncated() bool {
	return d.err == errDataTruncatedError
}

func newCacheData(key cacheKey) *cacheData {
	// Construct a time range for this data.
	created := time.Now().UTC()
	var tr lmav1.TimeRange
	if key.relative {
		tr.From = created.Add(time.Duration(-key.start) * time.Second)
		tr.To = created.Add(time.Duration(-key.end) * time.Second)
	} else {
		tr.From = time.Unix(key.start, 0)
		tr.To = time.Unix(key.end, 0)
	}

	return &cacheData{
		pending:   make(chan struct{}),
		created:   created,
		timeRange: tr,
	}
}

// needsUpdating returns true if this particular cache data should be updated.
//
// Lock should be held by caller.
func (e *cacheEntry) needsUpdating(createdCutoff, settleCutoff time.Time) bool {
	if e.update != nil {
		// An update is already in progress.
		return false
	}

	// No update is in progress. If the original request is not pending then check if the creation time indicates we
	// should update.
	select {
	case <-e.data.pending:
		// Data is populated. Check creation time.
		if e.data.err != nil {
			// Failed to previously fetch the data and so does need updating.
			return true
		} else if createdCutoff.Before(e.data.created) {
			// This entry was created recently and so does not need updating.
			return false
		} else if e.relative {
			// This indicates a time relative to "now". This entry should be updated.
			return true
		} else if settleCutoff.Before(time.Unix(e.end, 0)) {
			// The entry is not relative to now and the end time of the entry is sufficiently recent we should do an
			// update to allow for late arriving data.
			return true
		}
		return false
	default:
		// Still pending the original request so does not need updating.
		return false
	}
}

// cacheEntryQueue is a queue struct used for queueing cacheEntry for access order.
type cacheEntryQueue struct {
	// Track the order these cached intervals are accessed.
	first *cacheEntry
	last  *cacheEntry
}

// add adds the cached data to the front of the queue. This may be called with data already in the queue.
func (q *cacheEntryQueue) add(d *cacheEntry) {
	if q.first == d {
		// Already the most recently accessed entry.
		return
	}
	if d.next != nil || d.prev != nil {
		// Already in the queue, so remove from the queue first.
		q.remove(d)
	}
	if q.first == nil {
		// The first entry to be added.
		q.first = d
		q.last = d
		return
	}
	q.first.prev, q.first, d.next = d, d, q.first
}

// remove removes the cached data from the queue. This may be called with data not in the queue.
func (q *cacheEntryQueue) remove(d *cacheEntry) {
	prev := d.prev
	next := d.next

	if prev != nil {
		prev.next = next
	} else if q.first == d {
		q.first = next
	}

	if next != nil {
		next.prev = prev
	} else if q.last == d {
		q.last = prev
	}

	d.prev = nil
	d.next = nil
}

// cacheKey is a key for accessing cacheEntry. It is basically a time and window combination, allowing for times
// relative to "now".   A time range "now-15m to now" will have the same key irrespective of the actual time (now).
type cacheKey struct {
	// Whether the time is absolute or relative to now.
	relative bool

	// The namespaces of this cache key.
	// Set if the originating request specified caching by focus, and the focus yielded a subset of all namespaces that
	// contains the entirety of the data required for the focus.
	namespaces string

	// If "relative" is true these are the start and end Unix time in seconds.
	// If "relative" is false, these are the offsets from "now" in seconds.
	start int64
	end   int64

	// The cluster name.
	cluster string
}

func (k cacheKey) String() string {
	if k.relative {
		start := time.Duration(k.start) * time.Second
		end := time.Duration(k.end) * time.Second
		return fmt.Sprintf("%s(now-%s->now-%s)", k.cluster, start, end)
	}
	start := time.Unix(k.start, 0)
	end := time.Unix(k.end, 0)
	return fmt.Sprintf("%s(%s->%s)", k.cluster, start, end)
}
