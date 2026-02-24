// Copyright (c) 2025 Tigera, Inc. All rights reserved.
package servicegraph

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/tools/cache"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	"github.com/projectcalico/calico/lma/pkg/auth"
	"github.com/projectcalico/calico/lma/pkg/httputils"
	"github.com/projectcalico/calico/lma/pkg/k8s"
	"github.com/projectcalico/calico/pkg/managedcluster"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
	"github.com/projectcalico/calico/ui-apis/pkg/middleware"
)

func NewServiceGraphStatsHandler(
	client ctrlclient.WithWatch,
	linseed lsclient.Client,
	clientSetFactory k8s.ClientSetFactory,
	cache ServiceGraphCache,
	config *Config,
) http.Handler {
	emptyServiceGroups := NewServiceGroups()
	emptyServiceGroups.FinishMappings()
	handler := serviceGraphStats{
		ctrlClient:         client,
		linseed:            linseed,
		clientSetFactory:   clientSetFactory,
		serviceGraphCache:  cache,
		emptyServiceGroups: emptyServiceGroups,
		config:             config,
		cachedStats:        make(map[string]*cachedStats),
	}
	go handler.cachedStatsUpdateLoop()
	return &handler
}

type serviceGraphStats struct {
	ctrlClient         ctrlclient.WithWatch
	linseed            lsclient.Client
	clientSetFactory   k8s.ClientSetFactory
	serviceGraphCache  ServiceGraphCache
	emptyServiceGroups ServiceGroups
	config             *Config
	cachedStats        map[string]*cachedStats
	cachedStatsMutex   sync.RWMutex
}

type cachedStats struct {
	l3FlowTotalCount        int64
	flowLogNamespacedCounts map[string]int64
	l3FlowNamespacedCounts  map[string]int64
}

func (s *serviceGraphStats) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r, err := s.getServiceGraphStatsRequest(w, req)
	if err != nil {
		httputils.EncodeError(w, err)
		return
	}

	var response *v1.ServiceGraphStatsResponse
	response, err = s.getGraphStatistics(req, r)
	if err != nil {
		httputils.EncodeError(w, err)
		return
	}

	httputils.Encode(w, response)
}

// getServiceGraphStatsRequest parses and validates the HTTP request body.
func (s *serviceGraphStats) getServiceGraphStatsRequest(w http.ResponseWriter, req *http.Request) (*v1.ServiceGraphStatsRequest, error) {
	var sgr v1.ServiceGraphStatsRequest
	if err := httputils.Decode(w, req, &sgr); err != nil {
		return nil, err
	}

	if err := validator.Validate(sgr); err != nil {
		return nil, &httputils.HttpStatusError{
			Status: http.StatusBadRequest,
			Msg:    fmt.Sprintf("Request body contains invalid data: %v", err),
			Err:    err,
		}
	}

	if sgr.Timeout.Duration == 0 {
		sgr.Timeout.Duration = middleware.DefaultRequestTimeout
	}

	cluster := middleware.MaybeParseClusterNameFromRequest(req)
	if sgr.Cluster == "" {
		sgr.Cluster = cluster
	}

	return &sgr, nil
}

// getGraphStatistics is responsible for computing whether, for a given time range, the service graph will take too long to load.
// The service graph takes too long to load if:
// - the count of flow logs is too high, OR
// - the count of L3 flows is too high for the time range
//
// This is because the service graph relies primarily on L3 flow data to build the graph, and L3 flows are an aggregation of flow logs.
// If the count of flow logs is too high, the aggregation will take too long to process the data and generate buckets.
// If the count of L3 flows (i.e. buckets) is too high, computing the required sub-aggregations for each bucket will take too long.
//
// This function aims to compute whether the service graph will take too long to load (i.e. is high volume) at two scopes:
// - global scope (TopologyStatistics)
// - namespace scope (NamespacesStatistics)
//
// However, at a large enough scale of flow logs, computation at the namespace scope will simply take too long.
// To complete its work as soon as possible, this function launches its queries in parallel.
// If we detect that the scale of flow logs is too high, we selectively cancel namespace-scoped queries.
//
// A per-cluster cache of namespace counts over the last 3 days is maintained to provide an approximation of the namespace
// scale if namespace-scoped queries are canceled.
//
// The global computation is always set in the response, as is the list of namespaces themselves - if we can't compute
// either of these (due to some unexpected failure or timeout), we will return an error.
// Namespace-scoped computations are virtually always set on the response, either from a namespaced-scoped query or
// from an approximation using the cache as described above. It is possible for namespace computations to be omitted if
// the namespace-scoped query is cancelled and the cache has not been filled.
//
// This function is comprehensively tested in servicegraph_fv_test.go.
func (s *serviceGraphStats) getGraphStatistics(req *http.Request, r *v1.ServiceGraphStatsRequest) (*v1.ServiceGraphStatsResponse, error) {
	handlerStart := time.Now()
	cluster := r.Cluster
	ctx := req.Context()

	// Set up contexts for our queries.
	// - All queries are subject to a global timeout to ensure we do not take too long to respond.
	// - Queries that give us namespace-scoped information are cancelable if we determine that the scale of flow logs is too high.
	baseCtx, cancelBaseCtx := context.WithTimeout(ctx, time.Second*time.Duration(s.config.GlobalStatsTimeoutSeconds))
	l3FlowCtx, cancelL3Flows := context.WithCancel(baseCtx)
	flowLogNsCtx, cancelFlowLogNs := context.WithCancel(baseCtx)
	defer cancelBaseCtx()
	defer cancelL3Flows()
	defer cancelFlowLogNs()

	c := newStatsChannels()
	w := newStatsWaitgroups(s.config.ParallelGraphStatsFetch)

	// Launch all of our queries in parallel to minimize response time.
	go s.getFlowLogCount(baseCtx, cluster, r.TimeRange, w, c.flowLogCountsChan)
	go s.getNamespaces(baseCtx, cluster, s.clientSetFactory, c.namespacesChan)
	go s.getFlowLogNamespaceCounts(flowLogNsCtx, cluster, r.TimeRange, w, c.flowLogNamespacedCountsChan)
	go s.getL3FlowNamespaceCounts(l3FlowCtx, cluster, r.TimeRange, &s.config.LargeL3FlowScaleThreshold, w, c.l3FlowNamespacedCountsChan)

	// Collect the flow log count result.
	flowLogCountRes := <-c.flowLogCountsChan
	if flowLogCountRes.err != nil {
		// We need to fail the request. We are required to set the global computation in the response, and the global
		// computation depends on the flow log count.
		log.Warnf("Flow log counts query failed: %v", flowLogCountRes.err)
		return nil, flowLogCountRes.err
	}

	// Determine if we should cancel our namespaced-scoped queries.
	cancelNamespacedL3FlowCall := flowLogCountRes.totalCount >= s.config.LargeFlowLogScaleThreshold
	cancelNamespacedFlowLogCall := flowLogCountRes.totalCount >= s.config.XLargeFlowLogScaleThreshold
	if cancelNamespacedL3FlowCall {
		cancelL3Flows()
	}
	if cancelNamespacedFlowLogCall {
		cancelFlowLogNs()
	}

	// Wait for the remaining queries to complete. Our namespaced-scope queries might complete as a result of cancellation.
	namespacesRes := <-c.namespacesChan
	if namespacesRes.err != nil {
		// We need to fail the request. While we are not required to perform computations at the namespace level, we ARE
		// required to return the namespaces themselves.
		log.Warnf("Namespaces query failed: %v", namespacesRes.err)
		return nil, namespacesRes.err
	}
	l3FlowNamespaceCountsRes := <-c.l3FlowNamespacedCountsChan
	if l3FlowNamespaceCountsRes.err != nil && !strings.Contains(l3FlowNamespaceCountsRes.err.Error(), context.Canceled.Error()) {
		// If the L3 flow query failed, and it was not a result of our own cancellation, we need to fail the request.
		// We are required to set the global computation in the response, and the global computation depends on the L3 flow count.
		// In the case that we cancel the query, we know that the L3 flow count is not required because we already know the flow log count is high.
		log.Warnf("L3 flow namespaced counts query failed: %v", l3FlowNamespaceCountsRes.err)
		return nil, l3FlowNamespaceCountsRes.err
	}
	flowLogNamespaceCountsRes := <-c.flowLogNamespacedCountsChan
	if flowLogNamespaceCountsRes.err != nil && !strings.Contains(flowLogNamespaceCountsRes.err.Error(), context.Canceled.Error()) {
		// If the namespaced flow log count query fails, we can proceed with processing the request, since it is not part of any required computation.
		log.Warnf("Flow log namespaced counts query failed: %v", flowLogNamespaceCountsRes.err)
	}

	// Start building the response.
	response := v1.ServiceGraphStatsResponse{}
	if r.IncludeDeveloperStats {
		response.DeveloperStatistics = initializeDeveloperStatistics()
	}

	// Perform the global computation.
	response.TopologyStatistics.HighVolume = flowLogCountRes.totalCount >= s.config.LargeFlowLogScaleThreshold || l3FlowNamespaceCountsRes.totalCount >= s.config.LargeL3FlowScaleThreshold

	// Determine the namespaces to include in the response, and provide namespace-scoped scale determinations.
	// Utilize the fetched namespace-scoped data to provide scale determinations, otherwise approximate using our namespace count cache.
	approximated := true
	notApproximated := false
	responseNamespaces := s.calculateResponseNamespaces(namespacesRes, flowLogNamespaceCountsRes, l3FlowNamespaceCountsRes)
	for _, ns := range responseNamespaces {
		namespaceStat := v1.NamespaceStatistics{Namespace: ns}

		// Counts might not exist if we canceled the request, the request errored, or we ended pagination early.
		namespacedFlowCount, namespacedFlowCountExists := flowLogNamespaceCountsRes.namespacedCounts[ns]
		namespacedL3FlowCount, namespacedL3FlowCountExists := l3FlowNamespaceCountsRes.namespacedCounts[ns]

		if namespacedFlowCountExists && namespacedL3FlowCountExists {
			// We have both pieces of information, we can use our full boolean expression to compute.
			highVol := namespacedFlowCount >= s.config.LargeFlowLogScaleThreshold || namespacedL3FlowCount >= s.config.LargeL3FlowScaleThreshold
			namespaceStat.HighVolume = &highVol
			namespaceStat.Approximated = &notApproximated
		}

		if namespacedFlowCountExists && !namespacedL3FlowCountExists && namespacedFlowCount >= s.config.LargeFlowLogScaleThreshold {
			// We only have the flow log count, but it's high, so it short-circuits the full boolean expression.
			highVol := true
			namespaceStat.HighVolume = &highVol
			namespaceStat.Approximated = &notApproximated
		}

		if !namespacedFlowCountExists && namespacedL3FlowCountExists && namespacedL3FlowCount >= s.config.LargeL3FlowScaleThreshold {
			// We only have the L3 flow count, but it's high, so it short-circuits the full boolean expression.
			highVol := true
			namespaceStat.HighVolume = &highVol
			namespaceStat.Approximated = &notApproximated
		}

		// If we've been unable to compute the high volume flag for a namespace based on the exact counts, we'll approximate it.
		if namespaceStat.HighVolume == nil {
			approximateHighVolume, nsCache, err := s.getApproximateNamespaceScale(r.Cluster, r.TimeRange, ns)
			if err != nil {
				log.Debugf("Failed to compute approximate high volume flag for namespace %s: %v", ns, err)
			} else {
				namespaceStat.HighVolume = &approximateHighVolume
				namespaceStat.Approximated = &approximated
				if r.IncludeDeveloperStats {
					response.DeveloperStatistics.NamespaceCacheCounts.NumFlowLogs[ns] = nsCache.flowLogNamespacedCounts[ns]
					response.DeveloperStatistics.NamespaceCacheCounts.NumL3Flows[ns] = nsCache.l3FlowNamespacedCounts[ns]
				}
			}
		}
		response.NamespacesStatistics = append(response.NamespacesStatistics, namespaceStat)
	}

	// If the global volume is low, we determine the edge count for the resulting service graph.
	// This information is utilized by the UI, since at a certain edge count, the UI will take too long to render.
	// As a side effect, this also warms the service graph cache for the eventual service graph request.
	if !response.TopologyStatistics.HighVolume {
		sgr, err := s.fetchServiceGraphResponse(ctx, cluster, r.TimeRange, r.Timeout)
		if err != nil {
			log.Warnf("Service graph fetch failed: %v", err)
		} else {
			edgeCount := len(sgr.Edges)
			response.TopologyStatistics.NumEdges = &edgeCount
		}
	}

	if r.IncludeDeveloperStats {
		response.DeveloperStatistics.Counts.NumFlowLogs = flowLogCountRes.totalCount
		response.DeveloperStatistics.Counts.NumL3Flows = l3FlowNamespaceCountsRes.totalCount
		response.DeveloperStatistics.NamespaceCounts.NumFlowLogs = flowLogNamespaceCountsRes.namespacedCounts
		response.DeveloperStatistics.NamespaceCounts.NumL3Flows = l3FlowNamespaceCountsRes.namespacedCounts
		response.DeveloperStatistics.Cancellations.NamespacedFlowLogCounts = cancelNamespacedFlowLogCall
		response.DeveloperStatistics.Cancellations.L3FlowCounts = cancelNamespacedL3FlowCall
		response.DeveloperStatistics.Truncations.NamespacedFlowLogCounts = flowLogNamespaceCountsRes.truncated
		response.DeveloperStatistics.Truncations.L3FlowCounts = l3FlowNamespaceCountsRes.truncated
	}

	if s.config.GraphStatsRequestLogging {
		pfx := func(label string) string {
			return fmt.Sprintf("/stats cl=%s, tr=%s [%s]", cluster, r.TimeRange, label)
		}
		log.Infof("%s highVol: %v, fetched_fl: %v, fetched_l3: %v", pfx("summary"), response.TopologyStatistics.HighVolume, !cancelNamespacedFlowLogCall, !cancelNamespacedL3FlowCall)
		log.Infof("%s total: %v, ns: %v, flow: %v, flowNs: %v, l3flow: %v", pfx("durations"), time.Since(handlerStart), namespacesRes.duration, flowLogCountRes.duration, flowLogNamespaceCountsRes.duration, l3FlowNamespaceCountsRes.duration)
		log.Infof("%s flow: %v, l3flow: %v (truncated: %v)", pfx("counts"), flowLogCountRes.totalCount, l3FlowNamespaceCountsRes.totalCount, l3FlowNamespaceCountsRes.truncated)
		log.Infof("%s resp: %v, cluster: %v, auth'd: %v, flow: %v, l3flow: %v, global: %v", pfx("ns counts"), len(response.NamespacesStatistics), namespacesRes.numTotal, len(namespacesRes.authorizedAPIServerNamespaces), len(flowLogNamespaceCountsRes.namespacedCounts), len(l3FlowNamespaceCountsRes.namespacedCounts), namespacesRes.globalAccess)
	}

	return &response, nil
}

func (s *serviceGraphStats) calculateResponseNamespaces(namespacesRes namespacesResult, flowLogNamespaceCountsRes flowLogNamespacedCountResult, l3FlowNamespaceCountsRes l3FlowNamespacedCountResult) []string {
	responseNamespaceSet := set.New[string]()
	// Start with the namespaces returned by the Kubernetes API server that we know the user is authorized to view flow-related resources in.
	for authorizedAPIServerNamespace := range namespacesRes.authorizedAPIServerNamespaces {
		responseNamespaceSet.Add(authorizedAPIServerNamespace)
	}

	// We can only safely add namespaces found in flow logs if the user has cluster-wide access to flow-related resources.
	// This is because there is no guarantee that a namespace found in the flow logs exists in the Kubernetes API server.
	// If a namespace is not found in the Kubernetes API server, the only way we can say the user is authorized to see it is
	// if they have cluster-wide access to flow-related resources.
	includeFlowNamespaces := namespacesRes.globalAccess
	if includeFlowNamespaces {
		for flowLogNamespace := range flowLogNamespaceCountsRes.namespacedCounts {
			responseNamespaceSet.Add(flowLogNamespace)
		}
		for l3FlowNamespace := range l3FlowNamespaceCountsRes.namespacedCounts {
			responseNamespaceSet.Add(l3FlowNamespace)
		}
	}

	responseNamespaces := responseNamespaceSet.Slice()
	sort.Strings(responseNamespaces)
	return responseNamespaces
}

func (s *serviceGraphStats) getFlowLogCount(ctx context.Context, cluster string, timeRange *lmav1.TimeRange, wgs statsWaitgroups, resultChan chan<- flowLogCountResult) {
	if !wgs.parallel {
		defer wgs.flowLogCount.Done()
	}

	start := time.Now()
	params := &lsv1.FlowLogCountParams{
		FlowLogParams: lsv1.FlowLogParams{
			QueryParams: lsv1.QueryParams{
				TimeRange: timeRange,
			},
		},
		CountType: lsv1.CountTypeGlobal,
	}
	countResp, err := s.linseed.FlowLogs(cluster).Count(ctx, params)
	if err != nil {
		resultChan <- flowLogCountResult{err: err, duration: time.Since(start)}
		return
	}
	resultChan <- flowLogCountResult{totalCount: *countResp.GlobalCount, duration: time.Since(start)}
}

func (s *serviceGraphStats) getFlowLogNamespaceCounts(ctx context.Context, cluster string, timeRange *lmav1.TimeRange, wgs statsWaitgroups, resultChan chan<- flowLogNamespacedCountResult) {
	if !wgs.parallel {
		wgs.flowLogCount.Wait()
		defer wgs.flowLogNsCount.Done()
	}
	start := time.Now()

	params := &lsv1.FlowLogCountParams{
		FlowLogParams: lsv1.FlowLogParams{
			QueryParams: lsv1.QueryParams{
				TimeRange:   timeRange,
				MaxPageSize: 10000,
				// Give Linseed a large timeout - let the user of this function cancel context to end the request early.
				Timeout: &metav1.Duration{Duration: 1 * time.Hour},
			},
		},
		CountType: lsv1.CountTypeNamespaced,
	}

	countResp, err := s.linseed.FlowLogs(cluster).Count(ctx, params)
	if err != nil {
		resultChan <- flowLogNamespacedCountResult{err: err, duration: time.Since(start)}
		return
	}

	resultChan <- flowLogNamespacedCountResult{namespacedCounts: countResp.NamespacedCounts, truncated: countResp.GlobalCountTruncated, duration: time.Since(start)}
}

func (s *serviceGraphStats) getL3FlowNamespaceCounts(ctx context.Context, cluster string, timeRange *lmav1.TimeRange, maxGlobalCount *int64, wgs statsWaitgroups, resultChan chan<- l3FlowNamespacedCountResult) {
	if !wgs.parallel {
		wgs.flowLogNsCount.Wait()
		defer wgs.l3FlowNsCount.Done()
	}

	start := time.Now()

	params := &lsv1.L3FlowCountParams{
		L3FlowParams: lsv1.L3FlowParams{
			QueryParams: lsv1.QueryParams{
				TimeRange:   timeRange,
				MaxPageSize: 1000,
				// Give Linseed a large timeout - let the user of this function cancel context to end the request early.
				Timeout: &metav1.Duration{Duration: 1 * time.Hour},
			},
		},
		MaxGlobalCount: maxGlobalCount,
	}

	countResp, err := s.linseed.L3Flows(cluster).Count(ctx, params)
	if err != nil {
		resultChan <- l3FlowNamespacedCountResult{err: err, duration: time.Since(start)}
		return
	}

	resultChan <- l3FlowNamespacedCountResult{totalCount: *countResp.GlobalCount, namespacedCounts: countResp.NamespacedCounts, truncated: countResp.GlobalCountTruncated, duration: time.Since(start)}
}

func (s *serviceGraphStats) getNamespaces(ctx context.Context, cluster string, clientSetFactory k8s.ClientSetFactory, resultChan chan<- namespacesResult) {
	c, err := clientSetFactory.NewClientSetForApplication(cluster)
	start := time.Now()
	if err != nil {
		resultChan <- namespacesResult{err: err, duration: time.Since(start)}
		return
	}

	apiServerNamespaces, err := c.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		resultChan <- namespacesResult{err: err, duration: time.Since(start)}
		return
	}

	userInfo, ok := request.UserFrom(ctx)
	if !ok {
		resultChan <- namespacesResult{err: errors.New("user not found in context"), duration: time.Since(start)}
	}
	authorizedNamespaces, globalAccess, err := authorizedNamespacesFromNamespacedEndpoints(ctx, clientSetFactory, userInfo, cluster)
	if err != nil {
		resultChan <- namespacesResult{err: err, duration: time.Since(start)}
		return
	}

	numFiltered := 0
	authorizedAPIServerNamespaces := make(map[string]bool)
	for _, apiServerNamespace := range apiServerNamespaces.Items {
		unauthorized := !globalAccess && !authorizedNamespaces[apiServerNamespace.Name]
		if unauthorized {
			numFiltered++
			continue
		}
		authorizedAPIServerNamespaces[apiServerNamespace.Name] = true
	}

	resultChan <- namespacesResult{authorizedAPIServerNamespaces: authorizedAPIServerNamespaces, globalAccess: globalAccess, numTotal: len(apiServerNamespaces.Items), numFiltered: numFiltered, duration: time.Since(start)}
}

func (s *serviceGraphStats) getApproximateNamespaceScale(cluster string, timeRange *lmav1.TimeRange, namespace string) (bool, *cachedStats, error) {
	cacheDuration := s.config.GraphStatsCacheDuration
	durationRatio := float64(timeRange.Duration()) / float64(cacheDuration)

	s.cachedStatsMutex.RLock()
	defer s.cachedStatsMutex.RUnlock()
	if s.cachedStats[cluster] == nil {
		return false, nil, fmt.Errorf("cached stats not set for cluster %s", cluster)
	}

	flowLogNamespacedCount, flowLogNamespacedCountExists := s.cachedStats[cluster].flowLogNamespacedCounts[namespace]
	l3FlowNamespacedCount, l3FlowNamespacedCountExists := s.cachedStats[cluster].l3FlowNamespacedCounts[namespace]

	if !flowLogNamespacedCountExists || !l3FlowNamespacedCountExists {
		return false, nil, fmt.Errorf("cached stats missing namespace %s for cluster %s", namespace, cluster)
	}

	// Flow log volume scales with time, so we scale the count based on how large the time range of the request is relative
	// to the time range of the cache.
	scaledFlowLogNamespaceCount := float64(flowLogNamespacedCount) * durationRatio

	// L3 flows do not scale with time: they represent the shape of traffic, not the volume.
	scaledL3FlowNamespaceCount := l3FlowNamespacedCount

	return int64(scaledFlowLogNamespaceCount) >= s.config.LargeFlowLogScaleThreshold || int64(scaledL3FlowNamespaceCount) >= s.config.LargeL3FlowScaleThreshold, s.cachedStats[cluster], nil
}

func (s *serviceGraphStats) getCachedStats(ctx context.Context, cluster string, timeRange *lmav1.TimeRange) (*cachedStats, error) {
	c := newStatsChannels()
	w := newStatsWaitgroups(true)
	go s.getFlowLogNamespaceCounts(ctx, cluster, timeRange, w, c.flowLogNamespacedCountsChan)
	go s.getL3FlowNamespaceCounts(ctx, cluster, timeRange, nil, w, c.l3FlowNamespacedCountsChan)

	flowLogNamespaceCountsRes := <-c.flowLogNamespacedCountsChan
	if flowLogNamespaceCountsRes.err != nil {
		return nil, flowLogNamespaceCountsRes.err
	}
	l3FlowNamespaceCountsRes := <-c.l3FlowNamespacedCountsChan
	if l3FlowNamespaceCountsRes.err != nil {
		return nil, l3FlowNamespaceCountsRes.err
	}

	return &cachedStats{
		flowLogNamespacedCounts: flowLogNamespaceCountsRes.namespacedCounts,
		l3FlowNamespacedCounts:  l3FlowNamespaceCountsRes.namespacedCounts,
		l3FlowTotalCount:        l3FlowNamespaceCountsRes.totalCount,
	}, nil
}

func (s *serviceGraphStats) cachedStatsUpdateLoop() {
	log.Infof("Starting cached stats update loop")
	// Refresh stats for the default cluster as soon as we start the loop.
	s.refreshCachedStats(k8s.DefaultCluster)

	// Establish our watches for managed clusters. This will trigger stats refreshing for managed clusters as they are discovered.
	s.establishManagedClusterWatches()

	// Then, refresh based on the set interval.
	ticker := time.NewTicker(s.config.GraphStatsCacheUpdateInterval)
	for range ticker.C {
		for cluster := range s.cachedStats {
			s.refreshCachedStats(cluster)
		}
	}
}

func (s *serviceGraphStats) refreshCachedStats(cluster string) {
	log.Infof("Refreshing cached stats for cluster=%s", cluster)

	// Check if cluster has been initialized in the cached stats map.
	s.cachedStatsMutex.RLock()
	_, clusterInitialized := s.cachedStats[cluster]
	s.cachedStatsMutex.RUnlock()

	// Initialize it if it hasn't been initialized. This way the cached stats map serves as a record of discovered
	// clusters, independent of whether the stats for each discovered cluster have been fetched yet.
	if !clusterInitialized {
		s.cachedStatsMutex.Lock()
		s.cachedStats[cluster] = nil
		s.cachedStatsMutex.Unlock()
	}

	// Fetch the stats. We don't need to hold the lock while we fetch.
	// We retry immediately in case the error is transient. If these attempts fail, we will retry again when the cache
	// update interval elapses.
	start := time.Now()
	var cs *cachedStats
	var err error
	for attempt := range 3 {
		cs, err = s.getCachedStats(context.Background(), cluster, &lmav1.TimeRange{
			From: time.Now().Add(-s.config.GraphStatsCacheDuration),
			To:   time.Now(),
		})

		if err == nil {
			break
		}
		log.Warnf("Retrying cached stats update for cluster=%s (attempt %d): %v", cluster, attempt, err)
		time.Sleep(10 * time.Second)
	}
	if err != nil {
		log.Errorf("Failed to update cached stats for cluster=%s: %v", cluster, err)
		return
	}
	log.Infof("Completed fetch of cached stats for cluster=%s in %v", cluster, time.Since(start))

	// Set the stats.
	s.cachedStatsMutex.Lock()
	s.cachedStats[cluster] = cs
	s.cachedStatsMutex.Unlock()
}

func (s *serviceGraphStats) deleteCachedStats(cluster string) {
	s.cachedStatsMutex.Lock()
	delete(s.cachedStats, cluster)
	s.cachedStatsMutex.Unlock()
}

func (s *serviceGraphStats) establishManagedClusterWatches() {
	managedClusterHandler := cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj any) {
			if mc, ok := obj.(*v3.ManagedCluster); ok {
				log.Infof("Received managed cluster deletion for cluster=%s", mc.Name)
				s.deleteCachedStats(mc.Name)
			}
		},
		AddFunc: func(obj any) {
			if mc, ok := obj.(*v3.ManagedCluster); ok {
				log.Infof("Received managed cluster add for cluster=%s", mc.Name)
				s.refreshCachedStats(mc.Name)
			}
		},
		UpdateFunc: func(_, obj any) {
			if mc, ok := obj.(*v3.ManagedCluster); ok {
				log.Infof("Received managed cluster update for cluster=%s", mc.Name)
				s.refreshCachedStats(mc.Name)
			}
		},
	}
	listWatcher := managedcluster.NewManagedClusterListWatcher(context.Background(), s.ctrlClient, s.config.TenantNamespace)
	mcInformer := cache.NewSharedIndexInformer(listWatcher, &v3.ManagedCluster{}, 0, cache.Indexers{})
	_, err := mcInformer.AddEventHandler(managedClusterHandler)
	if err != nil {
		log.Fatalf("Failed to watch managed clusters: %v", err)
	}
	go mcInformer.Run(nil)
}

func (s *serviceGraphStats) fetchServiceGraphResponse(ctx context.Context, cluster string, timeRange *lmav1.TimeRange, timeout metav1.Duration) (*v1.ServiceGraphResponse, error) {
	serviceGraphReq := &v1.ServiceGraphRequest{
		Cluster:      cluster,
		TimeRange:    timeRange,
		Timeout:      timeout,
		SelectedView: v1.GraphView{},
		ForceRefresh: false,
	}

	return HandleServiceGraphRequest(
		ctx,
		cluster,
		serviceGraphReq,
		s.emptyServiceGroups,
		s.serviceGraphCache,
		WithExcludeStatsFromFlows(true),
	)
}

func authorizedNamespacesFromNamespacedEndpoints(
	ctx context.Context,
	csFactory k8s.ClientSetFactory,
	user user.Info,
	cluster string,
) (namespaces map[string]bool, clusterWide bool, err error) {
	verbs, err := auth.PerformUserAuthorizationReviewForLogs(ctx, csFactory, user, cluster)
	if err != nil {
		return nil, false, err
	}

	var podListClusterWide bool
	podListNamespaces := make(map[string]bool)

	var networkSetListClusterWide bool
	networkSetListNamespaces := make(map[string]bool)

	for _, r := range verbs {
		if r.Resource != "pods" && r.Resource != "networksets" {
			continue
		}

		for _, v := range r.Verbs {
			if v.Verb != "list" {
				continue
			}

			for _, rg := range v.ResourceGroups {
				switch r.Resource {
				case "pods":
					if rg.Namespace == "" {
						podListClusterWide = true
					} else {
						podListNamespaces[rg.Namespace] = true
					}
				case "networksets":
					if rg.Namespace == "" {
						networkSetListClusterWide = true
					} else {
						networkSetListNamespaces[rg.Namespace] = true
					}
				}
			}
		}
	}

	// If the user can see all namespaces via Pods or NetworkSets, they have explicit cluster-wide visibility for namespaces.
	// We do not infer the same for HEPs and GlobalNetworkSets - they are not namespaced, so their permissions do not give
	// us information about what namespaces the user is privy to.
	if podListClusterWide || networkSetListClusterWide {
		return nil, true, nil
	}

	union := make(map[string]bool)
	for ns := range podListNamespaces {
		union[ns] = true
	}
	for ns := range networkSetListNamespaces {
		union[ns] = true
	}

	return union, false, nil
}

func initializeDeveloperStatistics() *v1.DeveloperStatistics {
	return &v1.DeveloperStatistics{
		NamespaceCounts: v1.NamespaceCounts{
			NumFlowLogs: make(map[string]int64),
			NumL3Flows:  make(map[string]int64),
		},
		NamespaceCacheCounts: v1.NamespaceCounts{
			NumFlowLogs: make(map[string]int64),
			NumL3Flows:  make(map[string]int64),
		},
	}
}

type flowLogCountResult struct {
	totalCount int64
	duration   time.Duration
	err        error
}

type flowLogNamespacedCountResult struct {
	namespacedCounts map[string]int64
	truncated        bool
	duration         time.Duration
	err              error
}

type l3FlowNamespacedCountResult struct {
	totalCount       int64
	namespacedCounts map[string]int64
	truncated        bool
	duration         time.Duration
	err              error
}

type namespacesResult struct {
	authorizedAPIServerNamespaces map[string]bool
	globalAccess                  bool
	numTotal                      int
	numFiltered                   int
	duration                      time.Duration
	err                           error
}

type statsWaitgroups struct {
	parallel       bool
	flowLogCount   *sync.WaitGroup
	flowLogNsCount *sync.WaitGroup
	l3FlowNsCount  *sync.WaitGroup
}

func newStatsWaitgroups(parallel bool) statsWaitgroups {
	wgs := statsWaitgroups{
		parallel:       parallel,
		flowLogCount:   &sync.WaitGroup{},
		flowLogNsCount: &sync.WaitGroup{},
		l3FlowNsCount:  &sync.WaitGroup{},
	}
	wgs.flowLogCount.Add(1)
	wgs.flowLogNsCount.Add(1)
	wgs.l3FlowNsCount.Add(1)
	return wgs
}

type statsChannels struct {
	namespacesChan              chan namespacesResult
	flowLogCountsChan           chan flowLogCountResult
	flowLogNamespacedCountsChan chan flowLogNamespacedCountResult
	l3FlowNamespacedCountsChan  chan l3FlowNamespacedCountResult
}

func newStatsChannels() statsChannels {
	return statsChannels{
		namespacesChan:              make(chan namespacesResult, 1),
		flowLogCountsChan:           make(chan flowLogCountResult, 1),
		flowLogNamespacedCountsChan: make(chan flowLogNamespacedCountResult, 1),
		l3FlowNamespacedCountsChan:  make(chan l3FlowNamespacedCountResult, 1),
	}
}
