// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package servicegraph

import (
	"time"
)

type Config struct {
	// The maximum number of entries that we keep in the warm cache.
	ServiceGraphCacheMaxEntries int

	// The maximum number of buckets per query. If specified can be used to increase the bucket size if the volume of
	// data is too large to handle with multuiple smaller queries.
	ServiceGraphCacheMaxBucketsPerQuery int

	// The maximum number of aggregated results per document type. If this is exceeded then the user should reduce the
	// time window.
	ServiceGraphCacheMaxAggregatedRecords int

	// The time after which cached entries that would be polled in the background are removed after the last time they
	// were accessed. This ensures cached entries are not polled forever if they are not being accessed.
	ServiceGraphCachePolledEntryAgeOut time.Duration

	// The time after which cached entries that are still being populated for the first time are removed after the last
	// time they were accessed. This is shorter than the entry age out to ensure we don't wait for long queries when no
	// client is requesting the data.
	ServiceGraphCacheSlowQueryEntryAgeOut time.Duration

	// The poll loop interval. The time between background polling of all cache entries that require periodic updates.
	ServiceGraphCachePollLoopInterval time.Duration

	// The min time between starting successive background data queries. This is used to ensure we are sending too many
	// requests in quick succession and overwhelming linseed or the kubernetes API. This does not gate user driven
	// queries.
	ServiceGraphCachePollQueryInterval time.Duration

	// The max time we expect it to take for data to be collected and stored. This is used to determine
	// whether a cache entry should be background polled for updates.
	ServiceGraphCacheDataSettleTime time.Duration

	// Whether or not to prefetch raw data when the cache is initialized.
	ServiceGraphCacheDataPrefetch bool

	// ServiceGraphCacheFetchL7 will instruct whether to fetch L7 data.
	ServiceGraphCacheFetchL7 bool
	// ServiceGraphCacheFetchDNS will instruct weather to fetch DNS data or not
	ServiceGraphCacheFetchDNS bool
	// ServiceGraphCacheFetchEvents will instruct weather to fetch Events data or not
	ServiceGraphCacheFetchEvents bool

	// Whether or not to fetch service graph statistics in parallel. When true, all statistics queries run
	// concurrently. When false, namespaced counts wait for the total flow log count to complete first.
	ParallelGraphStatsFetch bool

	// Whether or not to log service graph statistics request details (durations, counts, etc).
	GraphStatsRequestLogging bool

	// Scale threshold for flow log count that the /stats handler considers excessively large. It will perform no further
	// computations if this threshold is met.
	XLargeFlowLogScaleThreshold int64

	// Scale threshold for flow log count that the /stats handler considers large. Only limited namespace computations will occur.
	LargeFlowLogScaleThreshold int64

	// Scale threshold for L3 flow count that the /stats handler considers large. Namespaces with counts above this threshold
	// are considered high volume.
	LargeL3FlowScaleThreshold int64

	// The base timeout set on all computations performed by the /stats handler.
	GlobalStatsTimeoutSeconds int

	// The interval at which the cache for namespaced service graph stats is updated.
	GraphStatsCacheUpdateInterval time.Duration

	// The duration that namespaced stats are cached from - the cache will hold namespaced counts between now and now-duration.
	GraphStatsCacheDuration time.Duration

	// TenantNamespace is the namespace of the tenant this instance is serving, or empty if this is a single-tenant cluster.
	TenantNamespace string

	// Whether or not to enable fine-grained RBAC on ServiceGraph queries. If set to false, then per-use RBAC will
	// not be enforced. This is primarily used for free-tier clusters that do not support per-user RBAC.
	FineGrainedRBAC bool
}
