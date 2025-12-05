// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package flows

import (
	"context"
	"fmt"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/json"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/backend"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/index"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/logtools"
	lmaindex "github.com/projectcalico/calico/linseed/pkg/internal/lma/elastic/index"
	lmaelastic "github.com/projectcalico/calico/lma/pkg/elastic"
)

type flowLogBackend struct {
	client               *elastic.Client
	lmaclient            lmaelastic.Client
	queryHelper          lmaindex.Helper
	initializer          bapi.IndexInitializer
	deepPaginationCutOff int64
	singleIndex          bool
	index                bapi.Index

	// Fields for the composite aggregation that computes namespaced counts.
	namespaceCountCompositeSources []lmaelastic.AggCompositeSourceInfo
	namespaceCountFieldTracker     *backend.FieldTracker

	// Migration knobs
	migrationMode bool
}

func NewFlowLogBackend(c lmaelastic.Client, cache bapi.IndexInitializer, deepPaginationCutOff int64, migrationMode bool) bapi.FlowLogBackend {
	return newFlowLogBackend(c, false, cache, deepPaginationCutOff, migrationMode)
}

// NewSingleIndexFlowLogBackend returns a new flow log backend that writes to a single index.
func NewSingleIndexFlowLogBackend(c lmaelastic.Client, cache bapi.IndexInitializer, deepPaginationCutOff int64, migrationMode bool, options ...index.Option) bapi.FlowLogBackend {
	return newFlowLogBackend(c, true, cache, deepPaginationCutOff, migrationMode, options...)
}

func newFlowLogBackend(c lmaelastic.Client, singleIndex bool, cache bapi.IndexInitializer, deepPaginationCutOff int64, migrationMode bool, options ...index.Option) bapi.FlowLogBackend {
	namespaceCountCompositeSources := []lmaelastic.AggCompositeSourceInfo{
		{Name: "source_ns", Field: "source_namespace"},
		{Name: "dest_ns", Field: "dest_namespace"},
	}

	indexTemplate := index.FlowLogIndex(options...)
	helper := lmaindex.SingleIndexFlowLogs()
	if !singleIndex {
		indexTemplate = index.FlowLogMultiIndex
		helper = lmaindex.MultiIndexFlowLogs()
	}

	return &flowLogBackend{
		client:                         c.Backend(),
		lmaclient:                      c,
		initializer:                    cache,
		deepPaginationCutOff:           deepPaginationCutOff,
		singleIndex:                    singleIndex,
		index:                          indexTemplate,
		queryHelper:                    helper,
		migrationMode:                  migrationMode,
		namespaceCountCompositeSources: namespaceCountCompositeSources,
		namespaceCountFieldTracker:     backend.NewFieldTracker(namespaceCountCompositeSources),
	}
}

type flowLogWithExtras struct {
	v1.FlowLog `json:",inline"`
	Tenant     string `json:"tenant,omitempty"`
}

// prepareForWrite sets the cluster field, and wraps the log in a document to set tenant if
// the backend is configured to write to a single index.
func (b *flowLogBackend) prepareForWrite(i bapi.ClusterInfo, f v1.FlowLog) interface{} {
	f.Cluster = i.Cluster
	if b.singleIndex {
		return flowLogWithExtras{
			FlowLog: f,
			Tenant:  i.Tenant,
		}
	}
	return f
}

// Create the given flow log in elasticsearch.
func (b *flowLogBackend) Create(ctx context.Context, i bapi.ClusterInfo, logs []v1.FlowLog) (*v1.BulkResponse, error) {
	log := bapi.ContextLogger(i)

	if err := i.Valid(); err != nil {
		return nil, err
	}

	err := b.initializer.Initialize(ctx, b.index, i)
	if err != nil {
		return nil, err
	}

	// Determine the index to write to using an alias
	alias := b.index.Alias(i)
	log.Debugf("Writing flow logs in bulk to alias %s", alias)

	// Build a bulk request using the provided logs.
	bulk := b.client.Bulk()

	for _, f := range logs {
		// Populate the log's GeneratedTime field.  This field exists to enable a way for
		// clients to efficiently query newly generated logs, and having Linseed fill it in
		// - instead of an upstream client - makes this less vulnerable to time skew between
		// clients, and between clients and Linseed.
		//
		// Why not compute `time.Now().UTC()` before this loop and then store the same value
		// in each log?  Because if we can advance GeneratedTime as much as possible
		// (i.e. to the real current time), a client will compute a later value for
		// `LatestSeenGeneratedTime`, and then a subsequent query with `GeneratedTime >=
		// LatestSeenGeneratedTime` will return fewer previously seen results.
		generatedTime := time.Now().UTC()
		f.GeneratedTime = &generatedTime

		// Set the ID, and remove it from the
		// body of the document.
		var id string
		if len(f.ID) != 0 {
			id = f.ID
			f.ID = ""
		}

		// Add this log to the bulk request.
		req := elastic.NewBulkIndexRequest().Index(alias).Doc(b.prepareForWrite(i, f))
		if b.migrationMode {
			if len(id) != 0 {
				req.Id(id)
			}
		}
		bulk.Add(req)
	}

	// Send the bulk request.
	resp, err := bulk.Do(ctx)
	if err != nil {
		log.Errorf("Error writing flow log: %s", err)
		return nil, fmt.Errorf("failed to write flow log: %s", err)
	}
	fields := logrus.Fields{
		"succeeded": len(resp.Succeeded()),
		"failed":    len(resp.Failed()),
	}
	log.WithFields(fields).Debugf("Flow log bulk request complete: %+v", resp)

	return &v1.BulkResponse{
		Total:     len(resp.Items),
		Succeeded: len(resp.Succeeded()),
		Failed:    len(resp.Failed()),
		Errors:    v1.GetBulkErrors(resp),
	}, nil
}

// List lists logs that match the given parameters.
func (b *flowLogBackend) List(ctx context.Context, i bapi.ClusterInfo, opts *v1.FlowLogParams) (*v1.List[v1.FlowLog], error) {
	log := bapi.ContextLogger(i)

	if err := i.Valid(); err != nil {
		return nil, err
	}

	query, startFrom, err := b.getSearch(ctx, i, opts)
	if err != nil {
		return nil, err
	}

	results, err := query.Do(ctx)
	if err != nil {
		return nil, err
	}

	logs := []v1.FlowLog{}
	for _, h := range results.Hits.Hits {
		l := v1.FlowLog{}
		err = json.Unmarshal(h.Source, &l)
		if err != nil {
			log.WithError(err).Error("Error unmarshalling log")
			continue
		}
		l.ID = h.Id
		logs = append(logs, l)
	}

	afterKey, err := b.afterKey(ctx, i, opts, results, log, startFrom)
	if err != nil {
		return nil, err
	}

	return &v1.List[v1.FlowLog]{
		Items:     logs,
		TotalHits: results.TotalHits(),
		AfterKey:  afterKey,
	}, nil
}

func (b *flowLogBackend) afterKey(ctx context.Context, i bapi.ClusterInfo, opts *v1.FlowLogParams, results *elastic.SearchResult, log *logrus.Entry, startFrom int) (map[string]interface{}, error) {
	// If an index has more than 10000 items or other value configured via index.max_result_window
	// setting in Elastic, we need to perform deep pagination
	useDeepPagination := b.migrationMode
	if !useDeepPagination {
		// This is how we determine that an index has more items
		// than index.max_result_window setting. TotalHits will
		// return a value equal to index.max_result_window setting
		useDeepPagination = results.TotalHits() >= b.deepPaginationCutOff
	}
	nextPointInTime, err := logtools.NextPointInTime(ctx, b.client, b.index.Index(i), results, log, useDeepPagination)
	if err != nil {
		return nil, err
	}
	afterKey := logtools.NextAfterKey(opts, startFrom, nextPointInTime, results, useDeepPagination)
	return afterKey, nil
}

func (b *flowLogBackend) Aggregations(ctx context.Context, i bapi.ClusterInfo, opts *v1.FlowLogAggregationParams) (*elastic.Aggregations, error) {
	if b.migrationMode {
		return nil, fmt.Errorf("aggregation queries are not allowed in migration mode")
	}

	// Get the base query.
	search, _, err := b.getSearch(ctx, i, &opts.FlowLogParams)
	if err != nil {
		return nil, err
	}

	// Add in any aggregations provided by the client. We need to handle two cases - one where this is a
	// time-series request, and another when it's just an aggregation request.
	if opts.NumBuckets > 0 {
		// Time-series.
		hist := elastic.NewAutoDateHistogramAggregation().
			Field(b.queryHelper.GetTimeField()).
			Buckets(opts.NumBuckets)
		for name, agg := range opts.Aggregations {
			hist = hist.SubAggregation(name, logtools.RawAggregation{RawMessage: agg})
		}
		search.Aggregation(v1.TimeSeriesBucketName, hist)
	} else {
		// Not time-series. Just add the aggs as they are.
		for name, agg := range opts.Aggregations {
			search = search.Aggregation(name, logtools.RawAggregation{RawMessage: agg})
		}
	}

	// Do the search.
	results, err := search.Do(ctx)
	if err != nil {
		return nil, err
	}

	return &results.Aggregations, nil
}

// Count returns count information for flow logs matching the query parameters.
func (b *flowLogBackend) Count(ctx context.Context, i bapi.ClusterInfo, opts *v1.FlowLogCountParams) (*v1.CountResponse, error) {
	log := bapi.ContextLogger(i)

	if err := i.Valid(); err != nil {
		return nil, err
	}

	if i.Cluster == "" {
		return nil, fmt.Errorf("no cluster ID on request")
	}

	var globalCount *int64
	if opts.CountType == v1.CountTypeGlobal || opts.CountType == v1.CountTypeGlobalAndNamespaced {
		q, err := b.buildQuery(i, &opts.FlowLogParams)
		if err != nil {
			return nil, err
		}

		c, err := b.client.Count(b.index.Index(i)).
			Query(q).
			Do(ctx)
		if err != nil {
			log.WithError(err).Error("Error performing global count query")
			return nil, fmt.Errorf("failed to count flow logs: %s", err)
		}
		globalCount = &c
	}

	var namespacedCount map[string]int64
	var err error
	if opts.CountType == v1.CountTypeNamespaced || opts.CountType == v1.CountTypeGlobalAndNamespaced {
		namespacedCount, err = b.namespacedCount(ctx, i, opts)
		if err != nil {
			return nil, err
		}
	}

	return &v1.CountResponse{
		GlobalCount:      globalCount,
		NamespacedCounts: namespacedCount,

		// The global count is never truncated since it is not computed with pagination.
		GlobalCountTruncated: false,
	}, nil
}

func (b *flowLogBackend) countQuery() *lmaelastic.CompositeAggregationQuery {
	/*
		"sources": [
			{"source_ns": {"terms": {"field": "source_namespace"}}},
			{"dest_ns": {"terms": {"field": "dest_namespace"}}}
		],
	*/
	return &lmaelastic.CompositeAggregationQuery{
		Name:                    "buckets",
		AggCompositeSourceInfos: b.namespaceCountCompositeSources,
	}
}

func (b *flowLogBackend) namespacedCount(ctx context.Context, i bapi.ClusterInfo, opts *v1.FlowLogCountParams) (map[string]int64, error) {
	log := bapi.ContextLogger(i)
	err := i.Valid()
	if err != nil {
		return nil, err
	}

	// Build the aggregation request.
	query := b.countQuery()
	query.Query, err = b.buildQuery(i, &opts.FlowLogParams)
	if err != nil {
		return nil, err
	}
	query.DocumentIndex = b.index.Index(i)
	query.MaxBucketsPerQuery = opts.GetMaxPageSize()

	// Build the bucket handler that we will pass to PagedCount. This handler will compute our namespace counts as each bucket is processed.
	namespacedCounts := make(map[string]int64)
	flowLogHandler := func(log *logrus.Entry, bucket *lmaelastic.CompositeAggregationBucket) {
		key := bucket.CompositeAggregationKey
		docCount := bucket.DocCount
		sourceNs := b.namespaceCountFieldTracker.ValueString(key, "source_namespace")
		destNs := b.namespaceCountFieldTracker.ValueString(key, "dest_namespace")

		if sourceNs != "" {
			namespacedCounts[sourceNs] += docCount
		}

		if destNs != "" && destNs != sourceNs {
			namespacedCounts[destNs] += docCount
		}
	}

	// Perform the request.
	_, _, err = lmaelastic.PagedCount(ctx, b.lmaclient, query, log, nil, flowLogHandler)
	if err != nil {
		return nil, err
	}

	return namespacedCounts, nil
}

func (b *flowLogBackend) getSearch(ctx context.Context, i bapi.ClusterInfo, opts *v1.FlowLogParams) (*elastic.SearchService, int, error) {
	if i.Cluster == "" {
		return nil, 0, fmt.Errorf("no cluster ID on request")
	}

	q, err := b.buildQuery(i, opts)
	if err != nil {
		return nil, 0, err
	}

	// Build the query, sorting by time.
	query := b.client.Search().
		Size(opts.GetMaxPageSize()).
		Query(q)

	// Configure pagination options
	var pitID string
	if b.migrationMode {
		// For migration mode, we enable deep pagination for each request
		// instead of deciding based on number of documents stored.
		// For the first page, we need to perform the query with a point
		// in time configured
		if ak := opts.GetAfterKey(); ak == nil {
			var err error
			pitID, err = logtools.OpenPointInTime(ctx, b.client, b.index.Index(i))
			if err != nil {
				return nil, 0, err
			}
		}
	}

	var startFrom int
	query, startFrom, err = logtools.ConfigureCurrentPage(query, opts, b.index.Index(i), b.migrationMode, pitID)
	if err != nil {
		return nil, 0, err
	}

	// Configure sorting.
	if len(opts.GetSortBy()) != 0 {
		for _, s := range opts.GetSortBy() {
			query.Sort(s.Field, !s.Descending)
		}
	} else {
		query.Sort(b.queryHelper.GetTimeField(), true)
	}

	return query, startFrom, nil
}

// buildQuery builds an elastic query using the given parameters.
func (b *flowLogBackend) buildQuery(i bapi.ClusterInfo, opts *v1.FlowLogParams) (elastic.Query, error) {
	// Start with the base flow log query using common fields.
	query, err := logtools.BuildQuery(b.queryHelper, i, opts)
	if err != nil {
		return nil, err
	}

	if len(opts.IPMatches) > 0 {
		for _, match := range opts.IPMatches {
			// Get the list of values as an interface{}, as needed for a terms query.
			values := []interface{}{}
			for _, t := range match.IPs {
				values = append(values, t)
			}

			switch match.Type {
			case v1.MatchTypeSource:
				query.Filter(elastic.NewTermsQuery("source_ip", values...))
			case v1.MatchTypeDest:
				query.Filter(elastic.NewTermsQuery("dest_ip", values...))
			case v1.MatchTypeAny:
				fallthrough
			default:
				// By default, treat as an "any" match. Return any flows that have a source
				// or destination name that matches.
				query.Filter(elastic.NewBoolQuery().Should(
					elastic.NewTermsQuery("source_ip", values...),
					elastic.NewTermsQuery("dest_ip", values...),
				).MinimumNumberShouldMatch(1))
			}
		}
	}

	// Configure policy match.
	q, err := BuildAllPolicyMatchQuery(opts.PolicyMatches)
	if err != nil {
		return nil, err
	}
	if q != nil {
		query.Filter(q)
	}

	eq, err := BuildEnforcedPolicyMatchQuery(opts.EnforcedPolicyMatches)
	if err != nil {
		return nil, err
	}
	if eq != nil {
		query.Filter(eq)
	}

	pq, err := BuildPendingPolicyMatchQuery(opts.PendingPolicyMatches)
	if err != nil {
		return nil, err
	}
	if pq != nil {
		query.Filter(pq)
	}

	return query, nil
}
