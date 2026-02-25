// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package dns

import (
	"context"
	"fmt"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/json"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/index"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/logtools"
	lmaindex "github.com/projectcalico/calico/linseed/pkg/internal/lma/elastic/index"
	lmaelastic "github.com/projectcalico/calico/lma/pkg/elastic"
)

type dnsLogBackend struct {
	client               *elastic.Client
	lmaclient            lmaelastic.Client
	queryHelper          lmaindex.Helper
	templates            bapi.IndexInitializer
	deepPaginationCutOff int64
	singleIndex          bool
	index                bapi.Index

	// Migration knobs
	migrationMode bool
}

func NewDNSLogBackend(c lmaelastic.Client, cache bapi.IndexInitializer, deepPaginationCutOff int64, migrationMode bool) bapi.DNSLogBackend {
	return &dnsLogBackend{
		client:               c.Backend(),
		lmaclient:            c,
		queryHelper:          lmaindex.MultiIndexDNSLogs(),
		templates:            cache,
		deepPaginationCutOff: deepPaginationCutOff,
		singleIndex:          false,
		index:                index.DNSLogMultiIndex,
		migrationMode:        migrationMode,
	}
}

func NewSingleIndexDNSLogBackend(c lmaelastic.Client, cache bapi.IndexInitializer, deepPaginationCutOff int64, migrationMode bool, options ...index.Option) bapi.DNSLogBackend {
	return &dnsLogBackend{
		client:               c.Backend(),
		lmaclient:            c,
		queryHelper:          lmaindex.SingleIndexDNSLogs(),
		templates:            cache,
		deepPaginationCutOff: deepPaginationCutOff,
		singleIndex:          true,
		index:                index.DNSLogIndex(options...),
		migrationMode:        migrationMode,
	}
}

type logWithExtras struct {
	v1.DNSLog `json:",inline"`
	Tenant    string `json:"tenant,omitempty"`
}

// prepareForWrite sets the cluster field, and wraps the log in a document to set tenant if
// the backend is configured to write to a single index.
func (b *dnsLogBackend) prepareForWrite(i bapi.ClusterInfo, l v1.DNSLog) any {
	l.Cluster = i.Cluster

	if b.singleIndex {
		return &logWithExtras{
			DNSLog: l,
			Tenant: i.Tenant,
		}
	}
	return l
}

func (b *dnsLogBackend) Create(ctx context.Context, i bapi.ClusterInfo, logs []v1.DNSLog) (*v1.BulkResponse, error) {
	log := bapi.ContextLogger(i)

	if err := i.Valid(); err != nil {
		return nil, err
	}

	err := b.templates.Initialize(ctx, b.index, i)
	if err != nil {
		return nil, err
	}

	// Determine the index to write to using an alias
	alias := b.index.Alias(i)
	log.Debugf("Writing DNS logs in bulk to alias %s", alias)

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
		var id string
		if len(f.ID) != 0 {
			id = f.ID
			f.ID = ""
		}
		// Add this log to the bulk request.
		dnsLog, err := json.Marshal(b.prepareForWrite(i, f))
		if err != nil {
			log.WithError(err).Warningf("Failed to marshal dns log and add it to the request %+v", f)
			continue
		}
		req := elastic.NewBulkIndexRequest().Index(alias).Doc(string(dnsLog))
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
		log.Errorf("Error writing DNS log: %s", err)
		return nil, fmt.Errorf("failed to write DNS log: %s", err)
	}
	log.WithField("count", len(logs)).Debugf("Wrote DNS log to index: %+v", resp)

	return &v1.BulkResponse{
		Total:     len(resp.Items),
		Succeeded: len(resp.Succeeded()),
		Failed:    len(resp.Failed()),
		Errors:    v1.GetBulkErrors(resp),
	}, nil
}

func (b *dnsLogBackend) Aggregations(ctx context.Context, i bapi.ClusterInfo, opts *v1.DNSAggregationParams) (*elastic.Aggregations, error) {
	if b.migrationMode {
		return nil, fmt.Errorf("aggregation queries are not allowed in migration mode")
	}

	// Get the base query.
	search, _, err := b.getSearch(ctx, i, &opts.DNSLogParams)
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

// List lists logs that match the given parameters.
func (b *dnsLogBackend) List(ctx context.Context, i bapi.ClusterInfo, opts *v1.DNSLogParams) (*v1.List[v1.DNSLog], error) {
	log := bapi.ContextLogger(i)

	query, startFrom, err := b.getSearch(ctx, i, opts)
	if err != nil {
		return nil, err
	}

	results, err := query.Do(ctx)
	if err != nil {
		return nil, err
	}

	logs := []v1.DNSLog{}
	for _, h := range results.Hits.Hits {
		l := v1.DNSLog{}
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

	return &v1.List[v1.DNSLog]{
		Items:     logs,
		TotalHits: results.TotalHits(),
		AfterKey:  afterKey,
	}, nil
}

func (b *dnsLogBackend) afterKey(ctx context.Context, i bapi.ClusterInfo, opts *v1.DNSLogParams, results *elastic.SearchResult, log *logrus.Entry, startFrom int) (map[string]any, error) {
	// If an index has more than 10000 items or other value configured via index.max_result_window
	// setting in Elastic, we need to perform deep pagination. Migration mode will use deep pagination
	// on all requests
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

func (b *dnsLogBackend) getSearch(ctx context.Context, i bapi.ClusterInfo, opts *v1.DNSLogParams) (*elastic.SearchService, int, error) {
	if i.Cluster == "" {
		return nil, 0, fmt.Errorf("no cluster ID on request")
	}

	q, err := b.buildQuery(i, opts)
	if err != nil {
		return nil, 0, err
	}

	// Build the query.
	query := b.client.Search().
		Size(opts.QueryParams.GetMaxPageSize()).
		Query(q)

	// Configure pagination options
	var startFrom int
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
func (b *dnsLogBackend) buildQuery(i bapi.ClusterInfo, opts *v1.DNSLogParams) (elastic.Query, error) {
	// Start with the base dns log query using common fields.
	query, err := logtools.BuildQuery(b.queryHelper, i, opts)
	if err != nil {
		return nil, err
	}

	if len(opts.DomainMatches) > 0 {
		for _, match := range opts.DomainMatches {
			// Get the list of values as an interface{}, as needed for a terms query.
			values := []any{}
			for _, t := range match.Domains {
				values = append(values, t)
			}

			switch match.Type {
			case v1.DomainMatchQname:
				query.Filter(elastic.NewTermsQuery("qname", values...))
			case v1.DomainMatchRRSet:
				query.Filter(elastic.NewNestedQuery("rrsets", elastic.NewTermsQuery("rrsets.name", values...)))
			case v1.DomainMatchRRData:
				query.Filter(elastic.NewNestedQuery("rrsets", elastic.NewTermsQuery("rrsets.rdata", values...)))
			default:
				query.Filter(elastic.NewBoolQuery().Should(
					elastic.NewTermsQuery("qname", values...),
					elastic.NewNestedQuery("rrsets", elastic.NewTermsQuery("rrsets.name", values...)),
					elastic.NewNestedQuery("rrsets", elastic.NewTermsQuery("rrsets.rdata", values...)),
				).MinimumNumberShouldMatch(1))
			}
		}
	}

	return query, nil
}
