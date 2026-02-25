// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package audit

import (
	"bytes"
	"context"
	"errors"
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

type auditLogBackend struct {
	client               *elastic.Client
	lmaclient            lmaelastic.Client
	queryHelper          lmaindex.Helper
	templates            bapi.IndexInitializer
	deepPaginationCutOff int64
	singleIndex          bool
	eeIndex              bapi.Index
	kubeIndex            bapi.Index
	anyIndex             bapi.Index

	// Migration knobs
	migrationMode bool
}

func NewBackend(c lmaelastic.Client, cache bapi.IndexInitializer, deepPaginationCutOff int64, migrationMode bool) bapi.AuditBackend {
	return &auditLogBackend{
		client:               c.Backend(),
		queryHelper:          lmaindex.MultiIndexAuditLogs(),
		lmaclient:            c,
		templates:            cache,
		deepPaginationCutOff: deepPaginationCutOff,
		singleIndex:          false,
		eeIndex:              index.AuditLogEEMultiIndex,
		kubeIndex:            index.AuditLogKubeMultiIndex,
		migrationMode:        migrationMode,

		// For multi-index, the log type is encoded into the index name, and so we need to return a wildcard index
		// name that matches all audit log types.
		anyIndex: index.NewMultiIndex("tigera_secure_ee_audit_*", bapi.DataType("any")),
	}
}

func NewSingleIndexBackend(c lmaelastic.Client, cache bapi.IndexInitializer, deepPaginationCutOff int64, migrationMode bool, options ...index.Option) bapi.AuditBackend {
	return &auditLogBackend{
		client:               c.Backend(),
		queryHelper:          lmaindex.SingleIndexAuditLogs(),
		lmaclient:            c,
		templates:            cache,
		deepPaginationCutOff: deepPaginationCutOff,
		singleIndex:          true,

		// For single-index, the log type is encoded into the document, and we use the same index for all log types.
		eeIndex:   index.AuditLogIndex(options...),
		kubeIndex: index.AuditLogIndex(options...),
		anyIndex:  index.AuditLogIndex(options...),

		migrationMode: migrationMode,
	}
}

// prepareForWrite sets the cluster field, and wraps the log in a document to set tenant if
// the backend is configured to write to a single index.
func (b *auditLogBackend) prepareForWrite(i bapi.ClusterInfo, k v1.AuditLogType, l v1.AuditLog) (any, error) {
	l.Cluster = i.Cluster

	// Audit logs have a special MarshalJSON implementation that we need to respect.
	bs, err := l.MarshalJSON()
	if err != nil {
		return nil, err
	}

	if b.singleIndex {
		// For single-index mode, we need to also include tenant in the document, as well
		// as the log type (EE or Kube)
		// AuditLogs have a custom JSON marshaler so we need to add this to the JSON directly.
		buf := bytes.NewBuffer(bytes.TrimSuffix(bs, []byte("}")))
		_, err := fmt.Fprintf(buf, `,"tenant":"%s","audit_type":"%s"}`, i.Tenant, k)
		return buf.String(), err
	}

	return string(bs), nil
}

// Create the given logs in elasticsearch.
func (b *auditLogBackend) Create(ctx context.Context, kind v1.AuditLogType, i bapi.ClusterInfo, logs []v1.AuditLog) (*v1.BulkResponse, error) {
	log := bapi.ContextLogger(i)

	if err := i.Valid(); err != nil {
		return nil, err
	}

	var idx bapi.Index
	switch kind {
	case v1.AuditLogTypeEE:
		idx = b.eeIndex
	case v1.AuditLogTypeKube:
		idx = b.kubeIndex
	case "":
		return nil, fmt.Errorf("no audit log type provided on List request")
	default:
		return nil, fmt.Errorf("invalid audit log type: %s", kind)
	}

	err := b.templates.Initialize(ctx, idx, i)
	if err != nil {
		return nil, err
	}

	// Determine the index to write to using an alias
	alias := b.writeAlias(kind, i)
	log.Debugf("Writing audit logs in bulk to alias %s", alias)

	// Build a bulk request using the provided logs.
	bulk := b.client.Bulk()

	for _, f := range logs {
		// Populate the log's GeneratedTime field.  This field exists to enable a way for
		// clients to efficiently query newly generated logs, and having Linseed fill it in
		// - instead of an upstream client - makes this less vulnerable to time skew between
		// clients, and between clients and Linseed.
		generatedTime := time.Now().UTC()
		f.GeneratedTime = &generatedTime
		var id string
		if len(f.ID) != 0 {
			id = f.ID
			f.ID = ""
		}

		doc, err := b.prepareForWrite(i, kind, f)
		if err != nil {
			log.Errorf("Error preparing audit log for write: %s", err)
			continue
		}

		// Add this log to the bulk request.
		req := elastic.NewBulkIndexRequest().Index(alias).Doc(doc)
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
		log.Errorf("Error writing log: %s", err)
		return nil, fmt.Errorf("failed to write log: %s", err)
	}
	fields := logrus.Fields{
		"succeeded": len(resp.Succeeded()),
		"failed":    len(resp.Failed()),
	}
	log.WithFields(fields).Debugf("Audit log bulk request complete: %+v", resp)

	return &v1.BulkResponse{
		Total:     len(resp.Items),
		Succeeded: len(resp.Succeeded()),
		Failed:    len(resp.Failed()),
		Errors:    v1.GetBulkErrors(resp),
	}, nil
}

// List lists logs that match the given parameters.
func (b *auditLogBackend) List(ctx context.Context, i bapi.ClusterInfo, opts *v1.AuditLogParams) (*v1.List[v1.AuditLog], error) {
	log := bapi.ContextLogger(i)

	query, startFrom, err := b.getSearch(ctx, i, opts)
	if err != nil {
		return nil, err
	}

	results, err := query.Do(ctx)
	if err != nil {
		return nil, err
	}

	auditLogs := []v1.AuditLog{}
	for _, h := range results.Hits.Hits {
		e := v1.AuditLog{}
		err = json.Unmarshal(h.Source, &e)
		if err != nil {
			log.WithError(err).Error("Error unmarshalling audit log")
			continue
		}
		if b.migrationMode {
			e.ID = h.Id
		}
		auditLogs = append(auditLogs, e)
	}

	afterKey, err := b.afterKey(ctx, i, opts, results, log, startFrom)
	if err != nil {
		return nil, err
	}

	return &v1.List[v1.AuditLog]{
		TotalHits: results.TotalHits(),
		Items:     auditLogs,
		AfterKey:  afterKey,
	}, nil
}

func (b *auditLogBackend) afterKey(ctx context.Context, i bapi.ClusterInfo, opts *v1.AuditLogParams, results *elastic.SearchResult, log *logrus.Entry, startFrom int) (map[string]any, error) {
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
	nextPointInTime, err := logtools.NextPointInTime(ctx, b.client, b.index(opts.Type, i), results, log, useDeepPagination)
	if err != nil {
		return nil, err
	}
	afterKey := logtools.NextAfterKey(opts, startFrom, nextPointInTime, results, useDeepPagination)
	return afterKey, nil
}

func (b *auditLogBackend) Aggregations(ctx context.Context, i bapi.ClusterInfo, opts *v1.AuditLogAggregationParams) (*elastic.Aggregations, error) {
	if b.migrationMode {
		return nil, fmt.Errorf("aggregation queries are not allowed in migration mode")
	}
	// Get the base query.
	search, _, err := b.getSearch(ctx, i, &opts.AuditLogParams)
	if err != nil {
		return nil, err
	}

	// Add in any aggregations provided by the client. We need to handle two cases - one where this is a
	// time-series request, and another when it's just an aggregation request.
	if opts.NumBuckets > 0 {
		// Time-series.
		hist := elastic.NewAutoDateHistogramAggregation().
			Field("requestReceivedTimestamp").
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

func (b *auditLogBackend) getSearch(ctx context.Context, i bapi.ClusterInfo, opts *v1.AuditLogParams) (*elastic.SearchService, int, error) {
	if err := i.Valid(); err != nil {
		return nil, 0, err
	}

	switch opts.Type {
	case v1.AuditLogTypeEE:
	case v1.AuditLogTypeKube:
	case v1.AuditLogTypeAny:
	case "":
		return nil, 0, fmt.Errorf("no audit log type provided on List request")
	default:
		return nil, 0, fmt.Errorf("invalid audit log type: %s", opts.Type)
	}

	q, err := b.buildQuery(i, opts)
	if err != nil {
		return nil, 0, err
	}

	// Build the query.
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
			pitID, err = logtools.OpenPointInTime(ctx, b.client, b.index(opts.Type, i))
			if err != nil {
				return nil, 0, err
			}
		}
	}

	var startFrom int
	query, startFrom, err = logtools.ConfigureCurrentPage(query, opts, b.index(opts.Type, i), b.migrationMode, pitID)
	if err != nil {
		return nil, 0, err
	}

	// Configure sorting.
	if len(opts.Sort) != 0 {
		for _, s := range opts.Sort {
			query.Sort(s.Field, !s.Descending)
		}
	} else {
		query.Sort("requestReceivedTimestamp", true)
	}
	return query, startFrom, nil
}

// buildQuery builds an elastic query using the given parameters.
func (b *auditLogBackend) buildQuery(i bapi.ClusterInfo, opts *v1.AuditLogParams) (elastic.Query, error) {
	// Start with the base flow log query using common fields.
	query, err := logtools.BuildQuery(b.queryHelper, i, opts)
	if err != nil {
		return nil, err
	}

	// For single-index, we also need to filter based on type.
	if b.singleIndex && opts.Type != v1.AuditLogTypeAny {
		query.Filter(elastic.NewTermQuery("audit_type", opts.Type))
	}

	// Check if any resource kinds were specified.
	if len(opts.Kinds) > 0 {
		values := []any{}
		for _, a := range opts.Kinds {
			values = append(values, a)
		}
		query.Filter(elastic.NewTermsQuery("objectRef.resource", values...))
	}

	// Match on author.
	if len(opts.Authors) > 0 {
		values := []any{}
		for _, a := range opts.Authors {
			values = append(values, a)
		}
		query.Filter(elastic.NewTermsQuery("user.username", values...))
	}

	// Match on verb.
	if len(opts.Verbs) > 0 {
		values := []any{}
		for _, a := range opts.Verbs {
			values = append(values, a)
		}
		query.Must(elastic.NewTermsQuery("verb", values...))
	}

	// Match on object.
	if len(opts.ObjectRefs) > 0 {
		objectMatches := []elastic.Query{}
		for _, o := range opts.ObjectRefs {
			objFilter := elastic.NewBoolQuery()
			if o.Resource != "" {
				objFilter.Filter(elastic.NewTermQuery("objectRef.resource", o.Resource))
			}
			if o.APIGroup != "" {
				objFilter.Filter(elastic.NewTermQuery("objectRef.apiGroup", o.APIGroup))
			}
			if o.APIVersion != "" {
				objFilter.Filter(elastic.NewTermQuery("objectRef.apiVersion", o.APIVersion))
			}
			if o.Name != "" {
				objFilter.Filter(elastic.NewTermQuery("objectRef.name", o.Name))
			}
			if o.Namespace != "" {
				if o.Namespace == "-" {
					// Match on lack of a namespace.
					objFilter.MustNot(elastic.NewExistsQuery("objectRef.namespace"))
				} else {
					// Match on the namespace value.
					objFilter.Filter(elastic.NewTermQuery("objectRef.namespace", o.Namespace))
				}
			}
			objectMatches = append(objectMatches, objFilter)
		}

		// We must match at least one of the provided object references.
		query.Must(elastic.NewBoolQuery().Should(objectMatches...))

		// Exclude any logs with no object information if an object ref is given.
		query.MustNot(
			elastic.NewTermQuery("responseObject.metadata", "{}"),
			elastic.NewTermQuery("objectRef", "{}"),
			elastic.NewTermQuery("RequestObject", "{}"),
		)
	}

	// Match on response codes.
	if len(opts.ResponseCodes) > 0 {
		values := []any{}
		for _, a := range opts.ResponseCodes {
			values = append(values, a)
		}
		query.Filter(elastic.NewTermsQuery("responseStatus.code", values...))
	}

	if len(opts.Stages) == 1 {
		query.Must(elastic.NewMatchQuery("stage", opts.Stages[0]))
	} else if len(opts.Stages) > 1 {
		// We only support a single stage at the moment.
		// Stage is defined as a text field, which means terms queries
		// don't work.
		return nil, errors.New("at most one stage may be present on audit log query")
	}

	if len(opts.Levels) > 0 {
		values := []any{}
		for _, a := range opts.Levels {
			values = append(values, a)
		}
		query.Filter(elastic.NewTermsQuery("level", values...))
	}

	if opts.ExcludeDryRuns {
		query.MustNot(elastic.NewWildcardQuery("requestURI", "*dryRun*"))
	}

	return query, nil
}

func (b *auditLogBackend) index(kind v1.AuditLogType, i bapi.ClusterInfo) string {
	switch kind {
	case v1.AuditLogTypeAny:
		return b.anyIndex.Index(i)
	case v1.AuditLogTypeKube:
		return b.kubeIndex.Index(i)
	case v1.AuditLogTypeEE:
		return b.eeIndex.Index(i)
	default:
		logrus.Fatalf("Unknown audit log type: %s", kind)
	}
	return ""
}

func (b *auditLogBackend) writeAlias(kind v1.AuditLogType, i bapi.ClusterInfo) string {
	if kind == v1.AuditLogTypeEE {
		return b.eeIndex.Alias(i)
	}
	return b.kubeIndex.Alias(i)
}
