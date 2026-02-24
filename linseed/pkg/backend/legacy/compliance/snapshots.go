// Copyright (c) 2023 Tigera All rights reserved.

package compliance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/sirupsen/logrus"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/backend"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/index"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/logtools"
	lmaindex "github.com/projectcalico/calico/linseed/pkg/internal/lma/elastic/index"
	lmaelastic "github.com/projectcalico/calico/lma/pkg/elastic"
	"github.com/projectcalico/calico/lma/pkg/list"
)

func NewSnapshotBackend(c lmaelastic.Client, cache bapi.IndexInitializer, deepPaginationCutOff int64, migrationMode bool) bapi.SnapshotsBackend {
	return &snapshotsBackend{
		client:               c.Backend(),
		lmaclient:            c,
		templates:            cache,
		deepPaginationCutOff: deepPaginationCutOff,
		queryHelper:          lmaindex.MultiIndexComplianceSnapshots(),
		singleIndex:          false,
		index:                index.ComplianceSnapshotMultiIndex,
		migrationMode:        migrationMode,
	}
}

func NewSingleIndexSnapshotBackend(c lmaelastic.Client, cache bapi.IndexInitializer, deepPaginationCutOff int64, migrationMode bool, options ...index.Option) bapi.SnapshotsBackend {
	return &snapshotsBackend{
		client:               c.Backend(),
		lmaclient:            c,
		templates:            cache,
		deepPaginationCutOff: deepPaginationCutOff,
		queryHelper:          lmaindex.SingleIndexComplianceSnapshots(),
		singleIndex:          true,
		index:                index.ComplianceSnapshotsIndex(options...),
		migrationMode:        migrationMode,
	}
}

type snapshotsBackend struct {
	client               *elastic.Client
	templates            bapi.IndexInitializer
	lmaclient            lmaelastic.Client
	deepPaginationCutOff int64
	queryHelper          lmaindex.Helper
	singleIndex          bool
	index                bapi.Index

	// Migration knobs
	migrationMode bool
}

// prepareForWrite sets the cluster field, and wraps the log in a document to set tenant if
// the backend is configured to write to a single index.
func (b *snapshotsBackend) prepareForWrite(i bapi.ClusterInfo, l *list.TimestampedResourceList) (any, error) {
	l.Cluster = i.Cluster

	if b.singleIndex {
		// Insert cluster and tenant into the document. TimestampedResourceLists have a custom
		// JSON marshaler so we need to add the cluster and tenant to the JSON directly.
		b, err := l.MarshalJSON()
		if err != nil {
			return nil, err
		}
		buf := bytes.NewBuffer(bytes.TrimSuffix(b, []byte("}")))
		_, err = fmt.Fprintf(buf, `,"tenant":"%s"}`, i.Tenant)
		return buf.String(), err
	}
	return l, nil
}

func (b *snapshotsBackend) List(ctx context.Context, i bapi.ClusterInfo, opts *v1.SnapshotParams) (*v1.List[v1.Snapshot], error) {
	log := bapi.ContextLogger(i)

	query, startFrom, err := b.getSearch(ctx, i, opts)
	if err != nil {
		return nil, err
	}

	results, err := query.Do(ctx)
	if err != nil {
		return nil, err
	}

	snapshots := []v1.Snapshot{}
	for _, h := range results.Hits.Hits {
		rl := list.TimestampedResourceList{}
		err = json.Unmarshal(h.Source, &rl)
		if err != nil {
			log.WithError(err).WithField("_source", string(h.Source)).Error("Error unmarshalling snapshot")
			continue
		}
		snapshot := v1.Snapshot{}
		snapshot.ID = backend.ToApplicationID(b.singleIndex, h.Id, i)
		snapshot.ResourceList = rl
		snapshots = append(snapshots, snapshot)
	}

	afterKey, err := b.afterKey(ctx, i, opts, results, log, startFrom)
	if err != nil {
		return nil, err
	}

	return &v1.List[v1.Snapshot]{
		Items:     snapshots,
		TotalHits: results.TotalHits(),
		AfterKey:  afterKey,
	}, nil
}

func (b *snapshotsBackend) afterKey(ctx context.Context, i bapi.ClusterInfo, opts *v1.SnapshotParams, results *elastic.SearchResult, log *logrus.Entry, startFrom int) (map[string]any, error) {
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

func (b *snapshotsBackend) Create(ctx context.Context, i bapi.ClusterInfo, l []v1.Snapshot) (*v1.BulkResponse, error) {
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
	log.Infof("Writing snapshot data in bulk to alias %s", alias)

	// Build a bulk request using the provided logs.
	bulk := b.client.Bulk()

	for _, f := range l {
		// Populate the log's GeneratedTime field.  This field exists to enable a way for
		// clients to efficiently query newly generated logs, and having Linseed fill it in
		// - instead of an upstream client - makes this less vulnerable to time skew between
		// clients, and between clients and Linseed.
		generatedTime := time.Now().UTC()
		f.ResourceList.GeneratedTime = &generatedTime

		// Add this log to the bulk request.
		doc, err := b.prepareForWrite(i, &f.ResourceList)
		if err != nil {
			log.WithError(err).Error("Error preparing snapshot for write")
			continue
		}

		req := elastic.NewBulkIndexRequest().Index(alias).Doc(doc).Id(backend.ToElasticID(b.singleIndex, f.ResourceList.String(), i))
		bulk.Add(req)
	}

	// Send the bulk request.
	resp, err := bulk.Do(ctx)
	if err != nil {
		log.Errorf("Error writing snapshot data: %s", err)
		return nil, fmt.Errorf("failed to write snapshot data: %s", err)
	}
	fields := logrus.Fields{
		"succeeded": len(resp.Succeeded()),
		"failed":    len(resp.Failed()),
	}
	log.WithFields(fields).Debugf("Compliance snapshot bulk request complete: %+v", resp)

	return &v1.BulkResponse{
		Total:     len(resp.Items),
		Succeeded: len(resp.Succeeded()),
		Failed:    len(resp.Failed()),
		Errors:    v1.GetBulkErrors(resp),
	}, nil
}

func (b *snapshotsBackend) getSearch(ctx context.Context, i bapi.ClusterInfo, opts *v1.SnapshotParams) (*elastic.SearchService, int, error) {
	if err := i.Valid(); err != nil {
		return nil, 0, err
	}

	q := b.buildQuery(i, opts)

	// Build the query, sorting by time.
	query := b.client.Search().
		Size(opts.GetMaxPageSize()).
		Query(q)

	// Configure pagination options
	var startFrom int
	var err error
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
	if len(opts.Sort) != 0 {
		for _, s := range opts.Sort {
			query.Sort(s.Field, !s.Descending)
		}
	} else {
		query.SortBy(elastic.NewFieldSort("requestCompletedTimestamp").Order(false), elastic.SortByDoc{})
	}

	return query, startFrom, nil
}

func (b *snapshotsBackend) buildQuery(i bapi.ClusterInfo, p *v1.SnapshotParams) elastic.Query {
	query, err := b.queryHelper.BaseQuery(i, p)
	if err != nil {
		return nil
	}

	if p.TimeRange != nil {
		query.Must(b.queryHelper.NewTimeRangeQuery(p.TimeRange))
	}

	if p.TypeMatch != nil {
		if p.TypeMatch.Kind != "" {
			query.Must(elastic.NewTermQuery("kind", p.TypeMatch.Kind))
		}
		if p.TypeMatch.APIVersion != "" {
			query.Must(elastic.NewTermQuery("apiVersion", p.TypeMatch.APIVersion))
		}
	}
	return query
}
