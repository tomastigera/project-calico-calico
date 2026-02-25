// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package threatfeeds

import (
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
)

func NewIPSetBackend(c lmaelastic.Client, cache bapi.IndexInitializer, deepPaginationCutOff int64, migrationMode bool) bapi.IPSetBackend {
	return &ipSetThreatFeedBackend{
		client:               c.Backend(),
		lmaclient:            c,
		templates:            cache,
		deepPaginationCutOff: deepPaginationCutOff,
		singleIndex:          false,
		index:                index.ThreatfeedsIPSetMultiIndex,
		queryHelper:          lmaindex.MultiIndexThreatfeedsIPSet(),
		migrationMode:        migrationMode,
	}
}

func NewSingleIndexIPSetBackend(c lmaelastic.Client, cache bapi.IndexInitializer, deepPaginationCutOff int64, migrationMode bool, options ...index.Option) bapi.IPSetBackend {
	return &ipSetThreatFeedBackend{
		client:               c.Backend(),
		lmaclient:            c,
		templates:            cache,
		deepPaginationCutOff: deepPaginationCutOff,
		singleIndex:          true,
		index:                index.ThreatFeedsIPSetIndex(options...),
		queryHelper:          lmaindex.SingleIndexThreatfeedsIPSet(),
		migrationMode:        migrationMode,
	}
}

type ipSetThreatFeedBackend struct {
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

type ipsetWithExtras struct {
	v1.IPSetThreatFeedData `json:",inline"`
	Tenant                 string `json:"tenant,omitempty"`
}

// prepareForWrite wraps a log in a document that includes the cluster and tenant if
// the backend is configured to write to a single index.
func (b *ipSetThreatFeedBackend) prepareForWrite(i bapi.ClusterInfo, l *v1.IPSetThreatFeedData) any {
	l.Cluster = i.Cluster

	if b.singleIndex {
		return &ipsetWithExtras{
			IPSetThreatFeedData: *l,
			Tenant:              i.Tenant,
		}
	}
	return l
}

func (b *ipSetThreatFeedBackend) Create(ctx context.Context, i bapi.ClusterInfo, feeds []v1.IPSetThreatFeed) (*v1.BulkResponse, error) {
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
	log.Infof("Writing ip set threat feeds data in bulk to alias %s", alias)

	// Build a bulk request using the provided threat feeds.
	bulk := b.client.Bulk()

	for _, f := range feeds {
		// Populate the log's GeneratedTime field.  This field exists to enable a way for
		// clients to efficiently query newly generated logs, and having Linseed fill it in
		// - instead of an upstream client - makes this less vulnerable to time skew between
		// clients, and between clients and Linseed.
		generatedTime := time.Now().UTC()
		f.Data.GeneratedTime = &generatedTime

		req := elastic.NewBulkIndexRequest().Index(alias).Doc(b.prepareForWrite(i, f.Data)).Id(backend.ToElasticID(b.singleIndex, f.ID, i))
		bulk.Add(req)
	}

	// Send the bulk request.
	resp, err := bulk.Do(ctx)
	if err != nil {
		log.Errorf("Error writing ip sets threat feeds data: %s", err)
		return nil, fmt.Errorf("failed to write ip sets threat feeds data: %s", err)
	}
	fields := logrus.Fields{
		"succeeded": len(resp.Succeeded()),
		"failed":    len(resp.Failed()),
	}
	log.WithFields(fields).Debugf("Threat feeds ip sets bulk request complete: %+v", resp)

	return &v1.BulkResponse{
		Total:     len(resp.Items),
		Succeeded: len(resp.Succeeded()),
		Failed:    len(resp.Failed()),
		Errors:    v1.GetBulkErrors(resp),
	}, nil
}

func (b *ipSetThreatFeedBackend) List(ctx context.Context, i bapi.ClusterInfo, params *v1.IPSetThreatFeedParams) (*v1.List[v1.IPSetThreatFeed], error) {
	log := bapi.ContextLogger(i)

	query, startFrom, err := b.getSearch(ctx, i, params)
	if err != nil {
		return nil, err
	}

	results, err := query.Do(ctx)
	if err != nil {
		return nil, err
	}

	feeds := []v1.IPSetThreatFeed{}
	for _, h := range results.Hits.Hits {
		feed := v1.IPSetThreatFeedData{}
		err = json.Unmarshal(h.Source, &feed)
		if err != nil {
			log.WithError(err).Error("Error unmarshalling threat feed")
			continue
		}
		ipSetFeed := v1.IPSetThreatFeed{
			ID:          backend.ToApplicationID(b.singleIndex, h.Id, i),
			Data:        &feed,
			SeqNumber:   h.SeqNo,
			PrimaryTerm: h.PrimaryTerm,
		}

		feeds = append(feeds, ipSetFeed)
	}

	afterKey, err := b.afterKey(ctx, i, params, results, log, startFrom)
	if err != nil {
		return nil, err
	}

	return &v1.List[v1.IPSetThreatFeed]{
		Items:     feeds,
		TotalHits: results.TotalHits(),
		AfterKey:  afterKey,
	}, nil
}

func (b *ipSetThreatFeedBackend) afterKey(ctx context.Context, i bapi.ClusterInfo, opts *v1.IPSetThreatFeedParams, results *elastic.SearchResult, log *logrus.Entry, startFrom int) (map[string]any, error) {
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

func (b *ipSetThreatFeedBackend) getSearch(ctx context.Context, i bapi.ClusterInfo, p *v1.IPSetThreatFeedParams) (*elastic.SearchService, int, error) {
	if err := i.Valid(); err != nil {
		return nil, 0, err
	}

	q, err := b.buildQuery(i, p)
	if err != nil {
		return nil, 0, err
	}

	// Build the query, sorting by time.
	query := b.client.Search().
		Size(p.GetMaxPageSize()).
		Query(q)

	// Configure pagination options
	var startFrom int
	var pitID string
	if b.migrationMode {
		// For migration mode, we enable deep pagination for each request
		// instead of deciding based on number of documents stored.
		// For the first page, we need to perform the query with a point
		// in time configured
		if ak := p.GetAfterKey(); ak == nil {
			var err error
			pitID, err = logtools.OpenPointInTime(ctx, b.client, b.index.Index(i))
			if err != nil {
				return nil, 0, err
			}
		}
	}

	query, startFrom, err = logtools.ConfigureCurrentPage(query, p, b.index.Index(i), b.migrationMode, pitID)
	if err != nil {
		return nil, 0, err
	}

	// Configure sorting.
	if len(p.GetSortBy()) != 0 {
		for _, s := range p.GetSortBy() {
			query.Sort(s.Field, !s.Descending)
		}
	} else {
		query.Sort(b.queryHelper.GetTimeField(), true)
	}

	return query, startFrom, nil
}

func (b *ipSetThreatFeedBackend) buildQuery(i bapi.ClusterInfo, p *v1.IPSetThreatFeedParams) (elastic.Query, error) {
	query, err := b.queryHelper.BaseQuery(i, p)
	if err != nil {
		return nil, err
	}

	if p.TimeRange != nil {
		query.Must(b.queryHelper.NewTimeRangeQuery(p.TimeRange))
	}

	if p.ID != "" {
		query.Must(elastic.NewTermQuery("_id", backend.ToElasticID(b.singleIndex, p.ID, i)))
	}

	return query, nil
}

func (b *ipSetThreatFeedBackend) Delete(ctx context.Context, i bapi.ClusterInfo, feeds []v1.IPSetThreatFeed) (*v1.BulkResponse, error) {
	if err := i.Valid(); err != nil {
		return nil, err
	}

	if err := b.checkTenancy(ctx, i, feeds); err != nil {
		logrus.WithError(err).Warn("Error checking tenancy")
		return &v1.BulkResponse{
			Total:     len(feeds),
			Succeeded: 0,
			Failed:    len(feeds),
			Errors:    []v1.BulkError{{Resource: "", Type: "document_missing_exception", Reason: err.Error()}},
			Deleted:   nil,
		}, nil
	}

	alias := b.index.Alias(i)

	// Build a bulk request using the provided feeds.
	bulk := b.client.Bulk()
	numToDelete := 0
	bulkErrs := []v1.BulkError{}
	for _, feed := range feeds {
		req := elastic.NewBulkDeleteRequest().Index(alias).Id(backend.ToElasticID(b.singleIndex, feed.ID, i))
		bulk.Add(req)
		numToDelete++
	}

	if numToDelete == 0 {
		// If there are no feeds to delete, short-circuit and return an empty response.
		return &v1.BulkResponse{
			Total:     len(bulkErrs),
			Succeeded: 0,
			Failed:    len(bulkErrs),
			Errors:    bulkErrs,
		}, nil
	}

	// Send the bulk request. Wait for results to be refreshed before replying,
	// so that subsequent reads show consistent data.
	resp, err := bulk.Refresh("wait_for").Do(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to delete feeds: %s", err)
	}

	// Convert individual success / failure responses.
	del := []v1.BulkItem{}
	for _, i := range resp.Deleted() {
		bi := v1.BulkItem{ID: i.Id, Status: i.Status}
		del = append(del, bi)
	}

	return &v1.BulkResponse{
		Total:     len(resp.Items),
		Succeeded: len(resp.Succeeded()),
		Failed:    len(resp.Failed()),
		Errors:    v1.GetBulkErrors(resp),
		Deleted:   del,
	}, nil
}

func (b *ipSetThreatFeedBackend) checkTenancy(ctx context.Context, i bapi.ClusterInfo, feeds []v1.IPSetThreatFeed) error {
	// If we're in single index mode, we need to check tenancy. Otherwise, we can skip this because
	// the index name already contains the cluster and tenant ID.
	if !b.singleIndex {
		return nil
	}

	// This is a shared index.
	// We need to protect against tenancy here. In single index mode without this check, any tenant could send a request which
	// deletes feeds for any other tenant if they guess the right ID.
	// Query the given feed IDs using the tenant and cluster from the request to ensure that each feed is visible to that tenant.
	ids := []string{}
	for _, feed := range feeds {
		ids = append(ids, backend.ToElasticID(b.singleIndex, feed.ID, i))
	}

	// Build a query which matches on:
	// - The given cluster and tenant (from BaseQuery)
	// - An OR combintation of the given IDs
	q, err := b.queryHelper.BaseQuery(i, nil)
	if err != nil {
		return err
	}
	q = q.Must(elastic.NewIdsQuery().Ids(ids...))
	idsQuery := b.client.Search().
		Size(len(ids)).
		Index(b.index.Index(i)).
		Query(q)
	idsResult, err := idsQuery.Do(ctx)
	if err != nil {
		return err
	}

	// Build a lookup map of the found feeds.
	foundIDs := map[string]struct{}{}
	for _, hit := range idsResult.Hits.Hits {
		foundIDs[backend.ToApplicationID(b.singleIndex, hit.Id, i)] = struct{}{}
	}

	// Now make sure that all of the given feeds were found.
	for _, feed := range feeds {
		if _, found := foundIDs[feed.ID]; !found {
			return fmt.Errorf("feed %s not found", feed.ID)
		}
	}
	return nil
}
