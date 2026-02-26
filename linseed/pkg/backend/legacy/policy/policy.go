// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Package policy provides backend storage and query logic for Calico policy activity logs.
// It supports bulk creation, deduplication, time-based queries, and aggregation over policy activity data.
// This implementation is optimized for Elasticsearch and supports both single-index and multi-index modes.

package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/sirupsen/logrus"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/index"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/logtools"
	lmaindex "github.com/projectcalico/calico/linseed/pkg/internal/lma/elastic/index"
	lmaelastic "github.com/projectcalico/calico/lma/pkg/elastic"
)

// policyBackend implements the PolicyBackend interface for storing and querying policy activity logs.
type policyBackend struct {
	esClient             *elastic.Client
	lmaclient            lmaelastic.Client
	templates            bapi.IndexInitializer
	deepPaginationCutOff int64
	queryHelper          lmaindex.Helper
	singleIndex          bool
	index                bapi.Index
	cancelCleanup        context.CancelFunc

	// policyActivityCache stores the last time we processed a specific deterministic ID.
	// This allows us to throttle writes to Elasticsearch without risking data loss.
	policyActivityCache sync.Map
	// dedupWindow defines how often we allow an update to pass through to ES.
	dedupWindow time.Duration

	// Migration knobs.
	migrationMode bool
}

// NewBackend creates a new policyBackend for multi-index mode.
func NewBackend(c lmaelastic.Client, cache bapi.IndexInitializer, deepPaginationCutOff int64, migrationMode bool, cleanupInterval, cleanupTTL time.Duration) bapi.PolicyBackend {
	ctx, cancel := context.WithCancel(context.Background())
	b := &policyBackend{
		esClient:             c.Backend(),
		lmaclient:            c,
		queryHelper:          lmaindex.MultiIndexPolicyActivity(),
		templates:            cache,
		deepPaginationCutOff: deepPaginationCutOff,
		singleIndex:          false,
		index:                index.PolicyActivityMultiIndex,
		migrationMode:        migrationMode,
		dedupWindow:          1 * time.Hour,
		cancelCleanup:        cancel,
	}
	go b.StartCacheCleanup(ctx, cleanupInterval, cleanupTTL)

	return b
}

// NewSingleIndexBackend creates a new policyBackend for single-index mode.
func NewSingleIndexBackend(c lmaelastic.Client, cache bapi.IndexInitializer, deepPaginationCutOff int64, migrationMode bool, cleanupInterval, cleanupTTL time.Duration, options ...index.Option) bapi.PolicyBackend {
	ctx, cancel := context.WithCancel(context.Background())
	b := &policyBackend{
		esClient:             c.Backend(),
		lmaclient:            c,
		queryHelper:          lmaindex.SingleIndexPolicyActivity(),
		templates:            cache,
		deepPaginationCutOff: deepPaginationCutOff,
		singleIndex:          true,
		index:                index.PolicyActivityIndex(options...),
		migrationMode:        migrationMode,
		dedupWindow:          1 * time.Hour,
		cancelCleanup:        cancel,
	}
	go b.StartCacheCleanup(ctx, cleanupInterval, cleanupTTL)

	return b
}

type logWithExtras struct {
	v1.PolicyActivity `json:",inline"`
	Tenant            string `json:"tenant,omitempty"`
}

// prepareForWrite wraps a log in a document that includes the cluster and tenant if
// the backend is configured to write to a single index.
func (b *policyBackend) prepareForWrite(i bapi.ClusterInfo, l v1.PolicyActivity) any {
	l.Cluster = i.Cluster
	if b.singleIndex {
		return &logWithExtras{
			PolicyActivity: l,
			Tenant:         i.Tenant,
		}
	}
	return l
}

// genDeterministicID creates a unique ID based on the content of the log.
// This ensures that the same Policy+Rule+Cluster always results in the same ID,
// forcing Elasticsearch to Update (overwrite) instead of Append (duplicate).
func genDeterministicID(policy v1.PolicyInfo, cluster, tenant, rule string) string {
	// We use a separator "|" to combine the fields.
	key := fmt.Sprintf("%s|%s|%s|%s|%s|%s", cluster, tenant, policy.Kind, policy.Namespace, policy.Name, rule)
	// We hash it simply to keep the ID length predictable and URL-safe.
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

// Create stores the given policy activity logs in Elasticsearch, deduplicating by deterministic ID and throttling updates.
func (b *policyBackend) Create(ctx context.Context, i bapi.ClusterInfo, logs []v1.PolicyActivity) (*v1.BulkResponse, error) {
	log := bapi.ContextLogger(i)

	if err := i.Valid(); err != nil {
		return nil, err
	}

	var candidates []v1.PolicyActivity
	for _, f := range logs {
		id := genDeterministicID(f.Policy, i.Cluster, i.Tenant, f.Rule)

		lastProcessed, found := b.policyActivityCache.Load(id)
		if found {
			lastTime := lastProcessed.(time.Time)
			if time.Since(lastTime) < b.dedupWindow {
				continue
			}
		}

		f.ID = id
		candidates = append(candidates, f)
	}

	if len(candidates) == 0 {
		return &v1.BulkResponse{
			Total:     len(logs),
			Succeeded: len(logs),
			Failed:    0,
		}, nil
	}

	err := b.templates.Initialize(ctx, b.index, i)
	if err != nil {
		return nil, err
	}
	alias := b.index.Alias(i)

	mget := b.esClient.MultiGet()
	for _, f := range candidates {
		mget.Add(elastic.NewMultiGetItem().Index(alias).Id(f.ID))
	}

	getResponse, err := mget.Do(ctx)
	if err != nil {
		log.WithError(err).Warn("Failed to check existing timestamps, proceeding with blind write")
	}

	var data []v1.PolicyActivity
	if getResponse != nil && len(getResponse.Docs) == len(candidates) {
		for idx, doc := range getResponse.Docs {
			candidate := candidates[idx]
			if !doc.Found {
				data = append(data, candidate)
				continue
			}
			var existing v1.PolicyActivity
			if err := json.Unmarshal(doc.Source, &existing); err != nil {
				data = append(data, candidate)
				continue
			}
			if candidate.LastEvaluated.After(existing.LastEvaluated) {
				data = append(data, candidate)
			} else {
				b.policyActivityCache.Store(candidate.ID, time.Now())
			}
		}
	} else {
		data = candidates
	}

	if len(data) == 0 {
		return &v1.BulkResponse{
			Total:     len(logs),
			Succeeded: len(logs),
			Failed:    0,
		}, nil
	}

	log.Debugf("Writing policy activity logs in bulk to alias %s", alias)
	bulk := b.esClient.Bulk()
	for _, f := range data {
		generatedTime := time.Now().UTC()
		f.GeneratedTime = &generatedTime

		id := f.ID
		f.ID = ""

		req := elastic.NewBulkIndexRequest().Index(alias).Doc(b.prepareForWrite(i, f))
		req.Id(id)
		bulk.Add(req)
	}

	resp, err := bulk.Do(ctx)
	if err != nil {
		log.Errorf("Error writing log: %s", err)
		return nil, fmt.Errorf("failed to write log: %s", err)
	}

	// This prevents data loss: if a write failed, we don't update the cache,
	// so the next retry will attempt to write it again.
	for _, item := range resp.Succeeded() {
		b.policyActivityCache.Store(item.Id, time.Now())
	}

	skippedCount := len(logs) - len(data)
	succeededCount := len(resp.Succeeded()) + skippedCount

	fields := logrus.Fields{
		"succeeded": len(resp.Succeeded()),
		"failed":    len(resp.Failed()),
		"throttled": skippedCount,
	}
	log.WithFields(fields).Debugf("Policy activity log bulk request complete: %+v", resp)

	return &v1.BulkResponse{
		Total:     len(logs),
		Succeeded: succeededCount,
		Failed:    len(resp.Failed()),
		Errors:    v1.GetBulkErrors(resp),
	}, nil
}

// List returns policy activity logs matching the given parameters.
func (b *policyBackend) List(ctx context.Context, i bapi.ClusterInfo, params *v1.PolicyActivityParams) (*v1.List[v1.PolicyActivity], error) {
	log := bapi.ContextLogger(i)

	search, startFrom, err := b.getSearch(i, params)
	if err != nil {
		return nil, err
	}

	results, err := search.Do(ctx)
	if err != nil {
		log.WithError(err).Errorf("Elasticsearch search failed for index %s with params: %+v", b.index.Alias(i), params)
		return nil, fmt.Errorf("elasticsearch search failed: %w", err)
	}

	logs := []v1.PolicyActivity{}
	for _, h := range results.Hits.Hits {
		l := v1.PolicyActivity{}
		err = json.Unmarshal(h.Source, &l)
		if err != nil {
			log.WithError(err).Error("Error unmarshaling policy activity log")
			continue
		}
		l.ID = h.Id
		logs = append(logs, l)
	}

	afterKey, err := b.afterKey(ctx, i, params, results, log, startFrom)
	if err != nil {
		return nil, err
	}

	return &v1.List[v1.PolicyActivity]{
		TotalHits: results.TotalHits(),
		Items:     logs,
		AfterKey:  afterKey,
	}, nil
}

// afterKey computes the pagination key for deep pagination support.
func (b *policyBackend) afterKey(ctx context.Context, i bapi.ClusterInfo, opts *v1.PolicyActivityParams, results *elastic.SearchResult, log *logrus.Entry, startFrom int) (map[string]any, error) {
	useDeepPagination := b.migrationMode
	if !useDeepPagination {
		useDeepPagination = results.TotalHits() >= b.deepPaginationCutOff
	}
	nextPointInTime, err := logtools.NextPointInTime(ctx, b.esClient, b.index.Index(i), results, log, useDeepPagination)
	if err != nil {
		return nil, err
	}
	afterKey := logtools.NextAfterKey(opts, startFrom, nextPointInTime, results, useDeepPagination)
	return afterKey, nil
}

// getSearch builds the Elasticsearch search service for policy activity queries.
func (b *policyBackend) getSearch(i bapi.ClusterInfo, opts *v1.PolicyActivityParams) (*elastic.SearchService, int, error) {
	if err := i.Valid(); err != nil {
		return nil, 0, err
	}

	q, err := b.buildQuery(i, opts)
	if err != nil {
		return nil, 0, err
	}
	query := b.esClient.Search(b.index.Alias(i)).
		Size(opts.GetMaxPageSize()).
		Query(q)

	var startFrom int
	var pitID string

	query, startFrom, err = logtools.ConfigureCurrentPage(query, opts, b.index.Index(i), b.migrationMode, pitID)
	if err != nil {
		return nil, 0, err
	}

	if len(opts.Sort) != 0 {
		for _, s := range opts.Sort {
			query.Sort(s.Field, !s.Descending)
		}
	} else {
		query.Sort(b.queryHelper.GetTimeField(), true)
	}
	return query, startFrom, nil
}

// buildQuery constructs an Elasticsearch query for policy activity logs using the provided parameters.
func (b *policyBackend) buildQuery(i bapi.ClusterInfo, opts *v1.PolicyActivityParams) (elastic.Query, error) {
	baseQ, err := logtools.BuildQuery(b.queryHelper, i, opts)
	if err != nil {
		return nil, err
	}

	boolQ := elastic.NewBoolQuery().Must(baseQ)

	if opts != nil && opts.Selector != "" {
		selQ, err := b.queryHelper.NewSelectorQuery(opts.Selector)
		if err != nil {
			return nil, err
		}
		boolQ.Filter(selQ)
	}

	if opts != nil && opts.TimeRange != nil {
		timeQ := b.queryHelper.NewTimeRangeQuery(opts.TimeRange)
		if timeQ != nil {
			boolQ.Filter(timeQ)
		}
	}

	if opts != nil {
		if len(opts.Rules) > 0 {
			rules := make([]any, len(opts.Rules))
			for i, r := range opts.Rules {
				rules[i] = r
			}
			boolQ.Filter(elastic.NewTermsQuery("rule", rules...))
		}
		if opts.Policy.Kind != "" {
			boolQ.Filter(elastic.NewTermQuery("policy.kind", opts.Policy.Kind))
		}
		if opts.Policy.Namespace != "" {
			boolQ.Filter(elastic.NewTermQuery("policy.namespace", opts.Policy.Namespace))
		}
		if opts.Policy.Name != "" {
			boolQ.Filter(elastic.NewTermQuery("policy.name", opts.Policy.Name))
		}
		if !opts.LastEvaluated.IsZero() {
			boolQ.Filter(elastic.NewRangeQuery("last_evaluated").Gte(opts.LastEvaluated))
		}
	}

	return boolQ, nil
}

// StartCacheCleanup starts a background routine to remove stale entries from the local cache.
func (b *policyBackend) StartCacheCleanup(ctx context.Context, interval time.Duration, ttl time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	logrus.Info("Starting policy activity cache cleanup routine")

	for {
		select {
		case <-ctx.Done():
			logrus.Info("Stopping policy activity cache cleanup routine")
			return
		case <-ticker.C:
			b.expireOldEntries(ttl)
		}
	}
}

// expireOldEntries iterates the local cache and deletes items that haven't been touched in 'ttl' time.
func (b *policyBackend) expireOldEntries(ttl time.Duration) {
	cutoff := time.Now().Add(-ttl)
	count := 0

	b.policyActivityCache.Range(func(key, value any) bool {
		lastSeen, ok := value.(time.Time)

		// If data is invalid or older than our TTL, delete it.
		if !ok || lastSeen.Before(cutoff) {
			b.policyActivityCache.CompareAndDelete(key, value)
			count++
		}
		return true
	})

	if count > 0 {
		logrus.WithField("count", count).Debug("Cleaned up stale policy activity cache entries")
	}
}

func (b *policyBackend) Close() {
	if b.cancelCleanup != nil {
		b.cancelCleanup()
	}
}

// GetPolicyActivity returns aggregated policy activity data for the given policies.
func (b *policyBackend) GetPolicyActivity(ctx context.Context, i bapi.ClusterInfo, req *v1.PolicyActivityRequest) (*v1.PolicyActivityResponse, error) {
	log := bapi.ContextLogger(i)

	if err := i.Valid(); err != nil {
		return nil, err
	}
	if err := req.Valid(); err != nil {
		return nil, err
	}

	if len(req.Policies) == 0 {
		return &v1.PolicyActivityResponse{Items: []v1.PolicyActivityResult{}}, nil
	}

	err := b.templates.Initialize(ctx, b.index, i)
	if err != nil {
		return nil, err
	}

	query := b.buildPolicyActivityQuery(i, req)

	results, err := b.esClient.Search(b.index.Index(i)).
		Size(10000).
		Query(query).
		Do(ctx)
	if err != nil {
		log.WithError(err).Error("Elasticsearch search failed for GetPolicyActivity")
		return nil, fmt.Errorf("elasticsearch search failed: %w", err)
	}

	return aggregatePolicyActivity(log, req, results), nil
}

// buildPolicyActivityQuery constructs an ES bool query that matches docs for
// any of the requested policies, filtered by generation prefix on the rule field.
func (b *policyBackend) buildPolicyActivityQuery(i bapi.ClusterInfo, req *v1.PolicyActivityRequest) *elastic.BoolQuery {
	shouldClauses := make([]elastic.Query, 0, len(req.Policies))
	for _, p := range req.Policies {
		policyQuery := elastic.NewBoolQuery().
			Filter(
				elastic.NewTermQuery("policy.kind", p.Kind),
				elastic.NewTermQuery("policy.name", p.Name),
				elastic.NewPrefixQuery("rule", fmt.Sprintf("%d|", p.Generation)),
			)
		if p.Namespace != "" {
			policyQuery.Filter(elastic.NewTermQuery("policy.namespace", p.Namespace))
		}
		shouldClauses = append(shouldClauses, policyQuery)
	}

	boolQuery := elastic.NewBoolQuery().
		Should(shouldClauses...).
		MinimumShouldMatch("1")

	if req.From != nil || req.To != nil {
		rangeQuery := elastic.NewRangeQuery("last_evaluated")
		if req.From != nil {
			rangeQuery.Gte(req.From)
		}
		if req.To != nil {
			rangeQuery.Lte(req.To)
		}
		boolQuery.Filter(rangeQuery)
	}

	if b.singleIndex {
		boolQuery.Filter(elastic.NewTermQuery("cluster", i.Cluster))
		if i.Tenant != "" {
			boolQuery.Filter(elastic.NewTermQuery("tenant", i.Tenant))
		}
	}

	return boolQuery
}

// policyKey uniquely identifies a policy by its kind, namespace, and name.
// It is used as a map key when fetching data from Elasticsearch and performing aggregations.
type policyKey struct {
	Kind      string
	Namespace string
	Name      string
}

// policyActivityEntry accumulates per-policy activity results during aggregation.
type policyActivityEntry struct {
	policy        v1.PolicyInfo
	lastEvaluated *time.Time
	rules         []v1.PolicyActivityRuleResult
}

// aggregatePolicyActivity groups ES hits by policy, parses rule strings, computes
// per-policy last_evaluated, and returns results in the same order as the request.
func aggregatePolicyActivity(log *logrus.Entry, req *v1.PolicyActivityRequest, results *elastic.SearchResult) *v1.PolicyActivityResponse {
	resultMap := make(map[policyKey]*policyActivityEntry)

	for _, hit := range results.Hits.Hits {
		var doc v1.PolicyActivity
		if err := json.Unmarshal(hit.Source, &doc); err != nil {
			log.WithError(err).Error("Error unmarshaling policy activity doc")
			continue
		}

		parts := strings.Split(doc.Rule, "|")
		if len(parts) < 3 {
			log.WithField("rule", doc.Rule).Warn("Skipping doc with unparsable rule string")
			continue
		}

		key := policyKey{Kind: doc.Policy.Kind, Namespace: doc.Policy.Namespace, Name: doc.Policy.Name}
		entry, ok := resultMap[key]
		if !ok {
			entry = &policyActivityEntry{policy: doc.Policy}
			resultMap[key] = entry
		}

		if entry.lastEvaluated == nil || doc.LastEvaluated.After(*entry.lastEvaluated) {
			t := doc.LastEvaluated
			entry.lastEvaluated = &t
		}

		entry.rules = append(entry.rules, v1.PolicyActivityRuleResult{
			Direction:     parts[1],
			Index:         parts[2],
			LastEvaluated: doc.LastEvaluated,
		})
	}

	// Build response preserving request order.
	items := make([]v1.PolicyActivityResult, 0, len(req.Policies))
	for _, p := range req.Policies {
		key := policyKey{Kind: p.Kind, Namespace: p.Namespace, Name: p.Name}
		entry, ok := resultMap[key]
		if !ok {
			continue
		}
		items = append(items, v1.PolicyActivityResult{
			Policy:        entry.policy,
			LastEvaluated: entry.lastEvaluated,
			Rules:         entry.rules,
		})
	}

	return &v1.PolicyActivityResponse{Items: items}
}

// Aggregations is a placeholder to satisfy the interface; aggregation queries are not supported for policy activity logs.
func (b *policyBackend) Aggregations(ctx context.Context, i bapi.ClusterInfo, p *v1.PolicyActivityParams) (*elastic.Aggregations, error) {
	return nil, nil
}
