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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/sirupsen/logrus"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/index"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/logtools"
	lmaelastic "github.com/projectcalico/calico/lma/pkg/elastic"
)

// policyBackend implements the PolicyBackend interface for storing and querying policy activity logs.
type policyBackend struct {
	esClient  *elastic.Client
	lmaclient lmaelastic.Client
	templates bapi.IndexInitializer
	index     bapi.Index

	cancelCleanup context.CancelFunc

	// policyActivityCache stores the last time we processed a specific deterministic ID.
	// This allows us to throttle writes to Elasticsearch without risking data loss.
	policyActivityCache sync.Map
	// dedupWindow defines how often we allow an update to pass through to ES.
	dedupWindow time.Duration
}

// NewBackend creates a new policyBackend. Policy activity always uses single-index mode.
func NewBackend(c lmaelastic.Client, cache bapi.IndexInitializer, cleanupInterval, cleanupTTL time.Duration, options ...index.Option) bapi.PolicyBackend {
	ctx, cancel := context.WithCancel(context.Background())
	b := &policyBackend{
		esClient:      c.Backend(),
		lmaclient:     c,
		templates:     cache,
		index:         index.PolicyActivityIndex(options...),
		dedupWindow:   1 * time.Hour,
		cancelCleanup: cancel,
	}
	go b.StartCacheCleanup(ctx, cleanupInterval, cleanupTTL)

	return b
}

type logWithExtras struct {
	v1.PolicyActivity `json:",inline"`
	Tenant            string `json:"tenant,omitempty"`
}

// prepareForWrite wraps a log in a document that includes the cluster and tenant.
func (b *policyBackend) prepareForWrite(i bapi.ClusterInfo, l v1.PolicyActivity) any {
	l.Cluster = i.Cluster
	return &logWithExtras{
		PolicyActivity: l,
		Tenant:         i.Tenant,
	}
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

// GetPolicyActivities returns aggregated policy activity data for the given policies.
func (b *policyBackend) GetPolicyActivities(ctx context.Context, i bapi.ClusterInfo, req *v1.PolicyActivityParams) (*v1.PolicyActivityResponse, error) {
	log := bapi.ContextLogger(i)

	if err := i.Valid(); err != nil {
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

	// Use search_after with a Point In Time (PIT) to paginate through result
	// sets that may exceed the 10k max_result_window. This is preferred over
	// the scroll API as it uses fewer cluster resources.
	pitID, err := logtools.OpenPointInTime(ctx, b.esClient, b.index.Index(i))
	if err != nil {
		log.WithError(err).Error("Failed to open point in time for GetPolicyActivities")
		return nil, fmt.Errorf("failed to open point in time: %w", err)
	}
	defer func() {
		if _, err := b.esClient.ClosePointInTime(pitID).Do(ctx); err != nil {
			log.WithError(err).Warn("Failed to close point in time")
		}
	}()

	var allHits []*elastic.SearchHit
	var searchAfter []any
	for {
		search := b.esClient.Search().
			Size(10000).
			Query(query).
			Sort("_shard_doc", true).
			PointInTime(elastic.NewPointInTimeWithKeepAlive(pitID, "10s"))
		if searchAfter != nil {
			search.SearchAfter(searchAfter...)
		}

		results, err := search.Do(ctx)
		if err != nil {
			log.WithError(err).Error("Elasticsearch search failed for GetPolicyActivities")
			return nil, fmt.Errorf("elasticsearch search failed: %w", err)
		}
		if len(results.Hits.Hits) == 0 {
			break
		}
		allHits = append(allHits, results.Hits.Hits...)
		lastHit := results.Hits.Hits[len(results.Hits.Hits)-1]
		searchAfter = lastHit.Sort
	}

	return aggregatePolicyActivity(log, req, allHits), nil
}

// buildPolicyActivityQuery constructs an ES bool query that matches docs for
// any of the requested policies, filtered by generation prefix on the rule field.
func (b *policyBackend) buildPolicyActivityQuery(i bapi.ClusterInfo, req *v1.PolicyActivityParams) *elastic.BoolQuery {
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

	boolQuery.Filter(elastic.NewTermQuery("cluster", i.Cluster))
	if i.Tenant != "" {
		boolQuery.Filter(elastic.NewTermQuery("tenant", i.Tenant))
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

// ruleKey identifies a unique rule within a policy by direction and index.
type ruleKey struct {
	Direction string
	Index     string
}

// policyActivityEntry accumulates per-policy activity results during aggregation.
type policyActivityEntry struct {
	policy        v1.PolicyInfo
	lastEvaluated *time.Time
	rules         map[ruleKey]v1.PolicyActivityRuleResult
}

var specialRuleIndices = map[string]string{
	"__IMPLICIT_DENIED__": "implicit_deny",
	"__UNKNOWN__":         "unknown",
}

// translateRuleIndex converts special rule index values to human-readable strings.
func translateRuleIndex(idx string) string {
	if v, ok := specialRuleIndices[idx]; ok {
		return v
	}
	return idx
}

// aggregatePolicyActivity groups ES hits by policy, parses rule strings, computes
// per-policy last_evaluated, and returns results in the same order as the request.
func aggregatePolicyActivity(log *logrus.Entry, req *v1.PolicyActivityParams, hits []*elastic.SearchHit) *v1.PolicyActivityResponse {
	resultMap := make(map[policyKey]*policyActivityEntry)

	for _, hit := range hits {
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
			entry = &policyActivityEntry{
				policy: doc.Policy,
				rules:  make(map[ruleKey]v1.PolicyActivityRuleResult),
			}
			resultMap[key] = entry
		}

		if entry.lastEvaluated == nil || doc.LastEvaluated.After(*entry.lastEvaluated) {
			t := doc.LastEvaluated
			entry.lastEvaluated = &t
		}

		ruleIdx := translateRuleIndex(parts[2])
		rk := ruleKey{Direction: parts[1], Index: ruleIdx}
		existing, exists := entry.rules[rk]
		if !exists || doc.LastEvaluated.After(existing.LastEvaluated) {
			entry.rules[rk] = v1.PolicyActivityRuleResult{
				Direction:     parts[1],
				Index:         ruleIdx,
				LastEvaluated: doc.LastEvaluated,
			}
		}
	}

	// Build response preserving request order.
	items := make([]v1.PolicyActivityResult, 0, len(req.Policies))
	for _, p := range req.Policies {
		key := policyKey{Kind: p.Kind, Namespace: p.Namespace, Name: p.Name}
		entry, ok := resultMap[key]
		if !ok {
			continue
		}
		rules := make([]v1.PolicyActivityRuleResult, 0, len(entry.rules))
		for _, r := range entry.rules {
			rules = append(rules, r)
		}
		sort.Slice(rules, func(i, j int) bool {
			if rules[i].Direction != rules[j].Direction {
				return rules[i].Direction < rules[j].Direction
			}
			return rules[i].Index < rules[j].Index
		})
		items = append(items, v1.PolicyActivityResult{
			Policy:        entry.policy,
			LastEvaluated: entry.lastEvaluated,
			Rules:         rules,
		})
	}

	return &v1.PolicyActivityResponse{Items: items}
}
