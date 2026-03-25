// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/index"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/logtools"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/templates"
	lmaindex "github.com/projectcalico/calico/linseed/pkg/internal/lma/elastic/index"
	lmaelastic "github.com/projectcalico/calico/lma/pkg/elastic"
)

const (
	typeField        = "type"
	name             = "name"
	severity         = "severity"
	source_namespace = "source_namespace"
	dest_namespace   = "dest_namespace"
	source_name      = "source_name"
	dest_name        = "dest_name"
	attack_vector    = "attack_vector"
	mitre_tactic     = "mitre_tactic"
	mitre_ids        = "mitre_ids"
)

var normalizedFields []string

func init() {
	var mappings struct {
		Properties map[string]struct {
			Type       string `json:"type"`
			Normalizer string `json:"normalizer"`
		} `json:"properties"`
	}
	err := json.Unmarshal([]byte(templates.EventsMappings), &mappings)
	if err != nil {
		panic(err)
	}

	for field, fieldProperties := range mappings.Properties {
		if fieldProperties.Type == "keyword" {
			if fieldProperties.Normalizer != "" {
				normalizedFields = append(normalizedFields, field)
			}
		}
	}
}

type eventsBackend struct {
	client               *elastic.Client
	lmaclient            lmaelastic.Client
	templates            bapi.IndexInitializer
	deepPaginationCutOff int64
	queryHelper          lmaindex.Helper
	singleIndex          bool
	index                bapi.Index

	// Migration knobs
	migrationMode bool
}

func NewBackend(c lmaelastic.Client, cache bapi.IndexInitializer, deepPaginationCutOff int64, migrationMode bool) bapi.EventsBackend {
	return &eventsBackend{
		client:               c.Backend(),
		lmaclient:            c,
		templates:            cache,
		queryHelper:          lmaindex.MultiIndexAlerts(),
		deepPaginationCutOff: deepPaginationCutOff,
		index:                index.EventsMultiIndex,
		migrationMode:        migrationMode,
	}
}

func NewSingleIndexBackend(c lmaelastic.Client, cache bapi.IndexInitializer, deepPaginationCutOff int64, migrationMode bool, options ...index.Option) bapi.EventsBackend {
	return &eventsBackend{
		client:               c.Backend(),
		lmaclient:            c,
		templates:            cache,
		queryHelper:          lmaindex.SingleIndexAlerts(),
		deepPaginationCutOff: deepPaginationCutOff,
		index:                index.AlertsIndex(options...),
		singleIndex:          true,
		migrationMode:        migrationMode,
	}
}

type withExtras struct {
	v1.Event `json:",inline"`
	Tenant   string `json:"tenant,omitempty"`
}

// prepareForWrite sets the cluster field, and wraps the log in a document to set tenant if
// the backend is configured to write to a single index.
func (b *eventsBackend) prepareForWrite(i bapi.ClusterInfo, l v1.Event) any {
	l.Cluster = i.Cluster

	// We don't want to include the ID in the document ever.
	l.ID = ""

	if b.singleIndex {
		return &withExtras{
			Event:  l,
			Tenant: i.Tenant,
		}
	}
	return l
}

// Create the given events in elasticsearch.
func (b *eventsBackend) Create(ctx context.Context, i bapi.ClusterInfo, events []v1.Event) (*v1.BulkResponse, error) {
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
	log.Debugf("Writing events in bulk to index %s", alias)

	// Build a bulk request using the provided events.
	bulk := b.client.Bulk()

	for _, event := range events {
		id := event.ID

		// Populate the log's GeneratedTime field.  This field exists to enable a way for
		// clients to efficiently query newly generated logs, and having Linseed fill it in
		// - instead of an upstream client - makes this less vulnerable to time skew between
		// clients, and between clients and Linseed.
		generatedTime := time.Now().UTC()
		event.GeneratedTime = &generatedTime

		eventJSON, err := json.Marshal(b.prepareForWrite(i, event))
		if err != nil {
			log.WithError(err).Warningf("Failed to marshal event and add it to the request %+v", event)
			continue
		}

		req := elastic.NewBulkIndexRequest().Index(alias).Doc(string(eventJSON)).Id(id)
		bulk.Add(req)
	}

	// Send the bulk request.
	resp, err := bulk.Do(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to write events: %s", err)
	}
	log.WithField("count", len(events)).Debugf("Wrote events to index: %+v", resp)

	return &v1.BulkResponse{
		Total:     len(resp.Items),
		Succeeded: len(resp.Succeeded()),
		Failed:    len(resp.Failed()),
		Errors:    v1.GetBulkErrors(resp),
	}, nil
}

// List lists events that match the given parameters.
func (b *eventsBackend) List(ctx context.Context, i bapi.ClusterInfo, opts *v1.EventParams) (*v1.List[v1.Event], error) {
	log := bapi.ContextLogger(i)

	if i.Cluster == "" {
		return nil, fmt.Errorf("no cluster ID on request")
	}

	q, err := logtools.BuildQuery(b.queryHelper, i, opts)
	if err != nil {
		return nil, err
	}

	// If an ID was given on the request, limit to just that ID.
	if opts.ID != "" {
		q.Must(elastic.NewTermQuery("_id", opts.ID))
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
				return nil, err
			}
		}
	}

	query, startFrom, err = logtools.ConfigureCurrentPage(query, opts, b.index.Index(i), b.migrationMode, pitID)
	if err != nil {
		return nil, err
	}

	// Configure sorting.
	if len(opts.GetSortBy()) != 0 {
		for _, s := range opts.GetSortBy() {
			query.Sort(s.Field, !s.Descending)
		}
	} else {
		query.SortBy(elastic.NewFieldSort(b.queryHelper.GetTimeField()).Order(true))
	}

	results, err := query.Do(ctx)
	if err != nil {
		return nil, err
	}

	events := []v1.Event{}
	for _, h := range results.Hits.Hits {
		event := v1.Event{}
		err = json.Unmarshal(h.Source, &event)
		if err != nil {
			log.WithError(err).Error("Error unmarshalling event")
			continue
		}
		event.ID = h.Id
		events = append(events, event)
	}

	afterKey, err := b.afterKey(ctx, i, opts, results, log, startFrom)
	if err != nil {
		return nil, err
	}

	return &v1.List[v1.Event]{
		Items:     events,
		AfterKey:  afterKey,
		TotalHits: results.TotalHits(),
	}, nil
}

func (b *eventsBackend) afterKey(ctx context.Context, i bapi.ClusterInfo, opts *v1.EventParams, results *elastic.SearchResult, log *logrus.Entry, startFrom int) (map[string]any, error) {
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

func (b *eventsBackend) UpdateDismissFlag(ctx context.Context, i bapi.ClusterInfo, events []v1.Event) (*v1.BulkResponse, error) {
	if i.Cluster == "" {
		return nil, fmt.Errorf("no cluster ID on request")
	}
	alias := b.index.Alias(i)

	// Build a bulk request using the provided events.
	bulk := b.client.Bulk()
	numToDismiss := 0
	bulkErrs := []v1.BulkError{}

	// Assert that all of the given events belong to the tenant.
	if err := b.checkTenancy(ctx, i, events); err != nil {
		logrus.WithError(err).Warn("Error checking tenancy")
		return &v1.BulkResponse{
			Total:     len(events),
			Succeeded: 0,
			Failed:    len(events),
			Errors:    []v1.BulkError{{Resource: "", Type: "document_missing_exception", Reason: err.Error()}},
			Deleted:   nil,
		}, nil
	}

	// We need to get the index of each event, as some older events may not belong to the current write index
	// (after an upgrade or index rollover for example).
	indexValues, err := b.getEventIndexValues(ctx, i, events)
	if err != nil {
		return nil, err
	}

	for _, event := range events {
		index, found := indexValues[event.ID]
		if !found {
			logrus.WithField("id", event.ID).Warn("Event not found with IDs query")
			// If event does not exists, proceed with query to get response status
			index = alias
		}
		if !strings.Contains(index, alias) {
			logrus.WithError(err).WithField("id", event.ID).WithField("index", index).WithField("alias", alias).Warn("Error checking index for event")
			bulkErrs = append(bulkErrs, v1.BulkError{Resource: event.ID, Type: "document_missing_exception", Reason: "event belongs to another index"})
			continue
		}

		req := elastic.NewBulkUpdateRequest().Index(index).Id(event.ID).Doc(map[string]bool{"dismissed": event.Dismissed})
		bulk.Add(req)
		numToDismiss++
	}

	if numToDismiss == 0 {
		// If there are no events to dismiss, short-circuit and return an empty response.
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
		return nil, fmt.Errorf("failed to dismiss events: %s", err)
	}

	// Convert individual success / failure responses.
	upd := []v1.BulkItem{}
	for _, i := range resp.Updated() {
		bi := v1.BulkItem{ID: i.Id, Status: i.Status}
		upd = append(upd, bi)
	}

	return &v1.BulkResponse{
		Total:     len(resp.Items),
		Succeeded: len(resp.Succeeded()),
		Failed:    len(resp.Failed()),
		Errors:    v1.GetBulkErrors(resp),
		Updated:   upd,
	}, nil
}

func (b *eventsBackend) getEventIndexValues(ctx context.Context, i bapi.ClusterInfo, events []v1.Event) (map[string]string, error) {
	ids := []string{}
	for _, event := range events {
		ids = append(ids, event.ID)
	}

	q, _ := b.queryHelper.BaseQuery(i, nil)
	q = q.Must(elastic.NewIdsQuery().Ids(ids...))

	// Build the query.
	idsQuery := b.client.Search().
		Size(len(ids)).
		Index(b.index.Index(i)).
		Query(q)

	indexValues := make(map[string]string)

	idsResult, err := idsQuery.Do(ctx)
	if err != nil {
		return nil, err
	}
	if idsResult.TotalHits() > 0 {
		for _, hit := range idsResult.Hits.Hits {
			indexValues[hit.Id] = hit.Index
		}
	}

	return indexValues, nil
}

func (b *eventsBackend) checkTenancy(ctx context.Context, i bapi.ClusterInfo, events []v1.Event) error {
	// If we're in single index mode, we need to check tenancy. Otherwise, we can skip this because
	// the index name already contains the cluster and tenant ID.
	if !b.singleIndex {
		return nil
	}

	// This is a shared index.
	// We need to protect against tenancy here. In single index mode without this check, any tenant could send a request which
	// dismisses or deletes events for any other tenant if they guess the right ID.
	// Query the given event IDs using the tenant and cluster from the request to ensure that each requested ID is visible to that tenant.
	ids := []string{}
	for _, event := range events {
		ids = append(ids, event.ID)
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

	// Build a lookup map of the found events.
	foundIDs := map[string]struct{}{}
	for _, hit := range idsResult.Hits.Hits {
		foundIDs[hit.Id] = struct{}{}
	}

	// Now make sure that all of the given events were found.
	for _, event := range events {
		if _, found := foundIDs[event.ID]; !found {
			return fmt.Errorf("event %s not found", event.ID)
		}
	}
	return nil
}

func (b *eventsBackend) Delete(ctx context.Context, i bapi.ClusterInfo, events []v1.Event) (*v1.BulkResponse, error) {
	if i.Cluster == "" {
		return nil, fmt.Errorf("no cluster ID on request")
	}
	alias := b.index.Alias(i)

	// We need to get the index of each event, as some older events may not belong to the current write index
	// (after an upgrade or index rollover for example).
	indexValues, err := b.getEventIndexValues(ctx, i, events)
	if err != nil {
		return nil, err
	}

	// Assert that all of the given events belong to the tenant.
	if err := b.checkTenancy(ctx, i, events); err != nil {
		logrus.WithError(err).Warn("Error checking tenancy")
		return &v1.BulkResponse{
			Total:     len(events),
			Succeeded: 0,
			Failed:    len(events),
			Errors:    []v1.BulkError{{Resource: "", Type: "document_missing_exception", Reason: err.Error()}},
			Deleted:   nil,
		}, nil
	}

	// Build a bulk request using the provided events.
	bulk := b.client.Bulk()
	numToDelete := 0
	bulkErrs := []v1.BulkError{}
	for _, event := range events {
		index, found := indexValues[event.ID]
		if !found {
			logrus.WithField("id", event.ID).Warn("Event not found with IDs query")
			// If event does not exists, proceed with query to get response status
			index = alias
		}
		if !strings.Contains(index, alias) {
			logrus.WithError(err).WithField("id", event.ID).WithField("index", index).WithField("alias", alias).Warn("Error checking index for event")
			bulkErrs = append(bulkErrs, v1.BulkError{Resource: event.ID, Type: "document_missing_exception", Reason: "event belongs to another index"})
			continue
		}
		req := elastic.NewBulkDeleteRequest().Index(index).Id(event.ID)
		bulk.Add(req)
		numToDelete++
	}

	if numToDelete == 0 {
		// If there are no events to delete, short-circuit and return an empty response, including
		// any errors that occurred during tenancy checks.
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
		return nil, fmt.Errorf("failed to delete events: %s", err)
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

func (b *eventsBackend) Statistics(ctx context.Context, i bapi.ClusterInfo, opts *v1.EventStatisticsParams) (*v1.EventStatistics, error) {
	if b.migrationMode {
		return nil, fmt.Errorf("statistics queries are not allowed in migration mode")
	}

	// We cannot sort by time for statistics.
	// This does not really make sense anyway.
	// TODO: Do we want to tighten up the types used?
	if len(opts.GetSortBy()) != 0 {
		for _, s := range opts.GetSortBy() {
			if s.Field == "time" {
				return nil, errors.New("sort_by time not supported for events statistics")
			}
		}
	}

	for i, h := range opts.SeverityHistograms {
		if h.Name == "" {
			return nil, fmt.Errorf("missing name for severity_histogram #%d", i)
		}
	}
	stats := v1.EventStatistics{}

	err := b.computeFieldValues(ctx, i, opts, &stats)
	if err != nil {
		return nil, err
	}

	err = b.computeDateHistograms(ctx, i, opts, &stats)
	if err != nil {
		return nil, err
	}

	return &stats, nil
}

func (b *eventsBackend) computeFieldValues(ctx context.Context, i bapi.ClusterInfo, opts *v1.EventStatisticsParams, stats *v1.EventStatistics) error {
	if opts.FieldValues == nil {
		return nil
	}

	stats.FieldValues = &v1.FieldValues{}

	// Get the base query.
	search, err := b.getStatisticsSearch(i, &opts.EventParams)
	if err != nil {
		return err
	}

	fieldsToProcess := []struct {
		field  string
		param  *v1.FieldValueParam
		values *[]v1.FieldValue
	}{
		{typeField, opts.FieldValues.TypeValues, &stats.FieldValues.TypeValues},
		{name, opts.FieldValues.NameValues, &stats.FieldValues.NameValues},
		{severity, opts.FieldValues.SeverityValues, nil}, // Severity is a special case that's handled differently
		{source_namespace, opts.FieldValues.SourceNamespaceValues, &stats.FieldValues.SourceNamespaceValues},
		{dest_namespace, opts.FieldValues.DestNamespaceValues, &stats.FieldValues.DestNamespaceValues},
		{source_name, opts.FieldValues.SourceNameValues, &stats.FieldValues.SourceNameValues},
		{dest_name, opts.FieldValues.DestNameValues, &stats.FieldValues.DestNameValues},
		{attack_vector, opts.FieldValues.AttackVectorValues, &stats.FieldValues.AttackVectorValues},
		{mitre_tactic, opts.FieldValues.MitreTacticValues, &stats.FieldValues.MitreTacticValues},
		{mitre_ids, opts.FieldValues.MitreIDsValues, &stats.FieldValues.MitreIDsValues},
	}

	// Add terms aggregations required by opts.FieldValues to the search request,
	// with a nested terms aggregation if specified by field.AggregateBy.
	for _, f := range fieldsToProcess {
		if f.param != nil && f.param.Count {
			termsAgg := elastic.NewTermsAggregation().Field(f.field)
			if f.field != severity && f.param.GroupBySeverity {
				termsAgg.SubAggregation(severity, elastic.NewTermsAggregation().Field(severity))
			}
			search = search.Aggregation(f.field, termsAgg)
		}
	}

	// Do the search.
	results, err := search.Do(ctx)
	if err != nil {
		return err
	}

	// Update stats with search results.
	for _, f := range fieldsToProcess {
		if f.param != nil && f.field == severity {
			err = b.updateSeverityValues(results.Aggregations, &stats.FieldValues.SeverityValues)
		} else {
			err = b.updateFieldValues(ctx, i, results.Aggregations, f.field, f.param, f.values)
		}
		if err != nil {
			return err
		}
	}

	return nil
}

func (b *eventsBackend) getStatisticsSearch(i bapi.ClusterInfo, opts *v1.EventParams) (*elastic.SearchService, error) {
	if i.Cluster == "" {
		return nil, fmt.Errorf("no cluster ID on request")
	}

	q, err := logtools.BuildQuery(b.queryHelper, i, opts)
	if err != nil {
		return nil, err
	}

	// Build the query.
	query := b.client.Search().
		Size(opts.GetMaxPageSize()).
		Query(q)

	// Configure pagination options
	query, _, err = logtools.ConfigureCurrentPage(query, opts, b.index.Index(i), false, "")
	if err != nil {
		return nil, err
	}

	// Configure sorting.
	if len(opts.GetSortBy()) != 0 {
		for _, s := range opts.GetSortBy() {
			query.Sort(s.Field, !s.Descending)
		}
	}
	// We do not default to sorting by time, as the mapping for the time field
	// does not work well with aggregations. This is not supported for events.

	return query, nil
}

func (b *eventsBackend) updateFieldValues(ctx context.Context, i bapi.ClusterInfo, aggs elastic.Aggregations, field string, param *v1.FieldValueParam, fieldValues *[]v1.FieldValue) error {
	if param != nil {
		bucket, found := aggs.Terms(field)
		if !found {
			// If there is no event found, the aggregation result will not be provided, so we can skip updating the result
			return nil
		}

		for _, item := range bucket.Buckets {
			stringValue, ok := item.Key.(string)
			if !ok {
				return fmt.Errorf("could not parse %v as a string", item.Key)
			}
			fieldValue := v1.FieldValue{Value: stringValue, Count: item.DocCount}

			if param.GroupBySeverity {
				if item.Aggregations == nil {
					return fmt.Errorf("could not find terms results for %s.severity", field)
				}

				err := b.updateSeverityValues(item.Aggregations, &fieldValue.BySeverity)
				if err != nil {
					return err
				}
			}

			// Aggregated name values are normalized to lower case...
			// From: https://www.elastic.co/guide/en/elasticsearch/reference/master/normalizer.html
			// "Also, the fact that keywords are converted prior to indexing also means that aggregations return normalized values"
			// Potential solution: https://stackoverflow.com/a/73216052/1412348
			// Instead, will query a sample value and use that, so that we don't have to update the index mappings.
			for _, normalizedFieldName := range normalizedFields {
				if field == normalizedFieldName {
					normalizedValue := fieldValue.Value
					sampleValue, err := b.getOriginalValue(ctx, i, field, normalizedValue)
					if err != nil {
						return err
					}
					fieldValue.Value = sampleValue
				}
			}

			*fieldValues = append(*fieldValues, fieldValue)
		}
	}
	return nil
}

func (b *eventsBackend) updateSeverityValues(aggs elastic.Aggregations, fieldValues *[]v1.SeverityValue) error {
	bucket, found := aggs.Terms(severity)
	if !found {
		return fmt.Errorf("could not find terms results for %s", severity)
	}

	for _, item := range bucket.Buckets {
		// Numbers in JSON are parsed as float64
		value, ok := item.Key.(float64)
		if !ok {
			return fmt.Errorf("could not parse %v as an float64", item.Key)
		}
		// severity is an int does not have fractional part
		fieldValue := v1.SeverityValue{Value: int(value), Count: item.DocCount}

		*fieldValues = append(*fieldValues, fieldValue)
	}

	return nil
}

func (b *eventsBackend) getOriginalValue(ctx context.Context, i bapi.ClusterInfo, fieldName string, normalizedValue string) (string, error) {
	// Mitre IDs are stored in an array so a different logic would be required.
	// We know how to capitalize them so let's save a query.
	if fieldName == mitre_ids {
		return strings.ToUpper(normalizedValue), nil
	}

	params := v1.EventParams{
		QueryParams: v1.QueryParams{
			MaxPageSize: 1,
		},
		LogSelectionParams: v1.LogSelectionParams{
			Selector: fmt.Sprintf("%s = '%s'", fieldName, normalizedValue),
		},
	}
	search, err := b.getStatisticsSearch(i, &params)
	if err != nil {
		return "", err
	}

	// Do the search.
	results, err := search.Do(ctx)
	if err != nil {
		return "", err
	}

	if len(results.Hits.Hits) != 1 {
		return "", fmt.Errorf("expecting exactly 1 event but got %d", len(results.Hits.Hits))
	}

	h := results.Hits.Hits[0]
	originalValue := gjson.Get(string(h.Source), fieldName).String()

	return originalValue, nil
}

func (b *eventsBackend) computeDateHistograms(ctx context.Context, i bapi.ClusterInfo, opts *v1.EventStatisticsParams, stats *v1.EventStatistics) error {
	stats.SeverityHistograms = make(map[string][]v1.HistogramBucket)

	for _, histogram := range opts.SeverityHistograms {
		// Get the base query.
		histParams := opts.EventParams
		if len(histogram.Selector) > 0 {
			if len(opts.Selector) == 0 {
				histParams.Selector = histogram.Selector
			} else {
				histParams.Selector = fmt.Sprintf("(%s) AND (%s)", opts.Selector, histogram.Selector)
			}
		}

		// We need one query per histogram.
		histSearch, err := b.getStatisticsSearch(i, &histParams)
		if err != nil {
			return err
		}

		termsAgg := elastic.NewDateHistogramAggregation().
			Field("time").
			CalendarInterval("1d")

		src, err := termsAgg.Source()
		if err != nil {
			return err
		}
		bytes, err := json.Marshal(src)
		if err != nil {
			return err
		}

		histSearch = histSearch.Aggregation(histogram.Name, logtools.RawAggregation{RawMessage: bytes})

		// Do the search.
		results, err := histSearch.Do(ctx)
		if err != nil {
			return err
		}

		// Update stats with results for dateHistogram.
		items, found := results.Aggregations.DateHistogram(histogram.Name)
		if !found {
			// If there is no event found, empty aggregation result will be provided.
			// This is expected to happen when the events index does not exists.
			logrus.Debugf("Could not find terms results for %s (expected when index does not exists)", histogram.Name)
			items = new(elastic.AggregationBucketHistogramItems)
		}

		values := []v1.HistogramBucket{}
		for _, b := range items.Buckets {
			dhb := v1.HistogramBucket{Time: b.Key, Value: b.DocCount}

			values = append(values, dhb)
		}

		stats.SeverityHistograms[histogram.Name] = values
	}

	return nil
}
