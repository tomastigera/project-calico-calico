// Copyright (c) 2023 Tigera, Inc. All rights reserved.
//

package query

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/maputil"
	"github.com/projectcalico/calico/libcalico-go/lib/validator/v3/query"
	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
)

const (
	AggregationBucketSize    = 10000
	DefaultLookback          = time.Minute * 10
	QuerySize                = 10000
	PaginationSize           = 500
	MaxErrorsSize            = 10
	AlertEventType           = "global_alert"
	CompositeAggregationName = "composite_aggs"
)

type Service interface {
	ExecuteAlert(context.Context, *v3.GlobalAlert) v3.GlobalAlertStatus
}

type service struct {
	// http client for making calls to the vulnerability api.
	httpClient *http.Client

	// clusterName is name of the cluster.
	clusterName string

	// query has the entire vulnerability query based on GlobalAlert fields.
	vulnerabilityQuery JsonObject

	// globalAlert has the copy of GlobalAlert, it is updated periodically when Linseed is queried for alert.
	globalAlert *v3.GlobalAlert

	// Linseed client
	linseedClient client.Client

	// Query Executor will query different types of data based on the alert data type definition
	queryExecutor QueryExecutor

	// QueryBuilder builds the query based on the alert definition
	queryBuilder QueryBuilder
}

// NewService builds Linseed query that will be used periodically to query Elasticsearch data.
func NewService(linseedClient client.Client, clusterName string, alert *v3.GlobalAlert) (Service, error) {
	e := &service{
		clusterName:   clusterName,
		linseedClient: linseedClient,
	}

	// We query the base API for the vulnerability dataset and Linseed for others.
	var err error
	if alert.Spec.DataSet == v3.GlobalAlertDataSetVulnerability {
		cfg, cfgErr := getImageAssuranceTLSConfig()
		if cfgErr != nil {
			return nil, cfgErr
		}
		e.httpClient = &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
		err = e.buildVulnerabilityQuery(alert)
	} else {
		e.queryExecutor, err = newGenericExecutor(e.linseedClient, e.clusterName, alert)
		if err != nil {
			return nil, err
		}

		e.queryBuilder, err = e.buildQueryConfiguration(alert)
		if err != nil {
			return nil, err
		}
	}

	if err != nil {
		return nil, err
	}

	return e, nil
}

// buildVulnerabilityQuery builds Vulnerability API query parameters from the fields in GlobalAlert spec.
func (e *service) buildVulnerabilityQuery(alert *v3.GlobalAlert) error {
	res, err := e.convertAlertSpecQueryToVulnerabilityQueryParameters(alert)
	if err != nil {
		return err
	}
	e.vulnerabilityQuery = res

	return nil
}

// convertAlertSpecQueryToVulnerabilityQueryParameters converts GlobalAlert's spec.query to Vulnerability API query parameters.
func (e *service) convertAlertSpecQueryToVulnerabilityQueryParameters(alert *v3.GlobalAlert) (JsonObject, error) {
	q, err := query.ParseQuery(substituteVariables(alert))
	if err != nil {
		log.WithError(err).Errorf("failed to parse spec.query in %s", alert.Name)
		return nil, err
	}

	err = query.Validate(q, query.IsValidVulnerabilityAtom)
	if err != nil {
		log.WithError(err).Errorf("failed to validate spec.query in %s", alert.Name)
		return nil, err
	}

	res := JsonObject{}
	for _, a := range q.Atoms() {
		res[a.Key] = a.Value
	}

	return res, nil
}

// buildQueryConfiguration build a specific query configuration from the fields in GlobalAlert spec.
// Alert queries can have a raw query definition,an aggregation definition,a look back window and pagination defined
// An aggregations query will be issued if spec.metric is set to either avg, min, max or sum.
// A composite aggregations query will be issued if spec.aggregateBy is set.
// The size parameter for the query is 0 if either composite or metric aggregations is set, or
// if GlobalAlert spec.metric is 0, as individual entries are not needed to generate events.
func (e *service) buildQueryConfiguration(alert *v3.GlobalAlert) (QueryBuilder, error) {
	aggs := e.buildMetricAggregation(alert.Spec.Field, alert.Spec.Metric)
	aggs = e.buildCompositeAggregation(alert, aggs)

	lookBack := DefaultLookback
	if alert.Spec.Lookback == nil || alert.Spec.Lookback.Duration <= 0 {
	} else {
		lookBack = alert.Spec.Lookback.Duration
	}

	size := 0
	if aggs == nil && alert.Spec.Metric != v3.GlobalAlertMetricCount {
		size = QuerySize
	}

	return QueryBuilder{
		lookBack:     lookBack,
		pageSize:     size,
		selector:     substituteVariables(alert),
		aggregations: aggs,
		dataType:     alert.Spec.DataSet,
	}, nil
}

// buildCompositeAggregation builds and returns a composite aggregations query for the GlobalAlert
func (e *service) buildCompositeAggregation(alert *v3.GlobalAlert, metrics JsonObject) JsonObject {
	var src []JsonObject
	if len(alert.Spec.AggregateBy) != 0 {
		for i := len(alert.Spec.AggregateBy) - 1; i >= 0; i-- {
			src = append(src, JsonObject{
				alert.Spec.AggregateBy[i]: JsonObject{
					"terms": JsonObject{
						"field": alert.Spec.AggregateBy[i],
					},
				},
			})
		}
	}
	var composite JsonObject
	if len(src) != 0 {
		composite = JsonObject{
			"composite": JsonObject{
				"size":    PaginationSize,
				"sources": src,
			},
		}
		if metrics != nil {
			composite["aggregations"] = metrics
		}
		return JsonObject{
			CompositeAggregationName: composite,
		}
	}

	return metrics
}

// buildMetricAggregation builds and returns a metric aggregations query for the GlobalAlert
func (e *service) buildMetricAggregation(field string, metric string) JsonObject {
	if metric == v3.GlobalAlertMetricCount || metric == "" {
		return nil
	}

	return JsonObject{
		field: JsonObject{
			metric: JsonObject{
				"field": field,
			},
		},
	}
}

// buildVulnerabilityLookBackRange builds the look back range query from GlobalAlert's spec.lookBack if it exists,
// else uses the default lookBack duration.
func (e *service) buildVulnerabilityLookBackRange(alert *v3.GlobalAlert) (JsonObject, error) {
	var timeField string
	switch alert.Spec.DataSet {
	case v3.GlobalAlertDataSetVulnerability:
		timeField = "start_date"
	default:
		return nil, fmt.Errorf("unknown dataset %s in GlobalAlert %s", alert.Spec.DataSet, alert.Name)
	}

	var lookback time.Duration
	if alert.Spec.Lookback == nil || alert.Spec.Lookback.Duration <= 0 {
		lookback = DefaultLookback
	} else {
		lookback = alert.Spec.Lookback.Duration
	}

	now := time.Now()
	return JsonObject{
		timeField:  now.Add(-lookback).Unix(),
		"end_date": now.Unix(),
	}, nil
}

// ExecuteAlert executes the query built from GlobalAlert, processes the resulting data,
// generates events and update the cached GlobalAlert status.
// If spec.aggregateBy is set, execute a query by paginating over composite aggregations.
// If both spec.metric and spec.aggregateBy are not set, events will be generated from raw logs
// returned as a result
// If spec.metric is set and spec.aggregateBy is not set, the result has only metric aggregations,
// verify it against spec.threshold to generate events.
func (e *service) ExecuteAlert(ctx context.Context, alert *v3.GlobalAlert) v3.GlobalAlertStatus {
	log.Infof("Executing query and processing result for GlobalAlert %s in cluster %s", alert.Name, e.clusterName)

	e.globalAlert = alert
	if e.globalAlert.Spec.DataSet == v3.GlobalAlertDataSetVulnerability {
		e.executeVulnerabilityQuery(ctx)
	} else if e.globalAlert.Spec.AggregateBy != nil {
		// composite aggregations query
		e.executeCompositeQuery(ctx)
	} else if e.globalAlert.Spec.Metric == "" {
		// normal query
		e.executePaginatedQuery(ctx)
	} else if e.globalAlert.Spec.Metric != "" {
		// metric aggregations query
		e.executeMetricQuery(ctx)
	} else {
		log.Errorf("failed to retrieve results for GlobalAlert %s", e.globalAlert.Name)
	}

	return e.globalAlert.Status
}

// executeCompositeQuery executes the composite aggregations query,
// if resulting data has after_key set, query again by setting the received after_key to get remaining aggregations buckets.
// Maximum number of buckets retrieved is based on AggregationBucketSize, if there are more buckets left it logs warning.
// For each bucket retrieved, verifies the values against the metrics in GlobalAlert and creates an event if alert conditions are satisfied.
// It sets and returns a GlobalAlert status with the last executed query time, last time an event was generated, health status and error conditions if unhealthy.
func (e *service) executeCompositeQuery(ctx context.Context) {
	var afterKey JsonObject
	var bucketCounter int

	// We make a copy of the initial aggregation parameters because
	// we will modify it to include an `after` key
	compositeAggs, err := maputil.Copy(e.queryBuilder.aggregations)
	if err != nil {
		log.WithError(err).Errorf("failed to copy composite aggregations for GlobalAlert %s", e.globalAlert.Name)
		return
	}

	now := time.Now()
	for bucketCounter = 0; bucketCounter < AggregationBucketSize; {
		aggregations, err := JsonObject(compositeAggs).Convert()
		if err != nil {
			log.WithError(err).Errorf("failed to convert composite aggregations for GlobalAlert %s", e.globalAlert.Name)
			e.setError(v3.ErrorCondition{Message: err.Error()})
			return
		}
		e.queryBuilder.BuildAggregatedQuery(now, aggregations)
		searchResult, err := e.queryExecutor.Aggregate(ctx, e.queryBuilder.BuildAggregatedQuery(now, aggregations))
		e.globalAlert.Status.LastExecuted = &metav1.Time{Time: time.Now()}
		if err != nil {
			log.WithError(err).Errorf("failed to execute query for GlobalAlert %s", e.globalAlert.Name)
			e.setError(v3.ErrorCondition{Message: err.Error()})
			return
		}
		aggBuckets, exists := searchResult.Composite(CompositeAggregationName)
		if !exists {
			e.globalAlert.Status.Healthy = true
			e.globalAlert.Status.ErrorConditions = nil
			return
		}

		afterKey = aggBuckets.AfterKey
		bucketCounter += len(aggBuckets.Buckets)
		if afterKey != nil {
			composite, ok := compositeAggs["composite_aggs"]
			if ok {
				obj, ok := composite.(map[string]any)["composite"]
				if ok {
					obj.(map[string]any)["after"] = afterKey
				}
			}
		}

		var events []lsv1.Event
		for _, b := range aggBuckets.Buckets {
			record := JsonObject{}

			// compare bucket value to GlobalAlert metric
			switch e.globalAlert.Spec.Metric {
			case "":
				// nothing to compare if metric not set.
			case v3.GlobalAlertMetricCount:
				if compare(float64(b.DocCount), e.globalAlert.Spec.Threshold, e.globalAlert.Spec.Condition) {
					record["count"] = b.DocCount
				} else {
					// alert condition not satisfied
					continue
				}
			default:
				metricAggs, exists := b.Terms(e.globalAlert.Spec.Field)
				if !exists {
					// noting to add to events index for this bucket.
					continue
				}
				var tempMetric float64
				if err := json.Unmarshal(metricAggs.Aggregations["value"], &tempMetric); err != nil {
					log.WithError(err).Errorf("failed to unmarshal GlobalAlert %s response", e.globalAlert.Name)
					e.setError(v3.ErrorCondition{Message: err.Error()})
					return
				}
				if compare(tempMetric, e.globalAlert.Spec.Threshold, e.globalAlert.Spec.Condition) {
					record[e.globalAlert.Spec.Metric] = tempMetric
				} else {
					// alert condition not satisfied
					continue
				}
			}
			// Add the bucket names into events document
			maps.Copy(record, b.Key)
			events = append(events, e.convert(record))

			e.globalAlert.Status.LastEvent = &metav1.Time{Time: time.Now()}
		}

		if !e.storeEvents(ctx, events) {
			return
		}

		if afterKey == nil {
			// we have processed all the buckets.
			break
		}
	}

	if bucketCounter > AggregationBucketSize && afterKey != nil {
		log.Warnf("More that %d buckets received in query result for GlobalAlert %s", AggregationBucketSize, e.globalAlert.Name)
	}

	e.globalAlert.Status.Healthy = true
	e.globalAlert.Status.ErrorConditions = nil
}

func (e *service) storeEvents(ctx context.Context, events []lsv1.Event) bool {
	if len(events) == 0 {
		return true
	}

	log.Infof("Storing number of events %v", len(events))
	response, err := e.linseedClient.Events(e.clusterName).Create(ctx, events)
	if err != nil {
		log.WithError(err).Errorf("failed to add events for GlobalAlert %s", e.globalAlert.Name)
		e.globalAlert.Status.Healthy = false
		e.globalAlert.Status.ErrorConditions = appendError(e.globalAlert.Status.ErrorConditions,
			v3.ErrorCondition{Message: err.Error()})
		return false
	}

	if len(response.Errors) != 0 {
		e.globalAlert.Status.Healthy = false
		for _, bulkErr := range response.Errors {
			e.globalAlert.Status.ErrorConditions = appendError(e.globalAlert.Status.ErrorConditions,
				v3.ErrorCondition{Message: bulkErr.Error()})
		}
		return false
	}

	return true
}

func (e *service) executePaginatedQuery(ctx context.Context) {
	// TODO: ALINA - Need to check with we were setting PaginationSize and QuerySize
	pages, errors := e.queryExecutor.Iterate(ctx, e.queryBuilder.BuildQuery(time.Now()))

	for page := range pages {
		var err error
		var events []lsv1.Event
		for _, record := range page.Items {
			e.globalAlert.Status.LastExecuted = &metav1.Time{Time: time.Now()}
			events = append(events, e.convert(record))
			e.globalAlert.Status.LastEvent = &metav1.Time{Time: time.Now()}
		}

		err = <-errors
		if err != nil {
			log.WithError(err).Errorf("failed to execute query for GlobalAlert %s", e.globalAlert.Name)
			e.setError(v3.ErrorCondition{Message: err.Error()})
			return
		}

		if !e.storeEvents(ctx, events) {
			return
		}
	}

	e.globalAlert.Status.Healthy = true
	e.globalAlert.Status.ErrorConditions = nil
}

// executeMetricQuery execute the aggregated metric query, creates an event if query result satisfies alert conditions.
// It sets and returns a GlobalAlert status with the last executed query time, last time an event was generated,
// health status and error conditions if unhealthy.
func (e *service) executeMetricQuery(ctx context.Context) {
	var event lsv1.Event
	switch e.globalAlert.Spec.Metric {
	case v3.GlobalAlertMetricCount:
		countValue, err := e.queryExecutor.Count(ctx, e.queryBuilder.BuildQuery(time.Now()))
		e.globalAlert.Status.LastExecuted = &metav1.Time{Time: time.Now()}

		if err != nil {
			log.WithError(err).Errorf("failed to execute query for GlobalAlert %s", e.globalAlert.Name)
			e.globalAlert.Status.Healthy = false
			e.globalAlert.Status.ErrorConditions = appendError(e.globalAlert.Status.ErrorConditions, v3.ErrorCondition{Message: err.Error()})
			return
		}

		if compare(float64(countValue), e.globalAlert.Spec.Threshold, e.globalAlert.Spec.Condition) {
			record := JsonObject{
				"count": countValue,
			}
			event = e.convert(record)
		}
	default:
		aggregations, err := e.queryBuilder.aggregations.Convert()
		if err != nil {
			log.WithError(err).Errorf("failed to execute query for GlobalAlert %s", e.globalAlert.Name)
			e.globalAlert.Status.Healthy = false
			e.globalAlert.Status.ErrorConditions = appendError(e.globalAlert.Status.ErrorConditions, v3.ErrorCondition{Message: err.Error()})
			return
		}

		result, err := e.queryExecutor.Aggregate(ctx, e.queryBuilder.BuildAggregatedQuery(time.Now(), aggregations))
		e.globalAlert.Status.LastExecuted = &metav1.Time{Time: time.Now()}

		if err != nil {
			log.WithError(err).Errorf("failed to execute query for GlobalAlert %s", e.globalAlert.Name)
			e.globalAlert.Status.Healthy = false
			e.globalAlert.Status.ErrorConditions = appendError(e.globalAlert.Status.ErrorConditions, v3.ErrorCondition{Message: err.Error()})
			return
		}

		metricAggs, exists := result.Terms(e.globalAlert.Spec.Field)
		if !exists {
			e.globalAlert.Status.Healthy = true
			e.globalAlert.Status.ErrorConditions = nil
			return
		}
		var tempMetric float64
		if err := json.Unmarshal(metricAggs.Aggregations["value"], &tempMetric); err != nil {
			log.WithError(err).Errorf("failed to unmarshal GlobalAlert %s response", e.globalAlert.Name)
			e.globalAlert.Status.Healthy = false
			e.globalAlert.Status.ErrorConditions = appendError(e.globalAlert.Status.ErrorConditions, v3.ErrorCondition{Message: err.Error()})
			return
		}
		if compare(tempMetric, e.globalAlert.Spec.Threshold, e.globalAlert.Spec.Condition) {
			event = e.convert(JsonObject{e.globalAlert.Spec.Metric: tempMetric})
		}
	}

	if event.Type != "" {
		if !e.storeEvents(ctx, []lsv1.Event{event}) {
			return
		}
		e.globalAlert.Status.LastEvent = &metav1.Time{Time: time.Now()}
	}

	e.globalAlert.Status.Healthy = true
	e.globalAlert.Status.ErrorConditions = nil
}

func (e *service) executeVulnerabilityQuery(ctx context.Context) {
	e.globalAlert.Status.LastExecuted = &metav1.Time{Time: time.Now()}

	if lookBackRange, err := e.buildVulnerabilityLookBackRange(e.globalAlert); err != nil {
		return
	} else {
		maps.Copy(e.vulnerabilityQuery, lookBackRange)
	}

	params := make(VulnerabilityQueryParameterMap)
	for k, v := range e.vulnerabilityQuery {
		switch v := v.(type) {
		case string:
			params[k] = v
		case int64:
			params[k] = strconv.FormatInt(v, 10)
		default:
			log.Warnf("invalid image assurance query parameter type for %s=%v", k, v)
		}
	}

	vulnerabilities, err := queryVulnerabilityDataset(e.httpClient, params)
	if err != nil {
		log.WithError(err).Error("failed to query image assurance API")
		e.globalAlert.Status.Healthy = false
		e.globalAlert.Status.ErrorConditions = appendError(e.globalAlert.Status.ErrorConditions, v3.ErrorCondition{Message: err.Error()})
		return
	}

	var events []lsv1.Event
	switch e.globalAlert.Spec.Metric {
	case v3.GlobalAlertMetricCount:
		if compare(float64(len(vulnerabilities)), e.globalAlert.Spec.Threshold, e.globalAlert.Spec.Condition) {
			events = append(events, e.convert(JsonObject{"count": len(vulnerabilities)}))
		}
	case v3.GlobalAlertMetricMax:
		field := e.globalAlert.Spec.Field
		for _, event := range vulnerabilities {
			v, ok := event[field]
			if !ok {
				log.Warnf("field %s is not found in response; skipping", field)
				continue
			}

			val, ok := v.(float64)
			if !ok {
				log.Warnf("failed to convert %s: %v to float64", field, v)
				continue
			}

			if compare(val, e.globalAlert.Spec.Threshold, e.globalAlert.Spec.Condition) {
				events = append(events, e.convert(event))
				e.globalAlert.Status.LastEvent = &metav1.Time{Time: time.Now()}
			}
		}
	default:
		for _, event := range vulnerabilities {
			events = append(events, e.convert(event))
			e.globalAlert.Status.LastEvent = &metav1.Time{Time: time.Now()}
		}
	}

	if !e.storeEvents(ctx, events) {
		return
	}

	e.globalAlert.Status.Healthy = true
	e.globalAlert.Status.ErrorConditions = nil
}

// setError sets the Status.Healthy to false, appends the given error to the Status
func (e *service) setError(err v3.ErrorCondition) {
	e.globalAlert.Status.Healthy = false
	e.globalAlert.Status.ErrorConditions = appendError(e.globalAlert.Status.ErrorConditions, err)
}

// toLinseedFormat an object that can be sent to events index.
func (e *service) convert(record JsonObject) lsv1.Event {
	description := e.substituteDescriptionContents(record)
	eventData := extractEventData(record)

	eventData.Time = lsv1.NewEventTimestamp(time.Now().Unix())
	eventData.Type = AlertEventType
	eventData.Description = description
	eventData.Severity = e.globalAlert.Spec.Severity
	eventData.Origin = e.globalAlert.Name

	return eventData
}

// substituteVariables finds variables in the query string and replace them with values from GlobalAlertSpec.Substitutions.
func substituteVariables(alert *v3.GlobalAlert) string {
	out := alert.Spec.Query
	variables, err := extractVariablesFromTemplate(out)
	if err != nil {
		log.WithError(err).Warnf("failed to build IN template for alert %s due to invalid formatting of bracketed variables", alert.Name)
		return out
	}
	if len(variables) > 0 {
		for _, variable := range variables {
			sub, err := findSubstitutionByVariableName(alert, variable)
			if err != nil {
				log.Warnf("failed to build IN template for alert %s due to wrong variable name %s", alert.Name, variable)
				return out
			}

			// Translate Substitution.Values into the set notation.
			patterns := []string{}
			for _, v := range sub.Values {
				if v != "" {
					patterns = append(patterns, strconv.Quote(v))
				}
			}
			if len(patterns) > 0 {
				out = strings.Replace(out, fmt.Sprintf("${%s}", variable), "{"+strings.Join(patterns, ",")+"}", 1)
			}
		}
	}
	return out
}

// substituteDescriptionContents substitute bracketed variables in description with it's value.
// If there is an error in substitution log error and return the partly substituted value.
func (e *service) substituteDescriptionContents(record JsonObject) string {
	description := e.globalAlert.Spec.Description
	vars, err := extractVariablesFromTemplate(description)
	if err != nil {
		log.WithError(err).Warnf("failed to build summary or description for alert %s due to invalid formatting of bracketed variables", e.globalAlert.Name)
	}

	// replace extracted variables with it's value
	for _, v := range vars {
		if value, ok := record[v]; !ok {
			log.Warnf("failed to build summary or description for alert %s due to missing value for variable %s", e.globalAlert.Name, v)
		} else {
			switch value := value.(type) {
			case string:
				description = strings.Replace(description, fmt.Sprintf("${%s}", v), value, 1)
			case int64:
				description = strings.Replace(description, fmt.Sprintf("${%s}", v), strconv.FormatInt(value, 10), 1)
			case float64:
				description = strings.Replace(description, fmt.Sprintf("${%s}", v), strconv.FormatFloat(value, 'f', 1, 64), 1)
			default:
				log.Warnf("failed to build summary or description for alert %s due to unsupported value type for variable %s", e.globalAlert.Name, v)
			}
		}
	}
	return description
}

// extractEventData checks the given record object for keys that are defined in Event,
// for each key found, it assigns them to Event.
func extractEventData(record JsonObject) lsv1.Event {
	var e lsv1.Event

	// translate common log fields to event top-level fields.
	if val, ok := record["source_ip"].(string); ok {
		e.SourceIP = &val
	}
	if val, ok := record["source_port"].(float64); ok {
		v := int64(val)
		e.SourcePort = &v
	}
	if val, ok := record["source_namespace"].(string); ok {
		e.SourceNamespace = val
	}
	if val, ok := record["source_name"].(string); ok {
		e.SourceName = val
	}
	if val, ok := record["source_name_aggr"].(string); ok {
		e.SourceNameAggr = val
	}
	if val, ok := record["dest_ip"].(string); ok {
		e.DestIP = &val
	}
	if val, ok := record["dest_port"].(float64); ok {
		v := int64(val)
		e.DestPort = &v
	}
	if val, ok := record["dest_namespace"].(string); ok {
		e.DestNamespace = val
	}
	if val, ok := record["dest_name"].(string); ok {
		e.DestName = val
	}
	if val, ok := record["dest_name_aggr"].(string); ok {
		e.DestNameAggr = val
	}
	if val, ok := record["host"].(string); ok {
		e.Host = val
	}

	// translate DNS log fields to event top-level fields.
	if val, ok := record["client_ip"].(string); ok {
		e.SourceIP = &val
	}
	if val, ok := record["client_name"].(string); ok {
		e.SourceName = val
	}
	if val, ok := record["client_name_aggr"].(string); ok {
		e.SourceNameAggr = val
	}
	if val, ok := record["client_namespace"].(string); ok {
		e.SourceNamespace = val
	}

	// translate Audit log fields to event top-level fields.
	if val, ok := record["objectRef"].(map[string]any); ok {
		if nestedVal, ok := val["name"].(string); ok {
			e.SourceName = nestedVal
		}
		if nestedVal, ok := val["namespace"].(string); ok {
			e.SourceNamespace = nestedVal
		}
	}
	if ips, ok := record["sourceIPs"].([]any); ok && len(ips) > 0 {
		for _, ip := range ips {
			if val, ok := ip.(string); ok {
				e.SourceIP = &val
				break
			}
		}
	}

	// Allow for nested structures specifically for WAF logs.
	if val, ok := record["source"].(map[string]any); ok {
		if nestedVal, ok := val["ip"].(string); ok {
			e.SourceIP = &nestedVal
		}
		if nestedVal, ok := val["hostname"].(string); ok {
			e.SourceName = nestedVal
		}
		if nestedVal, ok := val["port_num"].(float64); ok {
			v := int64(nestedVal)
			e.SourcePort = &v
		}
	}
	if val, ok := record["destination"].(map[string]any); ok {
		if nestedVal, ok := val["ip"].(string); ok {
			e.DestIP = &nestedVal
		}
		if nestedVal, ok := val["hostname"].(string); ok {
			e.DestName = nestedVal
		}
		if nestedVal, ok := val["port_num"].(float64); ok {
			v := int64(nestedVal)
			e.DestPort = &v
		}
	}

	e.Record = record
	return e
}

// extractVariablesFromTemplate extracts and returns array of variables in the template string.
func extractVariablesFromTemplate(s string) ([]string, error) {
	var res []string
	for s != "" {
		start := strings.Index(s, "${")
		if start < 0 {
			break
		}
		s = s[start+2:]
		end := strings.Index(s, "}")
		if end < 0 {
			return nil, fmt.Errorf("unterminated }")
		}
		res = append(res, s[:end])
		s = s[end+1:]
	}
	return res, nil
}

// findSubstitutionByVariableName finds the substitution from spec by variable name.
func findSubstitutionByVariableName(alert *v3.GlobalAlert, variable string) (*v3.GlobalAlertSubstitution, error) {
	var substitution *v3.GlobalAlertSubstitution
	for _, sub := range alert.Spec.Substitutions {
		if strings.EqualFold(variable, sub.Name) {
			if substitution != nil {
				return nil, fmt.Errorf("found more than one substitution for variable %s", variable)
			} else {
				substitution = sub.DeepCopy()
			}
		}
	}
	if substitution != nil {
		return substitution, nil
	}
	return nil, fmt.Errorf("variable %s not found", variable)
}

// compare returns a boolean after comparing the given input.
func compare(left, right float64, operation string) bool {
	switch operation {
	case "eq":
		return left == right
	case "not_eq":
		return left != right
	case "lt":
		return left < right
	case "lte":
		return left <= right
	case "gt":
		return left > right
	case "gte":
		return left >= right
	default:
		log.Errorf("unexpected comparison operation %s", operation)
		return false
	}
}

// appendError appends the given error to the list of errors, ensures there are only `MaxErrorsSize` recent errors.
func appendError(errs []v3.ErrorCondition, err v3.ErrorCondition) []v3.ErrorCondition {
	errs = append(errs, err)
	if len(errs) > MaxErrorsSize {
		errs = errs[1:]
	}
	return errs
}
