// Copyright (c) 2023 Tigera, Inc. All rights reserved.
package flows

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/olivere/elastic/v7"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/types"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/backend"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/index"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/logtools"
	lmaindex "github.com/projectcalico/calico/linseed/pkg/internal/lma/elastic/index"
	"github.com/projectcalico/calico/lma/pkg/api"
	lmaelastic "github.com/projectcalico/calico/lma/pkg/elastic"
)

const (
	// TODO(rlb): We might want to abbreviate these to reduce the amount of data on the wire, json parsing and
	//           memory footprint.  Possibly a significant saving with large clusters or long time ranges.  These
	//           could be anything really as long as each is unique.
	FlowAggSumNumFlows                 = "sum_num_flows"
	FlowAggSumNumFlowsStarted          = "sum_num_flows_started"
	FlowAggSumNumFlowsCompleted        = "sum_num_flows_completed"
	FlowAggSumPacketsIn                = "sum_packets_in"
	FlowAggSumBytesIn                  = "sum_bytes_in"
	FlowAggSumPacketsOut               = "sum_packets_out"
	FlowAggSumBytesOut                 = "sum_bytes_out"
	FlowAggSumTransitPacketsIn         = "sum_transit_packets_in"
	FlowAggSumTransitPacketsOut        = "sum_transit_packets_out"
	FlowAggSumTransitBytesIn           = "sum_transit_bytes_in"
	FlowAggSumTransitBytesOut          = "sum_transit_bytes_out"
	FlowAggSumTCPRetranmissions        = "sum_tcp_total_retransmissions"
	FlowAggSumTCPLostPackets           = "sum_tcp_lost_packets"
	FlowAggSumTCPUnrecoveredTO         = "sum_tcp_unrecovered_to"
	FlowAggSumHTTPDeniedIn             = "sum_http_requests_denied_in"
	FlowAggSumHTTPAllowedIn            = "sum_http_requests_allowed_in"
	FlowAggMinProcessNames             = "process_names_min_num"
	FlowAggMinProcessIds               = "process_ids_min_num"
	FlowAggMinTCPSendCongestionWindow  = "tcp_min_send_congestion_window"
	FlowAggMinTCPMSS                   = "tcp_min_mss"
	FlowAggMaxProcessNames             = "process_names_max_num"
	FlowAggMaxProcessIds               = "process_ids_max_num"
	FlowAggMaxTCPSmoothRTT             = "tcp_max_smooth_rtt"
	FlowAggMaxTCPMinRTT                = "tcp_max_min_rtt"
	FlowAggMeanTCPSendCongestionWindow = "tcp_mean_send_congestion_window"
	FlowAggMeanTCPSmoothRTT            = "tcp_mean_smooth_rtt"
	FlowAggMeanTCPMinRTT               = "tcp_mean_min_rtt"
	FlowAggMeanTCPMSS                  = "tcp_mean_mss"

	// The path to the policies field in the ES document.
	policiesPath  = "policies"
	policiesField = "policies"

	// The keys for the policies sub-fields in the ES document.
	allPoliciesSubField      = "all_policies"
	enforcedPoliciesSubField = "enforced_policies"
	pendingPoliciesSubField  = "pending_policies"
	transitPoliciesSubField  = "transit_policies"
)

// flowBackend implements the Backend interface for flows stored
// in elasticsearch in the legacy storage model.
type flowBackend struct {
	// Elasticsearch client.
	lmaclient lmaelastic.Client

	// Track mapping of field name to its index in the ES response.
	ft *backend.FieldTracker

	// The sources and aggregations to use when building an aggregation query against ES.
	compositeSources []lmaelastic.AggCompositeSourceInfo
	aggSums          []lmaelastic.AggSumInfo
	aggMins          []lmaelastic.AggMaxMinInfo
	aggMaxs          []lmaelastic.AggMaxMinInfo
	aggMeans         []lmaelastic.AggMeanInfo
	aggNested        []lmaelastic.AggNestedTermInfo
	aggTerms         []lmaelastic.AggTermInfo

	queryHelper lmaindex.Helper
	index       bapi.Index
}

// BucketConverter is a helper interface used as part of the cmd/converter tooling to convert
// elasticsearch results into v1.L3Flow objects.
type BucketConverter interface {
	BaseQuery() *lmaelastic.CompositeAggregationQuery
	ConvertBucket(log *logrus.Entry, bucket *lmaelastic.CompositeAggregationBucket) *v1.L3Flow
}

func NewBucketConverter() BucketConverter {
	fb := NewFlowBackend(nil)
	return fb.(*flowBackend)
}

func NewFlowBackend(c lmaelastic.Client) bapi.FlowBackend {
	return newFlowBackend(c, false)
}

func NewSingleIndexFlowBackend(c lmaelastic.Client, options ...index.Option) bapi.FlowBackend {
	return newFlowBackend(c, true, options...)
}

func newFlowBackend(c lmaelastic.Client, singleIndex bool, options ...index.Option) bapi.FlowBackend {
	// These are the keys which define a flow in ES, and will be used to create buckets in the ES result.
	compositeSources := []lmaelastic.AggCompositeSourceInfo{
		{Name: "cluster", Field: "cluster"},
		{Name: "dest_type", Field: "dest_type"},
		{Name: "dest_namespace", Field: "dest_namespace"},
		{Name: "dest_name_aggr", Field: "dest_name_aggr"},
		{Name: "dest_service_namespace", Field: "dest_service_namespace", Order: "desc"},
		{Name: "dest_service_name", Field: "dest_service_name"},
		{Name: "dest_service_port_name", Field: "dest_service_port"},
		{Name: "dest_service_port_num", Field: "dest_service_port_num", AllowMissingBucket: true},
		{Name: "proto", Field: "proto"},
		{Name: "dest_port_num", Field: "dest_port"},
		{Name: "source_type", Field: "source_type"},
		{Name: "source_namespace", Field: "source_namespace"},
		{Name: "source_name_aggr", Field: "source_name_aggr"},
		{Name: "process_name", Field: "process_name"},
		{Name: "reporter", Field: "reporter"},
		{Name: "action", Field: "action"},
	}

	sums := []lmaelastic.AggSumInfo{
		{Name: FlowAggSumNumFlows, Field: "num_flows"},
		{Name: FlowAggSumNumFlowsStarted, Field: "num_flows_started"},
		{Name: FlowAggSumNumFlowsCompleted, Field: "num_flows_completed"},
		{Name: FlowAggSumPacketsIn, Field: "packets_in"},
		{Name: FlowAggSumBytesIn, Field: "bytes_in"},
		{Name: FlowAggSumPacketsOut, Field: "packets_out"},
		{Name: FlowAggSumBytesOut, Field: "bytes_out"},
		{Name: FlowAggSumTransitBytesIn, Field: "transit_bytes_in"},
		{Name: FlowAggSumTransitBytesOut, Field: "transit_bytes_out"},
		{Name: FlowAggSumTransitPacketsIn, Field: "transit_packets_in"},
		{Name: FlowAggSumTransitPacketsOut, Field: "transit_packets_out"},
		{Name: FlowAggSumTCPRetranmissions, Field: "tcp_total_retransmissions"},
		{Name: FlowAggSumTCPLostPackets, Field: "tcp_lost_packets"},
		{Name: FlowAggSumTCPUnrecoveredTO, Field: "tcp_unrecovered_to"},
		{Name: FlowAggSumHTTPAllowedIn, Field: "http_requests_allowed_in"},
		{Name: FlowAggSumHTTPDeniedIn, Field: "http_requests_denied_in"},
	}
	mins := []lmaelastic.AggMaxMinInfo{
		{Name: FlowAggMinProcessNames, Field: "num_process_names"},
		{Name: FlowAggMinProcessIds, Field: "num_process_ids"},
		{Name: FlowAggMinTCPSendCongestionWindow, Field: "tcp_min_send_congestion_window"},
		{Name: FlowAggMinTCPMSS, Field: "tcp_min_mss"},
	}
	maxs := []lmaelastic.AggMaxMinInfo{
		{Name: FlowAggMaxProcessNames, Field: "num_process_names"},
		{Name: FlowAggMaxProcessIds, Field: "num_process_ids"},
		{Name: FlowAggMaxTCPSmoothRTT, Field: "tcp_max_smooth_rtt"},
		{Name: FlowAggMaxTCPMinRTT, Field: "tcp_max_min_rtt"},
	}
	means := []lmaelastic.AggMeanInfo{
		{Name: FlowAggMeanTCPSendCongestionWindow, Field: "tcp_mean_send_congestion_window"},
		{Name: FlowAggMeanTCPSmoothRTT, Field: "tcp_mean_smooth_rtt"},
		{Name: FlowAggMeanTCPMinRTT, Field: "tcp_mean_min_rtt"},
		{Name: FlowAggMeanTCPMSS, Field: "tcp_mean_mss"},
	}

	// We use a nested terms aggregation in order to query all the label key/value pairs
	// attached to the source and destination for this flow over it's life.
	//
	// NOTE: Nested terms aggregations have an inherent limit of 10 results. As a result,
	// for endpoints with many labels this can result in an incomplete response. We could use
	// a composite aggregation or increase the size instead, but that is more computationally expensive. A nested
	// terms aggregation is consistent with past behavior.
	// https://www.elastic.co/guide/en/elasticsearch/reference/current/search-aggregations-bucket-terms-aggregation.html#search-aggregations-bucket-terms-aggregation-size
	nested := []lmaelastic.AggNestedTermInfo{
		{
			Name:  "dest_labels",
			Path:  "dest_labels",
			Term:  "by_kvpair",
			Field: "dest_labels.labels",
		},
		{
			Name:  "source_labels",
			Path:  "source_labels",
			Term:  "by_kvpair",
			Field: "source_labels.labels",
		},
	}

	terms := []lmaelastic.AggTermInfo{
		{Name: "dest_domains"},
		{Name: "source_ip"},
		{Name: "dest_ip"},

		{Name: allPoliciesSubField, Field: fmt.Sprintf("%s.%s", policiesField, allPoliciesSubField)},
		{Name: enforcedPoliciesSubField, Field: fmt.Sprintf("%s.%s", policiesField, enforcedPoliciesSubField)},
		{Name: pendingPoliciesSubField, Field: fmt.Sprintf("%s.%s", policiesField, pendingPoliciesSubField)},
		{Name: transitPoliciesSubField, Field: fmt.Sprintf("%s.%s", policiesField, transitPoliciesSubField)},
	}

	indexTemplate := index.FlowLogIndex(options...)
	helper := lmaindex.SingleIndexFlowLogs()
	if !singleIndex {
		indexTemplate = index.FlowLogMultiIndex
		helper = lmaindex.MultiIndexFlowLogs()
	}

	return &flowBackend{
		lmaclient:   c,
		ft:          backend.NewFieldTracker(compositeSources),
		index:       indexTemplate,
		queryHelper: helper,

		// Configuration for the aggregation queries we make against ES.
		compositeSources: compositeSources,
		aggSums:          sums,
		aggMins:          mins,
		aggMaxs:          maxs,
		aggMeans:         means,
		aggNested:        nested,
		aggTerms:         terms,
	}
}

func (b *flowBackend) BaseQuery() *lmaelastic.CompositeAggregationQuery {
	return &lmaelastic.CompositeAggregationQuery{
		Name:                    "buckets",
		AggCompositeSourceInfos: b.compositeSources,
		AggSumInfos:             b.aggSums,
		AggMaxInfos:             b.aggMaxs,
		AggMinInfos:             b.aggMins,
		AggMeanInfos:            b.aggMeans,
		AggNestedTermInfos:      b.aggNested,
		AggTermInfos:            b.aggTerms,
	}
}

func (b *flowBackend) countQuery() *lmaelastic.CompositeAggregationQuery {
	return &lmaelastic.CompositeAggregationQuery{
		Name:                    "buckets",
		AggCompositeSourceInfos: b.compositeSources,
	}
}

// List returns all flows which match the given options.
func (b *flowBackend) List(ctx context.Context, i bapi.ClusterInfo, opts *v1.L3FlowParams) (*v1.List[v1.L3Flow], error) {
	log := bapi.ContextLogger(i)

	err := i.Valid()
	if err != nil {
		return nil, err
	}

	// Build the aggregation request.
	query := b.BaseQuery()
	query.Query, err = b.buildQuery(i, opts)
	if err != nil {
		return nil, err
	}
	query.DocumentIndex = b.index.Index(i)
	query.MaxBucketsPerQuery = opts.GetMaxPageSize()
	log.Debugf("Listing flows from index %s", query.DocumentIndex)

	// Perform the request.
	page, key, err := lmaelastic.PagedSearch(ctx, b.lmaclient, query, log, b.ConvertBucket, opts.AfterKey)
	return &v1.List[v1.L3Flow]{
		Items:    page,
		AfterKey: key,
	}, err
}

func (b *flowBackend) Count(ctx context.Context, i bapi.ClusterInfo, opts *v1.L3FlowCountParams) (*v1.CountResponse, error) {
	log := bapi.ContextLogger(i)
	err := i.Valid()
	if err != nil {
		return nil, err
	}

	// Build the aggregation request.
	query := b.countQuery()
	query.Query, err = b.buildQuery(i, &opts.L3FlowParams)
	if err != nil {
		return nil, err
	}
	query.DocumentIndex = b.index.Index(i)
	query.MaxBucketsPerQuery = opts.GetMaxPageSize()

	// Build the bucket handler that we will pass to PagedCount. This handler will compute our namespace counts as each bucket is processed.
	namespacedCounts := make(map[string]int64)
	flowNewHandler := func(log *logrus.Entry, bucket *lmaelastic.CompositeAggregationBucket) {
		flow := b.ConvertBucketToBaseFlow(log, bucket)
		sourceNs := flow.Key.Source.Namespace
		destNs := flow.Key.Destination.Namespace

		if sourceNs != "" {
			namespacedCounts[sourceNs]++
		}

		if destNs != "" && destNs != sourceNs {
			namespacedCounts[destNs]++
		}
	}

	// Perform the request.
	globalCount, truncated, err := lmaelastic.PagedCount(ctx, b.lmaclient, query, log, opts.MaxGlobalCount, flowNewHandler)
	if err != nil {
		return nil, err
	}
	countResponse := v1.CountResponse{
		GlobalCount:          &globalCount,
		GlobalCountTruncated: truncated,
	}
	if !truncated {
		// We have only constructed a complete namespace count if the global count was not truncated.
		// Therefore, only include the namespace counts in the response if the global count was not truncated.
		countResponse.NamespacedCounts = namespacedCounts
	}

	return &countResponse, nil
}

func (b *flowBackend) ConvertBucketToBaseFlow(log *logrus.Entry, bucket *lmaelastic.CompositeAggregationBucket) *v1.L3Flow {
	key := bucket.CompositeAggregationKey

	// Build the flow, starting with the key.
	flow := v1.L3Flow{Key: v1.L3FlowKey{}}
	flow.Key.Reporter = v1.FlowReporter(b.ft.ValueString(key, "reporter"))
	flow.Key.Action = v1.FlowAction(b.ft.ValueString(key, "action"))
	flow.Key.Protocol = b.ft.ValueString(key, "proto")
	flow.Key.Source = v1.Endpoint{
		Type:           v1.EndpointType(b.ft.ValueString(key, "source_type")),
		AggregatedName: b.ft.ValueString(key, "source_name_aggr"),
		Namespace:      b.ft.ValueString(key, "source_namespace"),
	}
	flow.Key.Destination = v1.Endpoint{
		Type:           v1.EndpointType(b.ft.ValueString(key, "dest_type")),
		AggregatedName: b.ft.ValueString(key, "dest_name_aggr"),
		Namespace:      b.ft.ValueString(key, "dest_namespace"),
		Port:           b.ft.ValueInt64(key, "dest_port"),
	}
	flow.Key.Cluster = b.ft.ValueString(key, "cluster")

	return &flow
}

// ConvertBucket turns a composite aggregation bucket into an L3Flow.
func (b *flowBackend) ConvertBucket(log *logrus.Entry, bucket *lmaelastic.CompositeAggregationBucket) *v1.L3Flow {
	key := bucket.CompositeAggregationKey

	// Get the base flow for this bucket.
	flow := b.ConvertBucketToBaseFlow(log, bucket)

	// Build the flow.
	flow.LogStats = &v1.LogStats{
		FlowLogCount: bucket.DocCount,
		LogCount:     int64(bucket.AggregatedSums[FlowAggSumNumFlows]),
		Started:      int64(bucket.AggregatedSums[FlowAggSumNumFlowsStarted]),
		Completed:    int64(bucket.AggregatedSums[FlowAggSumNumFlowsCompleted]),
	}

	flow.Service = &v1.Service{
		Name:      b.ft.ValueString(key, "dest_service_name"),
		Namespace: b.ft.ValueString(key, "dest_service_namespace"),
		Port:      b.ft.ValueInt64(key, "dest_service_port_num"),
		PortName:  b.ft.ValueString(key, "dest_service_port"),
	}

	flow.TrafficStats = &v1.TrafficStats{
		PacketsIn:         int64(bucket.AggregatedSums[FlowAggSumPacketsIn]),
		PacketsOut:        int64(bucket.AggregatedSums[FlowAggSumPacketsOut]),
		BytesIn:           int64(bucket.AggregatedSums[FlowAggSumBytesIn]),
		BytesOut:          int64(bucket.AggregatedSums[FlowAggSumBytesOut]),
		TransitPacketsIn:  int64(bucket.AggregatedSums[FlowAggSumTransitPacketsIn]),
		TransitPacketsOut: int64(bucket.AggregatedSums[FlowAggSumTransitPacketsOut]),
		TransitBytesIn:    int64(bucket.AggregatedSums[FlowAggSumTransitBytesIn]),
		TransitBytesOut:   int64(bucket.AggregatedSums[FlowAggSumTransitBytesOut]),
	}

	if flow.Key.Protocol == "tcp" {
		flow.TCPStats = &v1.TCPStats{
			TotalRetransmissions:     int64(bucket.AggregatedSums[FlowAggSumTCPRetranmissions]),
			LostPackets:              int64(bucket.AggregatedSums[FlowAggSumTCPLostPackets]),
			UnrecoveredTo:            int64(bucket.AggregatedSums[FlowAggSumTCPUnrecoveredTO]),
			MinSendCongestionWindow:  bucket.AggregatedMin[FlowAggMinTCPSendCongestionWindow],
			MinMSS:                   bucket.AggregatedMin[FlowAggMinTCPMSS],
			MaxSmoothRTT:             bucket.AggregatedMax[FlowAggMaxTCPSmoothRTT],
			MaxMinRTT:                bucket.AggregatedMax[FlowAggMaxTCPMinRTT],
			MeanSendCongestionWindow: bucket.AggregatedMean[FlowAggMeanTCPSendCongestionWindow],
			MeanSmoothRTT:            bucket.AggregatedMean[FlowAggMeanTCPSmoothRTT],
			MeanMinRTT:               bucket.AggregatedMean[FlowAggMeanTCPMinRTT],
			MeanMSS:                  bucket.AggregatedMean[FlowAggMeanTCPMSS],
		}
	}

	flow.HTTPStats = &v1.HTTPStats{
		AllowedIn: int64(bucket.AggregatedSums[FlowAggSumHTTPAllowedIn]),
		DeniedIn:  int64(bucket.AggregatedSums[FlowAggSumHTTPDeniedIn]),
	}

	// Determine the process info if available in the logs.
	// var processes v1.GraphEndpointProcesses
	processName := b.ft.ValueString(key, "process_name")
	if processName != "" {
		flow.Process = &v1.Process{Name: processName}
		flow.ProcessStats = &v1.ProcessStats{
			MinNumNamesPerFlow: int(bucket.AggregatedMin[FlowAggMinProcessNames]),
			MaxNumNamesPerFlow: int(bucket.AggregatedMax[FlowAggMaxProcessNames]),
			MinNumIDsPerFlow:   int(bucket.AggregatedMin[FlowAggMinProcessIds]),
			MaxNumIDsPerFlow:   int(bucket.AggregatedMax[FlowAggMaxProcessIds]),
		}
	}

	// Handle label aggregation.
	flow.DestinationLabels = getLabelsFromLabelAggregation(log, bucket.AggregatedTerms, "dest_labels")
	flow.SourceLabels = getLabelsFromLabelAggregation(log, bucket.AggregatedTerms, "source_labels")

	// Add in policies.
	flow.EnforcedPolicies = getPoliciesFromAggregation(log, enforcedPoliciesSubField, bucket.AggregatedTerms)
	flow.PendingPolicies = getPoliciesFromAggregation(log, pendingPoliciesSubField, bucket.AggregatedTerms)
	flow.TransitPolicies = getPoliciesFromAggregation(log, transitPoliciesSubField, bucket.AggregatedTerms)

	// Determine all policies, preferring all_policies when present.
	allPolicies := getPoliciesFromAggregation(log, allPoliciesSubField, bucket.AggregatedTerms)
	if len(allPolicies) > 0 {
		flow.Policies = allPolicies
	} else {
		// Fallback: combine enforced, and the staged policies from pending for backward compatibility.
		if len(flow.EnforcedPolicies) > 0 || len(flow.PendingPolicies) > 0 {
			allPolicies = append(allPolicies, flow.EnforcedPolicies...)
			for _, p := range flow.PendingPolicies {
				if p.IsStaged {
					allPolicies = append(allPolicies, p)
				}
			}
			flow.Policies = allPolicies
		} else {
			// No policies of any kind.
			flow.Policies = nil
		}
	}

	// Add in the destination domains.
	flow.DestDomains = getDestDomainsFromAggregation(log, bucket.AggregatedTerms)

	// Add source IPs and destination IPs
	flow.SourceIPs = getValuesFromAggregation(log, bucket.AggregatedTerms, "source_ip")
	flow.DestinationIPs = getValuesFromAggregation(log, bucket.AggregatedTerms, "dest_ip")

	return flow
}

// buildQuery builds an elastic query using the given parameters.
func (b *flowBackend) buildQuery(i bapi.ClusterInfo, opts *v1.L3FlowParams) (elastic.Query, error) {
	query, err := b.queryHelper.BaseQuery(i, opts)
	if err != nil {
		return nil, err
	}

	// Every request has at least a time-range limitation.
	query.Filter(b.queryHelper.NewTimeRangeQuery(
		logtools.WithDefaultLast5Minutes(opts.TimeRange),
	))

	if len(opts.Actions) > 0 {
		// Filter-in any flows with one of the given actions.
		values := []interface{}{}
		for _, a := range opts.Actions {
			values = append(values, a)
		}
		query.Filter(elastic.NewTermsQuery("action", values...))
	}

	if len(opts.SourceTypes) > 0 {
		// Filter-in any flows with one of the given actions.
		values := []interface{}{}
		for _, t := range opts.SourceTypes {
			values = append(values, t)
		}
		query.Filter(elastic.NewTermsQuery("source_type", values...))
	}

	if len(opts.DestinationTypes) > 0 {
		// Filter-in any flows with one of the given actions.
		values := []interface{}{}
		for _, t := range opts.DestinationTypes {
			values = append(values, t)
		}
		query.Filter(elastic.NewTermsQuery("dest_type", values...))
	}

	if len(opts.NamespaceMatches) > 0 {
		for _, match := range opts.NamespaceMatches {
			// Get the list of values as an interface{}, as needed for a terms query.
			values := []interface{}{}
			for _, t := range match.Namespaces {
				values = append(values, t)
			}

			switch match.Type {
			case v1.MatchTypeSource:
				if len(match.Namespaces) == 1 {
					query.Filter(elastic.NewTermQuery("source_namespace", match.Namespaces[0]))
				} else {
					query.Filter(elastic.NewTermsQuery("source_namespace", values...))
				}
			case v1.MatchTypeDest:
				if len(match.Namespaces) == 1 {
					query.Filter(elastic.NewTermQuery("dest_namespace", match.Namespaces[0]))
				} else {
					query.Filter(elastic.NewTermsQuery("dest_namespace", values...))
				}
			case v1.MatchTypeAny:
				fallthrough
			default:
				// By default, treat as an "any" match. Return any flows that have a source
				// or destination namespace that matches.
				query.Filter(elastic.NewBoolQuery().Should(
					elastic.NewTermsQuery("source_namespace", values...),
					elastic.NewTermsQuery("dest_namespace", values...),
				).MinimumNumberShouldMatch(1))
			}
		}
	}

	if len(opts.NameAggrMatches) > 0 {
		for _, match := range opts.NameAggrMatches {
			// Get the list of values as an interface{}, as needed for a terms query.
			values := []interface{}{}
			for _, t := range match.Names {
				values = append(values, t)
			}

			switch match.Type {
			case v1.MatchTypeSource:
				query.Filter(elastic.NewTermsQuery("source_name_aggr", values...))
			case v1.MatchTypeDest:
				query.Filter(elastic.NewTermsQuery("dest_name_aggr", values...))
			case v1.MatchTypeAny:
				fallthrough
			default:
				// By default, treat as an "any" match. Return any flows that have a source
				// or destination name that matches.
				query.Filter(elastic.NewBoolQuery().Should(
					elastic.NewTermsQuery("source_name_aggr", values...),
					elastic.NewTermsQuery("dest_name_aggr", values...),
				).MinimumNumberShouldMatch(1))
			}
		}
	}

	if len(opts.PolicyMatches) > 0 {
		// Filter-in any flow logs that match any of the given policies.all_policies matches.
		q, err := BuildAllPolicyMatchQuery(opts.PolicyMatches)
		if err != nil {
			return nil, err
		}
		if q != nil {
			query.Filter(q)
		}
	}

	if len(opts.EnforcedPolicyMatches) > 0 {
		// Filter-in any flow logs that match any of the given policies.enforced_policies matches.
		q, err := BuildEnforcedPolicyMatchQuery(opts.EnforcedPolicyMatches)
		if err != nil {
			return nil, err
		}
		if q != nil {
			query.Filter(q)
		}
	}

	if len(opts.PendingPolicyMatches) > 0 {
		// Filter-in any flow logs that match any of the given policies.pending_policies matches.
		q, err := BuildPendingPolicyMatchQuery(opts.PendingPolicyMatches)
		if err != nil {
			return nil, err
		}
		if q != nil {
			query.Filter(q)
		}
	}

	if len(opts.TransitPolicyMatches) > 0 {
		// Filter-in any flow logs that match any of the given policies.transit_policies matches.
		q, err := BuildTransitPolicyMatchQuery(opts.TransitPolicyMatches)
		if err != nil {
			return nil, err
		}
		if q != nil {
			query.Filter(q)
		}
	}

	// Add in label selectors, if specified.
	if len(opts.SourceSelectors) != 0 {
		query.Filter(buildLabelSelectorFilter(opts.SourceSelectors, "source_labels"))
	}
	if len(opts.DestinationSelectors) != 0 {
		query.Filter(buildLabelSelectorFilter(opts.DestinationSelectors, "dest_labels"))
	}

	return query, nil
}

// IMPORTANT: This function does not create the correct Elasticsearch query from the label selector and needs to be redone.
// It tries to find docs that have labels name "<key>.<operator>.<value>" which could be "name!=foobar" or "namecontainsfoobar".
// The only successful queries generated by this function are those with an operator of "=".
//
// Builds a nested filter for LabelSelectors
// The LabelSelector allows a user describe matching the labels in elasticsearch. If multiple values are specified,
// a "terms" query will be created with as follows:
//
// "terms": {
// "<labelType>.labels": [
//
//		 "<key><operator><value1>",
//		 "<key><operator><value2>",
//		 ]
//	}
//
// If only one value is specified a "term" query is created as follows:
//
//	"term": {
//	 "<labelType>.labels": <key><operator><value>"
//	}
func buildLabelSelectorFilter(labelSelectors []v1.LabelSelector, path string) *elastic.NestedQuery {
	termsKey := fmt.Sprintf("%s.labels", path)
	var labelValues []interface{}
	var selectorQueries []elastic.Query
	for _, selector := range labelSelectors {
		keyAndOperator := fmt.Sprintf("%s%s", selector.Key, selector.Operator)
		if len(selector.Values) == 1 {
			selectorQuery := elastic.NewTermQuery(termsKey, fmt.Sprintf("%s%s", keyAndOperator, selector.Values[0]))
			selectorQueries = append(selectorQueries, selectorQuery)
		} else {
			for _, value := range selector.Values {
				labelValues = append(labelValues, fmt.Sprintf("%s%s", keyAndOperator, value))
			}
			selectorQuery := elastic.NewTermsQuery(termsKey, labelValues...)
			selectorQueries = append(selectorQueries, selectorQuery)
		}
	}
	return elastic.NewNestedQuery(path, elastic.NewBoolQuery().Filter(selectorQueries...))
}

// getLabelsFromLabelAggregation parses the labels out from the given aggregation and puts them into a map map[string][]FlowResponseLabels
// that can be sent back in the response.
func getLabelsFromLabelAggregation(log *logrus.Entry, terms map[string]*lmaelastic.AggregatedTerm, k string) []v1.FlowLabels {
	tracker := NewLabelTracker()
	for i, count := range terms[k].Buckets {
		label, ok := i.(string)
		if !ok {
			log.WithField("value", i).Warning("skipping bucket with non-string label")
			continue
		}
		labelParts := strings.Split(label, "=")
		if len(labelParts) != 2 {
			log.WithField("value", label).Warning("skipping bucket with key with invalid format (format should be 'key=value')")
			continue
		}

		labelName, labelValue := labelParts[0], labelParts[1]
		tracker.Add(labelName, labelValue, count)
	}

	return tracker.Labels()
}

func NewLabelTracker() *LabelTracker {
	return &LabelTracker{
		s:         make(map[string]map[string]int64),
		allValues: make(map[string][]string),
	}
}

type LabelTracker struct {
	// Map of key, to map of value to count. e.g.,
	//
	// { "k1": {"v1": 1, v2: 2}, "k2": {"v3": 1}}
	//
	// We need to aggregate all of the labels across multiple flow logs, where we can have
	// one flow log with key1 = A and another flow log with key1 = B
	s map[string]map[string]int64

	// Keeps track of all the keys we have seen. Used in the final calculation for
	// sorting to produce deterministic results.
	allKeys []string

	// Keeps track of all the values we have seen for each key. Used in the final calculation
	// for sorting to produce deterministic results.
	allValues map[string][]string
}

func (t *LabelTracker) Add(k, v string, count int64) {
	if _, ok := t.s[k]; !ok {
		// New label key
		t.s[k] = map[string]int64{}
		t.allKeys = append(t.allKeys, k)
	}
	if _, ok := t.s[k][v]; !ok {
		// New value for this key.
		t.s[k][v] = 0
		t.allValues[k] = append(t.allValues[k], v)
	}

	// Increment the count.
	t.s[k][v] += count
}

func (t *LabelTracker) Labels() []v1.FlowLabels {
	labels := []v1.FlowLabels{}

	// Sort keys so we get a consistenly ordered output.
	sort.Strings(t.allKeys)

	for _, key := range t.allKeys {
		allValuesForKey := t.allValues[key]

		// Again, sort the values slice so that we get consistent output.
		sort.Strings(allValuesForKey)

		// Build up the flow labels for this key, adding each value and count.
		flowLabels := v1.FlowLabels{Key: key}
		for _, value := range allValuesForKey {
			count := t.s[key][value]
			flowLabels.Values = append(flowLabels.Values, v1.FlowLabelValue{
				Value: value,
				Count: count,
			})
		}
		labels = append(labels, flowLabels)
	}
	return labels
}

// getDestDomainsFromAggregation parses and sorts the destination domain logs out from the
// given AggregationSingleBucket into a FlowResponse that can be sent back in the response.
func getDestDomainsFromAggregation(log *logrus.Entry, terms map[string]*lmaelastic.AggregatedTerm) []string {
	domains := []string{}
	if terms, found := terms["dest_domains"]; found {
		for k := range terms.Buckets {
			key, ok := k.(string)
			if !ok {
				// This means the flow log is invalid so just skip it, otherwise a minor issue with a single flow
				// could completely disable this endpoint.
				logrus.WithField("key", key).Warning("skipping policy that failed to parse")
				continue
			}
			domains = append(domains, strings.TrimSpace(key))
		}
	}
	sort.Strings(domains)

	return domains
}

// getValuesFromAggregation parses and sorts the values out from the
// given AggregationSingleBucket into an array that can be sent back in the response.
func getValuesFromAggregation(log *logrus.Entry, terms map[string]*lmaelastic.AggregatedTerm, resultKey string) []string {
	values := []string{}
	if terms, found := terms[resultKey]; found {
		for k := range terms.Buckets {
			key, ok := k.(string)
			if !ok {
				// This means the flow log is invalid so just skip it, otherwise a minor issue with a single flow
				// could completely disable this endpoint.
				log.WithField("key", key).Warningf("skipping value that failed to parse from %s", resultKey)
				continue
			}
			values = append(values, strings.TrimSpace(key))
		}
	}
	sort.Strings(values)

	return values
}

// getPoliciesFromPolicyBucket parses the policy logs out from the given AggregationSingleBucket into a FlowResponsePolicy
// that can be sent back in the response.
func getPoliciesFromAggregation(log *logrus.Entry, termKey string, terms map[string]*lmaelastic.AggregatedTerm) []v1.Policy {
	var policies []v1.Policy
	if terms, found := terms[termKey]; found {
		// Policies aren't necessarily ordered in the flow log, so we parse out the
		// policies from the flow log and sort them first.
		//
		// We use a set to ensure uniqueness, as the same policy could be represented in different syntaxes in the flow log.
		uniquePolicies := make(map[types.PolicyID]api.PolicyHit)
		for k, count := range terms.Buckets {
			key, ok := k.(string)
			if !ok {
				// This means the flow log is invalid so just skip it, otherwise a minor issue with a single flow
				// could completely disable this endpoint.
				logrus.WithField("key", key).Warning("skipping policy that failed to parse")
				continue
			}

			policyHit, err := api.PolicyHitFromFlowLogPolicyString(key, count)
			if err != nil {
				// This means the flow log is invalid so just skip it, otherwise a minor issue with a single flow
				// could completely disable this endpoint.
				logrus.WithError(err).WithField("key", key).Warning("skipping policy that failed to parse")
				continue
			}

			k := types.PolicyID{
				Name:      policyHit.Name(),
				Namespace: policyHit.Namespace(),
				Kind:      policyHit.Kind(),
			}
			if _, exists := uniquePolicies[k]; !exists {
				uniquePolicies[k] = policyHit
			}
		}

		// Now sort the policies.
		var policyHits api.SortablePolicyHits
		for _, policyHit := range uniquePolicies {
			policyHits = append(policyHits, policyHit)
		}
		sort.Sort(policyHits)

		// Note: Linseed returns all policies, regardless of RBAC. It's the responsibility of the client code to
		// perform filtering of the returned policies to remove any that the user does not have permission to view.
		// TODO: Should we (and can we) perform that RBAC here?
		for _, policyHit := range policyHits {
			policies = append(policies, v1.Policy{
				Action:       string(policyHit.Action()),
				Tier:         policyHit.Tier(),
				Kind:         policyHit.Kind(),
				Namespace:    policyHit.Namespace(),
				Name:         policyHit.Name(),
				IsStaged:     policyHit.IsStaged(),
				IsKubernetes: policyHit.IsKubernetes(),
				IsProfile:    policyHit.IsProfile(),
				Count:        policyHit.Count(),
				RuleID:       policyHit.RuleIdIndex(),
			})
		}
	}
	return policies
}
