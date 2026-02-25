package pip

import (
	"context"
	"fmt"
	"sort"

	log "github.com/sirupsen/logrus"

	lapi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/lma/pkg/api"
	"github.com/projectcalico/calico/lma/pkg/elastic"
	"github.com/projectcalico/calico/ui-apis/pkg/pip/policycalc"
)

var (
	// This is the full set of composite sources required by PIP.
	// The order of this is important since ES orders its responses based on this source order - and PIP utilizes this
	// to simplify the aggregation processing allowing us to pipeline the conversion.
	PIPCompositeSources = []elastic.AggCompositeSourceInfo{
		// This first set of fields matches the set requested by the API and will never
		// be modified by the policy calculation. These are non-aggregated and non-cached in the pipeline converter and
		// a single set of these values represents a single flow.
		{Name: "source_type", Field: "source_type"},
		{Name: "source_namespace", Field: "source_namespace"},
		{Name: "source_name", Field: "source_name_aggr"},
		{Name: "dest_type", Field: "dest_type"},
		{Name: "dest_namespace", Field: "dest_namespace"},
		{Name: "dest_name", Field: "dest_name_aggr"},

		// These are additional fields that we require to do the policy calculation, but we aggregate out
		// in the pipeline processing. These are before the reporter and action (which we don't aggregate out),
		// because we need to correlate source/dest flows - in particular when we are making use of archived policy
		// data to fill in the gaps.
		{Name: "proto", Field: "proto"},
		{Name: "source_ip", Field: "source_ip"},
		{Name: "source_name_full", Field: "source_name"},
		{Name: "source_port", Field: "source_port"},
		{Name: "dest_ip", Field: "dest_ip"},
		{Name: "dest_name_full", Field: "dest_name"},
		{Name: "dest_port", Field: "dest_port"},

		// We need to group together source and dest flows for the same connection (or related connections), so that we
		// are able to use the calculated source action in the destination flow (so we can marry up the two halves of the
		// flow). These are not aggregated out.
		//
		// In general we'd expect one action for flows where all of the other values are the same, however due to some
		// aggregated or unreported data there is always a level of granularity that we may be aggregating over. In
		// these cases we do our best by using the historical policy matches to attempt to fill-in unknowns.
		//
		// For the cases we get multiple source actions, then we only expect dest results when the source result was
		// "allow", and no dest results when it was "deny".
		{Name: "action", Field: "action"},
		{Name: "reporter", Field: "reporter"},
	}

	// ^^^ A note on the above regarding source/dest names ^^^
	// The UI queries for "source_name" and "dest_name" which are extracted from the backing fields "source_name_aggr"
	// and "dest_name_aggr". So we use "source_name_full" and "dest_name_full" for the backing "source_name" and
	// "dest_name" fields.
	// As it happens we actually use index values to access these fields in the parse composite sources when
	// processing the flow, so we shouldn't need any magic code to handle the cross-over naming scheme. When we actually
	// base the query on the parsed UI request then we'll need to be more clever.

	// Indexes into the raw flow data.
	PIPCompositeSourcesRawIdxSourceType      = 0
	PIPCompositeSourcesRawIdxSourceNamespace = 1
	PIPCompositeSourcesRawIdxSourceNameAggr  = 2
	PIPCompositeSourcesRawIdxDestType        = 3
	PIPCompositeSourcesRawIdxDestNamespace   = 4
	PIPCompositeSourcesRawIdxDestNameAggr    = 5
	PIPCompositeSourcesRawIdxProto           = 6
	PIPCompositeSourcesRawIdxSourceIP        = 7
	PIPCompositeSourcesRawIdxSourceName      = 8
	PIPCompositeSourcesRawIdxSourcePort      = 9
	PIPCompositeSourcesRawIdxDestIP          = 10
	PIPCompositeSourcesRawIdxDestName        = 11
	PIPCompositeSourcesRawIdxDestPort        = 12
	PIPCompositeSourcesRawIdxAction          = 13
	PIPCompositeSourcesRawIdxReporter        = 14

	// The number of entries that we need to check to determine if we have "clocked" to the next flow, or to the next
	// connection group (or related set of connections when aggregating over source and IP).
	// See comments for PIPCompositeSources above.
	PIPCompositeSourcesNumSameFlow      = PIPCompositeSourcesRawIdxProto  // Up to, not including, the proto field (excludes reporter and action)
	PIPCompositeSourcesNumSameConnGroup = PIPCompositeSourcesRawIdxAction // Up to, not including, the action field

	// The number of flows to return to the UI.
	UINumAggregatedFlows = 1000
)

// ProcessedFlows contains a set of related aggregated flows returned from the ProcessFlowLogs pipeline processor.
type ProcessedFlows struct {
	Before []*elastic.CompositeAggregationBucket
	After  []*elastic.CompositeAggregationBucket
}

// SearchAndProcessCompositeAggrFlows provides a pipeline to search elastic flow logs, translate the results based on PIP and
// stream aggregated results through the returned channel.
//
// This will exit cleanly if the context is cancelled.
func (p *pip) SearchAndProcessFlowLogs(
	ctx context.Context,
	pager client.ListPager[lapi.L3Flow],
	cluster string,
	calc policycalc.PolicyCalculator,
	limit int32,
	impactedOnly bool,
	flowFilter elastic.FlowFilter,
) (<-chan ProcessedFlows, <-chan error) {
	results := make(chan ProcessedFlows, UINumAggregatedFlows)
	errs := make(chan error, 1)

	// Create a cancellable context so we can exit cleanly when we hit our target number of aggregated results.
	ctx, cancel := context.WithCancel(ctx)

	// Start a paged search.
	pages, errors := pager.Stream(ctx, p.lsclient.L3Flows(cluster).List)

	var sent int
	go func() {
		defer func() {
			cancel()
			close(results)
			close(errs)
		}()

		// Initialize the last known raw flow key to simplify our processing, and the last raw connection key.
		lastRawFlowKey := make(elastic.CompositeAggregationKey, PIPCompositeSourcesNumSameFlow)
		lastRawConnectionKey := make(elastic.CompositeAggregationKey, PIPCompositeSourcesNumSameConnGroup)

		// Initialize the before/after caches of aggregations with common non-aggregated, non-cached indices.
		cacheBefore := make(sortedCache, 0)
		cacheAfter := make(sortedCache, 0)
		cacheImpacted := false

		// Obtain separately source allow/deny and dest allow/deny.  The destination allow/deny need to be married
		// up to the source allow flow.
		var srcAllowFlow, srcDenyFlow, dstAllowFlow, dstDenyFlow *api.Flow
		var srcAllowRawBucket, srcDenyRawBucket, dstAllowRawBucket, dstDenyRawBucket *elastic.CompositeAggregationBucket

		// Handler function to calculate the result for a given connection.
		processConnectionGroup := func() {
			log.Debug("Process connection group")

			if srcDenyFlow != nil {
				// We have a flow denied at source. Let's calculate the beforeSrc and afterSrc behavior of that flow at
				// source. This may explicitly add some destination flows to account for the fact that we don't have
				// destination flow data to work with since the flow never reached the destination.
				log.Debug("Including source denied flow")
				modified, beforeSrc, afterSrc := calc.CalculateSource(srcDenyFlow)
				cacheImpacted = cacheImpacted || modified

				// Aggregate the beforeSrc/afterSrc buckets for this flow. Aggregate the beforeSrc buckets first though because
				// we modify the rawBucket in the aggregateRawFlowBucket call to update the policies - we want the
				// beforeSrc information to remain as originally queried when we aggregate if the policies
				// were not re-calculated.
				aggregateRawFlowBucket(
					api.ReporterTypeSource, lastRawFlowKey, srcDenyRawBucket, beforeSrc.Action, beforeSrc, &cacheBefore,
				)
				aggregateRawFlowBucket(
					api.ReporterTypeSource, lastRawFlowKey, srcDenyRawBucket, afterSrc.Action, afterSrc, &cacheAfter,
				)

				// Denied source flows are interesting. If the remote dest is a Calico managed endpoint *and* the action
				// has been modified from denied then we need to add some flow data for the remote. Since we won't have
				// the actual data, all we can do is add a fake flow with minimal available data.
				if srcDenyFlow.Destination.IsCalicoManagedEndpoint() &&
					(afterSrc.Action&api.ActionFlagAllow != 0 || beforeSrc.Action&api.ActionFlagAllow != 0) {
					log.Debug("Including fake destination flow due to source flow changing from denied")
					destFlow := api.Flow{
						Reporter:    api.ReporterTypeDestination,
						Source:      srcDenyFlow.Source,
						Destination: srcDenyFlow.Destination,
						ActionFlag:  0,
						Proto:       srcDenyFlow.Proto,
						IPVersion:   srcDenyFlow.IPVersion,
						Policies:    nil,
					}
					_, beforeDest, afterDest := calc.CalculateDest(&destFlow, beforeSrc.Action, afterSrc.Action)

					// Aggregate the beforeSrc/afterSrc buckets for this flow. Aggregate the beforeSrc buckets first though because
					// we modify the rawBucket in the aggregateRawFlowBucket call to update the policies - we want the
					// beforeSrc information to remain as originally queried when we aggregate if the policies
					// were not re-calculated.
					aggregateRawFlowBucket(
						api.ReporterTypeDestination, lastRawFlowKey, srcDenyRawBucket, beforeSrc.Action, beforeDest, &cacheBefore,
					)
					aggregateRawFlowBucket(
						api.ReporterTypeDestination, lastRawFlowKey, srcDenyRawBucket, afterSrc.Action, afterDest, &cacheAfter,
					)
				}

				// Reset data so it is not counted again.
				srcDenyFlow = nil
				srcDenyRawBucket = nil
			}

			// Handle source allowed flow if present.
			srcAllowActionBefore, srcAllowActionAfter := api.ActionFlagAllow, api.ActionFlagAllow
			if srcAllowFlow != nil {
				// We have a flow allowed at source. Let's calculate the before and after behavior of that flow at
				// source. This will never add or remove destination flows - however the actions will instruct the
				// calculation code to add, remove and set the source action accordingly in the calculation of the
				// destination flows (if any were gathered) below.
				log.Debug("Including source allowed flow")
				modified, before, after := calc.CalculateSource(srcAllowFlow)
				cacheImpacted = cacheImpacted || modified

				// Aggregate the before/after buckets for this flow. Aggregate the before buckets first though because
				// we modify the rawBucket in the aggregateRawFlowBucket call to update the policies - we want the
				// before information to remain as originally queried when we aggregate if the policies
				// were not re-calculated.
				aggregateRawFlowBucket(
					api.ReporterTypeSource, lastRawFlowKey, srcAllowRawBucket, before.Action, before, &cacheBefore,
				)
				aggregateRawFlowBucket(
					api.ReporterTypeSource, lastRawFlowKey, srcAllowRawBucket, after.Action, after, &cacheAfter,
				)

				// Update the source action allow for before and after calculation. The source action before should
				// still be "allow" unless  we were recalculating and a discrepancy was found between the flow logs and
				// the policies.
				//
				// These are used as input into the recalculation of the destination api.
				srcAllowActionBefore = before.Action
				srcAllowActionAfter = after.Action

				// Reset data so it is not counted again.
				srcAllowFlow = nil
				srcAllowRawBucket = nil
			}

			if dstDenyFlow != nil {
				// Recalculate the flow originally denied at dest. If either before/after source action is denied then
				// we remove the corresponding before/after dest flow.
				log.Debug("Including dest denied flow")
				modified, before, after := calc.CalculateDest(dstDenyFlow, srcAllowActionBefore, srcAllowActionAfter)
				cacheImpacted = cacheImpacted || modified

				// Aggregate the before/after buckets for this flow. Aggregate the before buckets first though because
				// we modify the rawBucket in the aggregateRawFlowBucket call to update the policies - we want the
				// before information to remain as originally queried when we aggregate if the policies
				// were not re-calculated.
				aggregateRawFlowBucket(
					api.ReporterTypeDestination, lastRawFlowKey, dstDenyRawBucket, srcAllowActionBefore, before, &cacheBefore,
				)
				aggregateRawFlowBucket(
					api.ReporterTypeDestination, lastRawFlowKey, dstDenyRawBucket, srcAllowActionAfter, after, &cacheAfter,
				)

				// Reset data so it is not counted again.
				dstDenyFlow = nil
				dstDenyRawBucket = nil
			}

			if dstAllowFlow != nil {
				// Recalculate the flow originally allowed at dest. If either before/after source action is denied then
				// we remove the corresponding before/after dest flow.
				log.Debug("Including dest allowed flow")
				modified, before, after := calc.CalculateDest(dstAllowFlow, srcAllowActionBefore, srcAllowActionAfter)
				cacheImpacted = cacheImpacted || modified

				// Aggregate the before/after buckets for this flow. Aggregate the before buckets first though because
				// we modify the rawBucket in the aggregateRawFlowBucket call to update the policies - we want the
				// before information to remain as originally queried when we aggregate if the policies
				// were not re-calculated.
				aggregateRawFlowBucket(
					api.ReporterTypeDestination, lastRawFlowKey, dstAllowRawBucket, srcAllowActionBefore, before, &cacheBefore,
				)
				aggregateRawFlowBucket(
					api.ReporterTypeDestination, lastRawFlowKey, dstAllowRawBucket, srcAllowActionAfter, after, &cacheAfter,
				)

				// Reset data so it is not counted again.
				dstAllowFlow = nil
				dstAllowRawBucket = nil
			}
		}

		// Handler function to send the result.
		sendResult := func() (exit bool) {
			defer func() {
				// Always reset the before/after sets of buckets ready for the next group. We can re-use the slice.
				cacheBefore = cacheBefore[:0]
				cacheAfter = cacheAfter[:0]
				cacheImpacted = false
			}()

			// Check that we have data to send, if not exit.
			if len(cacheBefore) == 0 && len(cacheAfter) == 0 {
				log.Debug("No data to send")
				return false
			}

			if impactedOnly && !cacheImpacted {
				log.Debug("Only include impacted data, and flow is not impacted")
				return false
			}

			if cacheImpacted {
				// The cache has been impacted by the resource update so we need to update all flows in the cache
				// accordingly.
				log.Debug("Cache impacted, include the flow")
				for i := range cacheBefore {
					cacheBefore[i].CompositeAggregationKey[elastic.FlowCompositeSourcesIdxImpacted].Value = true
				}
				for i := range cacheAfter {
					cacheAfter[i].CompositeAggregationKey[elastic.FlowCompositeSourcesIdxImpacted].Value = true
				}
				// Based on the flow endpoints, check if the user has sufficient RBAC to see the flow. Note that we only
				// need to look at the first original flow in the group since all flows in the group will between the same
				// endpoints.
			} else if include, err := flowFilter.IncludeFlow(cacheBefore[0]); err != nil {
				// Unable to check RBAC permissions.
				log.WithError(err).Info("Error determining RBAC for flow")
				errs <- err
				return true
			} else if !include {
				// RBAC indicates that the flow should not be included.  Note that we always include impacted api.
				log.Debug("Users RBAC disallows flow")
				return false
			}

			// We are including the api. We may need to obfuscate the policies - do that now.
			for i := range cacheBefore {
				if err := flowFilter.ModifyFlow(cacheBefore[i]); err != nil {
					// Unable to check RBAC permissions.
					log.WithError(err).Info("Error determining RBAC for policy obfuscation in original requests")
					errs <- err
					return true
				}
			}
			for i := range cacheAfter {
				if err := flowFilter.ModifyFlow(cacheAfter[i]); err != nil {
					// Unable to check RBAC permissions.
					log.WithError(err).Info("Error determining RBAC for policy obfuscation in processed requests")
					errs <- err
					return true
				}
			}

			// Sort the before and after caches and copy into a results struct.
			log.Debug("Packaging up data and sending")
			result := ProcessedFlows{
				Before: cacheBefore.SortAndCopy(),
				After:  cacheAfter.SortAndCopy(),
			}

			select {
			case <-ctx.Done():
				errs <- ctx.Err()
				return true
			case results <- result:
				// Increment the number sent by the number of flows in the "before" set. We use this for consistency
				// with the non-PIP case.
				sent += len(cacheBefore)
			}

			if sent >= int(limit) {
				// We reached or exceeded the maximum number of aggregated api.
				log.Debug("Reached or exceeded our limit of flows to return")
				return true
			}

			return false
		}

		// Iterate through all the raw buckets from ES until the channel is closed. Buckets are ordered in the natural
		// order of the composite sources, thus we can enumerate, process and aggregate related buckets, forwarding the
		// aggregated bucket when the new raw bucket belongs in a different aggregation group.
		for page := range pages {
			for _, f := range page.Items {
				// Convert to a raw bucket. Ideally we don't need to do this, but the PIP code and API response is written in terms of
				// elastic buckets and so for legacy reasons we convert a nice api.L3Flow struct into a messay ES bucket struct.
				rawBucket := bucketFromFlow(&f)

				// Check the last raw connection key to see if we have clocked the connection, if so calculate the new
				// source/dest flow for the connection.
				if !lastRawConnectionKey.SameBucket(rawBucket.CompositeAggregationKey) {
					log.Debug("Clocked to next connection")

					// Process the connection group.
					processConnectionGroup()

					// Update the last connection key. We only track the indices that are common to the new connection.
					lastRawConnectionKey = rawBucket.CompositeAggregationKey[:PIPCompositeSourcesNumSameConnGroup]
				}

				// Check the last raw flow key to see if we have clocked flows, if so send any aggregated results and reset
				// the aggregations. Composite key values are returned in strict order.
				if !lastRawFlowKey.SameBucket(rawBucket.CompositeAggregationKey) {
					log.Debug("Clocked to next flow")

					// Handle the aggregated results by sending over the results channel. If this indicates we should
					// exit (either due to error or we've hit our results limit) then exit.
					if exit := sendResult(); exit {
						return
					}

					// Update the last flow key. We only track the indices that are common to the new set of flow
					// aggregations.
					lastRawFlowKey = rawBucket.CompositeAggregationKey[:PIPCompositeSourcesNumSameFlow]
				}

				log.Debug("Process flow")

				// There is a possibility that through config changes we get allow and deny results for both source and dest.
				// We combine the results to give just a single source and dest flow as follows:
				// - Convert deny+allow for the same endpoint to an unknown
				// - Only include overlapping intersecting labels and policies
				// Convert the received flow into the format understood by PIP.
				flow := api.FromLinseedFlow(f)
				if flow == nil {
					continue
				}

				// Recorded flows can only have a reported action of allow or deny. No other bits in the action flags should
				// be set.
				switch flow.Reporter {
				case api.ReporterTypeSource:
					switch flow.ActionFlag {
					case api.ActionFlagAllow:
						srcAllowFlow = flow
						srcAllowRawBucket = rawBucket
					case api.ActionFlagDeny:
						srcDenyFlow = flow
						srcDenyRawBucket = rawBucket
					}
				case api.ReporterTypeDestination:
					switch flow.ActionFlag {
					case api.ActionFlagAllow:
						dstAllowFlow = flow
						dstAllowRawBucket = rawBucket
					case api.ActionFlagDeny:
						dstDenyFlow = flow
						dstDenyRawBucket = rawBucket
					}
				}
			}
		}

		// We reached the end of the enumeration. Process and send any data we have accumulated.
		log.Debug("Exited main search loop - processing remaining cached entries")
		processConnectionGroup()
		if exit := sendResult(); exit {
			return
		}

		// If there was an error, send that. All data that we gathered has been sent now.
		// We can use the blocking version of the channel operator since the error channel will have been closed (it
		// is closed alongside the results channel).
		if err, ok := <-errors; ok {
			log.WithError(err).Warning("Hit error querying flows")
			errs <- err
		}
	}()

	return results, errs
}

func bucketFromFlow(flow *lapi.L3Flow) *elastic.CompositeAggregationBucket {
	bucket := &elastic.CompositeAggregationBucket{}
	bucket.CompositeAggregationKey = []elastic.CompositeAggregationSourceValue{
		// Order matters!
		{Name: "source_type", Value: string(flow.Key.Source.Type)},
		{Name: "source_namespace", Value: elastic.EmptyToDash(flow.Key.Source.Namespace)},
		{Name: "source_name", Value: flow.Key.Source.AggregatedName},
		{Name: "dest_type", Value: string(flow.Key.Destination.Type)},
		{Name: "dest_namespace", Value: elastic.EmptyToDash(flow.Key.Destination.Namespace)},
		{Name: "dest_name", Value: flow.Key.Destination.AggregatedName},
		{Name: "proto", Value: string(flow.Key.Protocol)},
		{Name: "source_ip", Value: ""},
		{Name: "source_name", Value: ""},
		{Name: "source_port", Value: flow.Key.Source.Port},
		{Name: "dest_ip", Value: ""},
		{Name: "dest_name", Value: ""},
		{Name: "dest_port", Value: flow.Key.Destination.Port},
		{Name: "action", Value: string(flow.Key.Action)},
		{Name: "reporter", Value: string(flow.Key.Reporter)},
	}

	// Zero out fields before filling them in with data, so we ensure they are always
	// present in the response.
	bucket.DocCount = 0
	bucket.AggregatedSums = map[string]float64{}
	bucket.AggregatedSums["sum_num_flows_started"] = float64(0)
	bucket.AggregatedSums["sum_num_flows_completed"] = float64(0)
	bucket.AggregatedSums["sum_packets_in"] = float64(0)
	bucket.AggregatedSums["sum_packets_out"] = float64(0)
	bucket.AggregatedSums["sum_bytes_in"] = float64(0)
	bucket.AggregatedSums["sum_bytes_out"] = float64(0)
	bucket.AggregatedSums["sum_http_requests_allowed_in"] = 0
	bucket.AggregatedSums["sum_http_requests_denied_in"] = 0
	bucket.AggregatedTerms = map[string]*elastic.AggregatedTerm{
		"dest_labels": {
			Buckets: map[any]int64{},
		},
		"source_labels": {
			Buckets: map[any]int64{},
		},
		"policies": {
			Buckets: map[any]int64{},
		},
	}

	// Now fill in with real data.
	if stats := flow.LogStats; stats != nil {
		bucket.DocCount = flow.LogStats.FlowLogCount
		bucket.AggregatedSums["sum_num_flows_started"] = float64(stats.Started)
		bucket.AggregatedSums["sum_num_flows_completed"] = float64(stats.Completed)
		for _, term := range bucket.AggregatedTerms {
			term.DocCount = bucket.DocCount
		}
	}
	if stats := flow.TrafficStats; stats != nil {
		bucket.AggregatedSums["sum_packets_in"] = float64(stats.PacketsIn)
		bucket.AggregatedSums["sum_packets_out"] = float64(stats.PacketsOut)
		bucket.AggregatedSums["sum_bytes_in"] = float64(stats.BytesIn)
		bucket.AggregatedSums["sum_bytes_out"] = float64(stats.BytesOut)
	}
	if stats := flow.HTTPStats; stats != nil {
		bucket.AggregatedSums["sum_http_requests_allowed_in"] = float64(stats.AllowedIn)
		bucket.AggregatedSums["sum_http_requests_denied_in"] = float64(stats.DeniedIn)
	}

	// Add in labels.
	for _, l := range flow.SourceLabels {
		for _, v := range l.Values {
			key := fmt.Sprintf("%s=%s", l.Key, v.Value)
			bucket.AggregatedTerms["source_labels"].Buckets[key] = v.Count
		}
	}
	for _, l := range flow.DestinationLabels {
		for _, v := range l.Values {
			key := fmt.Sprintf("%s=%s", l.Key, v.Value)
			bucket.AggregatedTerms["dest_labels"].Buckets[key] = v.Count
		}
	}
	return bucket
}

// aggregateRawFlowBucket aggregates the raw aggregation bucket into the further aggregated sets of related buckets in
// the supplied cache. The cache is updated as a result of the aggregation.
//   - The rawFlowKey is the composite aggregation key common to all entries in the flow (i.e. it contains the first
//     PIPCompositeSourcesNumSameFlow indices)
//   - The rawBucket contains the full set of indices for the connection which, with the exception of reporter, action,
//     and the rawFlowKey indices, will be filtered out.
func aggregateRawFlowBucket(
	reporter api.ReporterType,
	rawFlowKey []elastic.CompositeAggregationSourceValue,
	rawBucket *elastic.CompositeAggregationBucket,
	srcAction api.ActionFlag,
	resp policycalc.EndpointResponse,
	cachePtr *sortedCache,
) {
	if resp.Include {
		b := getOrCreateAggregatedBucketFromRawFlowBucket(
			string(reporter), srcAction.ToFlowActionString(), resp.Action.ToFlowActionString(),
			rawFlowKey, cachePtr,
		)

		// Modify the policies to those calculated if policies were calculated.
		if resp.Policies != nil {
			rawBucket.SetAggregatedTermsFromStringSlice(elastic.FlowAggregatedTermsNamePolicies, resp.Policies.FlowLogPolicyStrings())
		}

		// Aggregate the raw flow data into the cached aggregated flow.
		b.Aggregate(rawBucket)
	}
}

// getOrCreateAggregatedBucketFromRawFlowBucket returns the currently cached bucket for the specified combination of
// reporter, source action and action. If the cache does not contain an entry, a new empty bucket is created and the
// cache updated.
func getOrCreateAggregatedBucketFromRawFlowBucket(
	reporter, sourceAction, action string,
	rawKey []elastic.CompositeAggregationSourceValue,
	cachePtr *sortedCache,
) *elastic.CompositeAggregationBucket {
	// Scan the cache to find the required entry. In general we don't expect many entries in the cache, so this
	// is probably better that using a map.
	cache := *cachePtr
	for i := range cache {
		if cache[i].CompositeAggregationKey[elastic.FlowCompositeSourcesIdxReporter].Value == reporter &&
			cache[i].CompositeAggregationKey[elastic.FlowCompositeSourcesIdxAction].Value == action &&
			cache[i].CompositeAggregationKey[elastic.FlowCompositeSourcesIdxSourceAction].Value == sourceAction {
			return cache[i]
		}
	}

	// Cached entry does not exist for the UI-aggregated set of data, create the bucket for this aggregation.
	key := make([]elastic.CompositeAggregationSourceValue, elastic.FlowCompositeSourcesNum)
	copy(key, rawKey)
	key[elastic.FlowCompositeSourcesIdxReporter] = elastic.CompositeAggregationSourceValue{
		Name:  "reporter",
		Value: reporter,
	}
	key[elastic.FlowCompositeSourcesIdxAction] = elastic.CompositeAggregationSourceValue{
		Name:  "action",
		Value: action,
	}
	key[elastic.FlowCompositeSourcesIdxSourceAction] = elastic.CompositeAggregationSourceValue{
		Name:  "source_action",
		Value: sourceAction,
	}
	// TODO(rlb): This is not a real key since for the other key values there can only be one value of this, but including as a
	//            key is a lot easier. Another alternative would be to include it as an aggregation so that we can see how much
	//            of this flow has changed.
	//            I've agreed this API with AV, so let's run with this for now, but in future we may want to revisit this.
	//            If we do revisit this then we should consider how this is weighted.  packets, flows etc - or perhaps we
	//            have a set of changed packets/flows/bytes etc.
	key[elastic.FlowCompositeSourcesIdxImpacted] = elastic.CompositeAggregationSourceValue{
		Name:  "flow_impacted",
		Value: false,
	}

	entry := elastic.NewCompositeAggregationBucket(0)
	entry.CompositeAggregationKey = key
	*cachePtr = append(cache, entry)

	return entry
}

// sortedCache is a sortable cache of CompositeAggregationBucket. Sorting is based solely on the Reporter, Action and
// SourceAction fields.
type sortedCache []*elastic.CompositeAggregationBucket

// Len implements the Sort interface.
func (s sortedCache) Len() int {
	return len(s)
}

// Less implements the Sort interface.
func (s sortedCache) Less(i, j int) bool {
	si := s[i].CompositeAggregationKey[elastic.FlowCompositeSourcesIdxReporter].String()
	sj := s[j].CompositeAggregationKey[elastic.FlowCompositeSourcesIdxReporter].String()
	if si < sj {
		return true
	} else if si > sj {
		return false
	}

	// Reporter index is equal, check action.
	si = s[i].CompositeAggregationKey[elastic.FlowCompositeSourcesIdxAction].String()
	sj = s[j].CompositeAggregationKey[elastic.FlowCompositeSourcesIdxAction].String()
	if si < sj {
		return true
	} else if si > sj {
		return false
	}

	// Action index is equal, check source action.
	si = s[i].CompositeAggregationKey[elastic.FlowCompositeSourcesIdxSourceAction].String()
	sj = s[j].CompositeAggregationKey[elastic.FlowCompositeSourcesIdxSourceAction].String()
	return si < sj
}

// Swap implements the Sort interface.
func (s sortedCache) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// SortAndCopy sorts and copies the cache.
func (s sortedCache) SortAndCopy() []*elastic.CompositeAggregationBucket {
	sort.Sort(s)
	d := make([]*elastic.CompositeAggregationBucket, len(s))
	copy(d, s)
	return d
}
