// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package servicegraph

import (
	"context"

	log "github.com/sirupsen/logrus"

	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
)

type L7Flow struct {
	Edge  FlowEdge
	Stats v1.GraphL7Stats
}

// GetL7FlowData queries and returns the set of L7 flow data.
func GetL7FlowData(ctx context.Context, lsClient client.Client, cluster string, tr lmav1.TimeRange, cfg *Config) (fs []L7Flow, err error) {
	// Trace progress.
	progress := newProgress("l7", tr)
	defer func() {
		progress.Complete(err)
	}()

	// addFlow adds an L7Flow to the response data for this request.
	addFlow := func(source, dest FlowEndpoint, svc v1.ServicePort, stats v1.GraphL7Stats) {
		if svc.Name != "" {
			fs = append(fs, L7Flow{
				Edge: FlowEdge{
					Source:      source,
					Dest:        dest,
					ServicePort: &svc,
				},
				Stats: stats,
			})
		} else {
			fs = append(fs, L7Flow{
				Edge: FlowEdge{
					Source: source,
					Dest:   dest,
				},
				Stats: stats,
			})
		}
		progress.IncAggregated()
		if log.IsLevelEnabled(log.DebugLevel) {
			if svc.Name != "" {
				log.Debugf("- Adding L7 flow: %s -> %s -> %s (stats %#v)", source, svc, dest, stats)
			} else {
				log.Debugf("- Adding L7 flow: %s -> %s (stats %#v)", source, dest, stats)
			}
		}
	}

	// Perform the L7 composite aggregation query.
	// Always ensure we cancel the query if we bail early.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Set up for performing paged list queries for L7 flows.
	params := lsv1.L7FlowParams{
		QueryParams: lsv1.QueryParams{TimeRange: &tr},
	}
	pager := client.NewListPager[lsv1.L7Flow](&params)
	results, errors := pager.Stream(ctx, lsClient.L7Flows(cluster).List)

	var foundFlow bool
	var l7Stats v1.GraphL7Stats
	var lastSource, lastDest FlowEndpoint
	var lastSvc v1.ServicePort
	for page := range results {
		for _, flow := range page.Items {
			progress.IncRaw()
			code := flow.Code
			source := FlowEndpoint{
				Type:      mapRawTypeToGraphNodeType(string(flow.Key.Source.Type), true, nil),
				NameAggr:  flow.Key.Source.AggregatedName,
				Namespace: flow.Key.Source.Namespace,
			}
			svc := v1.ServicePort{
				NamespacedName: v1.NamespacedName{
					Name:      flow.Key.DestinationService.Service.Name,
					Namespace: flow.Key.DestinationService.Service.Namespace,
				},
				Protocol: flow.Key.Protocol,
				PortName: flow.Key.DestinationService.PortName,
				Port:     int(flow.Key.DestinationService.Port),
			}
			dest := FlowEndpoint{
				Type:      mapRawTypeToGraphNodeType(string(flow.Key.Destination.Type), true, nil),
				NameAggr:  flow.Key.Destination.AggregatedName,
				Namespace: flow.Key.Destination.Namespace,
				PortNum:   int(flow.Key.Destination.Port),
				Protocol:  flow.Key.Protocol,
			}

			l7PacketStats := v1.GraphL7PacketStats{
				GraphByteStats: v1.GraphByteStats{
					BytesIn:  flow.Stats.BytesIn,
					BytesOut: flow.Stats.BytesOut,
				},
				MeanDuration: float64(flow.Stats.MeanDuration), // TODO: Should these be float64 on linseed API?
				MinDuration:  float64(flow.Stats.MinDuration),
				MaxDuration:  float64(flow.Stats.MaxDuration),
				Count:        flow.LogCount,
			}

			if !foundFlow {
				// For the first entry we need to store off the first flow details.
				lastSource, lastDest, lastSvc = source, dest, svc
				foundFlow = true
			} else if lastSource != source || lastSvc != svc || lastDest != dest {
				addFlow(lastSource, lastDest, lastSvc, l7Stats)
				lastSource, lastDest, lastSvc, l7Stats = source, dest, svc, v1.GraphL7Stats{}
			}

			if log.IsLevelEnabled(log.DebugLevel) {
				if svc.Name != "" {
					log.Debugf("Processing L7 flow: %s -> %s -> %s (code %d)", source, svc, dest, code)
				} else {
					log.Debugf("Processing L7 flow: %s -> %s (code %d)", source, dest, code)
				}
			}

			if code >= 100 && code < 600 {
				if code < 200 {
					l7Stats.ResponseCode1xx = l7Stats.ResponseCode1xx.Combine(l7PacketStats)
				} else if code < 300 {
					l7Stats.ResponseCode2xx = l7Stats.ResponseCode2xx.Combine(l7PacketStats)
				} else if code < 400 {
					l7Stats.ResponseCode3xx = l7Stats.ResponseCode3xx.Combine(l7PacketStats)
				} else if code < 500 {
					l7Stats.ResponseCode4xx = l7Stats.ResponseCode4xx.Combine(l7PacketStats)
				} else {
					l7Stats.ResponseCode5xx = l7Stats.ResponseCode5xx.Combine(l7PacketStats)
				}
			} else {
				// Either not a number or not a valid response code.  Bucket in the no-response category.
				l7Stats.NoResponse = l7Stats.NoResponse.Combine(l7PacketStats)
			}

			// Track the number of aggregated flows. Bail if we hit the absolute maximum number of aggregated flows.
			if len(fs) > cfg.ServiceGraphCacheMaxAggregatedRecords {
				return fs, errDataTruncatedError
			}
		}
	}
	if foundFlow {
		addFlow(lastSource, lastDest, lastSvc, l7Stats)
	}

	return fs, <-errors
}
