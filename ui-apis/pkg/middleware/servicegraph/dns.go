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

type DNSLog struct {
	Endpoint FlowEndpoint
	Stats    v1.GraphDNSStats
}

// GetDNSClientData queries and returns the set of DNS logs.
func GetDNSClientData(ctx context.Context, lsClient client.Client, cluster string, tr lmav1.TimeRange, cfg *Config) (logs []DNSLog, err error) {
	// Trace progress.
	progress := newProgress("dns", tr)
	defer func() {
		progress.Complete(err)
	}()

	addLog := func(source FlowEndpoint, stats *v1.GraphDNSStats) {
		logs = append(logs, DNSLog{
			Endpoint: source,
			Stats:    *stats,
		})
		progress.IncAggregated()
	}

	// Perform the DNS composite aggregation query.
	// Always ensure we cancel the query if we bail early.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Set up for performing paged list queries for DNS flows.
	params := lsv1.DNSFlowParams{
		QueryParams: lsv1.QueryParams{TimeRange: &tr},
	}
	pager := client.NewListPager[lsv1.DNSFlow](&params)
	results, errors := pager.Stream(ctx, lsClient.DNSFlows(cluster).List)

	var foundLog bool
	var dnsStats *v1.GraphDNSStats
	var lastSource FlowEndpoint
	for page := range results {
		for _, flow := range page.Items {
			progress.IncRaw()
			code := flow.Key.ResponseCode
			source := FlowEndpoint{
				Type:      v1.GraphNodeTypeReplicaSet,
				NameAggr:  flow.Key.Source.AggregatedName,
				Namespace: flow.Key.Source.Namespace,
			}

			if !foundLog {
				// For the first entry we need to store off the first flow details.
				lastSource = source
				foundLog = true
			} else if lastSource != source {
				addLog(lastSource, dnsStats)
				lastSource, dnsStats = source, nil
			}

			if flow.LatencyStats != nil {
				gls := v1.GraphLatencyStats{
					MeanRequestLatency: flow.LatencyStats.MeanRequestLatency,
					MinRequestLatency:  flow.LatencyStats.MinRequestLatency,
					MaxRequestLatency:  flow.LatencyStats.MaxRequestLatency,
					LatencyCount:       int64(flow.LatencyStats.LatencyCount),
				}
				dnsStats = dnsStats.Combine(&v1.GraphDNSStats{
					GraphLatencyStats: gls,
					ResponseCodes: map[string]v1.GraphDNSResponseCode{
						code: {
							Code:              code,
							Count:             flow.Count,
							GraphLatencyStats: gls,
						},
					},
				})
			}

			if log.IsLevelEnabled(log.DebugLevel) {
				log.Debugf("Processing DNS Log: %s (code %s)", source, code)
			}

			// Track the number of aggregated logs. Bail if we hit the absolute maximum number of aggregated logs.
			if len(logs) > cfg.ServiceGraphCacheMaxAggregatedRecords {
				return logs, errDataTruncatedError
			}
		}
	}
	if foundLog {
		addLog(lastSource, dnsStats)
	}

	return logs, <-errors
}
