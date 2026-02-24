// Copyright (c) 2023 Tigera, Inc. All rights reserved.
//

package query

import (
	"context"
	gojson "encoding/json"
	"fmt"
	"time"

	"github.com/olivere/elastic/v7"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
)

// JsonObject is used to define a JSON object as a map representation
// This structure is kept in order to maintain compatibility with
// the extraction of an Event from all data types
type JsonObject map[string]any

func (obj JsonObject) Convert() (map[string]gojson.RawMessage, error) {
	jsonMap := make(map[string]gojson.RawMessage)
	for k, v := range obj {
		raw, err := gojson.Marshal(v)
		if err != nil {
			return nil, err
		}
		jsonMap[k] = raw
	}

	return jsonMap, nil
}

// QueryBuilder is builds a tailored a query defined by a GlobalAlert
type QueryBuilder struct {
	// lookBack will determine how far back we will
	// query data
	lookBack time.Duration

	// pagination size used when querying data
	pageSize int

	// selector will filter data based on the provided selection
	selector string

	// aggregations will define an aggregated query; for composite aggregation, we will make a copy of
	// this field and alter it with `after` key
	aggregations JsonObject

	// dataType will instruct the QueryExecutor what data set
	// to use when issuing a query
	dataType string
}

func (q QueryBuilder) queryParams(now time.Time) lsv1.QueryParams {
	return lsv1.QueryParams{
		TimeRange: &lmav1.TimeRange{
			From: now.Add(-1 * q.lookBack),
			To:   now,
		},
		MaxPageSize: q.pageSize,
	}
}

// BuildQuery will construct a Linseed specific query based on the
// type of data specified in the alert
func (q QueryBuilder) BuildQuery(endTime time.Time) lsv1.Params {
	switch q.dataType {
	case v3.GlobalAlertDataSetAudit:
		return &lsv1.AuditLogParams{
			QueryParams: q.queryParams(endTime),
			Type:        lsv1.AuditLogTypeAny,
			Selector:    q.selector,
		}
	case v3.GlobalAlertDataSetDNS:
		return &lsv1.DNSLogParams{
			QueryParams: q.queryParams(endTime),
			LogSelectionParams: lsv1.LogSelectionParams{
				Selector: q.selector,
			},
		}

	case v3.GlobalAlertDataSetFlows:
		return &lsv1.FlowLogParams{
			QueryParams: q.queryParams(endTime),
			LogSelectionParams: lsv1.LogSelectionParams{
				Selector: q.selector,
			},
		}

	case v3.GlobalAlertDataSetL7:
		return &lsv1.L7LogParams{
			QueryParams: q.queryParams(endTime),
			LogSelectionParams: lsv1.LogSelectionParams{
				Selector: q.selector,
			},
		}

	case v3.GlobalAlertDataSetWAF:
		return &lsv1.WAFLogParams{
			QueryParams: q.queryParams(endTime),
			Selector:    q.selector,
		}
	}

	return nil
}

// BuildAggregatedQuery will construct an aggregated query specific to Linseed based on the type of data specified in the alert
func (q QueryBuilder) BuildAggregatedQuery(endTime time.Time, aggregations map[string]gojson.RawMessage) lsv1.Params {
	switch q.dataType {
	case v3.GlobalAlertDataSetAudit:
		return &lsv1.AuditLogAggregationParams{
			AuditLogParams: lsv1.AuditLogParams{
				QueryParams: q.queryParams(endTime),
				Type:        lsv1.AuditLogTypeAny,
				Selector:    q.selector,
			},
			Aggregations: aggregations,
		}
	case v3.GlobalAlertDataSetDNS:
		return &lsv1.DNSAggregationParams{
			DNSLogParams: lsv1.DNSLogParams{
				QueryParams: q.queryParams(endTime),
				LogSelectionParams: lsv1.LogSelectionParams{
					Selector: q.selector,
				},
			},
			Aggregations: aggregations,
		}
	case v3.GlobalAlertDataSetFlows:
		return &lsv1.FlowLogAggregationParams{
			FlowLogParams: lsv1.FlowLogParams{
				QueryParams: q.queryParams(endTime),
				LogSelectionParams: lsv1.LogSelectionParams{
					Selector: q.selector,
				},
			},
			Aggregations: aggregations,
		}
	case v3.GlobalAlertDataSetL7:
		return &lsv1.L7AggregationParams{
			L7LogParams: lsv1.L7LogParams{
				QueryParams: q.queryParams(endTime),
				LogSelectionParams: lsv1.LogSelectionParams{
					Selector: q.selector,
				},
			},
			Aggregations: aggregations,
		}
	case v3.GlobalAlertDataSetWAF:
		return &lsv1.WAFLogAggregationParams{
			WAFLogParams: lsv1.WAFLogParams{
				QueryParams: q.queryParams(endTime),
				Selector:    q.selector,
			},
			Aggregations: aggregations,
		}
	}

	return nil
}

// QueryExecutor executes queries needed to extract statistics or raw data
// from our database in order to comply with the definition of a GlobalAlert
type QueryExecutor interface {
	// Aggregate executes an aggregated query when an alert has the field
	// aggregate_by populated or when need to aggregate over data and extract
	// metrics such as avg/sum/min/max
	Aggregate(ctx context.Context, params lsv1.Params) (elastic.Aggregations, error)
	// Count will count the number of return item when a query is
	// defined in the alert definition alongside metric field count
	Count(ctx context.Context, params lsv1.Params) (int64, error)
	// Iterate will query and raw data from our database in accordance
	// to the query defined on the alert definition
	Iterate(ctx context.Context, params lsv1.Params) (<-chan lsv1.List[JsonObject], <-chan error)
}

type (
	listFn        func(context.Context, lsv1.Params, lsv1.Listable) error
	aggregationFn func(context.Context, lsv1.Params) (elastic.Aggregations, error)
)

type genericExecutor struct {
	listFn
	aggregationFn
}

func newGenericExecutor(client client.Client, clusterName string, alert *v3.GlobalAlert) (*genericExecutor, error) {
	switch alert.Spec.DataSet {
	case v3.GlobalAlertDataSetAudit:
		return &genericExecutor{
			listFn:        client.AuditLogs(clusterName).ListInto,
			aggregationFn: client.AuditLogs(clusterName).Aggregations,
		}, nil
	case v3.GlobalAlertDataSetDNS:
		return &genericExecutor{
			listFn:        client.DNSLogs(clusterName).ListInto,
			aggregationFn: client.DNSLogs(clusterName).Aggregations,
		}, nil
	case v3.GlobalAlertDataSetFlows:
		return &genericExecutor{
			listFn:        client.FlowLogs(clusterName).ListInto,
			aggregationFn: client.FlowLogs(clusterName).Aggregations,
		}, nil
	case v3.GlobalAlertDataSetL7:
		return &genericExecutor{
			listFn:        client.L7Logs(clusterName).ListInto,
			aggregationFn: client.L7Logs(clusterName).Aggregations,
		}, nil
	case v3.GlobalAlertDataSetWAF:
		return &genericExecutor{
			listFn:        client.WAFLogs(clusterName).ListInto,
			aggregationFn: client.WAFLogs(clusterName).Aggregations,
		}, nil
	}

	return nil, fmt.Errorf("unknown dataset %s in GlobalAlert %s", alert.Spec.DataSet, alert.Name)
}

func (g genericExecutor) Count(ctx context.Context, params lsv1.Params) (int64, error) {
	result := lsv1.List[JsonObject]{}
	err := g.listFn(ctx, params, &result)
	if err != nil {
		return 0, err
	}

	return result.TotalHits, nil
}

func (g genericExecutor) Iterate(ctx context.Context, params lsv1.Params) (<-chan lsv1.List[JsonObject], <-chan error) {
	wrapFn := func(ctx context.Context, params lsv1.Params) (*lsv1.List[JsonObject], error) {
		logs := lsv1.List[JsonObject]{}
		err := g.listFn(ctx, params, &logs)
		return &logs, err
	}

	pager := client.NewListPager[JsonObject](params)
	return pager.Stream(ctx, wrapFn)
}

func (g genericExecutor) Aggregate(ctx context.Context, params lsv1.Params) (elastic.Aggregations, error) {
	return g.aggregationFn(ctx, params)
}
