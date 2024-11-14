package linseed

import (
	"context"
	"encoding/json"
	"time"

	"github.com/olivere/elastic/v7"
	"go.uber.org/zap"

	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/query"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/query/result"
	"github.com/tigera/tds-apiserver/lib/slices"
	"github.com/tigera/tds-apiserver/pkg/logging"
)

type collectionClientFlows struct {
	logger logging.Logger
	client lsclient.Client
}

// TODO: This document should contain relevant fields instead of the entirety of the FlowLog
type flowLogDocument struct {
	lsv1.FlowLog
	Cluster query.ManagedClusterName `json:"cluster"`
}

var _ linseedCollectionClient = &collectionClientFlows{}

func newLinseedCollectionClientFlows(logger logging.Logger, client lsclient.Client) linseedCollectionClient {
	return &collectionClientFlows{
		logger: logger,
		client: client,
	}
}

func (c *collectionClientFlows) Params(params *queryParams, aggregations map[string]json.RawMessage) (lsv1.Params, error) {
	flowLogsLogParams := &lsv1.FlowLogParams{
		QueryParams: params.QueryParams,
		LogSelectionParams: lsv1.LogSelectionParams{
			Selector: params.selector,
		},
	}

	if len(aggregations) > 0 {
		flowLogsAggregationParams := &lsv1.FlowLogAggregationParams{
			FlowLogParams: *flowLogsLogParams,
			Aggregations:  aggregations,
		}
		return flowLogsAggregationParams, nil
	}

	return flowLogsLogParams, nil
}

func (c *collectionClientFlows) List(ctx context.Context, clusterName query.ManagedClusterName, params lsv1.Params) (result.QueryResult, error) {
	c.logger.DebugC(ctx, "FlowLogs.List",
		zap.String("clusterName", string(clusterName)),
		zap.Any("params", params))

	listResult, err := c.client.FlowLogs(string(clusterName)).List(ctx, params)
	if err != nil {
		return result.QueryResult{}, err
	}

	return result.QueryResult{
		Hits: listResult.TotalHits,
		Documents: slices.Map(listResult.Items, func(i lsv1.FlowLog) result.QueryResultDocument {
			return result.QueryResultDocument{Content: flowLogDocument{FlowLog: i, Cluster: clusterName}, Timestamp: time.Unix(i.Timestamp, 0).UTC()}
		}),
	}, nil
}

func (c *collectionClientFlows) Aggregations(ctx context.Context, clusterName query.ManagedClusterName, params lsv1.Params) (elastic.Aggregations, error) {
	c.logger.DebugC(ctx, "FlowLogs.Aggregations",
		zap.String("clusterName", string(clusterName)),
		zap.Any("params", params))

	return c.client.FlowLogs(string(clusterName)).Aggregations(ctx, params)
}
