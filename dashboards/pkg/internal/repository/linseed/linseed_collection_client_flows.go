package linseed

import (
	"context"
	"encoding/json"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/lib/slices"

	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/query/result"
	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
)

type collectionClientFlows struct {
	logger logging.Logger
	client lsclient.Client
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
		QueryParams:           params.linseedQueryParams,
		QuerySortParams:       params.linseedQuerySortParams,
		LogSelectionParams:    params.linseedLogSelectionParams,
		EnforcedPolicyMatches: params.enforcedPolicyMatches,
		PendingPolicyMatches:  params.pendingPolicyMatches,
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

func (c *collectionClientFlows) List(ctx context.Context, params lsv1.Params) (result.QueryResult, error) {
	c.logger.DebugC(ctx, "FlowLogs.List",
		logging.Any("params", params))

	listResult, err := c.client.FlowLogs(lsv1.QueryMultipleClusters).List(ctx, params)
	if err != nil {
		return result.QueryResult{}, err
	}

	return result.QueryResult{
		Hits: listResult.TotalHits,
		Documents: slices.Map(listResult.Items, func(item lsv1.FlowLog) result.QueryResultDocument {
			return result.QueryResultDocument{
				Content:   item,
				Timestamp: time.Unix(item.StartTime, 0).UTC(),
			}
		}),
	}, nil
}

func (c *collectionClientFlows) Aggregations(ctx context.Context, params lsv1.Params) (elastic.Aggregations, error) {
	c.logger.DebugC(ctx, "FlowLogs.Aggregations",
		logging.Any("params", params))

	return c.client.FlowLogs(lsv1.QueryMultipleClusters).Aggregations(ctx, params)
}
