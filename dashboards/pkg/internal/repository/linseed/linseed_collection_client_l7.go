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

type collectionClientL7 struct {
	logger logging.Logger
	client lsclient.Client
}

var _ linseedCollectionClient = &collectionClientL7{}

func newLinseedCollectionClientL7(logger logging.Logger, client lsclient.Client) linseedCollectionClient {
	return &collectionClientL7{
		logger: logger,
		client: client,
	}
}

func (c *collectionClientL7) Params(params *queryParams, aggregations map[string]json.RawMessage) (lsv1.Params, error) {
	l7LogParams := &lsv1.L7LogParams{
		QueryParams:        params.linseedQueryParams,
		QuerySortParams:    params.linseedQuerySortParams,
		LogSelectionParams: params.linseedLogSelectionParams,
	}

	if len(aggregations) > 0 {
		return &lsv1.L7AggregationParams{
			L7LogParams:  *l7LogParams,
			Aggregations: aggregations,
		}, nil
	}

	return l7LogParams, nil
}

func (c *collectionClientL7) List(ctx context.Context, params lsv1.Params) (result.QueryResult, error) {
	c.logger.DebugC(ctx, "L7Logs.List",
		logging.Any("params", params))

	listResult, err := c.client.L7Logs(lsv1.QueryMultipleClusters).List(ctx, params)
	if err != nil {
		return result.QueryResult{}, err
	}

	return result.QueryResult{
		Hits: listResult.TotalHits,
		Documents: slices.Map(listResult.Items, func(item lsv1.L7Log) result.QueryResultDocument {
			return result.QueryResultDocument{
				Content:   item,
				Timestamp: time.Unix(item.StartTime, 0).UTC(),
			}
		}),
	}, nil
}

func (c *collectionClientL7) Aggregations(ctx context.Context, params lsv1.Params) (elastic.Aggregations, error) {
	c.logger.DebugC(ctx, "L7Logs.Aggregations",
		logging.Any("params", params))

	return c.client.L7Logs(lsv1.QueryMultipleClusters).Aggregations(ctx, params)
}
