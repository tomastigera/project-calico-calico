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

type collectionClientWAF struct {
	logger logging.Logger
	client lsclient.Client
}

var _ linseedCollectionClient = &collectionClientWAF{}

func newLinseedCollectionClientWAF(logger logging.Logger, client lsclient.Client) linseedCollectionClient {
	return &collectionClientWAF{
		logger: logger,
		client: client,
	}
}

func (c *collectionClientWAF) Params(params *queryParams, aggregations map[string]json.RawMessage) (lsv1.Params, error) {
	wafLogsLogParams := &lsv1.WAFLogParams{
		QueryParams:     params.linseedQueryParams,
		Selector:        params.linseedLogSelectionParams.Selector,
		QuerySortParams: params.linseedQuerySortParams,
	}

	if len(aggregations) > 0 {
		wafLogsAggregationParams := &lsv1.WAFLogAggregationParams{
			WAFLogParams: *wafLogsLogParams,
			Aggregations: aggregations,
		}
		return wafLogsAggregationParams, nil
	}

	return wafLogsLogParams, nil
}

func (c *collectionClientWAF) List(ctx context.Context, params lsv1.Params) (result.QueryResult, error) {
	c.logger.DebugC(ctx, "WAFLogs.List",
		logging.Any("params", params))

	listResult, err := c.client.WAFLogs(lsv1.QueryMultipleClusters).List(ctx, params)
	if err != nil {
		return result.QueryResult{}, err
	}

	return result.QueryResult{
		Hits: listResult.TotalHits,
		Documents: slices.Map(listResult.Items, func(item lsv1.WAFLog) result.QueryResultDocument {
			return result.QueryResultDocument{
				Content:   item,
				Timestamp: time.Unix(item.Timestamp.Unix(), 0).UTC(),
			}
		}),
	}, nil
}

func (c *collectionClientWAF) Aggregations(ctx context.Context, params lsv1.Params) (elastic.Aggregations, error) {
	c.logger.DebugC(ctx, "WAFLogs.Aggregations",
		logging.Any("params", params))

	return c.client.WAFLogs(lsv1.QueryMultipleClusters).Aggregations(ctx, params)
}
