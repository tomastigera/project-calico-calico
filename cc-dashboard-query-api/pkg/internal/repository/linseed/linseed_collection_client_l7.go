package linseed

import (
	"context"
	"encoding/json"
	"time"

	"github.com/olivere/elastic/v7"

	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/query"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/query/result"
	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/lib/slices"
)

type collectionClientL7 struct {
	logger logging.Logger
	client lsclient.Client
}

// TODO: This document should contain relevant fields instead of the entirety of the L7Log
type l7LogDocument struct {
	lsv1.L7Log
	Cluster query.ManagedClusterName `json:"cluster"`
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
		QueryParams: params.linseedQueryParams,
		LogSelectionParams: lsv1.LogSelectionParams{
			Selector: params.selector,
		},
		QuerySortParams: params.linseedQuerySortParams,
	}

	if len(aggregations) > 0 {
		return &lsv1.L7AggregationParams{
			L7LogParams:  *l7LogParams,
			Aggregations: aggregations,
		}, nil
	}

	return l7LogParams, nil
}

func (c *collectionClientL7) List(ctx context.Context, clusterName query.ManagedClusterName, params lsv1.Params) (result.QueryResult, error) {
	c.logger.DebugC(ctx, "L7Logs.List",
		logging.String("clusterName", string(clusterName)),
		logging.Any("params", params))

	listResult, err := c.client.L7Logs(string(clusterName)).List(ctx, params)
	if err != nil {
		return result.QueryResult{}, err
	}

	return result.QueryResult{
		Hits: listResult.TotalHits,
		Documents: slices.Map(listResult.Items, func(i lsv1.L7Log) result.QueryResultDocument {
			return result.QueryResultDocument{
				Content:   l7LogDocument{L7Log: i, Cluster: clusterName},
				Timestamp: time.Unix(i.StartTime, 0).UTC(),
			}
		}),
	}, nil
}

func (c *collectionClientL7) Aggregations(ctx context.Context, clusterName query.ManagedClusterName, params lsv1.Params) (elastic.Aggregations, error) {
	c.logger.DebugC(ctx, "L7Logs.Aggregations",
		logging.String("clusterName", string(clusterName)),
		logging.Any("params", params))

	return c.client.L7Logs(string(clusterName)).Aggregations(ctx, params)
}
