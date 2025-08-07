package linseed

import (
	"context"
	"encoding/json"

	"github.com/olivere/elastic/v7"

	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/query/result"
	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

// linseedCollectionClient interface to a collection-specific client
type linseedCollectionClient interface {
	// Params build collection-specific params
	Params(queryParams *queryParams, aggregations map[string]json.RawMessage) (lsv1.Params, error)

	// List non-aggregated document list query
	List(ctx context.Context, params lsv1.Params) (result.QueryResult, error)

	// Aggregations Aggregated documents query
	Aggregations(ctx context.Context, params lsv1.Params) (elastic.Aggregations, error)
}
