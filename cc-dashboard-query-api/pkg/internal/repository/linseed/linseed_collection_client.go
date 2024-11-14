package linseed

import (
	"context"
	"encoding/json"

	"github.com/olivere/elastic/v7"

	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/query"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/query/result"
)

// linseedCollectionClient interface to a collection-specific client
type linseedCollectionClient interface {
	// Params build collection-specific params
	Params(queryParams *queryParams, aggregations map[string]json.RawMessage) (lsv1.Params, error)

	// List non-aggregated document list query
	List(ctx context.Context, clusterName query.ManagedClusterName, params lsv1.Params) (result.QueryResult, error)

	// Aggregations Aggregated documents query
	Aggregations(ctx context.Context, clusterName query.ManagedClusterName, params lsv1.Params) (elastic.Aggregations, error)
}
