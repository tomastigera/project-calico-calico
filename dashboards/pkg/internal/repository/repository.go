package repository

import (
	"context"

	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/query"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/query/result"
)

type Repository interface {
	Query(ctx context.Context, req query.QueryRequest) (result.QueryResult, error)
}
