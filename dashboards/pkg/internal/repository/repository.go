package repository

import (
	"context"

	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/query"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/query/result"
)

type Repository interface {
	Query(ctx context.Context, req query.QueryRequest) (result.QueryResult, error)
}
