package fake

import (
	"context"

	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/query"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/query/result"
	"github.com/projectcalico/calico/dashboards/pkg/internal/repository"
)

type FakeRepository struct {
	queries []query.QueryRequest
}

var _ repository.Repository = (*FakeRepository)(nil)

func NewFakeRepository() *FakeRepository {
	return &FakeRepository{}
}

func (f *FakeRepository) Query(ctx context.Context, req query.QueryRequest) (result.QueryResult, error) {
	f.queries = append(f.queries, req)
	return result.QueryResult{}, nil
}

func (f *FakeRepository) Queries() []query.QueryRequest {
	return f.queries
}
