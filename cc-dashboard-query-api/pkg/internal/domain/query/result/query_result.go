package result

import (
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/aggregations"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/groups"
)

type QueryResult struct {
	Hits         int64
	Documents    []QueryResultDocument
	Aggregations aggregations.AggregationValues
	GroupValues  groups.GroupValues

	Err error
}

var _ groups.AppendableGroupValue = &QueryResult{}

func QueryResultWithError(err error) QueryResult {
	return QueryResult{Err: err}
}

func (q *QueryResult) AppendGroupValue(groupValue *groups.GroupValue) {
	q.GroupValues = append(q.GroupValues, groupValue)
}

func (q *QueryResult) Calculate() error {
	if err := q.Aggregations.Calculate(); err != nil {
		return err
	}

	if err := q.GroupValues.Calculate(); err != nil {
		return err
	}
	return nil
}
