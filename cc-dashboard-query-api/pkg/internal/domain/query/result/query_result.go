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
}

var _ groups.AppendableGroupValue = &QueryResult{}

func (q *QueryResult) AppendGroupValue(groupValue *groups.GroupValue) {
	q.GroupValues = append(q.GroupValues, groupValue)
}
