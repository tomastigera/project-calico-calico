package groups

import (
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/aggregations"
)

type GroupType string
type GroupSortOrderType string

const (
	GroupTypeTime     = GroupType("time")
	GroupTypeDiscrete = GroupType("discrete")
	// GroupTypeDistinct is an alias for discrete. TODO: remove GroupTypeDiscrete once all existing queries are using the discrete type
	GroupTypeDistinct = GroupType("distinct")

	GroupSortOrderTypeSelf  = GroupSortOrderType("self")
	GroupSortOrderTypeCount = GroupSortOrderType("count")
	// GroupSortOrderTypeAggregation = GroupSortOrderType("aggregation") // TODO: implement during phase 2
)

type Group interface {
	Type() GroupType
	Interval() string
	MaxValues() int
	FieldName() string
	SortOrder() GroupSortOrder
}

type GroupSortOrder struct {
	Asc            bool
	Type           GroupSortOrderType
	AggregationKey string
}

type AppendableGroupValue interface {
	AppendGroupValue(*GroupValue)
}

var _ AppendableGroupValue = &GroupValue{}

type Groups []Group

type GroupValue struct {
	Key            string
	DocCount       int64
	Aggregations   aggregations.AggregationValues
	SubGroupValues GroupValues
}

type GroupValues []*GroupValue

func (g *GroupValue) AppendGroupValue(groupValue *GroupValue) {
	g.SubGroupValues = append(g.SubGroupValues, groupValue)
}
