package groups

import (
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/aggregations"
)

type GroupType string
type GroupSortOrderType string

const (
	GroupTypeTime     = GroupType("time")
	GroupTypeDiscrete = GroupType("discrete")
)

type Group interface {
	Type() GroupType
	Interval() string
	MaxValues() int
	FieldName() string
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
