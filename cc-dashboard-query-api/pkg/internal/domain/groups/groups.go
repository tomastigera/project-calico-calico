package groups

import (
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/aggregations"
)

type GroupType string

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

func (g GroupValues) Calculate() error {
	for _, groupValue := range g {
		if err := groupValue.Aggregations.Calculate(); err != nil {
			return err
		}

		if err := groupValue.SubGroupValues.Calculate(); err != nil {
			return err
		}
	}
	return nil
}
