package aggregations

type AggregationSum struct {
	fieldName string
}

var _ Aggregation = AggregationSum{}

func NewAggregationSum(fieldName string) Aggregation {
	return AggregationSum{fieldName: fieldName}
}

func (a AggregationSum) FieldName() string {
	return a.fieldName
}
