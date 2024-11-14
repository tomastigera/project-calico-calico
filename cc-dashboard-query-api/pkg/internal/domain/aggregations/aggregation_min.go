package aggregations

type AggregationMin struct {
	fieldName string
}

var _ Aggregation = AggregationMin{}

func NewAggregationMin(fieldName string) Aggregation {
	return AggregationMin{fieldName: fieldName}
}

func (a AggregationMin) FieldName() string {
	return a.fieldName
}
