package aggregations

type AggregationMax struct {
	fieldName string
}

var _ Aggregation = AggregationMax{}

func NewAggregationMax(fieldName string) Aggregation {
	return AggregationMax{fieldName: fieldName}
}

func (a AggregationMax) FieldName() string {
	return a.fieldName
}
