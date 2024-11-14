package aggregations

type AggregationAvg struct {
	fieldName string
}

var _ Aggregation = AggregationAvg{}

func NewAggregationAvg(fieldName string) Aggregation {
	return AggregationAvg{fieldName: fieldName}
}

func (a AggregationAvg) FieldName() string {
	return a.fieldName
}
