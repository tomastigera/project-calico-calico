package aggregations

type AggregationPercentile struct {
	pct       float64
	fieldName string
}

var _ Aggregation = AggregationPercentile{}

func NewAggregationPercentile(fieldName string, pct float64) Aggregation {
	return AggregationPercentile{
		fieldName: fieldName,
		pct:       pct,
	}
}

func (a AggregationPercentile) FieldName() string {
	return a.fieldName
}

func (a AggregationPercentile) Percentile() float64 {
	return a.pct
}
