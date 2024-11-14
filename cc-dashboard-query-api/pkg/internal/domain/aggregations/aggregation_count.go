package aggregations

type AggregationCount struct {
}

var _ Aggregation = AggregationCount{}

func NewAggregationCount() Aggregation {
	return AggregationCount{}
}
