package aggregations

type AggregationCount struct {
	key     AggregationKey
	order   int
	sortAsc bool
}

var _ Aggregation = AggregationCount{}

func NewAggregationCount(key AggregationKey, order int, sortAsc bool) Aggregation {
	return AggregationCount{key: key, order: order, sortAsc: sortAsc}
}

func (a AggregationCount) Key() AggregationKey {
	return a.key
}

func (a AggregationCount) Order() int {
	return a.order
}

func (a AggregationCount) SortAsc() bool {
	return a.sortAsc
}
