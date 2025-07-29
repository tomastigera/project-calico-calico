package aggregations

type Aggregation interface {
	Key() AggregationKey
	Order() int
	SortAsc() bool
}

type AggregationKey string

type Aggregations []Aggregation
