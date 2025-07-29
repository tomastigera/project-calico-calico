package aggregations

type AggregationMin struct {
	key       AggregationKey
	order     int
	sortAsc   bool
	fieldName string
}

var _ Aggregation = AggregationMin{}

func NewAggregationMin(key AggregationKey, order int, fieldName string, sortAsc bool) Aggregation {
	return AggregationMin{key: key, order: order, fieldName: fieldName, sortAsc: sortAsc}
}

func (a AggregationMin) FieldName() string {
	return a.fieldName
}

func (a AggregationMin) Key() AggregationKey {
	return a.key
}

func (a AggregationMin) Order() int {
	return a.order
}

func (a AggregationMin) SortAsc() bool {
	return a.sortAsc
}
