package aggregations

type AggregationSum struct {
	key       AggregationKey
	order     int
	sortAsc   bool
	fieldName string
}

var _ Aggregation = AggregationSum{}

func NewAggregationSum(key AggregationKey, order int, fieldName string, sortAsc bool) Aggregation {
	return AggregationSum{key: key, order: order, fieldName: fieldName, sortAsc: sortAsc}
}

func (a AggregationSum) FieldName() string {
	return a.fieldName
}

func (a AggregationSum) Key() AggregationKey {
	return a.key
}

func (a AggregationSum) Order() int {
	return a.order
}

func (a AggregationSum) SortAsc() bool {
	return a.sortAsc
}
