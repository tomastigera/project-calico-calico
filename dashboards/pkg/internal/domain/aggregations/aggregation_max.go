package aggregations

type AggregationMax struct {
	key       AggregationKey
	order     int
	sortAsc   bool
	fieldName string
}

var _ Aggregation = AggregationMax{}

func NewAggregationMax(key AggregationKey, order int, fieldName string, sortAsc bool) Aggregation {
	return AggregationMax{key: key, order: order, fieldName: fieldName, sortAsc: sortAsc}
}

func (a AggregationMax) FieldName() string {
	return a.fieldName
}

func (a AggregationMax) Key() AggregationKey {
	return a.key
}

func (a AggregationMax) Order() int {
	return a.order
}

func (a AggregationMax) SortAsc() bool {
	return a.sortAsc
}
