package aggregations

type AggregationAvg struct {
	key       AggregationKey
	order     int
	sortAsc   bool
	fieldName string
}

var _ Aggregation = AggregationAvg{}

func NewAggregationAvg(key AggregationKey, order int, fieldName string, sortAsc bool) Aggregation {
	return AggregationAvg{key: key, order: order, fieldName: fieldName, sortAsc: sortAsc}
}

func (a AggregationAvg) FieldName() string {
	return a.fieldName
}

func (a AggregationAvg) Key() AggregationKey {
	return a.key
}

func (a AggregationAvg) Order() int {
	return a.order
}

func (a AggregationAvg) SortAsc() bool {
	return a.sortAsc
}
