package aggregations

type AggregationPercentile struct {
	key       AggregationKey
	pct       float64
	order     int
	sortAsc   bool
	fieldName string
}

var _ Aggregation = AggregationPercentile{}

func NewAggregationPercentile(key AggregationKey, order int, fieldName string, pct float64, sortAsc bool) Aggregation {
	return AggregationPercentile{
		key:       key,
		pct:       pct,
		order:     order,
		sortAsc:   sortAsc,
		fieldName: fieldName,
	}
}

func (a AggregationPercentile) FieldName() string {
	return a.fieldName
}

func (a AggregationPercentile) Percentile() float64 {
	return a.pct
}

func (a AggregationPercentile) Key() AggregationKey {
	return a.key
}

func (a AggregationPercentile) Order() int {
	return a.order
}

func (a AggregationPercentile) SortAsc() bool {
	return a.sortAsc
}
