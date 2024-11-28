package aggregations

/* TODO: Fix linseed to return query results for multiple managed clusters from a single query
 */

type AggregationValue interface {
	Value() any
}

type aggregationValue[T int64 | float64] struct {
	value *T
}

type AggregationValues map[string]AggregationValue

// NewAggregationValue Creates a new aggregation value.
func NewAggregationValue[T int64 | float64](value *T) AggregationValue {
	aggValue := &aggregationValue[T]{
		value: value,
	}

	return aggValue
}

func (a *aggregationValue[T]) Value() any {
	return a.value
}
