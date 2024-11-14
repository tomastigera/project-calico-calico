package aggregations

import (
	"golang.org/x/exp/slices"
)

/* Each api query results in a linseed query for each managed cluster for phase 1 of this project.
 * AggregationValue provides a hacky way to calculate aggregation results from multiple managed clusters
 *
 * TODO: Fix linseed to return query results for multiple managed clusters from a single query and remove the
 * calculation code below for nobana phase 2
 */

type AggregationValue interface {
	Append(AggregationValue)
	Calculate() error
	Value() any
}

type aggregationValue[T int64 | float64] struct {
	value            *T
	additionalValues []*T
	calculateFunc    func() error
}

type AggregationValues map[string]AggregationValue

// NewAggregationValue Creates a new aggregation value.
// TODO: Remove the calculate* methods hack and fix linseed to have elastic provide multi-cluster results with a single
// aggregation
func NewAggregationValue[T int64 | float64](value *T, agg Aggregation) AggregationValue {
	aggValue := &aggregationValue[T]{
		value: value,
	}

	switch agg.(type) { // TODO: This block and the methods being assigned to below must be removed on phase 2
	case AggregationCount:
		aggValue.calculateFunc = aggValue.calculateSum
	case AggregationSum:
		aggValue.calculateFunc = aggValue.calculateSum
	case AggregationPercentile:
		aggValue.calculateFunc = aggValue.calculateSum
	case AggregationMin:
		aggValue.calculateFunc = aggValue.calculateMin
	case AggregationMax:
		aggValue.calculateFunc = aggValue.calculateMax
	case AggregationAvg:
		aggValue.calculateFunc = aggValue.calculateAvg
	}

	return aggValue
}

func (a AggregationValues) Calculate() error {
	for _, aggValue := range a {
		if err := aggValue.Calculate(); err != nil {
			return err
		}
	}
	return nil
}

// Calculate This is a temporary phase 1 quickfix solution for multi cluster queries that will be replaced on
// phase 2 with a linseed/ES multi-cluster aggregation
func (a *aggregationValue[T]) Calculate() error {
	var err error
	if a.calculateFunc != nil {
		err = a.calculateFunc()
	}

	// testify always fails function comparison https://pkg.go.dev/github.com/stretchr/testify/require#Equal
	// unset a.calculateFunc to ensure require.Equals tests do not fail due to function comparison
	a.calculateFunc = nil
	return err
}

func (a *aggregationValue[T]) Append(additionalValue AggregationValue) {
	switch av := additionalValue.(type) {
	case *aggregationValue[T]:
		a.additionalValues = append(a.additionalValues, av.value)
	}
}

func (a *aggregationValue[T]) Value() any {
	return a.value
}

func (a *aggregationValue[T]) calculateSum() error {
	var total *T
	for _, v := range append(a.additionalValues, a.value) {
		if v == nil {
			continue
		}

		if total == nil {
			total = new(T)
		}

		*total += *v
	}

	a.value = total
	a.additionalValues = nil
	return nil
}

func (a *aggregationValue[T]) calculateMin() error {
	var values []T
	for _, v := range append(a.additionalValues, a.value) {
		if v != nil {
			values = append(values, *v)
		}
	}

	if len(values) > 0 {
		minValue := slices.Min(values)
		a.value = &minValue
	}
	a.additionalValues = nil
	return nil
}

func (a *aggregationValue[T]) calculateMax() error {
	var values []T
	for _, v := range append(a.additionalValues, a.value) {
		if v != nil {
			values = append(values, *v)
		}
	}

	if len(values) > 0 {
		maxValue := slices.Max(values)
		a.value = &maxValue
	}
	a.additionalValues = nil
	return nil
}

func (a *aggregationValue[T]) calculateAvg() error {
	valueCount := len(append(a.additionalValues, a.value))
	if err := a.calculateSum(); err != nil {
		return err
	}

	if a.value != nil {
		avg := *a.value / T(valueCount)
		a.value = &avg
	}

	a.additionalValues = nil
	return nil
}
