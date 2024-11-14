package aggregations

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

type testValue[T int64 | float64] struct {
	values        []T
	expectedValue T
}

func TestAggregationValue(t *testing.T) {

	testCases := []struct {
		aggregationName   string
		aggregation       Aggregation
		valuesInt64       testValue[int64]
		valuesFloat64     testValue[float64]
		expectedFieldName string
	}{
		{
			aggregation:     NewAggregationCount(),
			valuesInt64:     testValue[int64]{expectedValue: int64(89), values: []int64{10, 20, 59}},
			valuesFloat64:   testValue[float64]{expectedValue: float64(89.5), values: []float64{10, 20, 59.5}},
			aggregationName: "count",
		},
		{
			aggregation:       NewAggregationSum("test-field-sum"),
			valuesInt64:       testValue[int64]{expectedValue: int64(89), values: []int64{10, 20, 59}},
			valuesFloat64:     testValue[float64]{expectedValue: float64(89.5), values: []float64{10, 20, 59.5}},
			aggregationName:   "sum",
			expectedFieldName: "test-field-sum",
		},
		{
			aggregation:       NewAggregationPercentile("test-field-percentile", 10),
			valuesInt64:       testValue[int64]{expectedValue: int64(89), values: []int64{10, 20, 59}},
			valuesFloat64:     testValue[float64]{expectedValue: float64(89.5), values: []float64{10, 20, 59.5}},
			aggregationName:   "percentile",
			expectedFieldName: "test-field-percentile",
		},
		{
			aggregation:       NewAggregationMin("test-field-min"),
			valuesInt64:       testValue[int64]{expectedValue: int64(10), values: []int64{10, 20, 59}},
			valuesFloat64:     testValue[float64]{expectedValue: float64(10), values: []float64{10, 20, 59.5}},
			aggregationName:   "min",
			expectedFieldName: "test-field-min",
		},
		{
			aggregation:       NewAggregationMax("test-field-max"),
			valuesInt64:       testValue[int64]{expectedValue: int64(59), values: []int64{10, 20, 59}},
			valuesFloat64:     testValue[float64]{expectedValue: 59.5, values: []float64{10, 20, 59.5}},
			aggregationName:   "max",
			expectedFieldName: "test-field-max",
		},
		{
			aggregation:       NewAggregationAvg("test-field-avg"),
			valuesInt64:       testValue[int64]{expectedValue: int64(29), values: []int64{10, 20, 59}},
			valuesFloat64:     testValue[float64]{expectedValue: float64(22), values: []float64{10, 20, 36}},
			aggregationName:   "avg",
			expectedFieldName: "test-field-avg",
		},
	}

	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("calculate aggregation %s", testCase.aggregationName), func(t *testing.T) {

			fieldName := ""
			switch a := testCase.aggregation.(type) {
			case AggregationAvg:
				fieldName = a.FieldName()
			case AggregationMax:
				fieldName = a.FieldName()
			case AggregationMin:
				fieldName = a.FieldName()
			case AggregationSum:
				fieldName = a.FieldName()
			case AggregationPercentile:
				fieldName = a.FieldName()
				require.Equal(t, 10.0, a.Percentile())
			}
			require.Equal(t, testCase.expectedFieldName, fieldName)

			t.Run("int64", func(t *testing.T) {
				aggValue := createAndAppendAggregationValue(t, testCase.valuesInt64.values, testCase.aggregation)
				require.NoError(t, aggValue.Calculate())

				value, ok := aggValue.Value().(*int64)
				require.True(t, ok)
				require.NotNil(t, value)
				require.Equal(t, testCase.valuesInt64.expectedValue, *value)
			})

			t.Run("float64", func(t *testing.T) {
				aggValue := createAndAppendAggregationValue(t, testCase.valuesFloat64.values, testCase.aggregation)
				require.NoError(t, aggValue.Calculate())

				value, ok := aggValue.Value().(*float64)
				require.True(t, ok)
				require.NotNil(t, value)
				require.Equal(t, testCase.valuesFloat64.expectedValue, *value)
			})
		})
	}
}

func createAndAppendAggregationValue[T int64 | float64](t *testing.T, values []T, aggregation Aggregation) AggregationValue {
	t.Helper()
	v := NewAggregationValue(&values[0], aggregation)
	for i := 1; i < len(values); i++ {
		v.Append(NewAggregationValue(&values[i], aggregation))
	}
	return v
}
