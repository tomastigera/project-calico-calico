package collections

type AggregationFunctionType string

const (
	AggregationFunctionTypeAvg           = AggregationFunctionType("avg")
	AggregationFunctionTypeMax           = AggregationFunctionType("max")
	AggregationFunctionTypeMin           = AggregationFunctionType("min")
	AggregationFunctionTypeSum           = AggregationFunctionType("sum")
	AggregationFunctionTypePercentile50  = AggregationFunctionType("p50")
	AggregationFunctionTypePercentile90  = AggregationFunctionType("p90")
	AggregationFunctionTypePercentile95  = AggregationFunctionType("p95")
	AggregationFunctionTypePercentile100 = AggregationFunctionType("p100")
)
