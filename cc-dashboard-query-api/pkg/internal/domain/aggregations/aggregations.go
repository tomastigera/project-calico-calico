package aggregations

type Aggregation interface{}

type AggregationKey string
type Aggregations map[AggregationKey]Aggregation
