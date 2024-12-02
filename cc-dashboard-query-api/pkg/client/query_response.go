package client

// QueryResponse A query response
type QueryResponse struct {
	Totals QueryResponseTotals `json:"totals"`

	Documents    []any                     `json:"documents,omitempty"`
	Aggregations QueryResponseAggregations `json:"aggregations,omitempty"`
	GroupValues  []QueryResponseGroupValue `json:"groupValues,omitempty"`
}

// QueryResponseTotals Total document results
type QueryResponseTotals struct {
	Type  string `json:"type"`
	Value int64  `json:"value"`
}

type QueryResponseAggregations map[string]QueryResponseValueAsString

type QueryResponseValueAsString struct {
	AsString string `json:"asString"`
}

type QueryResponseGroupValue struct {
	Key          string                    `json:"key"`
	Aggregations QueryResponseAggregations `json:"aggregations,omitempty"`

	// TODO: set type to []QueryResponseGroupValue once tds-apiserver/pkg/http/handleradapters/openapi.go gets
	// fixed to not panic with a slice field of the same type as the parent struct
	NestedValues []any `json:"nestedValues,omitempty"`
}

type AppendableQueryResponseGroupValue interface {
	Append(QueryResponseGroupValue)
}

var _ AppendableQueryResponseGroupValue = &QueryResponse{}
var _ AppendableQueryResponseGroupValue = &QueryResponseGroupValue{}

func (q *QueryResponse) Append(value QueryResponseGroupValue) {
	q.GroupValues = append(q.GroupValues, value)
}

func (q *QueryResponseGroupValue) Append(value QueryResponseGroupValue) {
	q.NestedValues = append(q.NestedValues, value)
}
