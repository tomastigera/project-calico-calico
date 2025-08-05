package client

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQueryRequest(t *testing.T) {

	t.Run("Unmarshal criterion value", func(t *testing.T) {
		jsonRepr := `
{
	"filters": [
		{"criterion": {"field": "foo", "type": "equals", "value": "bar"}},
		{"criterion": {"field": "foo", "type": "equals", "value": 123}},
		{"criterion": {"field": "foo", "type": "equals", "value": 123.456}}
	]
}`

		queryRequest := &QueryRequest{}
		err := json.UnmarshalFromString(jsonRepr, queryRequest)
		require.NoError(t, err)

		require.Equal(t, &QueryRequest{
			Filters: []QueryRequestFilter{
				{Criterion: QueryRequestFilterCriterion{Field: "foo", Type: "equals", Value: QueryRequestFilterCriterionValue{value: "bar"}}},
				{Criterion: QueryRequestFilterCriterion{Field: "foo", Type: "equals", Value: QueryRequestFilterCriterionValue{value: int64(123)}}},
				{Criterion: QueryRequestFilterCriterion{Field: "foo", Type: "equals", Value: QueryRequestFilterCriterionValue{value: 123.456}}},
			},
		}, queryRequest)
	})
}
