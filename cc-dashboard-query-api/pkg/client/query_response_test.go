package client

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tigera/tds-apiserver/lib/slices"
)

func TestQueryResponse(t *testing.T) {

	t.Run("write csv", func(t *testing.T) {
		t.Run("no values", func(t *testing.T) {
			subject := QueryResponse{}

			w := &bytes.Buffer{}
			err := subject.WriteCSV(w, nil)
			require.NoError(t, err)

			require.Equal(t, "\n", w.String())
		})

		t.Run("no columns set", func(t *testing.T) {
			subject := QueryResponse{
				Documents: slices.Map([]map[string]string{
					{"test-key1": "test-value1"},
					{"test-key2": "test-value2"},
				}, func(m map[string]string) any { return m }),
			}

			w := &bytes.Buffer{}
			err := subject.WriteCSV(w, nil)
			require.NoError(t, err)

			require.Equal(t, "\n\n\n", w.String())
		})

		t.Run("document results", func(t *testing.T) {
			subject := QueryResponse{
				Documents: slices.Map([]map[string]string{
					{"test-key1-0": "test-value1-0", "test-key1-1": "test-value1-1", "test-key1-2": "test-value1-2"},
				}, func(m map[string]string) any { return m }),
			}

			testCases := []struct {
				name     string
				columns  []string
				expected string
			}{
				{
					name:     "all fields",
					columns:  []string{"test-key1-0", "test-key1-1", "test-key1-2"},
					expected: "test-key1-0,test-key1-1,test-key1-2\ntest-value1-0,test-value1-1,test-value1-2\n",
				},
				{
					name:     "all fields with aliases",
					columns:  []string{"test-key1-0:first column", "test-key1-1:second column", "test-key1-2:third column"},
					expected: "first column,second column,third column\ntest-value1-0,test-value1-1,test-value1-2\n",
				},
				{
					name:     "fields subset",
					columns:  []string{"test-key1-2", "test-key1-0"},
					expected: "test-key1-2,test-key1-0\ntest-value1-2,test-value1-0\n",
				},
				{
					name:     "unknown fields are ignored",
					columns:  []string{"test-key1-2", "test-key1-0", "unknown-field"},
					expected: "test-key1-2,test-key1-0,unknown-field\ntest-value1-2,test-value1-0,\n",
				},
			}

			for _, tc := range testCases {

				t.Run(tc.name, func(t *testing.T) {
					w := &bytes.Buffer{}
					err := subject.WriteCSV(w, tc.columns)
					require.NoError(t, err)

					require.Equal(t, tc.expected, w.String())
				})
			}
		})

		t.Run("groups and aggregations results", func(t *testing.T) {
			queryResponseGroupValueToAny := func(qrgv QueryResponseGroupValue) any {
				return qrgv
			}

			subject := QueryResponse{
				GroupValues: []QueryResponseGroupValue{
					{Key: "g0:0", NestedValues: slices.Map([]QueryResponseGroupValue{
						{Key: "g0:0:g1:0", Aggregations: map[string]QueryResponseValueAsString{
							"agg1": {AsString: "100"},
							"agg2": {AsString: "200"},
						}},
					}, queryResponseGroupValueToAny)},
					{Key: "g0:1", NestedValues: slices.Map([]QueryResponseGroupValue{
						{Key: "g0:1:g1:0", Aggregations: map[string]QueryResponseValueAsString{
							"agg1": {AsString: "300"},
							"agg2": {AsString: "400"},
						}},
						{Key: "g0:1:g1:1", Aggregations: map[string]QueryResponseValueAsString{
							"agg1": {AsString: "500"},
							"agg2": {AsString: "600"},
						}},
					}, queryResponseGroupValueToAny)},
				},
			}

			testCases := []struct {
				name     string
				columns  []string
				expected string
			}{
				{
					name:    "all fields",
					columns: []string{"groupBys(0)", "groupBys(1)", "aggregations(agg1)", "aggregations(agg2)"},
					expected: "groupBys(0),groupBys(1),aggregations(agg1),aggregations(agg2)\n" +
						"g0:0,g0:0:g1:0,100,200\n" +
						"g0:1,g0:1:g1:0,300,400\n" +
						"g0:1,g0:1:g1:1,500,600\n",
				},
				{
					name:    "all fields with aliases",
					columns: []string{"groupBys(0):first group", "groupBys(1):second group", "aggregations(agg1):first aggregation", "aggregations(agg2):second aggregation"},
					expected: "first group,second group,first aggregation,second aggregation\n" +
						"g0:0,g0:0:g1:0,100,200\n" +
						"g0:1,g0:1:g1:0,300,400\n" +
						"g0:1,g0:1:g1:1,500,600\n",
				},
				{
					name:    "fields subset",
					columns: []string{"groupBys(1)", "aggregations(agg2)", "aggregations(agg1)"},
					expected: "groupBys(1),aggregations(agg2),aggregations(agg1)\n" +
						"g0:0:g1:0,200,100\n" +
						"g0:1:g1:0,400,300\n" +
						"g0:1:g1:1,600,500\n",
				},
				{
					name:    "unknown fields are ignored",
					columns: []string{"groupBys(1)", "groupBys(99)", "aggregations(agg2)", "aggregations(unknown-aggregation)"},
					expected: "groupBys(1),groupBys(99),aggregations(agg2),aggregations(unknown-aggregation)\n" +
						"g0:0:g1:0,,200,\n" +
						"g0:1:g1:0,,400,\n" +
						"g0:1:g1:1,,600,\n",
				},
			}

			for _, tc := range testCases {

				t.Run(tc.name, func(t *testing.T) {
					w := &bytes.Buffer{}
					err := subject.WriteCSV(w, tc.columns)
					require.NoError(t, err)

					require.Equal(t, tc.expected, w.String())
				})
			}
		})
	})
}
