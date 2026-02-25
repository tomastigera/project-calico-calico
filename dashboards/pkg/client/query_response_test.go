package client

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQueryResponse(t *testing.T) {

	t.Run("csv output", func(t *testing.T) {
		t.Run("no values", func(t *testing.T) {
			subject := QueryResponse{}

			w := &bytes.Buffer{}
			err := subject.WriteCSV(w, nil, 0)
			require.NoError(t, err)

			require.Equal(t, "\n", w.String())
		})

		t.Run("no columns set", func(t *testing.T) {
			subject := QueryResponse{
				Documents: []QueryResponseDocument{
					{"test-key1": "test-value1"},
					{"test-key2": "test-value2"},
				},
			}

			w := &bytes.Buffer{}
			err := subject.WriteCSV(w, nil, 0)
			require.NoError(t, err)

			require.Equal(t, "\n\n\n", w.String())
		})

		t.Run("document results", func(t *testing.T) {
			subject := QueryResponse{
				Documents: []QueryResponseDocument{
					{"test-key1-0": "test-value1-0", "test-key1-1": "test-value1-1", "test-key1-2": "test-value1-2"},
				},
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
					err := subject.WriteCSV(w, tc.columns, 0)
					require.NoError(t, err)

					require.Equal(t, tc.expected, w.String())
				})
			}
		})

		t.Run("nested fields", func(t *testing.T) {
			subject := QueryResponse{
				Documents: []QueryResponseDocument{
					{
						"simple": "value",
						"parent": map[string]any{
							"child": "nested-value",
							"deep": map[string]any{
								"grandchild": "deep-value",
							},
						},
						"broken": "not-a-map",
					},
				},
			}

			testCases := []struct {
				name     string
				columns  []string
				expected string
			}{
				{
					name:     "simple nested field",
					columns:  []string{"parent.child"},
					expected: "parent.child\nnested-value\n",
				},
				{
					name:     "deeply nested field",
					columns:  []string{"parent.deep.grandchild"},
					expected: "parent.deep.grandchild\ndeep-value\n",
				},
				{
					name:     "missing nested field",
					columns:  []string{"parent.missing"},
					expected: "parent.missing\n\n",
				},
				{
					name:     "nested access on non-map",
					columns:  []string{"broken.child"},
					expected: "broken.child\n\n",
				},
				{
					name:     "mixed fields",
					columns:  []string{"simple", "parent.child", "parent.deep.grandchild"},
					expected: "simple,parent.child,parent.deep.grandchild\nvalue,nested-value,deep-value\n",
				},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					w := &bytes.Buffer{}
					err := subject.WriteCSV(w, tc.columns, 0)
					require.NoError(t, err)
					require.Equal(t, tc.expected, w.String())
				})
			}
		})

		t.Run("array fields", func(t *testing.T) {
			subject := QueryResponse{
				Documents: []QueryResponseDocument{
					{
						"simple_array": []any{"val1", "val2"},
						"mixed_array":  []any{"val1", 123, true},
						"empty_array":  []any{},
					},
				},
			}

			testCases := []struct {
				name     string
				columns  []string
				expected string
			}{
				{
					name:     "simple string array",
					columns:  []string{"simple_array"},
					expected: "simple_array\nval1;val2\n",
				},
				{
					name:     "mixed type array",
					columns:  []string{"mixed_array"},
					expected: "mixed_array\nval1;123;true\n",
				},
				{
					name:     "empty array",
					columns:  []string{"empty_array"},
					expected: "empty_array\n\n",
				},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					w := &bytes.Buffer{}
					err := subject.WriteCSV(w, tc.columns, 0)
					require.NoError(t, err)
					require.Equal(t, tc.expected, w.String())
				})
			}
		})

		t.Run("group values with no aggregation results are included", func(t *testing.T) {

			subject := QueryResponse{
				GroupValues: []QueryResponseGroupValue{
					{Key: "g0:0", NestedValues: []QueryResponseGroupValue{
						{Key: "g0:0-g1:0", Aggregations: QueryResponseAggregations{"agg1": QueryResponseValueAsString{AsString: "100"}}},
						{Key: "g0:0-g1:1", Aggregations: QueryResponseAggregations{"agg1": QueryResponseValueAsString{AsString: "200"}}},
					}},
					{Key: "g0:1", NestedValues: []QueryResponseGroupValue{
						{Key: "g0:1-g1:0", Aggregations: nil},
						{Key: "g0:1-g1:1", Aggregations: QueryResponseAggregations{"agg1": QueryResponseValueAsString{AsString: "300"}}},
					}},
					{Key: "g0:2", NestedValues: []QueryResponseGroupValue{
						{Key: "g0:2-g1:0", Aggregations: QueryResponseAggregations{"agg1": QueryResponseValueAsString{AsString: "400"}}},
						{Key: "g0:2-g1:1", Aggregations: nil},
					}},
					{Key: "g0:3", NestedValues: nil},
				},
			}

			w := &bytes.Buffer{}
			err := subject.WriteCSV(w, []string{"groupBys(0)", "groupBys(1)", "aggregations(agg1)"}, 0)
			require.NoError(t, err)

			require.Equal(t, "groupBys(0),groupBys(1),aggregations(agg1)\n"+
				"g0:0,g0:0-g1:0,100\n"+
				"g0:0,g0:0-g1:1,200\n"+
				"g0:1,g0:1-g1:0,\n"+
				"g0:1,g0:1-g1:1,300\n"+
				"g0:2,g0:2-g1:0,400\n"+
				"g0:2,g0:2-g1:1,\n"+
				"g0:3,,\n", w.String())
		})

		t.Run("groups and aggregations results", func(t *testing.T) {
			subject := QueryResponse{
				GroupValues: []QueryResponseGroupValue{
					{Key: "g0:0", NestedValues: []QueryResponseGroupValue{
						{Key: "g0:0:g1:0", Aggregations: map[string]QueryResponseValueAsString{
							"agg1": {AsString: "100"},
							"agg2": {AsString: "200"},
						}},
					}},
					{Key: "g0:1", NestedValues: []QueryResponseGroupValue{
						{Key: "g0:1:g1:0", Aggregations: map[string]QueryResponseValueAsString{
							"agg1": {AsString: "300"},
							"agg2": {AsString: "400"},
						}},
						{Key: "g0:1:g1:1", Aggregations: map[string]QueryResponseValueAsString{
							"agg1": {AsString: "500"},
							"agg2": {AsString: "600"},
						}},
					}},
				},
			}

			testCases := []struct {
				name     string
				columns  []string
				expected string
			}{
				{
					name:    "all aggregations and groupBys",
					columns: []string{"groupBys(0)", "groupBys(1)", "aggregations(agg1)", "aggregations(agg2)"},
					expected: "groupBys(0),groupBys(1),aggregations(agg1),aggregations(agg2)\n" +
						"g0:0,g0:0:g1:0,100,200\n" +
						"g0:1,g0:1:g1:0,300,400\n" +
						"g0:1,g0:1:g1:1,500,600\n",
				},
				{
					name:    "alias set for all aggregations and groupBys",
					columns: []string{"groupBys(0):first group", "groupBys(1):second group", "aggregations(agg1):first aggregation", "aggregations(agg2):second aggregation"},
					expected: "first group,second group,first aggregation,second aggregation\n" +
						"g0:0,g0:0:g1:0,100,200\n" +
						"g0:1,g0:1:g1:0,300,400\n" +
						"g0:1,g0:1:g1:1,500,600\n",
				},
				{
					name:    "subset of aggregations and groupBys",
					columns: []string{"groupBys(1)", "aggregations(agg2)", "aggregations(agg1)"},
					expected: "groupBys(1),aggregations(agg2),aggregations(agg1)\n" +
						"g0:0:g1:0,200,100\n" +
						"g0:1:g1:0,400,300\n" +
						"g0:1:g1:1,600,500\n",
				},
				{
					name:    "unknown aggregations and groupBys values are set to empty",
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
					err := subject.WriteCSV(w, tc.columns, 0)
					require.NoError(t, err)

					require.Equal(t, tc.expected, w.String())
				})
			}
		})

		t.Run("limit rows", func(t *testing.T) {
			subject := QueryResponse{
				Documents: []QueryResponseDocument{
					{"col1": "val1"},
					{"col1": "val2"},
					{"col1": "val3"},
				},
			}

			w := &bytes.Buffer{}
			err := subject.WriteCSV(w, []string{"col1"}, 2)
			require.NoError(t, err)

			require.Equal(t, "col1\nval1\nval2\n", w.String())
		})

		t.Run("limit rows with groups", func(t *testing.T) {
			subject := QueryResponse{
				GroupValues: []QueryResponseGroupValue{
					{Key: "g1", NestedValues: []QueryResponseGroupValue{
						{Key: "g1-1", Aggregations: QueryResponseAggregations{"agg": QueryResponseValueAsString{AsString: "1"}}},
						{Key: "g1-2", Aggregations: QueryResponseAggregations{"agg": QueryResponseValueAsString{AsString: "2"}}},
					}},
					{Key: "g2", NestedValues: []QueryResponseGroupValue{
						{Key: "g2-1", Aggregations: QueryResponseAggregations{"agg": QueryResponseValueAsString{AsString: "3"}}},
					}},
				},
			}

			w := &bytes.Buffer{}
			err := subject.WriteCSV(w, []string{"groupBys(0)", "groupBys(1)", "aggregations(agg)"}, 2)
			require.NoError(t, err)

			require.Equal(t, "groupBys(0),groupBys(1),aggregations(agg)\ng1,g1-1,1\ng1,g1-2,2\n", w.String())
		})
	})
}
