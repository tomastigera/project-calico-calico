package linseed

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/stretchr/testify/require"

	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/aggregations"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/groups"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/query/result"
)

type fakeGroup struct {
	groups.Group
}

func (c fakeGroup) Type() groups.GroupType {
	return "fake-group"
}

func TestLinseedGroups(t *testing.T) {

	groupSortOrder := groups.GroupSortOrder{Type: groups.GroupSortOrderTypeSelf}

	groupTime := groups.NewGroupTime("field1", "PT15M", 0, groupSortOrder)
	groupDiscrete := groups.NewGroupDiscrete("field1", 10, groupSortOrder)

	t.Run("from domain to elastic", func(t *testing.T) {
		t.Run("query group to elastic aggregation", func(t *testing.T) {
			t.Run("time group interval adjustment for result count limit", func(t *testing.T) {
				groupTime2 := groups.NewGroupTime("field1", "PT1M", 0, groupSortOrder)
				elasticGroups, err := queryGroupsToElastic(groups.Groups{groupTime2}, nil, time.Hour*200)
				require.NoError(t, err)
				require.Len(t, elasticGroups, 1)
				require.Equal(t, elastic.
					NewDateHistogramAggregation().
					Field("field1").
					FixedInterval("120m").
					OrderByKey(false), elasticGroups[0].elasticAggregation)

				groupTime2 = groups.NewGroupTime("field1", "PT1M", 0, groupSortOrder)
				elasticGroups, err = queryGroupsToElastic(groups.Groups{groupTime2}, nil, time.Hour)
				require.NoError(t, err)
				require.Len(t, elasticGroups, 1)
				require.Equal(t, elastic.
					NewDateHistogramAggregation().
					Field("field1").
					FixedInterval("1m").
					OrderByKey(false), elasticGroups[0].elasticAggregation)
			})

			t.Run("time group order", func(t *testing.T) {
				t.Run("unknown type", func(t *testing.T) {
					groupTime2 := groups.NewGroupTime("field1", "PT15M", 0, groups.GroupSortOrder{Type: "unknown"})
					_, err := queryGroupsToElastic(groups.Groups{groupTime2}, nil, time.Hour)
					require.ErrorContains(t, err, "unknown sort order 'unknown' for time group 'field1'")
				})
				t.Run("desc", func(t *testing.T) {
					groupTime2 := groups.NewGroupTime("field1", "PT15M", 0, groupSortOrder)
					elasticGroups, err := queryGroupsToElastic(groups.Groups{groupTime2}, nil, time.Hour)
					require.NoError(t, err)
					require.Len(t, elasticGroups, 1)
					require.Equal(t, elastic.
						NewDateHistogramAggregation().
						Field("field1").
						FixedInterval("15m").
						OrderByKey(false), elasticGroups[0].elasticAggregation)
				})
				t.Run("asc", func(t *testing.T) {
					groupTime2 := groups.NewGroupTime("field1", "PT15M", 0, groups.GroupSortOrder{Type: groups.GroupSortOrderTypeSelf, Asc: true})
					elasticGroups, err := queryGroupsToElastic(groups.Groups{groupTime2}, nil, time.Hour)
					require.NoError(t, err)
					require.Len(t, elasticGroups, 1)
					require.Equal(t, elastic.
						NewDateHistogramAggregation().
						Field("field1").
						FixedInterval("15m").
						OrderByKey(true), elasticGroups[0].elasticAggregation)
				})
			})

			t.Run("with no subaggregations", func(t *testing.T) {

				expectedGroupTimeElasticAggregation := elastic.
					NewDateHistogramAggregation().
					Field("field1").
					FixedInterval("15m").
					OrderByKey(false)

				expectedGroupDiscreteElasticAggregation := elastic.
					NewTermsAggregation().
					Field("field1").
					Size(10).
					OrderByKey(false)

				elasticGroups, err := queryGroupsToElastic(groups.Groups{groupTime}, nil, 0)
				require.NoError(t, err)
				require.Len(t, elasticGroups, 1)
				require.Equal(t, expectedGroupTimeElasticAggregation, elasticGroups[0].elasticAggregation)

				elasticGroups, err = queryGroupsToElastic(groups.Groups{groupDiscrete}, nil, 0)
				require.NoError(t, err)
				require.Len(t, elasticGroups, 1)
				require.Equal(t, expectedGroupDiscreteElasticAggregation, elasticGroups[0].elasticAggregation)
			})

			t.Run("with subaggregations", func(t *testing.T) {
				elasticAggregations := map[string]elastic.Aggregation{
					"a1": elastic.NewTermsAggregation().Field("t1"),
					"a2": elastic.NewSumAggregation().Field("s1"),
					"a3": elastic.NewAvgAggregation().Field("avg1"),
				}

				expectedGroupTimeElasticAggregation := elastic.
					NewDateHistogramAggregation().
					Field("field1").
					FixedInterval("15m").
					OrderByKey(false).
					SubAggregation("a1", elastic.NewTermsAggregation().Field("t1")).
					SubAggregation("a2", elastic.NewSumAggregation().Field("s1")).
					SubAggregation("a3", elastic.NewAvgAggregation().Field("avg1"))

				expectedGroupDiscreteElasticAggregation := elastic.
					NewTermsAggregation().
					Field("field1").
					Size(10).
					OrderByKey(false).
					SubAggregation("a1", elastic.NewTermsAggregation().Field("t1")).
					SubAggregation("a2", elastic.NewSumAggregation().Field("s1")).
					SubAggregation("a3", elastic.NewAvgAggregation().Field("avg1"))

				elasticGroups, err := queryGroupsToElastic(groups.Groups{groupTime}, elasticAggregations, 0)
				require.NoError(t, err)
				require.Len(t, elasticGroups, 1)
				require.Equal(t, expectedGroupTimeElasticAggregation, elasticGroups[0].elasticAggregation)

				elasticGroups, err = queryGroupsToElastic(groups.Groups{groupDiscrete}, elasticAggregations, 0)
				require.NoError(t, err)
				require.Len(t, elasticGroups, 1)
				require.Equal(t, expectedGroupDiscreteElasticAggregation, elasticGroups[0].elasticAggregation)
			})

			t.Run("with minimum time interval", func(t *testing.T) {
				expectedElasticAggregation := elastic.
					NewDateHistogramAggregation().
					Field("field1").
					FixedInterval("1m").
					OrderByKey(false)

				queryGroups := groups.Groups{
					groups.NewGroupTime("field1", "1s", 10, groupSortOrder),
				}

				elasticGroups, err := queryGroupsToElastic(queryGroups, nil, 0)
				require.NoError(t, err)
				require.Len(t, elasticGroups, 1)
				require.Equal(t, expectedElasticAggregation, elasticGroups[0].elasticAggregation)
			})
		})
	})

	t.Run("elastic result to domain", func(t *testing.T) {
		t.Run("group values from elastic", func(t *testing.T) {
			t.Run("unknown group type", func(t *testing.T) {
				_, err := queryGroupsToElastic(groups.Groups{fakeGroup{Group: groupDiscrete}}, nil, 0)
				require.ErrorContains(t, err, "unexpected fake-group groupBy for field field1")
			})

			t.Run("aggregation not found", func(t *testing.T) {
				elasticGroups, err := queryGroupsToElastic(groups.Groups{groupDiscrete}, nil, 0)
				require.NoError(t, err)
				require.Len(t, elasticGroups, 1)

				var res result.QueryResult
				err = elasticGroups.fromElastic(0, nil, nil, &res)
				require.NoError(t, err)
				require.Nil(t, res.GroupValues)
				require.Nil(t, res.Aggregations)
			})

			t.Run("aggregation found", func(t *testing.T) {
				elasticResult := elastic.Aggregations{
					"g0": json.RawMessage(`{"buckets": [{"key":"test-123","doc_count":99},{"key":"test-456","doc_count":11}]}`),
				}

				elasticGroups, err := queryGroupsToElastic(groups.Groups{groupDiscrete}, nil, 0)
				require.NoError(t, err)
				require.Len(t, elasticGroups, 1)

				var res result.QueryResult
				err = elasticGroups.fromElastic(0, elasticResult, nil, &res)
				require.NoError(t, err)

				require.NoError(t, err)
				require.NotNil(t, res.GroupValues)
				require.Len(t, res.GroupValues, 2)
				require.Equal(t, "test-123", res.GroupValues[0].Key)
				require.Equal(t, "test-456", res.GroupValues[1].Key)
				require.Equal(t, int64(99), res.GroupValues[0].DocCount)
				require.Equal(t, int64(11), res.GroupValues[1].DocCount)
			})

			t.Run("from discrete group", func(t *testing.T) {
				elasticResult := elastic.Aggregations{
					"g0": json.RawMessage(`{"buckets": [{"key": 1734382560000, "doc_count": 315, "a_#flows": {"value": 4616.0 } }, {"key": 1734382680000, "doc_count": 626, "a_#flows": {"value": 10121.0 } } ] }`),
				}

				elasticGroups, err := queryGroupsToElastic(groups.Groups{groupDiscrete}, nil, 0)
				require.NoError(t, err)
				require.Len(t, elasticGroups, 1)

				var res result.QueryResult
				err = elasticGroups.fromElastic(0, elasticResult, nil, &res)
				require.NoError(t, err)
				require.Len(t, res.GroupValues, 2)
				require.Equal(t, "1734382560000", res.GroupValues[0].Key)
				require.Equal(t, "1734382680000", res.GroupValues[1].Key)
			})

			t.Run("from multiple discrete group", func(t *testing.T) {
				elasticResult := elastic.Aggregations{
					"g0-1": jsonMarshal(t, map[string]any{
						"buckets": []map[string]any{
							{"key": []string{"g0-value1", "g1-value1"}, "doc_count": 11},
							{"key": []string{"g0-value2", "g1-value2"}, "doc_count": 22},
						},
					}),
				}

				groupDiscrete2 := groups.NewGroupDiscrete("field2", 10, groupSortOrder)

				elasticGroups, err := queryGroupsToElastic(groups.Groups{groupDiscrete, groupDiscrete2}, nil, 0)
				require.NoError(t, err)
				require.Len(t, elasticGroups, 1)

				var res result.QueryResult
				err = elasticGroups.fromElastic(0, elasticResult, nil, &res)
				require.NoError(t, err)

				require.Equal(t, groups.GroupValues{
					&groups.GroupValue{
						Key:          "g0-value1",
						DocCount:     11,
						Aggregations: aggregations.AggregationValues{},
						SubGroupValues: groups.GroupValues{
							&groups.GroupValue{
								Key:          "g1-value1",
								DocCount:     11,
								Aggregations: aggregations.AggregationValues{},
							},
						},
					},
					&groups.GroupValue{
						Key:          "g0-value2",
						DocCount:     22,
						Aggregations: aggregations.AggregationValues{},
						SubGroupValues: groups.GroupValues{
							&groups.GroupValue{
								Key:          "g1-value2",
								DocCount:     22,
								Aggregations: aggregations.AggregationValues{},
							},
						},
					},
				}, res.GroupValues)
			})

			t.Run("from time group", func(t *testing.T) {
				elasticResult := elastic.Aggregations{
					"g0": json.RawMessage(`{"buckets": [{"key": 1734382560000, "doc_count": 315, "a_#flows": {"value": 4616.0 } }, {"key": 1734382680000, "doc_count": 626, "a_#flows": {"value": 10121.0 } } ] }`),
				}

				elasticGroups, err := queryGroupsToElastic(groups.Groups{groupDiscrete}, nil, 0)
				require.NoError(t, err)
				require.Len(t, elasticGroups, 1)

				var res result.QueryResult
				err = elasticGroups.fromElastic(0, elasticResult, nil, &res)
				require.NoError(t, err)

				require.Len(t, res.GroupValues, 2)
				require.Equal(t, "1734382560000", res.GroupValues[0].Key)
				require.Equal(t, "1734382680000", res.GroupValues[1].Key)
			})
		})

		t.Run("query groups from elastic", func(t *testing.T) {
			queryRequestAggregations := aggregations.Aggregations{
				"count": aggregations.NewAggregationCount(),
			}
			elasticResult := elastic.Aggregations{
				"g0": jsonMarshal(t, map[string]any{
					"buckets": []map[string]any{
						{
							"key":       float64(1),
							"doc_count": 11,
							"g1": map[string]any{
								"buckets": []map[string]any{
									{"key": "g1-value1", "doc_count": 111},
								},
							},
						},
						{
							"key":       float64(2),
							"doc_count": 22,
							"g1": map[string]any{
								"buckets": []map[string]any{
									{"key": "g1-value2", "doc_count": 222},
								},
							},
						},
					},
				}),
			}

			elasticGroups, err := queryGroupsToElastic(groups.Groups{groupTime, groupDiscrete}, nil, 0)
			require.NoError(t, err)
			require.Len(t, elasticGroups, 2)

			var res result.QueryResult
			err = elasticGroups.fromElastic(0, elasticResult, queryRequestAggregations, &res)
			require.NoError(t, err)

			require.Equal(t, groups.GroupValues{
				&groups.GroupValue{
					Key:          "1",
					DocCount:     11,
					Aggregations: aggregations.AggregationValues{},
					SubGroupValues: groups.GroupValues{
						&groups.GroupValue{
							Key:      "g1-value1",
							DocCount: 111,
							Aggregations: aggregations.AggregationValues{
								"count": aggregations.NewAggregationValue[int64](intp(111)),
							},
						},
					},
				},
				&groups.GroupValue{
					Key:          "2",
					DocCount:     22,
					Aggregations: aggregations.AggregationValues{},
					SubGroupValues: groups.GroupValues{
						&groups.GroupValue{
							Key:      "g1-value2",
							DocCount: 222,
							Aggregations: aggregations.AggregationValues{
								"count": aggregations.NewAggregationValue[int64](intp(222)),
							},
						},
					},
				},
			}, res.GroupValues)
		})
	})
}

func jsonMarshal(t *testing.T, object any) json.RawMessage {
	t.Helper()

	jsonBytes, err := json.Marshal(object)
	require.NoError(t, err)

	return jsonBytes
}
