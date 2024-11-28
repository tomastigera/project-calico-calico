package linseed

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/stretchr/testify/require"

	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/aggregations"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/groups"
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

			t.Run("unknown group type", func(t *testing.T) {
				_, err := queryGroupToElasticAggregation(fakeGroup{Group: groupDiscrete}, nil, nil, 0)
				require.ErrorContains(t, err, "unknown group type 'fake-group'")
			})

			t.Run("time group interval adjustment for result count limit", func(t *testing.T) {
				groupTime2 := groups.NewGroupTime("field1", "PT1M", 0, groupSortOrder)
				aggregation, err := queryGroupToElasticAggregation(groupTime2, nil, nil, time.Hour*200)
				require.NoError(t, err)
				require.Equal(t, elastic.
					NewDateHistogramAggregation().
					Field("field1").
					FixedInterval("7200s").
					OrderByKey(false), aggregation)

				groupTime2 = groups.NewGroupTime("field1", "PT1M", 0, groupSortOrder)
				aggregation, err = queryGroupToElasticAggregation(groupTime2, nil, nil, time.Hour)
				require.NoError(t, err)
				require.Equal(t, elastic.
					NewDateHistogramAggregation().
					Field("field1").
					FixedInterval("1m").
					OrderByKey(false), aggregation)
			})

			t.Run("time group order", func(t *testing.T) {
				t.Run("unknown type", func(t *testing.T) {
					groupTime2 := groups.NewGroupTime("field1", "PT15M", 0, groups.GroupSortOrder{Type: "unknown"})
					_, err := queryGroupToElasticAggregation(groupTime2, nil, nil, time.Hour)
					require.ErrorContains(t, err, "unknown sort order 'unknown' for time group 'field1'")
				})
				t.Run("desc", func(t *testing.T) {
					groupTime2 := groups.NewGroupTime("field1", "PT15M", 0, groupSortOrder)
					aggregation, err := queryGroupToElasticAggregation(groupTime2, nil, nil, time.Hour)
					require.NoError(t, err)
					require.Equal(t, elastic.
						NewDateHistogramAggregation().
						Field("field1").
						FixedInterval("15m").
						OrderByKey(false), aggregation)
				})
				t.Run("asc", func(t *testing.T) {
					groupTime2 := groups.NewGroupTime("field1", "PT15M", 0, groups.GroupSortOrder{Type: groups.GroupSortOrderTypeSelf, Asc: true})
					aggregation, err := queryGroupToElasticAggregation(groupTime2, nil, nil, time.Hour)
					require.NoError(t, err)
					require.Equal(t, elastic.
						NewDateHistogramAggregation().
						Field("field1").
						FixedInterval("15m").
						OrderByKey(true), aggregation)
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

				aggregation, err := queryGroupToElasticAggregation(groupTime, nil, nil, 0)
				require.NoError(t, err)
				require.Equal(t, expectedGroupTimeElasticAggregation, aggregation)

				aggregation, err = queryGroupToElasticAggregation(groupDiscrete, nil, nil, 0)
				require.NoError(t, err)
				require.Equal(t, expectedGroupDiscreteElasticAggregation, aggregation)
			})

			t.Run("with subaggregations", func(t *testing.T) {
				elasticAggregations := map[string]elastic.Aggregation{
					"a1": elastic.NewTermsAggregation().Field("t1"),
					"a2": elastic.NewSumAggregation().Field("s1"),
				}
				subGroupAggregation := &subAggregation{key: "sg1", aggregation: elastic.NewAvgAggregation().Field("avg1")}

				expectedGroupTimeElasticAggregation := elastic.
					NewDateHistogramAggregation().
					Field("field1").
					FixedInterval("15m").
					OrderByKey(false).
					SubAggregation("a1", elastic.NewTermsAggregation().Field("t1")).
					SubAggregation("a2", elastic.NewSumAggregation().Field("s1")).
					SubAggregation("sg1", elastic.NewAvgAggregation().Field("avg1"))

				expectedGroupDiscreteElasticAggregation := elastic.
					NewTermsAggregation().
					Field("field1").
					Size(10).
					OrderByKey(false).
					SubAggregation("a1", elastic.NewTermsAggregation().Field("t1")).
					SubAggregation("a2", elastic.NewSumAggregation().Field("s1")).
					SubAggregation("sg1", elastic.NewAvgAggregation().Field("avg1"))

				elasticAggregation, err := queryGroupToElasticAggregation(groupTime, elasticAggregations, subGroupAggregation, 0)
				require.NoError(t, err)
				require.Equal(t, expectedGroupTimeElasticAggregation, elasticAggregation)

				elasticAggregation, err = queryGroupToElasticAggregation(groupDiscrete, elasticAggregations, subGroupAggregation, 0)
				require.NoError(t, err)
				require.Equal(t, expectedGroupDiscreteElasticAggregation, elasticAggregation)
			})
		})

		t.Run("query group to elastic", func(t *testing.T) {
			queryGroups := groups.Groups{
				groups.NewGroupDiscrete("field1", 10, groupSortOrder),
			}

			t.Run("with no subaggregations", func(t *testing.T) {
				expectedElasticAggregation := elastic.
					NewTermsAggregation().
					Field("field1").
					Size(10).
					OrderByKey(false)

				elasticAggregation, err := queryGroupsToElastic(0, queryGroups, nil, 0)
				require.NoError(t, err)
				require.Equal(t, expectedElasticAggregation, elasticAggregation)
			})

			t.Run("with subaggregations", func(t *testing.T) {
				expectedElasticAggregation := elastic.
					NewTermsAggregation().
					Field("field1").
					Size(10).
					OrderByKey(false).
					// Note: NewAggregationCount() does not generate an elastic aggregation since it relies on the docCount
					SubAggregation("a_a2", elastic.NewSumAggregation().Field("f1")).
					SubAggregation("a_a3", elastic.NewPercentilesAggregation().Field("f2").Percentiles(95))

				domainAggregations := aggregations.Aggregations{
					"a1": aggregations.NewAggregationCount(),
					"a2": aggregations.NewAggregationSum("f1"),
					"a3": aggregations.NewAggregationPercentile("f2", 95),
				}

				elasticAggregation, err := queryGroupsToElastic(0, queryGroups, domainAggregations, 0)
				require.NoError(t, err)
				require.Equal(t, expectedElasticAggregation, elasticAggregation)
			})
		})
	})

	t.Run("elastic result to domain", func(t *testing.T) {
		t.Run("group buckets from elastic", func(t *testing.T) {
			t.Run("unknown group type", func(t *testing.T) {
				_, err := groupBucketsFromElastic("", fakeGroup{Group: groupDiscrete}, nil)
				require.ErrorContains(t, err, "unknown group type 'fake-group'")
			})

			t.Run("aggregation not found", func(t *testing.T) {
				aggregationBucketItems, err := groupBucketsFromElastic("", groupDiscrete, nil)
				require.NoError(t, err)
				require.Nil(t, aggregationBucketItems)
			})

			t.Run("aggregation found", func(t *testing.T) {
				elasticResult := elastic.Aggregations{
					"g0": json.RawMessage(`{"buckets": [{"key":"test-123","doc_count":99},{"key":"test-456","doc_count":11}]}`),
				}
				aggregationBucketItems, err := groupBucketsFromElastic("g0", groupDiscrete, elasticResult)
				require.NoError(t, err)
				require.NotNil(t, aggregationBucketItems)

				var resultBucketItems []aggregationBucketItem
				for _, bucketItem := range aggregationBucketItems {
					resultBucketItems = append(resultBucketItems, bucketItem)
				}

				require.Len(t, resultBucketItems, 2)
				require.Equal(t, "test-123", resultBucketItems[0].key)
				require.Equal(t, "test-456", resultBucketItems[1].key)
				require.Equal(t, int64(99), resultBucketItems[0].docCount)
				require.Equal(t, int64(11), resultBucketItems[1].docCount)
			})
		})

		t.Run("query groups from elastic", func(t *testing.T) {
			queryRequestAggregations := aggregations.Aggregations{
				"count": aggregations.NewAggregationCount(),
			}
			elasticResult := elastic.Aggregations{
				"g0": json.RawMessage(`{"buckets": [{"key":"test-123","doc_count":99},{"key":"test-456","doc_count":11}]}`),
			}

			groupValue := &groups.GroupValue{}

			aggValue1 := int64(99)
			aggValue2 := int64(11)
			expectedAggregationValue1 := aggregations.NewAggregationValue[int64](&aggValue1)
			expectedAggregationValue2 := aggregations.NewAggregationValue[int64](&aggValue2)

			err := queryGroupsFromElastic(0, groups.Groups{groupDiscrete, groupTime}, queryRequestAggregations, elasticResult, groupValue)
			require.NoError(t, err)

			require.Equal(t, &groups.GroupValue{
				SubGroupValues: groups.GroupValues{
					&groups.GroupValue{
						Key:      "test-123",
						DocCount: 99,
						Aggregations: aggregations.AggregationValues{
							"count": expectedAggregationValue1,
						},
					},
					&groups.GroupValue{
						Key:      "test-456",
						DocCount: 11,
						Aggregations: aggregations.AggregationValues{
							"count": expectedAggregationValue2,
						},
					},
				},
			}, groupValue)
		})
	})
}
