package linseed

import (
	"testing"

	"github.com/olivere/elastic/v7"
	"github.com/stretchr/testify/require"

	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/groups"
)

func TestGroupAggregation(t *testing.T) {
	groupTime := groups.NewGroupTime("field1", "PT15M", 0)
	groupDiscrete := groups.NewGroupDiscrete("field1", 10)

	t.Run("unknown group type", func(t *testing.T) {
		_, err := newGroupAggregation(0, groups.Groups{fakeGroup{Group: groupDiscrete}}, 0)
		require.ErrorContains(t, err, "unknown group type 'fake-group'")
	})

	t.Run("empty groups", func(t *testing.T) {
		_, err := newGroupAggregation(0, groups.Groups{}, 0)
		require.ErrorContains(t, err, "unexpected empty query group list")
	})

	t.Run("time group", func(t *testing.T) {
		groupTime2 := groups.NewGroupTime("field2", "PT15M", 0)

		testCases := []struct {
			name          string
			groups        groups.Groups
			expectSuccess bool
		}{
			{
				name:          "is allowed as first group",
				groups:        groups.Groups{groupTime},
				expectSuccess: true,
			},
			{
				name:          "is allowed as first group for discrete subgroup",
				groups:        groups.Groups{groupTime, groupDiscrete},
				expectSuccess: true,
			},
			{
				name:          "is not allowed past time group",
				groups:        groups.Groups{groupTime2, groupTime},
				expectSuccess: false,
			},
			{
				name:          "is not allowed past discrete groups",
				groups:        groups.Groups{groupDiscrete, groupTime},
				expectSuccess: false,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := queryGroupsToElastic(tc.groups, nil, 0)
				if tc.expectSuccess {
					require.NoError(t, err)
				} else {
					require.ErrorContains(t, err, "unexpected time groupBy for field field1")
				}
			})
		}
	})

	t.Run("discrete group", func(t *testing.T) {
		t.Run("single group is converted into a terms aggregation", func(t *testing.T) {
			elasticGroups, err := queryGroupsToElastic(groups.Groups{groupDiscrete}, nil, 0)
			require.NoError(t, err)
			require.Len(t, elasticGroups, 1)

			require.IsType(t, &elastic.TermsAggregation{}, elasticGroups[0].elasticAggregation)
		})

		t.Run("multiple groups are converted into a multi terms aggregation", func(t *testing.T) {
			groupDiscrete2 := groups.NewGroupDiscrete("field2", 10)
			elasticGroups, err := queryGroupsToElastic(groups.Groups{groupDiscrete, groupDiscrete2}, nil, 0)
			require.NoError(t, err)
			require.Len(t, elasticGroups, 1)

			require.IsType(t, &elastic.MultiTermsAggregation{}, elasticGroups[0].elasticAggregation)
		})
	})

	t.Run("bucket item mapping", func(t *testing.T) {
		t.Run("terms buckets", func(t *testing.T) {
			testCases := []struct {
				name       string
				bucketItem *elastic.AggregationBucketKeyItem
				expected   aggregationBucketItem
			}{
				{
					name: "with key set",
					bucketItem: &elastic.AggregationBucketKeyItem{
						Key: "key1",
					},
					expected: aggregationBucketItem{
						keys: []string{"key1"},
					},
				},
				{
					name: "with key_number set",
					bucketItem: &elastic.AggregationBucketKeyItem{
						KeyNumber: "1234",
					},
					expected: aggregationBucketItem{
						keys: []string{"1234"},
					},
				},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					aggItem := mapAggregationBucketKeyItem(tc.bucketItem)

					require.Equal(t, tc.expected, aggItem)
				})
			}
		})

		t.Run("multi terms buckets", func(t *testing.T) {
			aggItem := mapAggregationBucketMultiKeyItems(&elastic.AggregationBucketMultiKeyItem{
				Key: []any{"key1", float64(1234)},
			})

			require.Equal(t, aggregationBucketItem{
				keys: []string{"key1", "1234"},
			}, aggItem)
		})

		t.Run("date histogram buckets", func(t *testing.T) {

			keyAsString := "1234"
			testCases := []struct {
				name       string
				bucketItem *elastic.AggregationBucketHistogramItem
				expected   aggregationBucketItem
			}{
				{
					name: "with key set",
					bucketItem: &elastic.AggregationBucketHistogramItem{
						Key: 1234,
					},
					expected: aggregationBucketItem{
						keys: []string{"1234"},
					},
				},
				{
					name: "with key_ss_string set",
					bucketItem: &elastic.AggregationBucketHistogramItem{
						KeyAsString: &keyAsString,
					},
					expected: aggregationBucketItem{
						keys: []string{"1234"},
					},
				},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					aggItem := mapAggregationBucketHistogramItem(tc.bucketItem)

					require.Equal(t, tc.expected, aggItem)
				})
			}
		})
	})
}
