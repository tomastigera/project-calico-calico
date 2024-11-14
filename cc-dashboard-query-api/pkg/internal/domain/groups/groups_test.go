package groups

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/aggregations"
)

func TestGroups(t *testing.T) {

	t.Run("append group values", func(t *testing.T) {
		g := &GroupValue{Key: "g"}
		g1 := &GroupValue{Key: "g1"}
		g2 := &GroupValue{Key: "g2"}

		g.AppendGroupValue(g1)
		g.AppendGroupValue(g2)

		require.Equal(t, g, &GroupValue{
			Key:            "g",
			SubGroupValues: []*GroupValue{{Key: "g1"}, {Key: "g2"}},
		})
	})

	t.Run("calculate calls it for all objects", func(t *testing.T) {
		v1, v2, v3 := int64(10), int64(23), int64(34)

		agg1 := aggregations.NewAggregationValue(&v1, aggregations.NewAggregationCount())
		agg1.Append(aggregations.NewAggregationValue(&v2, aggregations.NewAggregationCount()))
		agg2 := aggregations.NewAggregationValue(&v1, aggregations.NewAggregationCount())
		agg2.Append(aggregations.NewAggregationValue(&v3, aggregations.NewAggregationCount()))
		agg3 := aggregations.NewAggregationValue(&v2, aggregations.NewAggregationCount())
		agg3.Append(aggregations.NewAggregationValue(&v3, aggregations.NewAggregationCount()))

		expectedv1 := int64(33)
		expectedAggregationValue1 := aggregations.NewAggregationValue(&expectedv1, nil)
		expectedv2 := int64(44)
		expectedAggregationValue2 := aggregations.NewAggregationValue(&expectedv2, nil)
		expectedv3 := int64(57)
		expectedAggregationValue3 := aggregations.NewAggregationValue(&expectedv3, nil)

		g := GroupValues{
			&GroupValue{
				Key:      "g1",
				DocCount: 123,
				Aggregations: aggregations.AggregationValues{
					"agg1": agg1,
					"agg2": agg2,
				},
				SubGroupValues: []*GroupValue{{
					Key:      "g1",
					DocCount: 100,
					Aggregations: aggregations.AggregationValues{
						"agg3": agg3,
					},
				}},
			},
			&GroupValue{
				Key:      "g2",
				DocCount: 456,
			},
		}

		require.NoError(t, g.Calculate())
		require.Equal(t, GroupValues{
			&GroupValue{
				Key:      "g1",
				DocCount: 123,
				Aggregations: aggregations.AggregationValues{
					"agg1": expectedAggregationValue1,
					"agg2": expectedAggregationValue2,
				},
				SubGroupValues: []*GroupValue{{
					Key:      "g1",
					DocCount: 100,
					Aggregations: aggregations.AggregationValues{
						"agg3": expectedAggregationValue3,
					},
				}},
			},
			&GroupValue{
				Key:      "g2",
				DocCount: 456,
			},
		}, g)
	})
}
