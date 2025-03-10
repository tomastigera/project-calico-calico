package linseed

import (
	"fmt"
	"time"

	"github.com/olivere/elastic/v7"

	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/aggregations"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/groups"
	"github.com/tigera/tds-apiserver/lib/slices"
)

type aggregation struct {
	agg                aggregations.Aggregation
	elasticAggregation elastic.Aggregation
}

type aggregationBucketItem struct {
	err          error
	keys         []string
	docCount     int64
	aggregations elastic.Aggregations
}

const (
	maxGroupTimeAggregationResults = 100
)

func (a aggregation) elasticKey() string {
	return "a_" + string(a.agg.Key())
}

// queryGroupsToElastic convert queryGroups and subAggregations into a slice of groupAggregation
func queryGroupsToElastic(
	queryGroups groups.Groups,
	subAggregations []aggregation,
	requestedInterval time.Duration,
) (groupAggregations, error) {
	if len(queryGroups) == 0 {
		return nil, fmt.Errorf("empty query group on group aggregation")
	}

	var g groupAggregations
	groupIndex := 0
	if queryGroups[0].Type() == groups.GroupTypeTime {
		group, err := newGroupAggregation(groupIndex, groups.Groups{queryGroups[groupIndex]}, requestedInterval)
		if err != nil {
			return nil, err
		}

		groupIndex++
		g = append(g, group)
	}

	nonDiscreteGroup, found := slices.Find(queryGroups[groupIndex:], func(g groups.Group) bool {
		return g.Type() != groups.GroupTypeDiscrete
	})

	if found {
		return nil, fmt.Errorf("unexpected %s groupBy for field %s", nonDiscreteGroup.Type(), nonDiscreteGroup.FieldName())
	}

	// process discrete groups
	if len(queryGroups) > groupIndex {
		elasticGroupDiscrete, err := newGroupAggregation(groupIndex, queryGroups[groupIndex:], requestedInterval)
		if err != nil {
			return nil, err
		}

		if len(g) > 0 {
			previousGroup := g[len(g)-1]
			previousGroup.subAggregation(elasticGroupDiscrete.aggregationKey, elasticGroupDiscrete.elasticAggregation)
		}

		g = append(g, elasticGroupDiscrete)
	}

	for i, group := range g {
		if i < len(g)-1 {
			group.setSortOrder(nil)
		} else {
			// set subAggregation on last group
			for _, agg := range subAggregations {
				if agg.elasticAggregation != nil {
					group.subAggregation(agg.elasticKey(), agg.elasticAggregation)
				}
			}
			group.setSortOrder(subAggregations)
		}
	}

	aggJson, err := elasticAggregationToJSON(g[0].elasticAggregation)
	if err != nil {
		return nil, err
	}
	g[0].aggJson = aggJson

	return g, nil
}

// bucketItemsToGroupValue Iterate bucketItems and recursively store bucket items into parent
func bucketItemsToGroupValue(
	g groupAggregations,
	groupIndex int,
	bucketItems []aggregationBucketItem,
	subAggregations []aggregation,
	parent groups.AppendableGroupValue,
) error {

	nextGroupIndex := groupIndex + 1
	for _, bucketItem := range bucketItems {
		if bucketItem.err != nil {
			return bucketItem.err
		}

		var firstGroupValue, parentGroupValue, lastGroupValue *groups.GroupValue
		for _, key := range bucketItem.keys { // process multi_terms keys

			// Each bucket item is stored in a groups.GroupValue
			lastGroupValue = &groups.GroupValue{
				Key:          key,
				DocCount:     bucketItem.docCount,
				Aggregations: make(aggregations.AggregationValues),
			}

			if parentGroupValue == nil {
				firstGroupValue = lastGroupValue
			} else {
				parentGroupValue.AppendGroupValue(lastGroupValue)
			}
			parentGroupValue = lastGroupValue
		}

		if lastGroupValue == nil {
			continue
		}

		// Append the current groupValue to either
		// - A QueryResult object (if this is the group at groupIndex == 0)
		// - The current group's parent GroupValue (for groups at groupIndex > 0)
		parent.AppendGroupValue(firstGroupValue)

		if len(g) == nextGroupIndex {

			for _, agg := range subAggregations {
				// Transform sub aggregations and store the results in groupValue.Aggregations
				err := elasticAggregationToQueryResult(agg, bucketItem.docCount, lastGroupValue.Aggregations, bucketItem.aggregations)
				if err != nil {
					return err
				}
			}
		} else if len(g) > nextGroupIndex {

			/* Each bucket item has group sub-aggregations for the group following the current group, and each of
			 * these following group sub-aggregations will have their own aggregations and group sub-aggregations.
			 *
			 * Call queryGroupsFromElastic for the next group with appendableGroupValue set to the current
			 * groups.groupValue, so the following group sub-aggregations bucket items will be stored into
			 * groupValue.SubGroupValues
			 *
			 * Note: for the group at groupIndex 0, appendableGroupValue will be a QueryResult struct instead of a
			 * groups.GroupValue struct
			 */

			err := g.fromElastic(
				nextGroupIndex,
				bucketItem.aggregations,
				subAggregations,
				lastGroupValue, // Store subgroup aggregations in the groupValue.SubGroupValues field
			)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
