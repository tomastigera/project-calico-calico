package linseed

import (
	"fmt"
	"strings"

	"github.com/olivere/elastic/v7"

	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/aggregations"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/groups"
)

type subAggregation struct {
	key         string
	aggregation elastic.Aggregation
}

type aggregationBucketItem struct {
	err          error
	key          string
	docCount     int64
	aggregations elastic.Aggregations
}

func errUnknownGroupType(groupType groups.GroupType) error {
	return fmt.Errorf("unknown group type '%s'", groupType)
}

func queryGroupToElasticAggregation(queryGroup groups.Group, elasticAggregations map[string]elastic.Aggregation, subGroupAggregation *subAggregation) (elastic.Aggregation, error) {

	groupType := queryGroup.Type()
	switch groupType {
	case groups.GroupTypeDiscrete:
		termsAggregation := elastic.NewTermsAggregation().
			Field(queryGroup.FieldName()).
			Size(queryGroup.MaxValues())

		// TODO: sorting

		if subGroupAggregation != nil {
			termsAggregation.SubAggregation(subGroupAggregation.key, subGroupAggregation.aggregation)
		}

		for aggKey, agg := range elasticAggregations {
			termsAggregation.SubAggregation(aggKey, agg)
		}

		return termsAggregation, nil
	case groups.GroupTypeTime:
		interval := strings.ToLower(strings.Replace(queryGroup.Interval(), "PT", "", -1))
		dateTimeHistogramAggregation := elastic.NewDateHistogramAggregation().
			Field(queryGroup.FieldName()).
			FixedInterval(interval)

		if subGroupAggregation != nil {
			dateTimeHistogramAggregation.SubAggregation(subGroupAggregation.key, subGroupAggregation.aggregation)
		}

		for aggKey, agg := range elasticAggregations {
			dateTimeHistogramAggregation.SubAggregation(aggKey, agg)
		}

		return dateTimeHistogramAggregation, nil
	}

	return nil, errUnknownGroupType(queryGroup.Type())
}

func queryGroupsToElastic(groupIndex int, queryGroups groups.Groups, groupAggregations aggregations.Aggregations) (elastic.Aggregation, error) {
	var subGroupAggregation *subAggregation

	if len(queryGroups) > 1 {
		var err error
		subGroupAggregation = &subAggregation{
			key: fmt.Sprintf("g%d", groupIndex+1),
		}
		subGroupAggregation.aggregation, err = queryGroupsToElastic(groupIndex+1, queryGroups[1:], groupAggregations)
		if err != nil {
			return nil, err
		}
	}

	elasticAggregations := make(map[string]elastic.Aggregation)
	for aggName, agg := range groupAggregations {
		elasticAggregation, err := queryAggregationToElastic(agg)
		if err != nil {
			return nil, err
		}

		if elasticAggregation != nil {
			elasticAggregations["a_"+string(aggName)] = elasticAggregation
		}
	}

	return queryGroupToElasticAggregation(queryGroups[0], elasticAggregations, subGroupAggregation)
}

// queryGroupsFromElastic Iterate queryRequestGroups and recursively store bucket aggregations and group aggregations
// into groups.GroupValue appended to appendableGroupValue
func queryGroupsFromElastic(groupIndex int, queryRequestGroups groups.Groups, queryRequestAggregations aggregations.Aggregations, resultAggregations elastic.Aggregations, appendableGroupValue groups.AppendableGroupValue) error {

	// Get the aggregation item buckets for the current group
	aggregationItemBuckets, err := groupBucketsFromElastic(
		fmt.Sprintf("g%d", groupIndex), // A group aggregation is identified by "g" + groupIndex
		queryRequestGroups[groupIndex],
		resultAggregations,
	)
	if err != nil {
		return err
	}

	for _, bucketItem := range aggregationItemBuckets {
		if bucketItem.err != nil {
			return bucketItem.err
		}

		// Each bucket item is stored in a groups.GroupValue
		groupValue := &groups.GroupValue{
			Key:          bucketItem.key,
			DocCount:     bucketItem.docCount,
			Aggregations: make(aggregations.AggregationValues),
		}

		for aggKey, agg := range queryRequestAggregations {
			// Transform aggregations and store the results in groupValue.Aggregations
			err := elasticAggregationToQueryResult(string(aggKey), agg, bucketItem.docCount, groupValue.Aggregations, bucketItem.aggregations)
			if err != nil {
				return err
			}
		}

		if groupIndex+1 < len(queryRequestGroups) {

			/* Each bucket item will have group sub-aggregations for the group following the current group, and each of
			 * these following group sub-aggregations will have their own aggregations and group sub-aggregations.
			 *
			 * Call queryGroupsFromElastic for the next group with appendableGroupValue set to the current
			 * groups.groupValue, so the following group sub-aggregations bucket items will be stored into
			 * groupValue.SubGroupValues
			 *
			 * Note: for the group at groupIndex 0, appendableGroupValue will be a QueryResult struct instead of a
			 * groups.GroupValue struct
			 */

			if err := queryGroupsFromElastic(
				groupIndex+1,
				queryRequestGroups,
				queryRequestAggregations,
				bucketItem.aggregations,
				groupValue, // Store subgroup aggregations in the groupValue.SubGroupValues field
			); err != nil {
				return err
			}
		}

		// Append the current groupValue to either
		// - The QueryResult (if this is the group at groupIndex == 0)
		// - The current group's parent group GroupValue (for groups at groupIndex > 0)
		appendableGroupValue.AppendGroupValue(groupValue)
	}

	return nil
}

func groupBucketsFromElastic(elasticGroupKey string, queryGroup groups.Group, resultAggregations elastic.Aggregations) ([]aggregationBucketItem, error) {

	var aggregationBucketItems []aggregationBucketItem
	switch queryGroup.Type() {
	case groups.GroupTypeDiscrete:
		aggBucketKeyItems, found := resultAggregations.Terms(elasticGroupKey)
		if !found {
			return nil, nil
		}

		for _, elasticBucketItem := range aggBucketKeyItems.Buckets {
			bucketItem := aggregationBucketItem{
				docCount:     elasticBucketItem.DocCount,
				aggregations: elasticBucketItem.Aggregations,
			}
			key, ok := elasticBucketItem.Key.(string)
			if !ok {
				key = elasticBucketItem.KeyNumber.String()
				if key == "" {
					bucketItem.err = fmt.Errorf("unable to get group %s aggregation bucket key", elasticGroupKey)
				}
			}
			bucketItem.key = key
			aggregationBucketItems = append(aggregationBucketItems, bucketItem)
		}
		return aggregationBucketItems, nil
	case groups.GroupTypeTime:
		aggBucketKeyItems, found := resultAggregations.DateHistogram(elasticGroupKey)
		if !found {
			return nil, nil
		}

		for _, elasticBucketItem := range aggBucketKeyItems.Buckets {
			bucketItem := aggregationBucketItem{
				docCount:     elasticBucketItem.DocCount,
				aggregations: elasticBucketItem.Aggregations,
			}

			if elasticBucketItem.KeyAsString == nil {
				bucketItem.err = fmt.Errorf("unable to get group %s aggregation bucket key", elasticGroupKey)
			} else {
				bucketItem.key = *elasticBucketItem.KeyAsString
			}
			aggregationBucketItems = append(aggregationBucketItems, bucketItem)
		}
		return aggregationBucketItems, nil
	}
	return nil, errUnknownGroupType(queryGroup.Type())
}
