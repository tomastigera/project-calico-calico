package linseed

import (
	"fmt"
	"strconv"
	"strings"
	"time"

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

const (
	maxGroupTimeAggregationResults = 100
)

func errUnknownGroupType(groupType groups.GroupType) error {
	return fmt.Errorf("unknown group type '%s'", groupType)
}

func queryGroupToElasticAggregation(queryGroup groups.Group, elasticAggregations map[string]elastic.Aggregation, subGroupAggregation *subAggregation, requestedPeriod time.Duration) (elastic.Aggregation, error) {

	groupType := queryGroup.Type()
	/* Phase 2: see GroupSortOrderTypeAggregation in cc-dashboard-query-api/pkg/internal/domain/groups/groups.go
	groupSortOrder := queryGroup.SortOrder()
	sortOrderAggregationKey := fmt.Sprintf("a_%s", groupSortOrder.AggregationKey)

	if groupSortOrder.Type == groups.GroupSortOrderTypeAggregation {
		if _, found := elasticAggregations[sortOrderAggregationKey]; !found {
			return nil, fmt.Errorf("invalid aggregation key '%s' in %s group %s", groupSortOrder.AggregationKey, groupType, queryGroup.FieldName())
		}
	}
	*/
	var elasticGroupAggregation elastic.Aggregation
	var appendSubAggregation func(name string, subAggregation elastic.Aggregation)
	switch groupType {
	case groups.GroupTypeDiscrete:
		termsAggregation := elastic.NewTermsAggregation().
			Field(queryGroup.FieldName()).
			Size(queryGroup.MaxValues())

		appendSubAggregation = func(name string, subAggregation elastic.Aggregation) {
			termsAggregation.SubAggregation(name, subAggregation)
		}

		switch sortOrder := queryGroup.SortOrder(); sortOrder.Type {
		case groups.GroupSortOrderTypeSelf:
			termsAggregation = termsAggregation.OrderByKey(sortOrder.Asc)
		case groups.GroupSortOrderTypeCount:
			termsAggregation = termsAggregation.OrderByCount(sortOrder.Asc)
		/* Phase 2: see GroupSortOrderTypeAggregation in cc-dashboard-query-api/pkg/internal/domain/groups/groups.go
		case groups.GroupSortOrderTypeAggregation:
			termsAggregation = termsAggregation.OrderByAggregation(fmt.Sprintf("a_%s", sortOrder.AggregationKey), sortOrder.Asc)
		*/
		default:
			return nil, fmt.Errorf("unknown sort order '%s' for %s group '%s'", sortOrder.Type, queryGroup.Type(), queryGroup.FieldName())
		}

		elasticGroupAggregation = termsAggregation
	case groups.GroupTypeTime:
		var interval time.Duration
		intervalValue := strings.ToLower(strings.Replace(queryGroup.Interval(), "PT", "", -1))
		if intervalValue != "" {
			var err error
			interval, err = time.ParseDuration(intervalValue)
			if err != nil {
				return nil, err
			}
		}

		// adjust interval to contain at most maxGroupTimeAggregationResults results
		if interval == 0 || int64(requestedPeriod/interval) > maxGroupTimeAggregationResults {
			intervalClamped := requestedPeriod / time.Duration(maxGroupTimeAggregationResults)
			if intervalClamped > interval {
				intervalValue = strconv.FormatInt(int64(intervalClamped.Seconds()), 10) + "s"
			}
		}

		dateTimeHistogramAggregation := elastic.NewDateHistogramAggregation().
			Field(queryGroup.FieldName()).
			FixedInterval(intervalValue)

		appendSubAggregation = func(name string, subAggregation elastic.Aggregation) {
			dateTimeHistogramAggregation.SubAggregation(name, subAggregation)
		}

		switch sortOrder := queryGroup.SortOrder(); sortOrder.Type {
		case groups.GroupSortOrderTypeSelf:
			dateTimeHistogramAggregation = dateTimeHistogramAggregation.OrderByKey(sortOrder.Asc)
		case groups.GroupSortOrderTypeCount:
			dateTimeHistogramAggregation = dateTimeHistogramAggregation.OrderByCount(sortOrder.Asc)
		/* Phase 2: see GroupSortOrderTypeAggregation in cc-dashboard-query-api/pkg/internal/domain/groups/groups.go
		case groups.GroupSortOrderTypeAggregation:
			dateTimeHistogramAggregation = dateTimeHistogramAggregation.OrderByAggregation(fmt.Sprintf("a_%s", sortOrder.AggregationKey), sortOrder.Asc)
		*/
		default:
			return nil, fmt.Errorf("unknown sort order '%s' for %s group '%s'", sortOrder.Type, queryGroup.Type(), queryGroup.FieldName())
		}

		elasticGroupAggregation = dateTimeHistogramAggregation
	default:
		return nil, errUnknownGroupType(queryGroup.Type())
	}

	if subGroupAggregation != nil {
		appendSubAggregation(subGroupAggregation.key, subGroupAggregation.aggregation)
	}

	for aggKey, agg := range elasticAggregations {
		appendSubAggregation(aggKey, agg)
	}

	return elasticGroupAggregation, nil
}

func queryGroupsToElastic(groupIndex int, queryGroups groups.Groups, elasticAggregations map[string]elastic.Aggregation, requestedPeriod time.Duration) (elastic.Aggregation, error) {
	var subGroupAggregation *subAggregation

	if len(queryGroups) > 1 {
		var err error
		subGroupAggregation = &subAggregation{
			key: fmt.Sprintf("g%d", groupIndex+1),
		}
		subGroupAggregation.aggregation, err = queryGroupsToElastic(groupIndex+1, queryGroups[1:], elasticAggregations, requestedPeriod)
		if err != nil {
			return nil, err
		}
	}

	if len(queryGroups) != 1 {
		elasticAggregations = nil
	}

	return queryGroupToElasticAggregation(queryGroups[0], elasticAggregations, subGroupAggregation, requestedPeriod)
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
