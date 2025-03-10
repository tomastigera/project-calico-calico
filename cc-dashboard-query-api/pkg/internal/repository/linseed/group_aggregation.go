package linseed

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/olivere/elastic/v7"

	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/aggregations"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/groups"
	tdsslices "github.com/tigera/tds-apiserver/lib/slices"
)

type sortOrderFunc func(asc bool)
type groupAggregation struct {
	elasticAggregation elastic.Aggregation

	aggJson        json.RawMessage
	aggregationKey string
	queryGroups    groups.Groups

	subAggregation func(aggKey string, agg elastic.Aggregation)
	orderByKey     sortOrderFunc
	orderByCount   sortOrderFunc
}

type groupAggregations []*groupAggregation

func newGroupAggregation(
	groupIndex int,
	queryGroups groups.Groups,
	requestedInterval time.Duration,
) (*groupAggregation, error) {
	g := &groupAggregation{
		queryGroups: queryGroups,
	}

	if len(queryGroups) == 0 {
		return nil, fmt.Errorf("unexpected empty query group list")
	}

	if len(queryGroups) == 1 {
		g.aggregationKey = fmt.Sprintf("g%d", groupIndex)

		switch groupType := queryGroups[0].Type(); groupType {
		case groups.GroupTypeTime:
			err := g.setElasticDateHistogramAggregation(queryGroups[0], requestedInterval)
			if err != nil {
				return nil, err
			}

		case groups.GroupTypeDiscrete:
			g.setElasticTermsAggregation(queryGroups[0])
		default:
			return nil, fmt.Errorf("unknown group type '%s'", groupType)
		}

	} else {
		g.aggregationKey = fmt.Sprintf("g%d-%d", groupIndex, groupIndex+len(queryGroups)-1)
		g.setElasticMultiTermsAggregation(queryGroups)
	}

	// set default group sort order
	// It will be replaced with aggregation auto sorting by https://tigera.atlassian.net/browse/TSLA-8709
	for _, queryGroup := range queryGroups {
		switch sortOrder := queryGroup.SortOrder(); sortOrder.Type {
		case groups.GroupSortOrderTypeSelf:
			g.orderByKey(sortOrder.Asc)
		case groups.GroupSortOrderTypeCount:
			g.orderByCount(sortOrder.Asc)
		default:
			return nil, fmt.Errorf("unknown sort order '%s' for %s group '%s'", sortOrder.Type, queryGroup.Type(), queryGroup.FieldName())
		}
	}

	return g, nil
}

func (g *groupAggregation) setElasticDateHistogramAggregation(
	queryGroup groups.Group,
	requestedInterval time.Duration,
) error {
	var interval time.Duration

	fixedInterval := strings.ToLower(strings.Replace(queryGroup.Interval(), "PT", "", -1))
	if fixedInterval != "" {
		var err error
		interval, err = time.ParseDuration(fixedInterval)
		if err != nil {
			return err
		}
	}

	// ensure a minimum interval of 1m
	interval = max(interval, 1*time.Minute)

	fixedIntervalMinutes := int(math.Ceil(requestedInterval.Minutes()))
	// adjust interval to contain at most maxGroupTimeAggregationResults results
	if interval <= 0 || fixedIntervalMinutes > maxGroupTimeAggregationResults {
		interval = requestedInterval / time.Duration(maxGroupTimeAggregationResults)
	}

	// Align fixed interval to a multiple of 1 minute
	fixedInterval = strconv.FormatInt(int64(interval.Minutes()), 10) + "m"

	dateTimeHistogramAggregation := elastic.NewDateHistogramAggregation().
		Field(queryGroup.FieldName()).
		FixedInterval(fixedInterval)

	g.elasticAggregation = dateTimeHistogramAggregation
	g.orderByKey = func(sortAsc bool) { dateTimeHistogramAggregation.OrderByKey(sortAsc) }
	g.orderByCount = func(sortAsc bool) { dateTimeHistogramAggregation.OrderByCount(sortAsc) }
	g.subAggregation = func(aggKey string, agg elastic.Aggregation) { dateTimeHistogramAggregation.SubAggregation(aggKey, agg) }

	return nil
}

func (g *groupAggregation) setElasticTermsAggregation(queryGroup groups.Group) {
	termsAggregation := elastic.NewTermsAggregation().
		Field(queryGroup.FieldName()).
		Size(queryGroup.MaxValues())

	g.elasticAggregation = termsAggregation

	g.orderByKey = func(sortAsc bool) { termsAggregation.OrderByKey(sortAsc) }
	g.orderByCount = func(sortAsc bool) { termsAggregation.OrderByCount(sortAsc) }
	g.subAggregation = func(aggKey string, agg elastic.Aggregation) { termsAggregation.SubAggregation(aggKey, agg) }
}

func (g *groupAggregation) setElasticMultiTermsAggregation(queryGroups groups.Groups) {
	multiTermsAggregation := elastic.NewMultiTermsAggregation().
		Size(slices.Min(tdsslices.Map(queryGroups, groups.Group.MaxValues))).
		Terms(tdsslices.Map(queryGroups, groups.Group.FieldName)...)

	g.elasticAggregation = multiTermsAggregation

	g.orderByKey = func(sortAsc bool) { multiTermsAggregation.OrderByKey(sortAsc) }
	g.orderByCount = func(sortAsc bool) { multiTermsAggregation.OrderByCount(sortAsc) }
	g.subAggregation = func(aggKey string, agg elastic.Aggregation) { multiTermsAggregation.SubAggregation(aggKey, agg) }
}

func (g groupAggregations) fromElastic(
	groupIndex int,
	resultAggregations elastic.Aggregations,
	subAggregations aggregations.Aggregations,
	parent groups.AppendableGroupValue,
) error {
	var bucketItems []aggregationBucketItem

	switch v := g[groupIndex].elasticAggregation.(type) {
	case *elastic.TermsAggregation:
		items, found := resultAggregations.Terms(g[groupIndex].aggregationKey)
		if !found {
			return nil
		}
		bucketItems = tdsslices.Map(items.Buckets, mapAggregationBucketKeyItem)
	case *elastic.MultiTermsAggregation:
		items, found := resultAggregations.MultiTerms(g[groupIndex].aggregationKey)
		if !found {
			return nil
		}
		bucketItems = tdsslices.Map(items.Buckets, mapAggregationBucketMultiKeyItems)
	case *elastic.DateHistogramAggregation:
		items, found := resultAggregations.DateHistogram(g[groupIndex].aggregationKey)
		if !found {
			return nil
		}
		bucketItems = tdsslices.Map(items.Buckets, mapAggregationBucketHistogramItem)
	default:
		return fmt.Errorf("unknown group aggregation type %T", v)
	}

	return bucketItemsToGroupValue(g, groupIndex, bucketItems, subAggregations, parent)
}

func mapAggregationBucketKeyItem(item *elastic.AggregationBucketKeyItem) aggregationBucketItem {
	var err error

	itemKey, ok := item.Key.(string)
	if !ok {
		itemKey = item.KeyNumber.String()
		if itemKey == "" {
			err = fmt.Errorf("unable to get group aggregation bucket key")
		}
	}

	return aggregationBucketItem{
		err:          err,
		keys:         []string{itemKey},
		docCount:     item.DocCount,
		aggregations: item.Aggregations,
	}
}

func mapAggregationBucketMultiKeyItems(item *elastic.AggregationBucketMultiKeyItem) aggregationBucketItem {
	var err error
	var itemKeys []string

	for _, itemKey := range item.Key {
		var key string

		switch v := itemKey.(type) {
		case string:
			key = v
		case float64:
			key = strconv.FormatFloat(v, 'f', -1, 64)
		default:
			return aggregationBucketItem{
				err:  fmt.Errorf("unable to get group aggregation bucket key"),
				keys: itemKeys,
			}
		}

		itemKeys = append(itemKeys, key)
	}

	return aggregationBucketItem{
		err:          err,
		keys:         itemKeys,
		docCount:     item.DocCount,
		aggregations: item.Aggregations,
	}
}

func mapAggregationBucketHistogramItem(item *elastic.AggregationBucketHistogramItem) aggregationBucketItem {
	var itemKey string
	if item.KeyAsString == nil {
		itemKey = strconv.FormatFloat(item.Key, 'f', -1, 64)
	} else {
		itemKey = *item.KeyAsString
	}

	return aggregationBucketItem{
		keys:         []string{itemKey},
		docCount:     item.DocCount,
		aggregations: item.Aggregations,
	}
}
