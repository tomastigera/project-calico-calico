// Copyright (c) 2025 Tigera, Inc. All rights reserved.
package index

import (
	"github.com/olivere/elastic/v7"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
)

func resourceGroupFilter(resourceGroup apiv3.AuthorizedResourceGroup, queries ...elastic.Query) []elastic.Query {
	if resourceGroup.ManagedCluster == "" {
		return queries
	}

	filterQuery := elastic.NewTermQuery("cluster", resourceGroup.ManagedCluster)

	var result, nonBoolQueries []elastic.Query
	for _, q := range queries {
		if boolQuery, ok := q.(*elastic.BoolQuery); ok {
			result = append(result, boolQuery.Filter(filterQuery))
		} else {
			nonBoolQueries = append(nonBoolQueries, q)
		}
	}

	if len(nonBoolQueries) > 0 {
		result = append(result, elastic.NewBoolQuery().
			Filter(filterQuery).
			Should(nonBoolQueries...).
			MinimumNumberShouldMatch(1))
	}

	return result
}
