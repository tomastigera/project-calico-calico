package linseed

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/olivere/elastic/v7"
	"github.com/stretchr/testify/require"

	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/aggregations"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/collections"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/groups"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/query"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/query/result"
	"github.com/tigera/tds-apiserver/pkg/logging"
)

func TestLinseedRepository(t *testing.T) {

	tenantID := "fake-tenant"
	ctx := context.Background()
	logger := logging.New("TestLinseedRepository")

	mockClient := lsclient.NewMockClient(tenantID)
	subject := NewLinseedRepositoryWithClient(logger, "", mockClient)

	t.Run("has a client for each collection", func(t *testing.T) {
		for _, c := range collections.Collections() {
			require.Contains(t, subject.clients, c.Name())
		}
	})

	t.Run("query", func(t *testing.T) {
		t.Run("empty result", func(t *testing.T) {
			mockClient.SetResults(rest.MockResult{})

			queryResult, err := subject.Query(ctx, query.QueryRequest{
				CollectionName: collections.CollectionNameDNS,
				ClusterID:      "fake-cluster",
			})
			require.NoError(t, err)
			require.Equal(t, result.QueryResult{
				Documents: []result.QueryResultDocument{},
			}, queryResult)
		})

		t.Run("results include cluster name", func(t *testing.T) {
			mockClient.SetResults(rest.MockResult{
				Body: json.RawMessage(`{"items": null}`),
			})

			queryResult, err := subject.Query(ctx, query.QueryRequest{
				CollectionName: collections.CollectionNameDNS,
				ClusterID:      "fake-cluster",
			})
			require.NoError(t, err)
			require.Equal(t, result.QueryResult{
				Documents: []result.QueryResultDocument{},
			}, queryResult)
		})
	})

	t.Run("aggregations", func(t *testing.T) {
		t.Run("are queried at root level with no groups", func(t *testing.T) {
			mockClient.SetResults(rest.MockResult{})

			aggSource, err := elastic.NewSumAggregation().Field("f1").Source()
			require.NoError(t, err)
			expectedAggregation, err := json.Marshal(aggSource)
			require.NoError(t, err)

			_, err = subject.Query(ctx, query.QueryRequest{
				CollectionName: collections.CollectionNameDNS,
				ClusterID:      "fake-cluster",
				Aggregations: map[aggregations.AggregationKey]aggregations.Aggregation{
					"agg1": aggregations.NewAggregationSum("f1"),
				},
			})
			require.NoError(t, err)

			requests := mockClient.Requests()
			require.Len(t, requests, 1)

			require.Equal(t, &lsv1.DNSAggregationParams{
				DNSLogParams: lsv1.DNSLogParams{
					QuerySortParams: lsv1.QuerySortParams{
						Sort: []lsv1.SearchRequestSortBy{
							{Field: "@timestamp", Descending: true},
						},
					},
				},
				Aggregations: map[string]json.RawMessage{
					"a_agg1": expectedAggregation,
				},
			}, requests[0].GetParams())
		})

		t.Run("are queried at the inner-most group level only", func(t *testing.T) {
			mockClient.SetResults(rest.MockResult{})

			aggSource, err := elastic.NewTermsAggregation().
				Field("fg1").
				Order("_count", true).
				Size(10).
				SubAggregation("g1",
					elastic.NewTermsAggregation().
						Field("fg2").
						Order("_count", true).
						Size(10).
						SubAggregation("a_agg1", elastic.NewSumAggregation().Field("f1"))).
				Source()
			require.NoError(t, err)
			expectedAggregation, err := json.Marshal(aggSource)
			require.NoError(t, err)

			_, err = subject.Query(ctx, query.QueryRequest{
				CollectionName: collections.CollectionNameDNS,
				ClusterID:      "fake-cluster",
				Aggregations: map[aggregations.AggregationKey]aggregations.Aggregation{
					"agg1": aggregations.NewAggregationSum("f1"),
				},
				Groups: groups.Groups{
					groups.NewGroupDiscrete("fg1", 10, groups.GroupSortOrder{Type: groups.GroupSortOrderTypeCount, Asc: true}),
					groups.NewGroupDiscrete("fg2", 10, groups.GroupSortOrder{Type: groups.GroupSortOrderTypeCount, Asc: true}),
				},
			})
			require.NoError(t, err)

			requests := mockClient.Requests()
			require.Len(t, requests, 1)

			require.Equal(t, &lsv1.DNSAggregationParams{
				DNSLogParams: lsv1.DNSLogParams{
					QuerySortParams: lsv1.QuerySortParams{
						Sort: []lsv1.SearchRequestSortBy{
							{Field: "@timestamp", Descending: true},
						},
					},
				},
				Aggregations: map[string]json.RawMessage{
					"g0": expectedAggregation,
				},
			}, requests[0].GetParams())
		})
	})
}
