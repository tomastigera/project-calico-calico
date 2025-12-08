package linseed

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/stretchr/testify/require"
	"github.com/tigera/tds-apiserver/lib/logging"

	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/query/result"
	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
)

func TestLinseedCollectionClientWAF(t *testing.T) {

	tenantID := "fake-tenant"
	ctx := context.Background()
	logger := logging.New("TestLinseedCollectionClientWAF")

	mockClient := lsclient.NewMockClient(tenantID)
	subject := newLinseedCollectionClientWAF(logger, mockClient)

	t.Run("params", func(t *testing.T) {
		now := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)

		testCases := []struct {
			name         string
			params       *queryParams
			aggregations map[string]json.RawMessage
			expected     lsv1.Params
		}{
			{
				name:   "default",
				params: newQueryParamsHelper(t, &now, "@timestamp", "sel1 = sel1", nil, nil),
				expected: &lsv1.WAFLogParams{
					QueryParams: expectedQueryParams(&now),
					Selector:    "sel1 = sel1",
					QuerySortParams: lsv1.QuerySortParams{
						Sort: []lsv1.SearchRequestSortBy{
							{Field: "@timestamp", Descending: true},
						},
					},
				},
			},
			{
				name:   "with aggregation",
				params: newQueryParamsHelper(t, &now, "@timestamp", "sel2 = sel2", nil, nil),
				aggregations: func(t *testing.T) map[string]json.RawMessage {
					agg0, err := elasticAggregationToJSON(elastic.NewTermsAggregation().Field("f1").
						SubAggregation("a_0", elastic.NewTermsAggregation().Field("fa1")).
						SubAggregation("g1",
							elastic.NewTermsAggregation().Field("f2").
								SubAggregation("a_0", elastic.NewTermsAggregation().Field("fa1"))))
					require.NoError(t, err)

					agg1, err := elasticAggregationToJSON(elastic.NewTermsAggregation().Field("fa1"))
					require.NoError(t, err)

					return map[string]json.RawMessage{"g0": agg0, "a_0": agg1}
				}(t),
				expected: &lsv1.WAFLogAggregationParams{
					WAFLogParams: lsv1.WAFLogParams{
						QueryParams: expectedQueryParams(&now),
						Selector:    "sel2 = sel2",
						QuerySortParams: lsv1.QuerySortParams{
							Sort: []lsv1.SearchRequestSortBy{
								{Field: "@timestamp", Descending: true},
							},
						},
					},
					Aggregations: map[string]json.RawMessage{
						"g0":  json.RawMessage(`{"aggregations":{"a_0":{"terms":{"field":"fa1"}},"g1":{"aggregations":{"a_0":{"terms":{"field":"fa1"}}},"terms":{"field":"f2"}}},"terms":{"field":"f1"}}`),
						"a_0": json.RawMessage(`{"terms":{"field":"fa1"}}`),
					},
				},
			},
			{
				name:   "with domain matches", // domain matches should be ignored for non-DNS collections
				params: newQueryParamsHelper(t, &now, "@timestamp", "sel3 = sel3", []string{"test-domain1.com", "test-domain2.com"}, nil),
				expected: &lsv1.WAFLogParams{
					QueryParams: expectedQueryParams(&now),
					Selector:    "sel3 = sel3",
					QuerySortParams: lsv1.QuerySortParams{
						Sort: []lsv1.SearchRequestSortBy{
							{Field: "@timestamp", Descending: true},
						},
					},
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				params, err := subject.Params(tc.params, tc.aggregations)
				require.NoError(t, err)
				require.Equal(t, tc.expected, params)
			})
		}
	})

	t.Run("list", func(t *testing.T) {
		endpoint1 := lsv1.WAFEndpoint{
			PodNameSpace: "test-namespace1",
		}
		endpoint2 := lsv1.WAFEndpoint{
			PodNameSpace: "test-namespace2",
		}
		date1 := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
		date2 := time.Date(2021, 1, 2, 3, 4, 5, 0, time.UTC)
		wafLogs := []lsv1.WAFLog{
			{Destination: &endpoint1, Cluster: "fake-cluster", Timestamp: time.Unix(date1.Unix(), 0).UTC()},
			{Destination: &endpoint2, Cluster: "fake-cluster", Timestamp: time.Unix(date2.Unix(), 0).UTC()},
		}

		mockClient.SetResults(rest.MockResult{
			Body: lsv1.List[lsv1.WAFLog]{
				Items:     wafLogs,
				TotalHits: 22,
			},
		})
		queryResult, err := subject.List(ctx, &lsv1.QueryParams{})
		require.NoError(t, err)
		require.Equal(t, result.QueryResult{
			Hits: 22,
			Documents: []result.QueryResultDocument{
				{Content: wafLogs[0], Timestamp: time.Unix(date1.Unix(), 0).UTC()},
				{Content: wafLogs[1], Timestamp: time.Unix(date2.Unix(), 0).UTC()},
			},
		}, queryResult)
	})

	t.Run("aggregations", func(t *testing.T) {
		expectedAggregations := elastic.Aggregations{
			"agg1": json.RawMessage(`{"buckets":[]}`),
			"agg2": json.RawMessage(`{"buckets":[]}`),
		}

		mockClient.SetResults(rest.MockResult{
			Body: map[string]json.RawMessage{
				"agg1": json.RawMessage(`{"buckets":[]}`),
				"agg2": json.RawMessage(`{"buckets":[]}`)},
		})

		aggrResult, err := subject.Aggregations(ctx, &lsv1.WAFLogAggregationParams{
			Aggregations: elastic.Aggregations{
				"agg1": json.RawMessage(`{"terms":{"field":"f1"}}`),
				"agg2": json.RawMessage(`{"terms":{"field":"f2"}}`),
			},
		})
		require.NoError(t, err)
		require.Equal(t, expectedAggregations, aggrResult)
	})
}
