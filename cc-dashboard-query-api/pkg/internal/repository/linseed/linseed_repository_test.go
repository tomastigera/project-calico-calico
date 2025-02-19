package linseed

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/tigera/tds-apiserver/lib/httpreply"
	"github.com/tigera/tds-apiserver/lib/logging"
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
				ClusterIDs:     []query.ManagedClusterName{"fake-cluster"},
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
				ClusterIDs:     []query.ManagedClusterName{"fake-cluster"},
			})
			require.NoError(t, err)
			require.Equal(t, result.QueryResult{
				Documents: []result.QueryResultDocument{},
			}, queryResult)
		})

		t.Run("returns bad request on selector errors", func(t *testing.T) {
			mockClient.SetResults(rest.MockResult{
				StatusCode: 500,
				Err:        errors.New(`[status 500] server error: Invalid selector (( field = "test-value" )) in request: invalid value for field: test-value")`),
			})

			_, err := subject.Query(ctx, query.QueryRequest{
				CollectionName: collections.CollectionNameDNS,
				ClusterIDs:     []query.ManagedClusterName{"fake-cluster"},
			})
			require.ErrorIs(t, err, httpreply.ToBadRequest(``))
			require.ErrorContains(t, err, "invalid value for field: test-value")
		})

		t.Run("returns bad request on token errors", func(t *testing.T) {
			mockClient.SetResults(rest.MockResult{
				StatusCode: 500,
				Err:        errors.New(`[status 500] server error: Invalid selector (bytes_in = -1) in request: 1:12: unexpected token \"-\" (expected <ident> | <string> | <int> | <float>)`),
			})

			_, err := subject.Query(ctx, query.QueryRequest{
				CollectionName: collections.CollectionNameDNS,
				ClusterIDs:     []query.ManagedClusterName{"fake-cluster"},
			})
			require.ErrorIs(t, err, httpreply.ToBadRequest(``))
			require.ErrorContains(t, err, "invalid criterion filter: (bytes_in = -1)'")
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
				ClusterIDs:     []query.ManagedClusterName{"fake-cluster"},
				Aggregations: map[aggregations.AggregationKey]aggregations.Aggregation{
					"agg1": aggregations.NewAggregationSum("f1"),
				},
			})
			require.NoError(t, err)

			requests := mockClient.Requests()
			require.Len(t, requests, 1)

			require.Equal(t, &lsv1.DNSAggregationParams{
				DNSLogParams: lsv1.DNSLogParams{
					QueryParams: lsv1.QueryParams{Clusters: []string{"fake-cluster"}},
					QuerySortParams: lsv1.QuerySortParams{
						Sort: []lsv1.SearchRequestSortBy{
							{Field: "start_time", Descending: true},
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
				ClusterIDs:     []query.ManagedClusterName{"fake-cluster"},
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
					QueryParams: lsv1.QueryParams{Clusters: []string{"fake-cluster"}},
					QuerySortParams: lsv1.QuerySortParams{
						Sort: []lsv1.SearchRequestSortBy{
							{Field: "start_time", Descending: true},
						},
					},
				},
				Aggregations: map[string]json.RawMessage{
					"g0": expectedAggregation,
				},
			}, requests[0].GetParams())
		})

		t.Run("percentiles are returned with the correct key", func(t *testing.T) {

			type testCase struct {
				key           string
				agg           aggregations.Aggregation
				elasticValue  map[string]float64
				expectedValue aggregations.AggregationValue
			}

			testPercentileAggregationValue := func(tc testCase) {

				// Note: marshalling elastic.AggregationPercentilesMetric results in incorrect keys since the struct
				// does not have json tags defined, so marshal it from a map[string]any instead
				elasticValuesBytes, err := json.Marshal(map[string]any{
					"values": tc.elasticValue,
				})
				require.NoError(t, err)

				resultAggregations := make(aggregations.AggregationValues)
				err = elasticAggregationToQueryResult(tc.key, tc.agg, 0, resultAggregations, elastic.Aggregations{
					"a_" + tc.key: elasticValuesBytes,
				})
				require.NoError(t, err)

				require.Equal(t, aggregations.AggregationValues{
					tc.key: tc.expectedValue,
				}, resultAggregations)
			}

			testPercentileAggregationValue(testCase{
				key:           "agg0",
				agg:           aggregations.NewAggregationPercentile("f1", 100),
				elasticValue:  map[string]float64{"100.0": 10100},
				expectedValue: aggregations.NewAggregationValue(floatp(10100)),
			})

			testPercentileAggregationValue(testCase{
				key:           "agg1",
				agg:           aggregations.NewAggregationPercentile("f1", 95),
				elasticValue:  map[string]float64{"95.0": 10095},
				expectedValue: aggregations.NewAggregationValue(floatp(10095)),
			})

			testPercentileAggregationValue(testCase{
				key:           "agg2",
				agg:           aggregations.NewAggregationPercentile("f1", 84.357),
				elasticValue:  map[string]float64{"84.357": 184357.33},
				expectedValue: aggregations.NewAggregationValue(floatp(184357.33)),
			})

			testPercentileAggregationValue(testCase{
				key:           "agg3",
				agg:           aggregations.NewAggregationPercentile("f1", 1),
				elasticValue:  map[string]float64{"1.0": 10001.4},
				expectedValue: aggregations.NewAggregationValue(floatp(10001.4)),
			})
		})
	})
}

func floatp(f float64) *float64 {
	return &f
}
