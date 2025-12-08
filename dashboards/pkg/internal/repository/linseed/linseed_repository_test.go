package linseed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/olivere/elastic/v7"
	"github.com/stretchr/testify/require"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/tds-apiserver/lib/httpreply"
	"github.com/tigera/tds-apiserver/lib/logging"

	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/aggregations"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/collections"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/groups"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/query"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/query/result"
	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
)

func TestLinseedRepository(t *testing.T) {

	tenantID := "fake-tenant"
	ctx := context.Background()
	logger := logging.New("TestLinseedRepository")

	mockClient := lsclient.NewMockClient(tenantID)
	subject := NewLinseedRepositoryWithClient(logger, "", mockClient)

	t.Run("has a client for each collection", func(t *testing.T) {
		for _, c := range collections.Collections(nil) {
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

		t.Run("returns unauthorized on auth error", func(t *testing.T) {
			mockClient.SetResults(rest.MockResult{
				StatusCode: 500,
				Err:        errors.New(`[status 401] server error: Unauthorized`),
			})

			_, err := subject.Query(ctx, query.QueryRequest{
				CollectionName: collections.CollectionNameDNS,
				ClusterIDs:     []query.ManagedClusterName{"fake-cluster"},
			})
			require.Equal(t, err, httpreply.ReplyAccessDenied)
		})

		t.Run("returns unauthorized on access forbidden", func(t *testing.T) {
			// This test case covers a scenario in which:
			// The namespaced RBAC feature is enabled
			// The user has management plane RBAC to view collections from the lma.tigera.io apiGroup
			// The user does not have managed plane RBAC to view logs
			mockClient.SetResults(rest.MockResult{
				StatusCode: 500,
				Err:        errors.New(`[status 500] server error: Forbidden`),
			})

			_, err := subject.Query(ctx, query.QueryRequest{
				CollectionName: collections.CollectionNameDNS,
				ClusterIDs:     []query.ManagedClusterName{"fake-cluster"},
			})
			require.Equal(t, err, httpreply.ReplyAccessDenied)
		})

		t.Run("permissions are set", func(t *testing.T) {
			expectedPermissions := []v3.AuthorizedResourceVerbs{{
				APIGroup: "fake-group",
				Resource: "fake-resource",
				Verbs: []v3.AuthorizedResourceVerb{{
					Verb: "get",
					ResourceGroups: []v3.AuthorizedResourceGroup{
						{ManagedCluster: "fake-cluster", Namespace: "fake-namespace"},
					},
				}},
			}}

			mockClient := lsclient.NewMockClient(tenantID)
			subject := NewLinseedRepositoryWithClient(logger, "", mockClient)

			mockClient.SetResults(rest.MockResult{})

			_, err := subject.Query(ctx, query.QueryRequest{
				CollectionName: collections.CollectionNameDNS,
				ClusterIDs:     []query.ManagedClusterName{"fake-cluster"},
				Permissions:    expectedPermissions,
			})

			require.NoError(t, err)
			requests := mockClient.Requests()
			require.Len(t, requests, 1)

			dnsLogParams, ok := requests[0].GetParams().(*lsv1.DNSLogParams)
			require.True(t, ok)
			require.Equal(t, expectedPermissions, dnsLogParams.Permissions)
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
				SortFieldName:  "start_time",
				ClusterIDs:     []query.ManagedClusterName{"fake-cluster"},
				Aggregations: aggregations.Aggregations{
					aggregations.NewAggregationSum("agg1", 0, "f1", false),
				},
			})
			require.NoError(t, err)

			requests := mockClient.Requests()
			require.Len(t, requests, 1)

			require.Equal(t, &lsv1.DNSAggregationParams{
				DNSLogParams: lsv1.DNSLogParams{
					QueryParams: lsv1.QueryParams{
						Clusters: []string{"fake-cluster"},
						AfterKey: map[string]any{"startFrom": 0},
					},
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

			aggSource, err := elastic.NewDateHistogramAggregation().
				Field("fg1").
				FixedInterval("1m").
				OrderByKey(true).
				SubAggregation("g1",
					elastic.NewTermsAggregation().
						Field("fg2").
						OrderByAggregation("a_agg1", false).
						Size(10).
						SubAggregation("a_agg1", elastic.NewSumAggregation().Field("f1"))).
				Source()
			require.NoError(t, err)
			expectedAggregation, err := json.Marshal(aggSource)
			require.NoError(t, err)

			_, err = subject.Query(ctx, query.QueryRequest{
				CollectionName: collections.CollectionNameDNS,
				SortFieldName:  "start_time",
				ClusterIDs:     []query.ManagedClusterName{"fake-cluster"},
				Aggregations: aggregations.Aggregations{
					aggregations.NewAggregationSum("agg1", 0, "f1", false),
				},
				Groups: groups.Groups{
					groups.NewGroupTime("fg1", "1M", 10),
					groups.NewGroupDiscrete("fg2", 10),
				},
			})
			require.NoError(t, err)

			requests := mockClient.Requests()
			require.Len(t, requests, 1)

			require.Equal(t, &lsv1.DNSAggregationParams{
				DNSLogParams: lsv1.DNSLogParams{
					QueryParams: lsv1.QueryParams{
						Clusters: []string{"fake-cluster"},
						AfterKey: map[string]any{"startFrom": 0},
					},
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
				agg           aggregation
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

				aggKey := string(tc.agg.agg.Key())

				resultAggregations := make(aggregations.AggregationValues)
				err = elasticAggregationToQueryResult(tc.agg, 0, resultAggregations, elastic.Aggregations{
					"a_" + aggKey: elasticValuesBytes,
				})
				require.NoError(t, err)

				require.Equal(t, aggregations.AggregationValues{
					aggKey: tc.expectedValue,
				}, resultAggregations)
			}

			newAggregationPercentile := func(pct float64) aggregation {
				return aggregation{
					agg:                aggregations.NewAggregationPercentile("agg1", 0, "f1", pct, false),
					elasticAggregation: elastic.NewPercentilesAggregation().Percentiles(pct),
				}
			}

			testPercentileAggregationValue(testCase{
				agg:           newAggregationPercentile(100),
				elasticValue:  map[string]float64{"100.0": 10100},
				expectedValue: aggregations.NewAggregationValue(floatp(10100)),
			})

			testPercentileAggregationValue(testCase{
				agg:           newAggregationPercentile(95),
				elasticValue:  map[string]float64{"95.0": 10095},
				expectedValue: aggregations.NewAggregationValue(floatp(10095)),
			})

			testPercentileAggregationValue(testCase{
				agg:           newAggregationPercentile(84.357),
				elasticValue:  map[string]float64{"84.357": 184357.33},
				expectedValue: aggregations.NewAggregationValue(floatp(184357.33)),
			})

			testPercentileAggregationValue(testCase{
				agg:           newAggregationPercentile(1),
				elasticValue:  map[string]float64{"1.0": 10001.4},
				expectedValue: aggregations.NewAggregationValue(floatp(10001.4)),
			})
		})

		t.Run("are ordered", func(t *testing.T) {
			testCases := []struct {
				name         string
				aggregations aggregations.Aggregations
			}{
				{
					name: "t1",
					aggregations: aggregations.Aggregations{
						aggregations.NewAggregationSum("agg30", 30, "f1", false),
						aggregations.NewAggregationSum("agg20", 20, "f1", false),
						aggregations.NewAggregationPercentile("agg10", 10, "f1", 95, false),
					},
				},
				{
					name: "t1",
					aggregations: aggregations.Aggregations{
						aggregations.NewAggregationSum("agg20", 20, "f1", false),
						aggregations.NewAggregationSum("agg30", 30, "f1", false),
						aggregations.NewAggregationPercentile("agg10", 10, "f1", 95, false),
					},
				},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {

					group1 := elastic.NewTermsAggregation().
						Field("fg2").
						Size(10).
						Order("a_agg10.95", false).
						Order("a_agg20", false).
						Order("a_agg30", false)

					for _, agg := range tc.aggregations {
						elasticAggregation, err := queryAggregationToElastic(agg)
						require.NoError(t, err)

						group1.SubAggregation(fmt.Sprintf("a_%s", agg.Key()), elasticAggregation)
					}

					aggSource, err := elastic.NewDateHistogramAggregation().
						Field("fg1").
						OrderByKey(true).
						FixedInterval("1m").
						SubAggregation("g1", group1).
						Source()
					require.NoError(t, err)
					expectedAggregation, err := json.Marshal(aggSource)
					require.NoError(t, err)

					mockClient.SetResults(rest.MockResult{})
					_, err = subject.Query(ctx, query.QueryRequest{
						CollectionName: collections.CollectionNameDNS,
						ClusterIDs:     []query.ManagedClusterName{"fake-cluster"},
						Aggregations:   tc.aggregations,
						Groups: groups.Groups{
							groups.NewGroupTime("fg1", "1M", 10),
							groups.NewGroupDiscrete("fg2", 10),
						},
					})
					require.NoError(t, err)

					requests := mockClient.Requests()
					require.Len(t, requests, 1)

					params, ok := requests[0].GetParams().(*lsv1.DNSAggregationParams)
					require.True(t, ok)
					require.Equal(t, map[string]json.RawMessage{
						"g0": expectedAggregation,
					}, params.Aggregations)
				})
			}
		})
	})
}

func floatp(f float64) *float64 {
	return &f
}
