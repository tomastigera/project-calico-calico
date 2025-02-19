package query

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/stretchr/testify/require"

	"k8s.io/apiserver/pkg/authentication/user"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	lsrest "github.com/projectcalico/calico/linseed/pkg/client/rest"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/client"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/aggregations"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/collections"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/groups"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/query"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/repository/linseed"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/security"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/security/fake"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/svc/managedclusters"
	"github.com/tigera/tds-apiserver/lib/httpreply"
	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/lib/slices"
)

// Note: elastic.AggregationBucketHistogramItem does not have json tags to Marshal, so use local structs instead
type bucketItem map[string]any

type bucketItems struct {
	Buckets []bucketItem `json:"buckets,omitempty"`
}

func TestQueryService(t *testing.T) {

	newAuthContext := func(t *testing.T, matchRules bool, clusterID string) security.Context {
		t.Helper()

		return security.NewUserAuthContext(
			context.Background(),
			&user.DefaultInfo{Name: "fake-user"},
			clusterID,
			fake.NewAuthorizer(matchRules),
			k8sfake.NewSimpleClientset(),
		)
	}

	ctx := newAuthContext(t, true, "cluster1")

	logger := logging.New("TestQueryService")

	tenantID := "fake-tenant"

	mockClient := lsclient.NewMockClient(tenantID)
	repository := linseed.NewLinseedRepositoryWithClient(logger, "", mockClient)

	managedClusterLister := managedclusters.NameListerFunc(func(ctx context.Context) ([]query.ManagedClusterName, error) {
		return []query.ManagedClusterName{"cluster1", "cluster2", "cluster3"}, nil
	})

	subject := NewQueryService(
		logger,
		repository,
		managedClusterLister,
		Config{
			QueryTimeout:           time.Duration(2) * time.Minute,
			MaxRequestFilters:      10,
			MaxRequestAggregations: 5,
		},
	)

	t.Run("authorization", func(t *testing.T) {
		t.Run("authorized", func(t *testing.T) {
			mockClient.SetResults(
				lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{})},
				lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{})},
			)
			_, err := subject.Query(ctx, client.QueryRequest{
				CollectionName: "flows",
				Filters: []client.QueryRequestFilter{
					{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
				},
			})

			require.NoError(t, err)
		})
		t.Run("unauthorized", func(t *testing.T) {
			ctx := newAuthContext(t, false, "cluster1")

			_, err := subject.Query(ctx, client.QueryRequest{
				CollectionName: "flows",
				Filters: []client.QueryRequestFilter{
					{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
				},
			})

			require.Equal(t, httpreply.ReplyAccessDenied, err)
		})

		t.Run("authorized", func(t *testing.T) {
			stringp := func(s string) *string { return &s }

			testCases := []struct {
				name              string
				matchingResources []fake.MatchingResource
				expectSuccess     bool
			}{
				{
					name: "partial for cluster1",
					matchingResources: []fake.MatchingResource{
						{APIGroup: "lma.tigera.io", ResourceNames: []string{"flows"}, Resource: stringp("cluster1")},
					},
					expectSuccess: false,
				},
				{
					name: "partial for cluster2",
					matchingResources: []fake.MatchingResource{
						{APIGroup: "lma.tigera.io", ResourceNames: []string{"flows"}, Resource: stringp("cluster2")},
					},
					expectSuccess: false,
				},
				{
					name: "all requested clusters",
					matchingResources: []fake.MatchingResource{
						{APIGroup: "lma.tigera.io", ResourceNames: []string{"flows"}, Resource: stringp("cluster1")},
						{APIGroup: "lma.tigera.io", ResourceNames: []string{"flows"}, Resource: stringp("cluster2")},
					},
					expectSuccess: true,
				},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					ctx := security.NewUserAuthContext(
						context.Background(),
						&user.DefaultInfo{Name: "fake-user"},
						"cluster3",
						fake.NewAuthorizerForMatchingResources(tc.matchingResources),
						k8sfake.NewSimpleClientset(),
					)

					mockClient.SetResults(
						lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{})},
					)

					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "flows",
						ClusterFilter:  []client.ManagedClusterName{"cluster1", "cluster2"},
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
						},
					})

					if tc.expectSuccess {
						require.NoError(t, err)
					} else {
						require.Equal(t, httpreply.ReplyAccessDenied, err)
					}
				})
			}
		})
	})

	t.Run("validation", func(t *testing.T) {
		t.Run("cluster", func(t *testing.T) {
			t.Run("unknown", func(t *testing.T) {
				ctx := newAuthContext(t, true, "cluster1")

				_, err := subject.Query(ctx, client.QueryRequest{
					CollectionName: "flows",
					ClusterFilter:  []client.ManagedClusterName{"unknown-cluster"},
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
					},
				})

				require.Equal(t, httpreply.ToBadRequest("empty clusterIDs not allowed for query parameters"), err)
			})

			t.Run("clusterFilter", func(t *testing.T) {
				testCases := []struct {
					name             string
					clusterFilter    []client.ManagedClusterName
					expectedClusters []string
					message          string
				}{
					{
						name:             "is empty",
						clusterFilter:    nil,
						expectedClusters: []string{"cluster1"},
						message:          "expected QueryParams cluster to match security.Context cluster",
					},
					{
						name:             "is set",
						clusterFilter:    []client.ManagedClusterName{"cluster2", "cluster3", "cluster-unknown"},
						expectedClusters: []string{"cluster2", "cluster3"},
						message:          "expected QueryParams cluster to match ManagedClusterLister clusters",
					},
				}

				for _, tc := range testCases {
					t.Run(tc.name, func(t *testing.T) {
						ctx := newAuthContext(t, true, "cluster1")

						mockClient.SetResults(
							lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{})},
						)

						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							ClusterFilter:  tc.clusterFilter,
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
							},
						})
						require.NoError(t, err)

						requests := mockClient.Requests()
						require.Len(t, requests, 1)
						require.IsType(t, &lsv1.FlowLogParams{}, requests[0].GetParams())

						flowLogParams := requests[0].GetParams().(*lsv1.FlowLogParams)
						require.Equal(t, tc.expectedClusters, flowLogParams.QueryParams.GetClusters(), tc.message)
					})
				}
			})
		})

		t.Run("unknown criterion type", func(t *testing.T) {
			_, err := subject.Query(ctx, client.QueryRequest{
				CollectionName: "flows",
				Filters: []client.QueryRequestFilter{
					{Criterion: client.QueryRequestFilterCriterion{Type: "unknown"}},
					{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
				},
			})
			require.ErrorContains(t, err, "invalid request: Key: 'QueryRequest.Filters[0].Criterion.Type' Error:Field validation for 'Type' failed")
		})
		t.Run("request filters limit", func(t *testing.T) {
			subject := NewQueryService(
				logger,
				repository,
				managedClusterLister,
				Config{
					QueryTimeout:           time.Duration(2) * time.Minute,
					MaxRequestFilters:      1,
					MaxRequestAggregations: 5,
				},
			)

			_, err := subject.Query(ctx, client.QueryRequest{
				CollectionName: "flows",
				Filters: []client.QueryRequestFilter{
					{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
					{Criterion: client.QueryRequestFilterCriterion{Type: "exists", Field: "dest_name"}},
				},
			})
			require.ErrorContains(t, err, "filters limit exceeded")
		})
		t.Run("request aggregations limit", func(t *testing.T) {
			subject := NewQueryService(
				logger,
				repository,
				managedClusterLister,
				Config{
					QueryTimeout:           time.Duration(2) * time.Minute,
					MaxRequestFilters:      10,
					MaxRequestAggregations: 1,
				},
			)

			_, err := subject.Query(ctx, client.QueryRequest{
				CollectionName: "flows",
				Filters: []client.QueryRequestFilter{
					{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
				},
				Aggregations: map[client.QueryRequestAggregationKey]client.QueryRequestAggregation{
					"agg1": {FieldName: "bytes_in", Function: client.QueryRequestAggregationFunction{Type: "max"}},
					"agg2": {FieldName: "bytes_in", Function: client.QueryRequestAggregationFunction{Type: "min"}},
				},
			})
			require.ErrorContains(t, err, "aggregations limit exceeded")
		})

		t.Run("time range criterion", func(t *testing.T) {
			t.Run("none", func(t *testing.T) {
				_, err := subject.Query(ctx, client.QueryRequest{
					CollectionName: "flows",
				})
				require.ErrorContains(t, err, "no time range filter set")
			})
			t.Run("empty", func(t *testing.T) {
				_, err := subject.Query(ctx, client.QueryRequest{
					CollectionName: "flows",
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange"}},
					},
				})
				require.ErrorContains(t, err, "unknown collection field name '' for criterion type 'relativeTimeRange''")
			})
			t.Run("invalid", func(t *testing.T) {
				t.Run("relativeTimeRange", func(t *testing.T) {
					t.Run("gte duration", func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "invalid1", LTE: "10m", Field: "start_time"}},
							},
						})
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `invalid value for relativeTimeRange gte field: invalid1`)
					})
					t.Run("lte duration", func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "10m", LTE: "invalid2", Field: "start_time"}},
							},
						})
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `invalid value for relativeTimeRange lte field: invalid2`)
					})
					t.Run("missing field", func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "10m", LTE: "5m"}},
							},
						})
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `unknown collection field name '' for criterion type 'relativeTimeRange'`)
					})
					t.Run("unknown field", func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "10m", LTE: "5m", Field: "unknown-field"}},
							},
						})
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `unknown collection field name 'unknown-field'`)
					})
					t.Run("incorrect field type", func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "10m", LTE: "5m", Field: "bytes_in"}},
							},
						})
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `invalid collection field 'bytes_in' for criterion type 'relativeTimeRange'`)
					})
				})
				t.Run("dateRange", func(t *testing.T) {
					t.Run("gte time", func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "dateRange", GTE: "invalid1", LTE: "2020-01-01T00:00:00Z", Field: "start_time"}},
							},
						})
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `invalid value 'invalid1' for criterion type 'dateRange' gte field`)
					})
					t.Run("lte time", func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "dateRange", GTE: "2020-01-01T00:00:00Z", LTE: "invalid2", Field: "start_time"}},
							},
						})
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `invalid value 'invalid2' for criterion type 'dateRange' lte field`)
					})
					t.Run("missing field", func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "dateRange", GTE: "2020-01-01T00:00:00Z", LTE: "2020-01-02T00:00:00Z"}},
							},
						})
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, "unknown collection field name '' for criterion type 'dateRange''")
					})
					t.Run("unknown field", func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "dateRange", GTE: "2020-01-01T00:00:00Z", LTE: "2020-01-02T00:00:00Z", Field: "unknown-field"}},
							},
						})
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `unknown collection field name 'unknown-field' for criterion type 'dateRange'`)
					})
					t.Run("incorrect field type", func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "dateRange", GTE: "2020-01-01T00:00:00Z", LTE: "2020-01-02T00:00:00Z", Field: "bytes_in"}},
							},
						})
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `invalid collection field 'bytes_in' for criterion type 'dateRange'`)
					})
					t.Run("gte is greater than lte", func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "dateRange", GTE: "2021-01-01T00:00:00Z", LTE: "2020-01-01T00:00:00Z", Field: "start_time"}},
							},
						})
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `invalid value for dateRange: gte is greater than lte`)
					})
					t.Run("gte field is mandatory", func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "dateRange", GTE: "", LTE: "", Field: "start_time"}},
							},
						})
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `invalid value '' for criterion type 'dateRange' gte field`)
					})

					t.Run("parse formats", func(t *testing.T) {
						testCases := []struct {
							name     string
							value    string
							expected time.Time
						}{
							{
								name:     "date only",
								value:    "2024-01-01",
								expected: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
							},
							{
								name:     "datetime",
								value:    "2024-01-01T12:00:00",
								expected: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
							},
							{
								name:     "datetime utc",
								value:    "2024-01-01T12:00:00Z",
								expected: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
							},
							{
								name:     "datetime with timezone",
								value:    "2024-01-01T12:00:00-07:00",
								expected: time.Date(2024, 1, 1, 12, 0, 0, 0, time.FixedZone("UTC-7", -7*60*60)),
							},
							{
								name:     "datetime nanoseconds utc",
								value:    "2024-01-01T12:00:00.000000123Z",
								expected: time.Date(2024, 1, 1, 12, 0, 0, 123, time.UTC),
							},
							{
								name:     "datetime nanoseconds with timezone",
								value:    "2024-01-01T12:00:00.000000123-07:00",
								expected: time.Date(2024, 1, 1, 12, 0, 0, 123, time.FixedZone("UTC-7", -7*60*60)),
							},
						}

						for _, testCase := range testCases {
							t.Run(testCase.name, func(t *testing.T) {
								mockClient.SetResults(
									lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{})},
								)
								_, err := subject.Query(ctx, client.QueryRequest{
									CollectionName: "flows",
									Filters: []client.QueryRequestFilter{
										{Criterion: client.QueryRequestFilterCriterion{Type: "dateRange", GTE: testCase.value, LTE: testCase.value, Field: "start_time"}},
									},
								})
								require.NoError(t, err, testCase)
								requests := mockClient.Requests()
								require.Len(t, requests, 1, testCase)
								require.IsType(t, &lsv1.FlowLogParams{}, requests[0].GetParams(), testCase)

								timeRange := requests[0].GetParams().(*lsv1.FlowLogParams).TimeRange
								require.True(t, testCase.expected.Equal(timeRange.From), testCase, timeRange.From)
								require.True(t, testCase.expected.Equal(timeRange.To), testCase, timeRange.To)
							})
						}
					})
				})
			})

			t.Run("multiple", func(t *testing.T) {
				_, err := subject.Query(ctx, client.QueryRequest{
					CollectionName: "flows",
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
					},
				})
				require.ErrorContains(t, err, "multiple time range filters set")
			})

			t.Run("collectionName", func(t *testing.T) {
				t.Run("unset", func(t *testing.T) {
					_, err := subject.Query(ctx,
						client.QueryRequest{
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
							},
						})
					require.ErrorContains(t, err, "unknown collection ''")
				})

				t.Run("invalid", func(t *testing.T) {
					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "unknown",
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
						},
					})
					require.ErrorContains(t, err, "unknown collection 'unknown'")
				})
			})
		})

		t.Run("exists criterion", func(t *testing.T) {

			t.Run("supported for text field", func(t *testing.T) {
				mockClient.SetResults(
					lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{})},
				)
				_, err := subject.Query(ctx, client.QueryRequest{
					CollectionName: "flows",
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
						{Criterion: client.QueryRequestFilterCriterion{Type: "exists", Field: "dest_domains"}},
					},
				})
				require.NoError(t, err)
			})

			t.Run("not supported for non-text field", func(t *testing.T) {
				for _, tc := range []string{
					"start_time", "bytes_in", "num_flows", "policy.type",
				} {
					t.Run(tc, func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
								{Criterion: client.QueryRequestFilterCriterion{Type: "exists", Field: tc}},
							},
						})
						require.ErrorContains(t, err, fmt.Sprintf("invalid collection field '%s' for criterion type 'exists'", tc))
					})
				}
			})
		})

		t.Run("range criterion", func(t *testing.T) {
			t.Run("invalid", func(t *testing.T) {
				t.Run("gte value", func(t *testing.T) {

					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "flows",
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
							{Criterion: client.QueryRequestFilterCriterion{Type: "range", GTE: "invalid-value", LTE: "10", Field: "bytes_in"}},
						},
					})
					require.ErrorContains(t, err, "failed to parse range gte field: invalid-value")
				})

				t.Run("lte value", func(t *testing.T) {
					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "flows",
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
							{Criterion: client.QueryRequestFilterCriterion{Type: "range", GTE: "10", LTE: "invalid-value", Field: "bytes_in"}},
						},
					})
					require.ErrorContains(t, err, "failed to parse range lte field: invalid-value")
				})

				t.Run("no values set", func(t *testing.T) {
					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "flows",
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
							{Criterion: client.QueryRequestFilterCriterion{Type: "range", Field: "bytes_in"}},
						},
					})
					require.ErrorContains(t, err, "invalid gte and lte values for range criterion")
				})

				t.Run("gte greater than lte", func(t *testing.T) {
					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "flows",
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
							{Criterion: client.QueryRequestFilterCriterion{Type: "range", GTE: "100", LTE: "1", Field: "bytes_in"}},
						},
					})
					require.ErrorContains(t, err, "invalid gte and lte values for range criterion")
				})
			})

			t.Run("success", func(t *testing.T) {
				t.Run("only gte field set", func(t *testing.T) {
					mockClient.SetResults(
						lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{})},
					)

					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "flows",
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
							{Criterion: client.QueryRequestFilterCriterion{Type: "range", GTE: "10", Field: "bytes_in"}},
						},
					})
					require.NoError(t, err)
				})
				t.Run("only lte field set", func(t *testing.T) {
					mockClient.SetResults(
						lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{})},
					)

					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "flows",
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
							{Criterion: client.QueryRequestFilterCriterion{Type: "range", LTE: "10", Field: "bytes_in"}},
						},
					})
					require.NoError(t, err)
				})

				t.Run("lte and gte fields set", func(t *testing.T) {
					t.Run("to the same value", func(t *testing.T) {
						mockClient.SetResults(
							lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{})},
						)

						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
								{Criterion: client.QueryRequestFilterCriterion{Type: "range", GTE: "99", LTE: "100", Field: "bytes_in"}},
							},
						})
						require.NoError(t, err)
					})

					t.Run("lte greater than gte", func(t *testing.T) {
						mockClient.SetResults(
							lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{})},
						)

						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "start_time"}},
								{Criterion: client.QueryRequestFilterCriterion{Type: "range", GTE: "99", LTE: "100", Field: "bytes_in"}},
							},
						})
						require.NoError(t, err)
					})
				})
			})
		})

		t.Run("maxDocs", func(t *testing.T) {

			setMockResult := func() {
				t.Helper()
				mockClient.SetResults(
					lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{TotalHits: 11, Items: []lsv1.FlowLog{
						{ID: "flow-log1", Cluster: "cluster1"},
						{ID: "flow-log2", Cluster: "cluster1"},
						{ID: "flow-log3", Cluster: "cluster1"},
						{ID: "flow-log4", Cluster: "cluster1"},
						{ID: "flow-log5", Cluster: "cluster1"},
						{ID: "flow-log6", Cluster: "cluster1"},
						{ID: "flow-log7", Cluster: "cluster1"},
						{ID: "flow-log8", Cluster: "cluster1"},
						{ID: "flow-log9", Cluster: "cluster1"},
						{ID: "flow-log10", Cluster: "cluster1"},
						{ID: "flow-log11", Cluster: "cluster1"},
					}})},
				)
			}

			t.Run("value is honoured", func(t *testing.T) {
				setMockResult()
				resp, err := subject.Query(ctx, client.QueryRequest{
					MaxDocs:        intp(2),
					CollectionName: "flows",
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"}},
					},
				})

				require.NoError(t, err)
				require.Len(t, resp.Documents, 2)

				require.Equal(t, []string{"flow-log1", "flow-log2"}, slices.Map(resp.Documents, documentToFlowLogID))
			})

			t.Run("default value", func(t *testing.T) {
				setMockResult()
				resp, err := subject.Query(ctx, client.QueryRequest{
					MaxDocs:        nil,
					CollectionName: "flows",
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"}},
					},
				})

				require.NoError(t, err)
				require.Len(t, resp.Documents, MaxQueryDocumentsDefault)
			})

			t.Run("limit", func(t *testing.T) {
				mockResult := lsv1.List[lsv1.FlowLog]{TotalHits: 1000}
				for i := int64(0); i < mockResult.TotalHits; i++ {
					mockResult.Items = append(mockResult.Items, lsv1.FlowLog{ID: "flow-log" + strconv.FormatInt(i, 10)})
				}
				mockClient.SetResults(lsrest.MockResult{Body: jsonMarshal(t, mockResult)})

				resp, err := subject.Query(ctx, client.QueryRequest{
					MaxDocs:        intp(1000),
					CollectionName: "flows",
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"}},
					},
				})

				require.NoError(t, err)
				require.Len(t, resp.Documents, MaxQueryDocumentsLimit)
			})
		})

		t.Run("groupBy combination", func(t *testing.T) {
			testCases := []struct {
				name     string
				valid    bool
				groupBys []client.QueryRequestGroup
			}{
				{
					name:  "invalid",
					valid: false,
					groupBys: []client.QueryRequestGroup{
						{FieldName: "bytes_in"},
						{FieldName: "action"},
					},
				},
				{
					name:  "valid for partial group list",
					valid: true,
					groupBys: []client.QueryRequestGroup{
						{FieldName: "source_namespace"},
						{FieldName: "source_name_aggr"},
						{FieldName: "source_name"},
					},
				},
				{
					name:  "valid for complete group list",
					valid: true,
					groupBys: []client.QueryRequestGroup{
						{FieldName: "source_namespace"},
						{FieldName: "source_name_aggr"},
						{FieldName: "source_name"},
						{FieldName: "dest_namespace"},
						{FieldName: "dest_name_aggr"},
						{FieldName: "dest_name"},
					},
				},
			}

			for _, testCase := range testCases {
				t.Run(testCase.name, func(t *testing.T) {
					if testCase.valid {
						mockClient.SetResults(lsrest.MockResult{Body: nil})
					}

					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "flows",
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"}},
						},
						GroupBys: testCase.groupBys,
					})

					if testCase.valid {
						require.NoError(t, err)
					} else {
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `invalid group combination`)
					}
				})
			}
		})
	})

	t.Run("aggregation", func(t *testing.T) {
		testCases := []struct {
			name         string
			valid        bool
			functionType client.AggregationFunctionType
		}{
			{
				name:         "valid",
				functionType: client.AggregationFunctionTypeSum,
				valid:        true,
			},
			{
				name:         "invalid",
				functionType: client.AggregationFunctionTypeAvg,
				valid:        false,
			},
			{
				name:         "valid for all",
				functionType: client.AggregationFunctionTypeCount,
				valid:        true,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				if tc.valid {
					mockClient.SetResults(lsrest.MockResult{Body: nil})
				}

				_, err := subject.Query(ctx, client.QueryRequest{
					MaxDocs:        intp(1000),
					CollectionName: "flows",
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"}},
					},
					Aggregations: client.QueryRequestAggregations{
						"agg0": {FieldName: "bytes_in", Function: client.QueryRequestAggregationFunction{Type: tc.functionType}},
					},
				})

				if tc.valid {
					require.NoError(t, err)
				} else {
					require.ErrorIs(t, err, httpreply.ToBadRequest(``))
					require.ErrorContains(t, err, `invalid aggregation function`)
				}
			})
		}
	})

	t.Run("percentile aggregation mapping", func(t *testing.T) {
		testCases := []struct {
			functionType       string
			expectedPercentile float64
		}{
			{functionType: "p50", expectedPercentile: 50},
			{functionType: "p90", expectedPercentile: 90},
			{functionType: "p95", expectedPercentile: 95},
			{functionType: "p100", expectedPercentile: 100},
		}

		queryCollection, found := slices.Find(collections.Collections(), func(collection collections.Collection) bool {
			return collection.Name() == "flows"
		})
		require.True(t, found)

		for _, tc := range testCases {
			t.Run(tc.functionType, func(t *testing.T) {
				agg, err := mapClientAggregation(client.QueryRequestAggregation{
					FieldName: "tcp_max_min_rtt",
					Function: client.QueryRequestAggregationFunction{
						Type: client.AggregationFunctionType(tc.functionType),
					},
				}, queryCollection)
				require.NoError(t, err)

				pct, ok := agg.(aggregations.AggregationPercentile)
				require.True(t, ok)

				require.Equal(t, tc.expectedPercentile, pct.Percentile())
			})
		}
	})

	t.Run("success", func(t *testing.T) {
		t.Run("single-tenant", func(t *testing.T) {
			t.Run("query", func(t *testing.T) {
				mockClient.SetResults(
					lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{TotalHits: 5, Items: []lsv1.FlowLog{
						{ID: "flow-log1", Cluster: "cluster1"},
						{ID: "flow-log2", Cluster: "cluster1"},
						{ID: "flow-log3", Cluster: "cluster1"},
						{ID: "flow-log4", Cluster: "cluster2"},
						{ID: "flow-log5", Cluster: "cluster2"},
					}})},
				)

				expectedFlowLogsIDs := []string{"flow-log1", "flow-log2", "flow-log3", "flow-log4", "flow-log5"}

				resp, err := subject.Query(ctx, client.QueryRequest{
					CollectionName: "flows",
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"}},
					},
				})

				require.NoError(t, err)
				require.Len(t, resp.Documents, 5)
				require.Equal(t, client.QueryResponseTotals{Value: 5}, resp.Totals)
				require.Empty(t, resp.GroupValues)
				require.Empty(t, resp.Aggregations)

				require.Equal(t, expectedFlowLogsIDs, slices.Map(resp.Documents, documentToFlowLogID))
			})

			t.Run("result", func(t *testing.T) {
				t.Run("groups", func(t *testing.T) {
					t.Run("max values", func(t *testing.T) {
						t.Run("discrete group", func(t *testing.T) {

							groupResults := []bucketItems{
								{
									Buckets: []bucketItem{
										{"key": "1"}, {"key": "2"}, {"key": "3"}, {"key": "4"},
										{"key": "5"}, {"key": "6"}, {"key": "7"}, {"key": "8"},
										{"key": "9"}, {"key": "10"}, {"key": "11"}, {"key": "12"},
									},
								},
								{
									Buckets: []bucketItem{
										{"key": "13"}, {"key": "14"}, {"key": "15"}, {"key": "16"},
									},
								},
							}

							t.Run("defaults to 10", func(t *testing.T) {
								// see defaultMaxValue in cc-dashboard-query-api/pkg/internal/domain/groups/group_discrete.go

								mockClient.SetResults(
									lsrest.MockResult{Body: jsonMarshal(t, elastic.Aggregations{
										"g0": jsonMarshal(t, groupResults[0]),
									})},
									lsrest.MockResult{Body: jsonMarshal(t, elastic.Aggregations{
										"g0": jsonMarshal(t, groupResults[1]),
									})},
								)

								resp, err := subject.Query(ctx, client.QueryRequest{
									CollectionName: "flows",
									Filters: []client.QueryRequestFilter{
										{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"}},
									},
									GroupBys: []client.QueryRequestGroup{
										{FieldName: "dest_namespace", MaxValues: 0},
									},
								})

								require.NoError(t, err)
								require.Empty(t, resp.Aggregations)

								require.Len(t, resp.GroupValues, 10)
							})

							mockClient.SetResults(
								lsrest.MockResult{Body: jsonMarshal(t, elastic.Aggregations{
									"g0": jsonMarshal(t, groupResults[0]),
								})},
								lsrest.MockResult{Body: jsonMarshal(t, elastic.Aggregations{
									"g0": jsonMarshal(t, groupResults[1]),
								})},
							)

							resp, err := subject.Query(ctx, client.QueryRequest{
								CollectionName: "flows",
								Filters: []client.QueryRequestFilter{
									{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"}},
								},
								GroupBys: []client.QueryRequestGroup{
									{FieldName: "dest_namespace", MaxValues: 11},
								},
							})

							require.NoError(t, err)
							require.Empty(t, resp.Aggregations)

							require.Len(t, resp.GroupValues, 11)
						})

						t.Run("time group", func(t *testing.T) {

							t.Run("no defaults", func(t *testing.T) {
								// Note that time group requests are limited in the elastic request by
								// maxGroupTimeAggregationResults

								groupResults := make([]bucketItems, 2)

								for i := 0; i < 1000; i++ {
									strIndex := strconv.FormatInt(int64(i), 10)
									groupResults[0].Buckets = append(groupResults[0].Buckets, bucketItem{"key_as_string": "gbi-0-" + strIndex})
									groupResults[1].Buckets = append(groupResults[1].Buckets, bucketItem{"key_as_string": "gbi-1-" + strIndex})
								}

								mockClient.SetResults(
									lsrest.MockResult{Body: jsonMarshal(t, elastic.Aggregations{
										"g0": jsonMarshal(t, groupResults[0]),
									})},
									lsrest.MockResult{Body: jsonMarshal(t, elastic.Aggregations{
										"g0": jsonMarshal(t, groupResults[1]),
									})},
								)

								resp, err := subject.Query(ctx, client.QueryRequest{
									CollectionName: "flows",
									Filters: []client.QueryRequestFilter{
										{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"}},
									},
									GroupBys: []client.QueryRequestGroup{
										{FieldName: "start_time"},
									},
								})

								require.NoError(t, err)
								require.Empty(t, resp.Aggregations)
								require.Len(t, resp.GroupValues, 1000)
							})

							groupResults := []bucketItems{
								{
									Buckets: []bucketItem{
										{"key_as_string": "1500"},
										{"key_as_string": "1600"},
										{"key_as_string": "1150"},
										{"key_as_string": "1800"},
									},
								},
								{
									Buckets: []bucketItem{
										{"key_as_string": "1400"},
										{"key_as_string": "1200"},
										{"key_as_string": "1900"},
									},
								},
								{
									Buckets: []bucketItem{
										{"key_as_string": "1300"},
										{"key_as_string": "1950"},
									},
								},
							}

							mockClient.SetResults(
								lsrest.MockResult{Body: jsonMarshal(t, elastic.Aggregations{
									"g0": jsonMarshal(t, groupResults[0]),
								})},
								lsrest.MockResult{Body: jsonMarshal(t, elastic.Aggregations{
									"g0": jsonMarshal(t, groupResults[1]),
								})},
								lsrest.MockResult{Body: jsonMarshal(t, elastic.Aggregations{
									"g0": jsonMarshal(t, groupResults[2]),
								})},
							)

							// Create a query service with 3 managed clusters
							subject := NewQueryService(
								logger,
								repository,
								managedclusters.NameListerFunc(func(ctx context.Context) ([]query.ManagedClusterName, error) {
									return []query.ManagedClusterName{"cluster1", "cluster2", "cluster3"}, nil
								}),
								Config{
									QueryTimeout:           time.Duration(2) * time.Minute,
									MaxRequestFilters:      10,
									MaxRequestAggregations: 5,
								},
							)

							resp, err := subject.Query(ctx, client.QueryRequest{
								CollectionName: "flows",
								ClusterFilter:  []client.ManagedClusterName{"cluster1", "cluster2", "cluster3"},
								Filters: []client.QueryRequestFilter{
									{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"}},
								},
								GroupBys: []client.QueryRequestGroup{
									{FieldName: "start_time", MaxValues: 3},
								},
							})
							require.NoError(t, err)
							require.Empty(t, resp.Aggregations)

							require.Equal(t, []client.QueryResponseGroupValue{
								{Key: "1500", Aggregations: client.QueryResponseAggregations{}},
								{Key: "1600", Aggregations: client.QueryResponseAggregations{}},
								{Key: "1150", Aggregations: client.QueryResponseAggregations{}},
							}, resp.GroupValues)
						})
					})
				})

				t.Run("count aggregation with no groups", func(t *testing.T) {
					subject := NewQueryService(
						logger,
						repository,
						managedClusterLister,
						Config{
							QueryTimeout:           time.Duration(2) * time.Minute,
							MaxRequestFilters:      10,
							MaxRequestAggregations: 5,
						},
					)

					mockClient.SetResults(
						lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{TotalHits: 3, Items: []lsv1.FlowLog{
							{ID: "flow-log1"},
							{ID: "flow-log2"},
							{ID: "flow-log3"},
						}})},
					)

					resp, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "flows",
						MaxDocs:        intp(0),
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"}},
						},
						Aggregations: client.QueryRequestAggregations{
							"a-count-aggregation": {
								FieldName: "_count",
								Function: client.QueryRequestAggregationFunction{
									Type: client.AggregationFunctionTypeCount,
								},
							},
						},
					})

					require.NoError(t, err)
					require.Empty(t, resp.Documents)
					require.Equal(t, client.QueryResponseTotals{Value: 3}, resp.Totals)
					require.Empty(t, resp.GroupValues)
					require.Equal(t, client.QueryResponseAggregations{
						"a-count-aggregation": {AsString: "3"},
					}, resp.Aggregations)
				})

				t.Run("sort order", func(t *testing.T) {
					collection, found := slices.Find(collections.Collections(), func(collection collections.Collection) bool {
						return collection.Name() == "flows"
					})
					require.True(t, found)

					t.Run("defaults", func(t *testing.T) {
						g, err := mapClientGroup(collection, client.QueryRequestGroup{FieldName: "dest_namespace"})
						require.NoError(t, err)
						require.True(t, g.SortOrder().Asc)
						require.Equal(t, groups.GroupSortOrderTypeCount, g.SortOrder().Type)

						g, err = mapClientGroup(collection, client.QueryRequestGroup{FieldName: "start_time"})
						require.NoError(t, err)
						require.True(t, g.SortOrder().Asc)
						require.Equal(t, groups.GroupSortOrderTypeSelf, g.SortOrder().Type)
					})

					t.Run("desc", func(t *testing.T) {
						g, err := mapClientGroup(collection, client.QueryRequestGroup{
							FieldName: "dest_namespace",
							Order:     &client.QueryRequestGroupOrder{Type: client.QueryRequestGroupOrderType(groups.GroupSortOrderTypeCount), SortAsc: false}},
						)
						require.NoError(t, err)
						require.False(t, g.SortOrder().Asc)
					})

					t.Run("asc", func(t *testing.T) {
						g, err := mapClientGroup(collection, client.QueryRequestGroup{
							FieldName: "dest_namespace",
							Order:     &client.QueryRequestGroupOrder{Type: client.QueryRequestGroupOrderType(groups.GroupSortOrderTypeCount), SortAsc: true}},
						)
						require.NoError(t, err)
						require.True(t, g.SortOrder().Asc)
					})
				})

				t.Run("time range fields", func(t *testing.T) {
					queryWithFilter := func(t *testing.T, filter client.QueryRequestFilter) *lsv1.FlowLogParams {
						t.Helper()
						subject := NewQueryService(
							logger,
							repository,
							managedClusterLister,
							Config{
								QueryTimeout:           time.Duration(2) * time.Minute,
								MaxRequestFilters:      10,
								MaxRequestAggregations: 5,
							},
						)

						mockClient.SetResults(
							lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{TotalHits: 0, Items: []lsv1.FlowLog{}})},
						)

						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							MaxDocs:        intp(0),
							Filters: []client.QueryRequestFilter{
								filter,
							},
							Aggregations: client.QueryRequestAggregations{
								"a-count-aggregation": {
									FieldName: "_count",
									Function: client.QueryRequestAggregationFunction{
										Type: client.AggregationFunctionTypeCount,
									},
								},
							},
						})
						require.NoError(t, err)
						requests := mockClient.Requests()
						require.Len(t, requests, 1)
						params, ok := requests[0].GetParams().(*lsv1.FlowLogParams)
						require.True(t, ok, "expected params type to be *lsv1.FlowLogParams, but it was %T", requests[0].GetParams())
						return params
					}

					t.Run("relativeTimeRange", func(t *testing.T) {
						params := queryWithFilter(t, client.QueryRequestFilter{
							Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"},
						})
						// require.Equal(t, lmav1.TimeField("start_time"), params.QueryParams.TimeRange.Field)  // TODO: enable once linseed supports date fields https://tigera.atlassian.net/browse/TSLA-8376
						require.Empty(t, params.QueryParams.TimeRange.Field)
					})

					t.Run("dateRange", func(t *testing.T) {
						params := queryWithFilter(t, client.QueryRequestFilter{
							Criterion: client.QueryRequestFilterCriterion{Type: "dateRange", GTE: "2020-01-01T00:00:00Z", LTE: "2020-01-02T00:00:00Z", Field: "end_time"},
						})
						//require.Equal(t, lmav1.TimeField("end_time"), params.QueryParams.TimeRange.Field) // TODO: enable once linseed supports date fields https://tigera.atlassian.net/browse/TSLA-8376
						require.Empty(t, params.QueryParams.TimeRange.Field)
					})
				})
			})
		})

		t.Run("multi-tenant", func(t *testing.T) {
			subject := NewQueryService(
				logger,
				repository,
				managedClusterLister,
				Config{
					QueryTimeout:           time.Duration(2) * time.Minute,
					MaxRequestFilters:      10,
					MaxRequestAggregations: 5,
				},
			)

			mockClient.SetResults(
				lsrest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{TotalHits: 5, Items: []lsv1.FlowLog{
					{ID: "flow-log1", Cluster: "cluster1"},
					{ID: "flow-log2", Cluster: "cluster1"},
					{ID: "flow-log3", Cluster: "cluster1"},
					{ID: "flow-log4", Cluster: "cluster2"},
					{ID: "flow-log5", Cluster: "cluster2"},
				}})},
			)

			expectedFlowLogsIDs := []string{"flow-log1", "flow-log2", "flow-log3", "flow-log4", "flow-log5"}

			resp, err := subject.Query(ctx, client.QueryRequest{
				CollectionName: "flows",
				Filters: []client.QueryRequestFilter{
					{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "start_time"}},
				},
			})

			require.NoError(t, err)
			require.Len(t, resp.Documents, 5)
			require.Equal(t, client.QueryResponseTotals{Value: 5}, resp.Totals)
			require.Empty(t, resp.GroupValues)
			require.Empty(t, resp.Aggregations)

			require.Equal(t, expectedFlowLogsIDs, slices.Map(resp.Documents, documentToFlowLogID))
		})
	})
}

func documentToFlowLogID(d any) string {
	return d.(lsv1.FlowLog).ID
}

func jsonMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()

	bytes, err := json.Marshal(v)
	require.NoError(t, err)

	return bytes
}

func intp(i int) *int {
	return &i
}
