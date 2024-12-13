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

	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apiserver/pkg/authentication/user"

	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/client"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/groups"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/query"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/repository/linseed"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/security"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/svc/managedclusters"
	"github.com/tigera/tds-apiserver/pkg/httpreply"
	"github.com/tigera/tds-apiserver/pkg/logging"
)

// Note: elastic.AggregationBucketHistogramItem does not have json tags to Marshal, so use local structs instead
type bucketItem map[string]any

type bucketItems struct {
	Buckets []bucketItem `json:"buckets,omitempty"`
}

func TestQueryService(t *testing.T) {

	ctx := security.NewUserAuthContext(
		context.Background(),
		&user.DefaultInfo{Name: "fake-user"},
		security.RBACAuthorizerFunc(
			func(usr user.Info, resources *authzv1.ResourceAttributes, nonResources *authzv1.NonResourceAttributes) (bool, error) {
				return true, nil
			}),
		"",
		"cluster1",
	)

	logger := logging.New("TestQueryService")

	tenantID := "fake-tenant"

	mockClient := lsclient.NewMockClient(tenantID)
	repository := linseed.NewLinseedRepositoryWithClient(logger, "", mockClient)

	managedClusterLister := managedclusters.NameListerFunc(func(ctx context.Context) ([]query.ManagedClusterName, error) {
		return []query.ManagedClusterName{"cluster1", "cluster2"}, nil
	})

	subject := NewQueryService(
		logger,
		repository,
		managedClusterLister,
		2*time.Minute,
		"",
	)

	t.Run("authorization", func(t *testing.T) {
		t.Run("authorized", func(t *testing.T) {

			mockClient.SetResults(
				rest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{})},
				rest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{})},
			)
			_, err := subject.Query(ctx, client.QueryRequest{
				CollectionName: "flows",
				Filters: []client.QueryRequestFilter{
					{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "@timestamp"}},
				},
			})

			require.NoError(t, err)
		})
		t.Run("unauthorized", func(t *testing.T) {

			ctx := security.NewUserAuthContext(
				context.Background(),
				&user.DefaultInfo{Name: "fake-user"},
				security.RBACAuthorizerFunc(
					func(usr user.Info, resources *authzv1.ResourceAttributes, nonResources *authzv1.NonResourceAttributes) (bool, error) {
						return false, nil
					}),
				"",
				"cluster1",
			)

			_, err := subject.Query(ctx, client.QueryRequest{
				CollectionName: "flows",
				Filters: []client.QueryRequestFilter{
					{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "@timestamp"}},
				},
			})

			require.Equal(t, err, httpreply.ReplyAccessDenied)
		})

		t.Run("partially authorized", func(t *testing.T) {
			// TODO: enable this test once cluster-scoped log authorization is implemented either by using a bulk SubjectAccessReview
			// or any other method
			t.Skipf("partial authorization is disabled until cluster-scoped logs are implemented")

			ctx := security.NewUserAuthContext(
				context.Background(),
				&user.DefaultInfo{Name: "fake-user"},
				security.RBACAuthorizerFunc(
					func(usr user.Info, resources *authzv1.ResourceAttributes, nonResources *authzv1.NonResourceAttributes) (bool, error) {
						return resources.Resource == "cluster1", nil
					}),
				"",
				"cluster1",
			)

			mockClient.SetResults(
				rest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{})},
			)

			_, err := subject.Query(ctx, client.QueryRequest{
				CollectionName: "flows",
				Filters: []client.QueryRequestFilter{
					{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "@timestamp"}},
				},
			})
			require.NoError(t, err)
		})
	})

	t.Run("validation", func(t *testing.T) {
		t.Run("unknown cluster", func(t *testing.T) {
			ctx := security.NewUserAuthContext(
				context.Background(),
				&user.DefaultInfo{Name: "fake-user"},
				security.RBACAuthorizerFunc(
					func(usr user.Info, resources *authzv1.ResourceAttributes, nonResources *authzv1.NonResourceAttributes) (bool, error) {
						return true, nil
					}),
				"",
				"unknown-cluster",
			)

			_, err := subject.Query(ctx, client.QueryRequest{
				CollectionName: "flows",
				Filters: []client.QueryRequestFilter{
					{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "@timestamp"}},
				},
			})
			require.ErrorContains(t, err, "cluster 'unknown-cluster' not found")
		})
		t.Run("unknown criterion type", func(t *testing.T) {
			_, err := subject.Query(ctx, client.QueryRequest{
				CollectionName: "flows",
				Filters: []client.QueryRequestFilter{
					{Criterion: client.QueryRequestFilterCriterion{Type: "unknown"}},
					{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "@timestamp"}},
				},
			})
			require.ErrorContains(t, err, "invalid request: Key: 'QueryRequest.Filters[0].Criterion.Type' Error:Field validation for 'Type' failed")
		})

		t.Run("unknown group type", func(t *testing.T) {
			_, err := subject.Query(ctx, client.QueryRequest{
				CollectionName: "flows",
				Filters: []client.QueryRequestFilter{
					{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "@timestamp"}},
				},
				GroupBys: []client.QueryRequestGroup{
					{Type: "unknown"},
				},
			})
			require.ErrorContains(t, err, "invalid request: Key: 'QueryRequest.GroupBys[0].Type' Error:Field validation for 'Type' failed")
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
								{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "invalid1", LTE: "10m", Field: "@timestamp"}},
							},
						})
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `invalid value for relativeTimeRange gte field: invalid1`)
					})
					t.Run("lte duration", func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "10m", LTE: "invalid2", Field: "@timestamp"}},
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
								{Criterion: client.QueryRequestFilterCriterion{Type: "dateRange", GTE: "invalid1", LTE: "2020-01-01T00:00:00Z", Field: "@timestamp"}},
							},
						})
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `invalid 'invalid1' value for criterion type 'dateRange'`)
					})
					t.Run("lte time", func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "dateRange", GTE: "2020-01-01T00:00:00Z", LTE: "invalid2", Field: "@timestamp"}},
							},
						})
						require.ErrorIs(t, err, httpreply.ToBadRequest(``))
						require.ErrorContains(t, err, `invalid 'invalid2' value for criterion type 'dateRange'`)
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
				})
			})

			t.Run("multiple", func(t *testing.T) {
				_, err := subject.Query(ctx, client.QueryRequest{
					CollectionName: "flows",
					ClusterFilter:  []client.ManagedClusterName{"cluster1"},
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "@timestamp"}},
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "@timestamp"}},
					},
				})
				require.ErrorContains(t, err, "multiple time range filters set")
			})

			t.Run("collectionName", func(t *testing.T) {
				_, err := subject.Query(ctx,
					client.QueryRequest{
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "@timestamp"}},
						},
					})
				require.ErrorContains(t, err, "unknown collection ''")

				t.Run("invalid", func(t *testing.T) {
					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "unknown",
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "@timestamp"}},
						},
					})
					require.ErrorContains(t, err, "unknown collection 'unknown'")
				})
			})
		})

		t.Run("exists criterion", func(t *testing.T) {

			t.Run("supported for text field", func(t *testing.T) {
				_, err := subject.Query(ctx, client.QueryRequest{
					CollectionName: "flows",
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "@timestamp"}},
						{Criterion: client.QueryRequestFilterCriterion{Type: "exists", Field: "dest_domains"}},
					},
				})
				require.NoError(t, err)
			})

			t.Run("not supported for non-text field", func(t *testing.T) {
				for _, tc := range []string{
					"@timestamp", "bytes_in", "num_flows", "policy.type",
				} {
					t.Run(tc, func(t *testing.T) {
						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "@timestamp"}},
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
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "@timestamp"}},
							{Criterion: client.QueryRequestFilterCriterion{Type: "range", GTE: "invalid-value", LTE: "10", Field: "bytes_in"}},
						},
					})
					require.ErrorContains(t, err, "failed to parse range gte field: invalid-value")
				})

				t.Run("lte value", func(t *testing.T) {
					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "flows",
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "@timestamp"}},
							{Criterion: client.QueryRequestFilterCriterion{Type: "range", GTE: "10", LTE: "invalid-value", Field: "bytes_in"}},
						},
					})
					require.ErrorContains(t, err, "failed to parse range lte field: invalid-value")
				})

				t.Run("no values set", func(t *testing.T) {
					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "flows",
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "@timestamp"}},
							{Criterion: client.QueryRequestFilterCriterion{Type: "range", Field: "bytes_in"}},
						},
					})
					require.ErrorContains(t, err, "invalid gte and lte values for range criterion")
				})

				t.Run("gte greater than lte", func(t *testing.T) {
					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "flows",
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "@timestamp"}},
							{Criterion: client.QueryRequestFilterCriterion{Type: "range", GTE: "100", LTE: "1", Field: "bytes_in"}},
						},
					})
					require.ErrorContains(t, err, "invalid gte and lte values for range criterion")
				})
			})

			t.Run("success", func(t *testing.T) {
				t.Run("only gte field set", func(t *testing.T) {
					mockClient.SetResults(
						rest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{})},
					)

					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "flows",
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "@timestamp"}},
							{Criterion: client.QueryRequestFilterCriterion{Type: "range", GTE: "10", Field: "bytes_in"}},
						},
					})
					require.NoError(t, err)
				})
				t.Run("only lte field set", func(t *testing.T) {
					mockClient.SetResults(
						rest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{})},
					)

					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "flows",
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "@timestamp"}},
							{Criterion: client.QueryRequestFilterCriterion{Type: "range", LTE: "10", Field: "bytes_in"}},
						},
					})
					require.NoError(t, err)
				})

				t.Run("lte and gte fields set", func(t *testing.T) {
					t.Run("to the same value", func(t *testing.T) {
						mockClient.SetResults(
							rest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{})},
						)

						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "@timestamp"}},
								{Criterion: client.QueryRequestFilterCriterion{Type: "range", GTE: "99", LTE: "100", Field: "bytes_in"}},
							},
						})
						require.NoError(t, err)
					})

					t.Run("lte greater than gte", func(t *testing.T) {
						mockClient.SetResults(
							rest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{})},
						)

						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M", Field: "@timestamp"}},
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
					rest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{TotalHits: 11, Items: []lsv1.FlowLog{
						{ID: "flow-log1"},
						{ID: "flow-log2"},
						{ID: "flow-log3"},
						{ID: "flow-log4"},
						{ID: "flow-log5"},
						{ID: "flow-log6"},
						{ID: "flow-log7"},
						{ID: "flow-log8"},
						{ID: "flow-log9"},
						{ID: "flow-log10"},
						{ID: "flow-log11"},
					}})},
				)
			}

			t.Run("value is honoured", func(t *testing.T) {
				setMockResult()
				resp, err := subject.Query(ctx, client.QueryRequest{
					MaxDocs:        intp(2),
					CollectionName: "flows",
					ClusterFilter:  []client.ManagedClusterName{"cluster1"},
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "@timestamp"}},
					},
				})

				require.NoError(t, err)
				require.Len(t, resp.Documents, 2)

				documents := documentsToClusterAndLogID(t, resp.Documents)
				require.Equal(t, map[string][]string{
					"cluster1": {"flow-log1", "flow-log2"},
				}, documents)
			})

			t.Run("default value", func(t *testing.T) {
				setMockResult()
				resp, err := subject.Query(ctx, client.QueryRequest{
					MaxDocs:        nil,
					CollectionName: "flows",
					ClusterFilter:  []client.ManagedClusterName{"cluster1"},
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "@timestamp"}},
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
				mockClient.SetResults(rest.MockResult{Body: jsonMarshal(t, mockResult)})

				resp, err := subject.Query(ctx, client.QueryRequest{
					MaxDocs:        intp(1000),
					CollectionName: "flows",
					ClusterFilter:  []client.ManagedClusterName{"cluster1"},
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "@timestamp"}},
					},
				})

				require.NoError(t, err)
				require.Len(t, resp.Documents, MaxQueryDocumentsLimit)
			})
		})
	})

	t.Run("success", func(t *testing.T) {
		t.Run("single-tenant", func(t *testing.T) {
			t.Run("query", func(t *testing.T) {
				mockClient.SetResults(
					rest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{TotalHits: 3, Items: []lsv1.FlowLog{
						{ID: "flow-log1"},
						{ID: "flow-log2"},
						{ID: "flow-log3"},
					}})},
					rest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{TotalHits: 2, Items: []lsv1.FlowLog{
						{ID: "flow-log4"},
						{ID: "flow-log5"},
					}})},
				)

				expectedFlowLogsIDs1 := []string{"flow-log1", "flow-log2", "flow-log3"}

				resp, err := subject.Query(ctx, client.QueryRequest{
					CollectionName: "flows",
					ClusterFilter:  []client.ManagedClusterName{"cluster1", "cluster2"},
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "@timestamp"}},
					},
				})

				require.NoError(t, err)
				require.Len(t, resp.Documents, 3)
				require.Equal(t, client.QueryResponseTotals{Value: 3}, resp.Totals)
				require.Empty(t, resp.GroupValues)
				require.Empty(t, resp.Aggregations)

				documents := documentsToClusterAndLogID(t, resp.Documents)
				require.Equal(t, map[string][]string{"cluster1": expectedFlowLogsIDs1}, documents)
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
									rest.MockResult{Body: jsonMarshal(t, elastic.Aggregations{
										"g0": jsonMarshal(t, groupResults[0]),
									})},
									rest.MockResult{Body: jsonMarshal(t, elastic.Aggregations{
										"g0": jsonMarshal(t, groupResults[1]),
									})},
								)

								resp, err := subject.Query(ctx, client.QueryRequest{
									CollectionName: "flows",
									ClusterFilter:  []client.ManagedClusterName{"cluster1", "cluster2"},
									Filters: []client.QueryRequestFilter{
										{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "@timestamp"}},
									},
									GroupBys: []client.QueryRequestGroup{
										{Type: client.GroupType(groups.GroupTypeDiscrete), MaxValues: 0},
									},
								})

								require.NoError(t, err)
								require.Empty(t, resp.Aggregations)

								require.Len(t, resp.GroupValues, 10)
							})

							mockClient.SetResults(
								rest.MockResult{Body: jsonMarshal(t, elastic.Aggregations{
									"g0": jsonMarshal(t, groupResults[0]),
								})},
								rest.MockResult{Body: jsonMarshal(t, elastic.Aggregations{
									"g0": jsonMarshal(t, groupResults[1]),
								})},
							)

							resp, err := subject.Query(ctx, client.QueryRequest{
								CollectionName: "flows",
								ClusterFilter:  []client.ManagedClusterName{"cluster1", "cluster2"},
								Filters: []client.QueryRequestFilter{
									{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "@timestamp"}},
								},
								GroupBys: []client.QueryRequestGroup{
									{Type: client.GroupType(groups.GroupTypeDiscrete), MaxValues: 11},
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
									rest.MockResult{Body: jsonMarshal(t, elastic.Aggregations{
										"g0": jsonMarshal(t, groupResults[0]),
									})},
									rest.MockResult{Body: jsonMarshal(t, elastic.Aggregations{
										"g0": jsonMarshal(t, groupResults[1]),
									})},
								)

								resp, err := subject.Query(ctx, client.QueryRequest{
									CollectionName: "flows",
									ClusterFilter:  []client.ManagedClusterName{"cluster1", "cluster2"},
									Filters: []client.QueryRequestFilter{
										{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "@timestamp"}},
									},
									GroupBys: []client.QueryRequestGroup{
										{Type: client.GroupType(groups.GroupTypeTime)},
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
								rest.MockResult{Body: jsonMarshal(t, elastic.Aggregations{
									"g0": jsonMarshal(t, groupResults[0]),
								})},
								rest.MockResult{Body: jsonMarshal(t, elastic.Aggregations{
									"g0": jsonMarshal(t, groupResults[1]),
								})},
								rest.MockResult{Body: jsonMarshal(t, elastic.Aggregations{
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
								2*time.Minute,
								"",
							)

							resp, err := subject.Query(ctx, client.QueryRequest{
								CollectionName: "flows",
								ClusterFilter:  []client.ManagedClusterName{"cluster1", "cluster2", "cluster3"},
								Filters: []client.QueryRequestFilter{
									{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "@timestamp"}},
								},
								GroupBys: []client.QueryRequestGroup{
									{Type: client.GroupType(groups.GroupTypeTime), MaxValues: 3},
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
					subject := NewQueryService(logger, repository, managedClusterLister, 2*time.Minute, "cc-tenant-acme")

					mockClient.SetResults(
						rest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{TotalHits: 3, Items: []lsv1.FlowLog{
							{ID: "flow-log1"},
							{ID: "flow-log2"},
							{ID: "flow-log3"},
						}})},
					)

					resp, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "flows",
						MaxDocs:        intp(0),
						ClusterFilter:  []client.ManagedClusterName{"cluster1", "cluster2"},
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "@timestamp"}},
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
					t.Run("defaults", func(t *testing.T) {
						g, err := mapClientGroup(client.QueryRequestGroup{Type: client.GroupType(groups.GroupTypeDiscrete)})
						require.NoError(t, err)
						require.True(t, g.SortOrder().Asc)
						require.Equal(t, groups.GroupSortOrderTypeCount, g.SortOrder().Type)

						g, err = mapClientGroup(client.QueryRequestGroup{Type: client.GroupType(groups.GroupTypeTime)})
						require.NoError(t, err)
						require.True(t, g.SortOrder().Asc)
						require.Equal(t, groups.GroupSortOrderTypeSelf, g.SortOrder().Type)
					})

					t.Run("desc", func(t *testing.T) {
						g, err := mapClientGroup(client.QueryRequestGroup{
							Type:  client.GroupType(groups.GroupTypeDiscrete),
							Order: &client.QueryRequestGroupOrder{Type: client.QueryRequestGroupOrderType(groups.GroupSortOrderTypeCount), SortAsc: false}},
						)
						require.NoError(t, err)
						require.False(t, g.SortOrder().Asc)
					})

					t.Run("asc", func(t *testing.T) {
						g, err := mapClientGroup(client.QueryRequestGroup{
							Type:  client.GroupType(groups.GroupTypeDiscrete),
							Order: &client.QueryRequestGroupOrder{Type: client.QueryRequestGroupOrderType(groups.GroupSortOrderTypeCount), SortAsc: true}},
						)
						require.NoError(t, err)
						require.True(t, g.SortOrder().Asc)
					})
				})

				t.Run("time range fields", func(t *testing.T) {
					queryWithFilter := func(t *testing.T, filter client.QueryRequestFilter) *lsv1.FlowLogParams {
						t.Helper()
						subject := NewQueryService(logger, repository, managedClusterLister, 2*time.Minute, "cc-tenant-acme")

						mockClient.SetResults(
							rest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{TotalHits: 0, Items: []lsv1.FlowLog{}})},
						)

						_, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							MaxDocs:        intp(0),
							ClusterFilter:  []client.ManagedClusterName{"cluster1", "cluster2"},
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
			subject := NewQueryService(logger, repository, managedClusterLister, 2*time.Minute, "cc-tenant-acme")

			mockClient.SetResults(
				rest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{TotalHits: 3, Items: []lsv1.FlowLog{
					{ID: "flow-log1"},
					{ID: "flow-log2"},
					{ID: "flow-log3"},
				}})},
				rest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{TotalHits: 2, Items: []lsv1.FlowLog{
					{ID: "flow-log4"},
					{ID: "flow-log5"},
				}})},
			)

			expectedFlowLogsIDs1 := []string{"flow-log1", "flow-log2", "flow-log3"}

			resp, err := subject.Query(ctx, client.QueryRequest{
				CollectionName: "flows",
				ClusterFilter:  []client.ManagedClusterName{"cluster1", "cluster2"},
				Filters: []client.QueryRequestFilter{
					{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", Field: "@timestamp"}},
				},
			})

			require.NoError(t, err)
			require.Len(t, resp.Documents, 3)
			require.Equal(t, client.QueryResponseTotals{Value: 3}, resp.Totals)
			require.Empty(t, resp.GroupValues)
			require.Empty(t, resp.Aggregations)

			documents := documentsToClusterAndLogID(t, resp.Documents)
			require.Equal(t, map[string][]string{"cluster1": expectedFlowLogsIDs1}, documents)
		})
	})
}

func documentsToClusterAndLogID(t *testing.T, documents []any) map[string][]string {
	t.Helper()

	var documentsSliceMap []map[string]any
	documentsJSON, err := json.Marshal(documents)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(documentsJSON, &documentsSliceMap))

	m := map[string][]string{}
	for _, d := range documentsSliceMap {
		cluster := d["cluster"].(string)
		if _, ok := m[cluster]; !ok {
			m[cluster] = []string{}
		}
		m[cluster] = append(m[cluster], d["id"].(string))
	}

	return m
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
