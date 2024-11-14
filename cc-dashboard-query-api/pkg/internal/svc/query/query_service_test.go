package query

import (
	"context"
	"encoding/json"
	"golang.org/x/exp/maps"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apiserver/pkg/authentication/user"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/client"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/aggregations"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/groups"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/query"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/query/result"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/repository/linseed"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/security"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/svc/managedclusters"
	"github.com/tigera/tds-apiserver/lib/slices"
	"github.com/tigera/tds-apiserver/pkg/httpreply"
	"github.com/tigera/tds-apiserver/pkg/logging"
)

func TestQueryService(t *testing.T) {

	ctx := security.NewUserAuthContext(
		context.Background(),
		&user.DefaultInfo{Name: "fake-user"},
		security.RBACAuthorizerFunc(
			func(usr user.Info, resources *authzv1.ResourceAttributes, nonResources *authzv1.NonResourceAttributes) (bool, error) {
				return true, nil
			}),
		"",
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
				rest.MockResult{Body: jsonMarshal(t, v1.List[v1.FlowLog]{})},
				rest.MockResult{Body: jsonMarshal(t, v1.List[v1.FlowLog]{})},
			)
			_, err := subject.Query(ctx, client.QueryRequest{
				CollectionName: "flows",
				Filters: []client.QueryRequestFilter{
					{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M"}},
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
			)

			_, err := subject.Query(ctx, client.QueryRequest{
				CollectionName: "flows",
				Filters: []client.QueryRequestFilter{
					{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M"}},
				},
			})

			require.ErrorIs(t, err, httpreply.ReplyAccessDenied)
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
			)

			mockClient.SetResults(
				rest.MockResult{Body: jsonMarshal(t, v1.List[v1.FlowLog]{})},
			)

			_, err := subject.Query(ctx, client.QueryRequest{
				CollectionName: "flows",
				Filters: []client.QueryRequestFilter{
					{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M"}},
				},
			})
			require.NoError(t, err)
		})
	})

	t.Run("validation", func(t *testing.T) {
		t.Run("unknown criterion type", func(t *testing.T) {
			_, err := subject.Query(ctx, client.QueryRequest{
				CollectionName: "flows",
				Filters: []client.QueryRequestFilter{
					{Criterion: client.QueryRequestFilterCriterion{Type: "unknown"}},
					{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M"}},
				},
			})
			require.ErrorContains(t, err, "invalid request: Key: 'QueryRequest.Filters[0].Criterion.Type' Error:Field validation for 'Type' failed")
		})

		t.Run("unknown group type", func(t *testing.T) {
			_, err := subject.Query(ctx, client.QueryRequest{
				CollectionName: "flows",
				Filters: []client.QueryRequestFilter{
					{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M"}},
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
				require.ErrorContains(t, err, "invalid relativeTimeRange duration")
			})
			t.Run("invalid", func(t *testing.T) {
				t.Run("relativeTimeRange", func(t *testing.T) {
					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "flows",
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "invalid1", LTE: "invalid2"}},
						},
					})
					require.ErrorIs(t, err, httpreply.ToBadRequest(`failed to parse relativeTimeRange gte field: time: invalid duration "invalid1"`))
				})
				t.Run("dateRange", func(t *testing.T) {
					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "flows",
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "dateRange", GTE: "invalid1", LTE: "invalid2"}},
						},
					})
					require.ErrorIs(t, err, httpreply.ToBadRequest(""))
				})
			})

			t.Run("multiple", func(t *testing.T) {
				_, err := subject.Query(ctx, client.QueryRequest{
					CollectionName: "flows",
					ClusterFilter:  []client.ManagedClusterName{"cluster1"},
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M"}},
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M"}},
					},
				})
				require.ErrorContains(t, err, "multiple time range filters set")
			})

			t.Run("collectionName", func(t *testing.T) {
				_, err := subject.Query(ctx,
					client.QueryRequest{
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M"}},
						},
					})
				require.ErrorContains(t, err, "unknown collection ''")

				t.Run("invalid", func(t *testing.T) {
					_, err := subject.Query(ctx, client.QueryRequest{
						CollectionName: "unknown",
						Filters: []client.QueryRequestFilter{
							{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M", LTE: "PT5M"}},
						},
					})
					require.ErrorContains(t, err, "unknown collection 'unknown'")
				})
			})
		})

		t.Run("clusterFilter", func(t *testing.T) {
			t.Run("query all clusters when empty", func(t *testing.T) {
				mockClient.SetResults(
					rest.MockResult{Body: jsonMarshal(t, v1.List[v1.FlowLog]{TotalHits: 1, Items: []v1.FlowLog{
						{ID: "flow-log1"},
					}})},
					rest.MockResult{Body: jsonMarshal(t, v1.List[v1.FlowLog]{TotalHits: 1, Items: []v1.FlowLog{
						{ID: "flow-log2"},
					}})},
				)

				resp, err := subject.Query(ctx, client.QueryRequest{
					CollectionName: "flows",
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M"}},
					},
				})

				require.NoError(t, err)
				require.Len(t, resp.Documents, 2)

				documents := documentsToClusterAndLogID(t, resp.Documents)
				// Check expected logs in both clusters because async mock Results may not always be set on the same cluster
				if slices.Contains(documents["cluster1"], "flow-log1") {
					require.ElementsMatch(t, []string{"flow-log1"}, documents["cluster1"])
					require.ElementsMatch(t, []string{"flow-log2"}, documents["cluster2"])
				} else {
					require.ElementsMatch(t, []string{"flow-log1"}, documents["cluster2"])
					require.ElementsMatch(t, []string{"flow-log2"}, documents["cluster1"])
				}
			})

			t.Run("filters out managed clusters", func(t *testing.T) {
				mockClient.SetResults(
					rest.MockResult{Body: jsonMarshal(t, v1.List[v1.FlowLog]{TotalHits: 1, Items: []v1.FlowLog{
						{ID: "flow-log1"},
					}})},
				)

				resp, err := subject.Query(ctx, client.QueryRequest{
					CollectionName: "flows",
					ClusterFilter:  []client.ManagedClusterName{"non-existing-managed-cluster", "cluster2"},
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M"}},
					},
				})

				require.NoError(t, err)
				require.Len(t, resp.Documents, 1)

				documents := documentsToClusterAndLogID(t, resp.Documents)
				require.Equal(t, map[string][]string{
					"cluster2": {"flow-log1"},
				}, documents)
			})

		})

		t.Run("maxDocs", func(t *testing.T) {

			setMockResult := func() {
				t.Helper()
				mockClient.SetResults(
					rest.MockResult{Body: jsonMarshal(t, v1.List[v1.FlowLog]{TotalHits: 11, Items: []v1.FlowLog{
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
					MaxDocs:        2,
					CollectionName: "flows",
					ClusterFilter:  []client.ManagedClusterName{"cluster1"},
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M"}},
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
					MaxDocs:        0,
					CollectionName: "flows",
					ClusterFilter:  []client.ManagedClusterName{"cluster1"},
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M"}},
					},
				})

				require.NoError(t, err)
				require.Len(t, resp.Documents, MaxQueryDocumentsDefault)
			})

			t.Run("limit", func(t *testing.T) {
				mockResult := v1.List[v1.FlowLog]{TotalHits: 1000}
				for i := int64(0); i < mockResult.TotalHits; i++ {
					mockResult.Items = append(mockResult.Items, v1.FlowLog{ID: "flow-log" + strconv.FormatInt(i, 10)})
				}
				mockClient.SetResults(rest.MockResult{Body: jsonMarshal(t, mockResult)})

				resp, err := subject.Query(ctx, client.QueryRequest{
					MaxDocs:        1000,
					CollectionName: "flows",
					ClusterFilter:  []client.ManagedClusterName{"cluster1"},
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M"}},
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
					rest.MockResult{Body: jsonMarshal(t, v1.List[v1.FlowLog]{TotalHits: 3, Items: []v1.FlowLog{
						{ID: "flow-log1"},
						{ID: "flow-log2"},
						{ID: "flow-log3"},
					}})},
					rest.MockResult{Body: jsonMarshal(t, v1.List[v1.FlowLog]{TotalHits: 2, Items: []v1.FlowLog{
						{ID: "flow-log4"},
						{ID: "flow-log5"},
					}})},
				)

				expectedFlowLogsIDs1 := []string{"flow-log1", "flow-log2", "flow-log3"}
				expectedFlowLogsIDs2 := []string{"flow-log4", "flow-log5"}

				resp, err := subject.Query(ctx, client.QueryRequest{
					CollectionName: "flows",
					ClusterFilter:  []client.ManagedClusterName{"cluster1", "cluster2"},
					Filters: []client.QueryRequestFilter{
						{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M"}},
					},
				})

				require.NoError(t, err)
				require.Len(t, resp.Documents, 5)
				require.Equal(t, client.QueryResponseTotals{Value: 5}, resp.Totals)
				require.Empty(t, resp.GroupValues)
				require.Empty(t, resp.Aggregations)

				documents := documentsToClusterAndLogID(t, resp.Documents)
				// Check expected logs in both clusters because async mock Results may not always be set on the same cluster
				if slices.Contains(documents["cluster1"], expectedFlowLogsIDs1[0]) {
					require.ElementsMatch(t, expectedFlowLogsIDs1, documents["cluster1"])
					require.ElementsMatch(t, expectedFlowLogsIDs2, documents["cluster2"])
				} else {
					require.ElementsMatch(t, expectedFlowLogsIDs1, documents["cluster2"])
					require.ElementsMatch(t, expectedFlowLogsIDs2, documents["cluster1"])
				}
			})

			t.Run("result aggregation", func(t *testing.T) {
				defineAggregations := func(vSum, vAvg, vMin, vMax, vPercentile float64, vCount int64) aggregations.AggregationValues {
					return aggregations.AggregationValues{
						"agg1": aggregations.NewAggregationValue(&vSum, aggregations.NewAggregationSum("f1")),
						"agg2": aggregations.NewAggregationValue(&vAvg, aggregations.NewAggregationAvg("f2")),
						"agg3": aggregations.NewAggregationValue(&vMin, aggregations.NewAggregationMin("f3")),
						"agg4": aggregations.NewAggregationValue(&vMax, aggregations.NewAggregationMax("f4")),
						"agg5": aggregations.NewAggregationValue(&vPercentile, aggregations.NewAggregationPercentile("f5", vPercentile)),
						"agg6": aggregations.NewAggregationValue(&vCount, aggregations.NewAggregationCount()),
					}
				}

				requireAggregationsEqual := func(t *testing.T, aggs1, aggs2 aggregations.AggregationValues) {
					t.Helper()
					require.True(t, maps.EqualFunc(aggs1, aggs2, func(v1, v2 aggregations.AggregationValue) bool {
						return reflect.DeepEqual(v1.Value(), v2.Value())
					}), "expected=%v actual=%v", aggs1, aggs2)
				}

				t.Run("aggregations", func(t *testing.T) {
					aggregatedResult := &result.QueryResult{
						Aggregations: make(aggregations.AggregationValues),
					}
					subject.aggregateSingleClusterResult(aggregatedResult, result.QueryResult{
						Hits: 25,
						Documents: []result.QueryResultDocument{
							{Timestamp: time.Date(2000, 1, 2, 3, 4, 5, 6, time.UTC), Content: "123"},
							{Timestamp: time.Date(2001, 1, 2, 3, 4, 5, 6, time.UTC), Content: 456},
						},
						Aggregations: defineAggregations(11, 22, 33, 44, 55, 66),
					})

					subject.aggregateSingleClusterResult(aggregatedResult, result.QueryResult{
						Hits: 100,
						Documents: []result.QueryResultDocument{
							{Timestamp: time.Date(2010, 1, 2, 3, 4, 5, 6, time.UTC), Content: "789"},
							{Timestamp: time.Date(2011, 1, 2, 3, 4, 5, 6, time.UTC), Content: 120},
						},
						Aggregations: defineAggregations(12, 32, 34, 45, 56, 67),
					})

					require.NoError(t, aggregatedResult.Calculate())

					require.Equal(t, int64(125), aggregatedResult.Hits)

					require.ElementsMatch(t, []result.QueryResultDocument{
						{Timestamp: time.Date(2000, 1, 2, 3, 4, 5, 6, time.UTC), Content: "123"},
						{Timestamp: time.Date(2001, 1, 2, 3, 4, 5, 6, time.UTC), Content: 456},
						{Timestamp: time.Date(2010, 1, 2, 3, 4, 5, 6, time.UTC), Content: "789"},
						{Timestamp: time.Date(2011, 1, 2, 3, 4, 5, 6, time.UTC), Content: 120},
					}, aggregatedResult.Documents)

					requireAggregationsEqual(t, defineAggregations(23, 27, 33, 45, 111, 133), aggregatedResult.Aggregations)
				})

				t.Run("groups", func(t *testing.T) {
					aggregatedResult := &result.QueryResult{
						Aggregations: make(aggregations.AggregationValues),
					}
					subject.aggregateSingleClusterResult(aggregatedResult, result.QueryResult{
						GroupValues: []*groups.GroupValue{
							{
								Key:          "g0-0",
								DocCount:     1100,
								Aggregations: defineAggregations(1, 2, 3, 4, 5, 6),
								SubGroupValues: []*groups.GroupValue{
									{Key: "g1", DocCount: 110, Aggregations: defineAggregations(11, 12, 13, 14, 15, 16)},
									{Key: "g2", DocCount: 220, Aggregations: defineAggregations(21, 22, 23, 24, 25, 26)},
								},
							},
							{
								Key:          "g0-1",
								DocCount:     1200,
								Aggregations: defineAggregations(31, 32, 33, 34, 35, 36),
								SubGroupValues: []*groups.GroupValue{
									{Key: "g2", DocCount: 330, Aggregations: defineAggregations(41, 42, 43, 44, 45, 46)},
								},
							},
						},
					})

					subject.aggregateSingleClusterResult(aggregatedResult, result.QueryResult{
						GroupValues: []*groups.GroupValue{
							{
								Key:          "g0-0",
								DocCount:     1300,
								Aggregations: defineAggregations(51, 52, 53, 54, 55, 56),
								SubGroupValues: []*groups.GroupValue{
									{Key: "g2", DocCount: 440, Aggregations: defineAggregations(61, 62, 63, 64, 65, 66)},
									{Key: "g3", DocCount: 550, Aggregations: defineAggregations(71, 72, 73, 74, 75, 76)},
								},
							},
							{
								Key:          "g0-1",
								DocCount:     1400,
								Aggregations: defineAggregations(81, 82, 83, 84, 85, 86),
								SubGroupValues: []*groups.GroupValue{
									{Key: "g2", DocCount: 660, Aggregations: defineAggregations(91, 92, 93, 94, 95, 96)},
									{Key: "g3", DocCount: 770, Aggregations: defineAggregations(101, 102, 103, 104, 105, 106)},
								},
							},
							{
								Key:          "g0-2",
								DocCount:     1111,
								Aggregations: defineAggregations(111, 112, 113, 114, 115, 116),
								SubGroupValues: []*groups.GroupValue{
									{Key: "g3", DocCount: 880, Aggregations: defineAggregations(121, 122, 123, 124, 125, 126)},
								},
							},
						},
					})

					require.NoError(t, aggregatedResult.Calculate())

					require.Len(t, aggregatedResult.GroupValues, 3)
					require.Equal(t, "g0-0", aggregatedResult.GroupValues[0].Key)
					require.Equal(t, "g0-1", aggregatedResult.GroupValues[1].Key)
					require.Equal(t, "g0-2", aggregatedResult.GroupValues[2].Key)
					require.Equal(t, int64(2400), aggregatedResult.GroupValues[0].DocCount)
					require.Equal(t, int64(2600), aggregatedResult.GroupValues[1].DocCount)
					require.Equal(t, int64(1111), aggregatedResult.GroupValues[2].DocCount)

					requireAggregationsEqual(t, defineAggregations(52, 27, 3, 54, 60, 62), aggregatedResult.GroupValues[0].Aggregations)
					requireAggregationsEqual(t, defineAggregations(112, 57, 33, 84, 120, 122), aggregatedResult.GroupValues[1].Aggregations)
					requireAggregationsEqual(t, defineAggregations(111, 112, 113, 114, 115, 116), aggregatedResult.GroupValues[2].Aggregations)

					require.Len(t, aggregatedResult.GroupValues[0].SubGroupValues, 3)
					require.Len(t, aggregatedResult.GroupValues[1].SubGroupValues, 2)
					require.Len(t, aggregatedResult.GroupValues[2].SubGroupValues, 1)

					require.Equal(t, "g1", aggregatedResult.GroupValues[0].SubGroupValues[0].Key)
					require.Equal(t, "g2", aggregatedResult.GroupValues[0].SubGroupValues[1].Key)
					require.Equal(t, "g3", aggregatedResult.GroupValues[0].SubGroupValues[2].Key)
					require.Equal(t, int64(110), aggregatedResult.GroupValues[0].SubGroupValues[0].DocCount)
					require.Equal(t, int64(660), aggregatedResult.GroupValues[0].SubGroupValues[1].DocCount)
					require.Equal(t, int64(550), aggregatedResult.GroupValues[0].SubGroupValues[2].DocCount)

					require.Equal(t, "g2", aggregatedResult.GroupValues[1].SubGroupValues[0].Key)
					require.Equal(t, "g3", aggregatedResult.GroupValues[1].SubGroupValues[1].Key)
					require.Equal(t, int64(990), aggregatedResult.GroupValues[1].SubGroupValues[0].DocCount)
					require.Equal(t, int64(770), aggregatedResult.GroupValues[1].SubGroupValues[1].DocCount)

					require.Equal(t, "g3", aggregatedResult.GroupValues[2].SubGroupValues[0].Key)
					require.Equal(t, int64(880), aggregatedResult.GroupValues[2].SubGroupValues[0].DocCount)

					requireAggregationsEqual(t, defineAggregations(11, 12, 13, 14, 15, 16), aggregatedResult.GroupValues[0].SubGroupValues[0].Aggregations)
					requireAggregationsEqual(t, defineAggregations(82, 42, 23, 64, 90, 92), aggregatedResult.GroupValues[0].SubGroupValues[1].Aggregations)
					requireAggregationsEqual(t, defineAggregations(71, 72, 73, 74, 75, 76), aggregatedResult.GroupValues[0].SubGroupValues[2].Aggregations)

					requireAggregationsEqual(t, defineAggregations(132, 67, 43, 94, 140, 142), aggregatedResult.GroupValues[1].SubGroupValues[0].Aggregations)
					requireAggregationsEqual(t, defineAggregations(101, 102, 103, 104, 105, 106), aggregatedResult.GroupValues[1].SubGroupValues[1].Aggregations)

					requireAggregationsEqual(t, defineAggregations(121, 122, 123, 124, 125, 126), aggregatedResult.GroupValues[2].SubGroupValues[0].Aggregations)
				})
			})
		})

		t.Run("multi-tenant", func(t *testing.T) {
			subject := NewQueryService(logger, repository, managedClusterLister, 2*time.Minute, "cc-tenant-acme")

			mockClient.SetResults(
				rest.MockResult{Body: jsonMarshal(t, v1.List[v1.FlowLog]{TotalHits: 3, Items: []v1.FlowLog{
					{ID: "flow-log1"},
					{ID: "flow-log2"},
					{ID: "flow-log3"},
				}})},
				rest.MockResult{Body: jsonMarshal(t, v1.List[v1.FlowLog]{TotalHits: 2, Items: []v1.FlowLog{
					{ID: "flow-log4"},
					{ID: "flow-log5"},
				}})},
			)

			expectedFlowLogsIDs1 := []string{"flow-log1", "flow-log2", "flow-log3"}
			expectedFlowLogsIDs2 := []string{"flow-log4", "flow-log5"}

			resp, err := subject.Query(ctx, client.QueryRequest{
				CollectionName: "flows",
				ClusterFilter:  []client.ManagedClusterName{"cluster1", "cluster2"},
				Filters: []client.QueryRequestFilter{
					{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M"}},
				},
			})

			require.NoError(t, err)
			require.Len(t, resp.Documents, 5)
			require.Equal(t, client.QueryResponseTotals{Value: 5}, resp.Totals)
			require.Empty(t, resp.GroupValues)
			require.Empty(t, resp.Aggregations)

			documents := documentsToClusterAndLogID(t, resp.Documents)
			// Check expected logs in both clusters because async mock Results may not always be set on the same cluster
			if slices.Contains(documents["cluster1"], expectedFlowLogsIDs1[0]) {
				require.ElementsMatch(t, expectedFlowLogsIDs1, documents["cluster1"])
				require.ElementsMatch(t, expectedFlowLogsIDs2, documents["cluster2"])
			} else {
				require.ElementsMatch(t, expectedFlowLogsIDs1, documents["cluster2"])
				require.ElementsMatch(t, expectedFlowLogsIDs2, documents["cluster1"])
			}
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
