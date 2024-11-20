package query

import (
	"context"
	"encoding/json"
	"golang.org/x/exp/maps"
	"reflect"
	"strconv"
	"sync"
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
	)

	logger := logging.New("TestQueryService")

	tenantID := "fake-tenant"

	mockClient := &concurrentMockClient{
		t:      t,
		m:      sync.Mutex{},
		client: lsclient.NewMockClient(tenantID),
	}
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
				rest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{})},
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
					rest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{TotalHits: 1, Items: []lsv1.FlowLog{
						{ID: "flow-log1"},
					}})},
					rest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{TotalHits: 1, Items: []lsv1.FlowLog{
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
					rest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{TotalHits: 1, Items: []lsv1.FlowLog{
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
				mockResult := lsv1.List[lsv1.FlowLog]{TotalHits: 1000}
				for i := int64(0); i < mockResult.TotalHits; i++ {
					mockResult.Items = append(mockResult.Items, lsv1.FlowLog{ID: "flow-log" + strconv.FormatInt(i, 10)})
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

			t.Run("result", func(t *testing.T) {
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

					t.Run("max values", func(t *testing.T) {
						t.Run("discrete group", func(t *testing.T) {

							groupResults := []bucketItems{
								{
									Buckets: []bucketItem{
										{"key": "1"}, {"key": "2"}, {"key": "3"}, {"key": "4"},
										{"key": "5"}, {"key": "6"}, {"key": "7"}, {"key": "8"},
									},
								},
								{
									Buckets: []bucketItem{
										{"key": "9"}, {"key": "10"}, {"key": "11"}, {"key": "12"},
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
										{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M"}},
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
									{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M"}},
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
										{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M"}},
									},
									GroupBys: []client.QueryRequestGroup{
										{Type: client.GroupType(groups.GroupTypeTime)},
									},
								})

								require.NoError(t, err)
								require.Empty(t, resp.Aggregations)
								require.Len(t, resp.GroupValues, 2000)
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
									{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M"}},
								},
								GroupBys: []client.QueryRequestGroup{
									{Type: client.GroupType(groups.GroupTypeTime), MaxValues: 3},
								},
							})
							require.NoError(t, err)
							require.Empty(t, resp.Aggregations)

							require.Equal(t, []client.QueryResponseGroupValue{
								{Key: "1150", Aggregations: client.QueryResponseAggregations{}},
								{Key: "1200", Aggregations: client.QueryResponseAggregations{}},
								{Key: "1300", Aggregations: client.QueryResponseAggregations{}},
							}, resp.GroupValues)
						})
					})
				})

				t.Run("results sort order", func(t *testing.T) {
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

					t.Run("documents", func(t *testing.T) {
						mockClient.SetResults(
							rest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{TotalHits: 3, Items: []lsv1.FlowLog{
								{ID: "flow-log1", Timestamp: 500},
								{ID: "flow-log2", Timestamp: 200},
								{ID: "flow-log3", Timestamp: 150},
							}})},
							rest.MockResult{Body: jsonMarshal(t, lsv1.List[lsv1.FlowLog]{TotalHits: 3, Items: []lsv1.FlowLog{
								{ID: "flow-log4", Timestamp: 600},
								{ID: "flow-log5", Timestamp: 300},
								{ID: "flow-log5", Timestamp: 400},
							}})},
						)

						resp, err := subject.Query(ctx, client.QueryRequest{
							CollectionName: "flows",
							ClusterFilter:  []client.ManagedClusterName{"cluster1", "cluster2"},
							Filters: []client.QueryRequestFilter{
								{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M"}},
							},
						})

						require.NoError(t, err)
						require.Len(t, resp.Documents, 6)
						require.Equal(t, client.QueryResponseTotals{Value: 6}, resp.Totals)
						require.Empty(t, resp.GroupValues)
						require.Empty(t, resp.Aggregations)

						require.Equal(t,
							[]int64{600, 500, 400, 300, 200, 150},
							slices.Map(resp.Documents, func(d any) int64 {
								var document struct {
									Timestamp int64 `json:"@timestamp"`
								}
								documentsJSON, err := json.Marshal(d)
								require.NoError(t, err)
								require.NoError(t, json.Unmarshal(documentsJSON, &document))
								return document.Timestamp
							}),
						)
					})

					t.Run("groups", func(t *testing.T) {

						groupResults := []bucketItems{
							{
								Buckets: []bucketItem{
									{
										"key":           "1500",
										"key_as_string": "1500",
										"g1": bucketItem{
											"buckets": []bucketItem{
												{"key": "g1-3", "doc_count": 3},
												{"key": "g1-9", "doc_count": 9},
												{"key": "g1-1", "doc_count": 1},
											},
										},
									},
									{"key_as_string": "1200"},
									{"key_as_string": "1150"},
								},
							},
							{
								Buckets: []bucketItem{
									{"key_as_string": "1600"},
									{"key_as_string": "1300"},
									{
										"key_as_string": "1400",
										"g1": bucketItem{
											"buckets": []bucketItem{
												{"key": "g1-30", "doc_count": 30},
												{"key": "g1-90", "doc_count": 90},
												{"key": "g1-10", "doc_count": 10},
											},
										},
									},
									{
										"key_as_string": "1500",
										"g1": bucketItem{
											"buckets": []bucketItem{
												{"key": "g1-7", "doc_count": 7},
												{"key": "g1-11", "doc_count": 11},
												{"key": "g1-2", "doc_count": 2},
											},
										},
									},
								},
							},
						}

						t.Run("desc", func(t *testing.T) {

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
									{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M"}},
								},
								GroupBys: []client.QueryRequestGroup{
									{Type: client.GroupType(groups.GroupTypeTime), Order: &client.QueryRequestGroupOrder{SortAsc: false}},
									{Type: client.GroupType(groups.GroupTypeDiscrete), Order: &client.QueryRequestGroupOrder{SortAsc: false}},
								},
							})

							require.NoError(t, err)
							require.Empty(t, resp.Aggregations)

							require.Equal(t, []client.QueryResponseGroupValue{
								{Key: "1600", Aggregations: client.QueryResponseAggregations{}},
								{Key: "1500", Aggregations: client.QueryResponseAggregations{}, NestedValues: []any{
									client.QueryResponseGroupValue{Key: "g1-11", Aggregations: client.QueryResponseAggregations{}},
									client.QueryResponseGroupValue{Key: "g1-9", Aggregations: client.QueryResponseAggregations{}},
									client.QueryResponseGroupValue{Key: "g1-7", Aggregations: client.QueryResponseAggregations{}},
									client.QueryResponseGroupValue{Key: "g1-3", Aggregations: client.QueryResponseAggregations{}},
									client.QueryResponseGroupValue{Key: "g1-2", Aggregations: client.QueryResponseAggregations{}},
									client.QueryResponseGroupValue{Key: "g1-1", Aggregations: client.QueryResponseAggregations{}},
								}},
								{Key: "1400", Aggregations: client.QueryResponseAggregations{}, NestedValues: []any{
									client.QueryResponseGroupValue{Key: "g1-90", Aggregations: client.QueryResponseAggregations{}},
									client.QueryResponseGroupValue{Key: "g1-30", Aggregations: client.QueryResponseAggregations{}},
									client.QueryResponseGroupValue{Key: "g1-10", Aggregations: client.QueryResponseAggregations{}},
								}},
								{Key: "1300", Aggregations: client.QueryResponseAggregations{}},
								{Key: "1200", Aggregations: client.QueryResponseAggregations{}},
								{Key: "1150", Aggregations: client.QueryResponseAggregations{}},
							}, resp.GroupValues)

						})

						t.Run("asc", func(t *testing.T) {

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
									{Criterion: client.QueryRequestFilterCriterion{Type: "relativeTimeRange", GTE: "PT15M"}},
								},
								GroupBys: []client.QueryRequestGroup{
									{Type: client.GroupType(groups.GroupTypeTime), Order: &client.QueryRequestGroupOrder{SortAsc: true}},
									{Type: client.GroupType(groups.GroupTypeDiscrete), Order: &client.QueryRequestGroupOrder{SortAsc: true}},
								},
							})

							require.NoError(t, err)
							require.Empty(t, resp.Aggregations)

							require.Equal(t, []client.QueryResponseGroupValue{
								{Key: "1150", Aggregations: client.QueryResponseAggregations{}},
								{Key: "1200", Aggregations: client.QueryResponseAggregations{}},
								{Key: "1300", Aggregations: client.QueryResponseAggregations{}},
								{Key: "1400", Aggregations: client.QueryResponseAggregations{}, NestedValues: []any{
									client.QueryResponseGroupValue{Key: "g1-10", Aggregations: client.QueryResponseAggregations{}},
									client.QueryResponseGroupValue{Key: "g1-30", Aggregations: client.QueryResponseAggregations{}},
									client.QueryResponseGroupValue{Key: "g1-90", Aggregations: client.QueryResponseAggregations{}},
								}},
								{Key: "1500", Aggregations: client.QueryResponseAggregations{}, NestedValues: []any{
									client.QueryResponseGroupValue{Key: "g1-1", Aggregations: client.QueryResponseAggregations{}},
									client.QueryResponseGroupValue{Key: "g1-2", Aggregations: client.QueryResponseAggregations{}},
									client.QueryResponseGroupValue{Key: "g1-3", Aggregations: client.QueryResponseAggregations{}},
									client.QueryResponseGroupValue{Key: "g1-7", Aggregations: client.QueryResponseAggregations{}},
									client.QueryResponseGroupValue{Key: "g1-9", Aggregations: client.QueryResponseAggregations{}},
									client.QueryResponseGroupValue{Key: "g1-11", Aggregations: client.QueryResponseAggregations{}},
								}},
								{Key: "1600", Aggregations: client.QueryResponseAggregations{}},
							}, resp.GroupValues)
						})
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

// Linseed MockClient implementation uses a non-exported restClient that does not handle concurrent results correctly
// so multi-cluster results will sometimes incorrectly contain the same MockResult with it
// Workaround: Implement a local mock client that handles concurrency
// TODO: phase 2: update linseed mock client to handle concurrency (see https://tigera.atlassian.net/browse/TSLA-8187 )
type concurrentMockClient struct {
	client lsclient.MockClient

	t *testing.T
	m sync.Mutex
}

var _ lsclient.MockClient = (*concurrentMockClient)(nil)

func (c *concurrentMockClient) RESTClient() rest.RESTClient {
	return c.client.RESTClient()
}

func (c *concurrentMockClient) L3Flows(cluster string) lsclient.L3FlowsInterface {
	c.t.Fatal("should not be called")
	return nil
}

func (c *concurrentMockClient) L7Flows(cluster string) lsclient.L7FlowsInterface {
	c.t.Fatal("should not be called")
	return nil
}

func (c *concurrentMockClient) DNSFlows(cluster string) lsclient.DNSFlowsInterface {
	c.t.Fatal("should not be called")
	return nil
}

func (c *concurrentMockClient) Events(cluster string) lsclient.EventsInterface {
	c.t.Fatal("should not be called")
	return nil
}

func (c *concurrentMockClient) AuditLogs(cluster string) lsclient.AuditLogsInterface {
	c.t.Fatal("should not be called")
	return nil
}

func (c *concurrentMockClient) BGPLogs(cluster string) lsclient.BGPLogsInterface {
	c.t.Fatal("should not be called")
	return nil
}

func (c *concurrentMockClient) Processes(cluster string) lsclient.ProcessesInterface {
	c.t.Fatal("should not be called")
	return nil
}

func (c *concurrentMockClient) WAFLogs(cluster string) lsclient.WAFLogsInterface {
	c.t.Fatal("should not be called")
	return nil
}

func (c *concurrentMockClient) Compliance(cluster string) lsclient.ComplianceInterface {
	c.t.Fatal("should not be called")
	return nil
}

func (c *concurrentMockClient) RuntimeReports(cluster string) lsclient.RuntimeReportsInterface {
	c.t.Fatal("should not be called")
	return nil
}

func (c *concurrentMockClient) ThreatFeeds(cluster string) lsclient.ThreatFeedsInterface {
	c.t.Fatal("should not be called")
	return nil
}

func (c *concurrentMockClient) SetResults(results ...rest.MockResult) {
	c.client.SetResults(results...)
}

func (c *concurrentMockClient) Requests() []*rest.MockRequest {
	return c.client.Requests()
}

func (c *concurrentMockClient) FlowLogs(cluster string) lsclient.FlowLogsInterface {
	return &concurrentMockFlowLogs{t: c.t, m: &c.m, cluster: cluster, client: c.client}
}

func (c *concurrentMockClient) DNSLogs(cluster string) lsclient.DNSLogsInterface {
	return &concurrentMockDNSLogs{t: c.t, m: &c.m, cluster: cluster, client: c.client}
}

func (c *concurrentMockClient) L7Logs(cluster string) lsclient.L7LogsInterface {
	return &concurrentMockL7Logs{t: c.t, m: &c.m, cluster: cluster, client: c.client}
}

/* concurrentMockDNSLogs */
type concurrentMockDNSLogs struct {
	client  lsclient.MockClient
	cluster string

	t *testing.T
	m *sync.Mutex
}

var _ lsclient.DNSLogsInterface = concurrentMockDNSLogs{}

func (c concurrentMockDNSLogs) List(ctx context.Context, params lsv1.Params) (*lsv1.List[lsv1.DNSLog], error) {
	dnsLogs := lsv1.List[lsv1.DNSLog]{}
	err := c.ListInto(ctx, params, &dnsLogs)
	if err != nil {
		return nil, err
	}
	return &dnsLogs, err
}

func (c concurrentMockDNSLogs) ListInto(ctx context.Context, params lsv1.Params, listable lsv1.Listable) error {
	c.m.Lock()
	defer c.m.Unlock()

	return c.client.DNSLogs(c.cluster).ListInto(ctx, params, listable)
}

func (c concurrentMockDNSLogs) Create(ctx context.Context, logs []lsv1.DNSLog) (*lsv1.BulkResponse, error) {
	c.t.Fatal("should not be called")
	return nil, nil
}

func (c concurrentMockDNSLogs) Aggregations(ctx context.Context, params lsv1.Params) (elastic.Aggregations, error) {
	c.m.Lock()
	defer c.m.Unlock()
	return c.client.DNSLogs(c.cluster).Aggregations(ctx, params)
}

/* concurrentMockFlowLogs */
type concurrentMockFlowLogs struct {
	client  lsclient.MockClient
	cluster string

	t *testing.T
	m *sync.Mutex
}

var _ lsclient.FlowLogsInterface = concurrentMockFlowLogs{}

func (c concurrentMockFlowLogs) List(ctx context.Context, params lsv1.Params) (*lsv1.List[lsv1.FlowLog], error) {
	flowLogs := lsv1.List[lsv1.FlowLog]{}
	err := c.ListInto(ctx, params, &flowLogs)
	if err != nil {
		return nil, err
	}
	return &flowLogs, err
}

func (c concurrentMockFlowLogs) ListInto(ctx context.Context, params lsv1.Params, listable lsv1.Listable) error {
	c.m.Lock()
	defer c.m.Unlock()

	return c.client.FlowLogs(c.cluster).ListInto(ctx, params, listable)
}

func (c concurrentMockFlowLogs) Create(ctx context.Context, logs []lsv1.FlowLog) (*lsv1.BulkResponse, error) {
	c.t.Fatal("should not be called")
	return nil, nil
}

func (c concurrentMockFlowLogs) Aggregations(ctx context.Context, params lsv1.Params) (elastic.Aggregations, error) {
	c.m.Lock()
	defer c.m.Unlock()

	return c.client.FlowLogs(c.cluster).Aggregations(ctx, params)
}

/* concurrentMockL7Logs */
type concurrentMockL7Logs struct {
	client  lsclient.MockClient
	cluster string

	t *testing.T
	m *sync.Mutex
}

var _ lsclient.L7LogsInterface = concurrentMockL7Logs{}

func (c concurrentMockL7Logs) List(ctx context.Context, params lsv1.Params) (*lsv1.List[lsv1.L7Log], error) {
	l7Logs := lsv1.List[lsv1.L7Log]{}
	err := c.ListInto(ctx, params, &l7Logs)
	if err != nil {
		return nil, err
	}
	return &l7Logs, err
}

func (c concurrentMockL7Logs) ListInto(ctx context.Context, params lsv1.Params, listable lsv1.Listable) error {
	c.m.Lock()
	defer c.m.Unlock()

	return c.client.L7Logs(c.cluster).ListInto(ctx, params, listable)
}

func (c concurrentMockL7Logs) Create(ctx context.Context, logs []lsv1.L7Log) (*lsv1.BulkResponse, error) {
	c.t.Fatal("should not be called")
	return nil, nil
}

func (c concurrentMockL7Logs) Aggregations(ctx context.Context, params lsv1.Params) (elastic.Aggregations, error) {
	c.m.Lock()
	defer c.m.Unlock()

	return c.client.L7Logs(c.cluster).Aggregations(ctx, params)
}
