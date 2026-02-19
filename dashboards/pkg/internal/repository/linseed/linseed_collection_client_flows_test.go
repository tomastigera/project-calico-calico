package linseed

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/stretchr/testify/require"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/lib/slices"

	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/collections"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/filters"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/query/result"
	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
)

func TestLinseedCollectionClientFlows(t *testing.T) {

	tenantID := "fake-tenant"
	ctx := context.Background()
	logger := logging.New("TestLinseedCollectionClientFlows")

	mockClient := lsclient.NewMockClient(tenantID)
	subject := newLinseedCollectionClientFlows(logger, mockClient)

	collectionsMap := slices.AssociateBy(collections.Collections(nil), func(c collections.Collection) collections.CollectionName {
		return c.Name()
	})

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
				params: newQueryParamsHelper(t, &now, "start_time", "sel1 = sel1", nil, nil),
				expected: &lsv1.FlowLogParams{
					QueryParams: expectedQueryParams(&now),
					LogSelectionParams: lsv1.LogSelectionParams{
						Selector: "sel1 = sel1",
					},
					QuerySortParams: lsv1.QuerySortParams{
						Sort: []lsv1.SearchRequestSortBy{
							{Field: "start_time", Descending: true},
						},
					},
				},
			},
			{
				name:   "with aggregation",
				params: newQueryParamsHelper(t, &now, "start_time", "sel2 = sel2", nil, nil),
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
				expected: &lsv1.FlowLogAggregationParams{
					FlowLogParams: lsv1.FlowLogParams{
						QueryParams: expectedQueryParams(&now),
						LogSelectionParams: lsv1.LogSelectionParams{
							Selector: "sel2 = sel2",
						},
						QuerySortParams: lsv1.QuerySortParams{
							Sort: []lsv1.SearchRequestSortBy{
								{Field: "start_time", Descending: true},
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
				params: newQueryParamsHelper(t, &now, "start_time", "sel3 = sel3", []string{"test-domain1.com", "test-domain2.com"}, nil),
				expected: &lsv1.FlowLogParams{
					QueryParams: expectedQueryParams(&now),
					LogSelectionParams: lsv1.LogSelectionParams{
						Selector: "sel3 = sel3",
					},
					QuerySortParams: lsv1.QuerySortParams{
						Sort: []lsv1.SearchRequestSortBy{
							{Field: "start_time", Descending: true},
						},
					},
				},
			},
			{
				name: "with permissions",
				params: newQueryParamsHelper(t, &now, "start_time", "sel4 = sel4", nil, []v3.AuthorizedResourceVerbs{
					{
						APIGroup: "lma.tigera.io", Resource: "pods", Verbs: []v3.AuthorizedResourceVerb{{
							Verb: "list", ResourceGroups: []v3.AuthorizedResourceGroup{
								{Namespace: "namespace1", ManagedCluster: "cluster1"},
								{Namespace: "namespace2"},
							},
						}},
					}}),
				expected: &lsv1.FlowLogParams{
					QueryParams: expectedQueryParams(&now),
					LogSelectionParams: lsv1.LogSelectionParams{
						Selector: "sel4 = sel4",
						Permissions: []v3.AuthorizedResourceVerbs{
							{
								APIGroup: "lma.tigera.io", Resource: "pods", Verbs: []v3.AuthorizedResourceVerb{{
									Verb: "list", ResourceGroups: []v3.AuthorizedResourceGroup{
										{Namespace: "namespace1", ManagedCluster: "cluster1"},
										{Namespace: "namespace2"},
									},
								}},
							}},
					},
					QuerySortParams: lsv1.QuerySortParams{
						Sort: []lsv1.SearchRequestSortBy{
							{Field: "start_time", Descending: true},
						},
					},
				},
			},
			{
				name: "with policy matches",
				params: func() *queryParams {
					qp, _ := newQueryParams(0, 0, "start_time", []string{"fake-cluster"}, nil)
					qp.linseedQueryParams.TimeRange = &lmav1.TimeRange{
						From: time.Date(2023, 1, 2, 3, 4, 5, 0, time.UTC),
						To:   time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
						Now:  &now,
					}
					policyTypeField, _ := collectionsMap[collections.CollectionNameFlows].Field(collections.FieldNamePolicyType)
					_ = qp.setCriteria(filters.Criteria{
						filters.NewEquals(policyTypeField, "staged", false),
						filters.NewEquals(policyTypeField, "enforced", false),
					}, now)
					return qp
				}(),
				expected: &lsv1.FlowLogParams{
					QueryParams: expectedQueryParams(&now),
					LogSelectionParams: lsv1.LogSelectionParams{
						Selector: "",
					},
					QuerySortParams: lsv1.QuerySortParams{
						Sort: []lsv1.SearchRequestSortBy{
							{Field: "start_time", Descending: true},
						},
					},
					EnforcedPolicyMatches: []lsv1.PolicyMatch{{Staged: false}},
					PendingPolicyMatches:  []lsv1.PolicyMatch{{Staged: true}},
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
		flowLogs := []lsv1.FlowLog{
			{DestName: "test-dst1", Cluster: "fake-cluster", TCPLostPackets: 11, StartTime: time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC).Unix()},
			{DestName: "test-dst2", Cluster: "fake-cluster", TCPLostPackets: 22, StartTime: time.Date(2021, 1, 2, 3, 4, 5, 0, time.UTC).Unix()},
		}

		mockClient.SetResults(rest.MockResult{
			Body: lsv1.List[lsv1.FlowLog]{
				Items:     flowLogs,
				TotalHits: 22,
			},
		})
		queryResult, err := subject.List(ctx, &lsv1.QueryParams{})
		require.NoError(t, err)
		require.Equal(t, result.QueryResult{
			Hits: 22,
			Documents: []result.QueryResultDocument{
				{
					Content: lsv1.FlowLog{
						DestName:       "test-dst1",
						Cluster:        "fake-cluster",
						TCPLostPackets: 11,
						StartTime:      time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC).Unix(),
					},
					Timestamp: time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC),
				},
				{
					Content: lsv1.FlowLog{
						DestName:       "test-dst2",
						Cluster:        "fake-cluster",
						TCPLostPackets: 22,
						StartTime:      time.Date(2021, 1, 2, 3, 4, 5, 0, time.UTC).Unix(),
					},
					Timestamp: time.Date(2021, 1, 2, 3, 4, 5, 0, time.UTC),
				},
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

		aggrResult, err := subject.Aggregations(ctx, &lsv1.FlowLogAggregationParams{
			Aggregations: elastic.Aggregations{
				"agg1": json.RawMessage(`{"terms":{"field":"f1"}}`),
				"agg2": json.RawMessage(`{"terms":{"field":"f2"}}`),
			},
		})
		require.NoError(t, err)
		require.Equal(t, expectedAggregations, aggrResult)
	})
}
