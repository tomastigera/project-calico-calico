package linseed

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/stretchr/testify/require"

	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/query/result"
	"github.com/tigera/tds-apiserver/pkg/logging"
)

func TestLinseedCollectionClientFlows(t *testing.T) {

	tenantID := "fake-tenant"
	ctx := context.Background()
	logger := logging.New("TestLinseedCollectionClientFlows")

	mockClient := lsclient.NewMockClient(tenantID)
	subject := newLinseedCollectionClientFlows(logger, mockClient)

	_, _ = ctx, subject
	t.Run("list", func(t *testing.T) {
		t.Run("params", func(t *testing.T) {
			t.Run("params", func(t *testing.T) {
				now := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
				repositoryQueryParams := newQueryParams(0)
				repositoryQueryParams.linseedQueryParams.TimeRange = &lmav1.TimeRange{
					From: time.Date(2023, 1, 2, 3, 4, 5, 0, time.UTC),
					To:   time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
					Now:  &now,
				}

				repositoryQueryParams.selector = "sel1 = sel1"
				// domain matches should be ignored for non-DNS collections
				repositoryQueryParams.domainMatches[lsv1.DomainMatchQname] = []string{"test-domain1.com", "test-domain2.com"}

				params, err := subject.Params(repositoryQueryParams, nil)
				require.NoError(t, err)
				require.Equal(t, &lsv1.FlowLogParams{
					QueryParams: repositoryQueryParams.linseedQueryParams,
					LogSelectionParams: lsv1.LogSelectionParams{
						Selector: "sel1 = sel1",
					},
					QuerySortParams: lsv1.QuerySortParams{
						Sort: []lsv1.SearchRequestSortBy{
							{Field: "@timestamp", Descending: true},
						},
					},
				}, params)
			})
		})

		t.Run("query result", func(t *testing.T) {
			flowLogs := []lsv1.FlowLog{
				{DestName: "test-dst1", TCPLostPackets: 11, Timestamp: time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC).Unix()},
				{DestName: "test-dst2", TCPLostPackets: 22, Timestamp: time.Date(2021, 1, 2, 3, 4, 5, 0, time.UTC).Unix()},
			}

			mockClient.SetResults(rest.MockResult{
				Body: lsv1.List[lsv1.FlowLog]{
					Items:     flowLogs,
					TotalHits: 22,
				},
			})
			queryResult, err := subject.List(ctx, "fake-cluster", &lsv1.QueryParams{})
			require.NoError(t, err)
			require.Equal(t, result.QueryResult{
				Hits: 22,
				Documents: []result.QueryResultDocument{
					{
						Content: flowLogDocument{
							Cluster: "fake-cluster",
							FlowLog: lsv1.FlowLog{
								DestName:       "test-dst1",
								TCPLostPackets: 11,
								Timestamp:      time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC).Unix(),
							},
						},
						Timestamp: time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC),
					},
					{
						Content: flowLogDocument{
							Cluster: "fake-cluster",
							FlowLog: lsv1.FlowLog{
								DestName:       "test-dst2",
								TCPLostPackets: 22,
								Timestamp:      time.Date(2021, 1, 2, 3, 4, 5, 0, time.UTC).Unix(),
							},
						},
						Timestamp: time.Date(2021, 1, 2, 3, 4, 5, 0, time.UTC),
					},
				},
			}, queryResult)
		})
	})

	t.Run("aggregations", func(t *testing.T) {
		t.Run("params", func(t *testing.T) {
			agg0, err := elasticAggregationToJSON(elastic.NewTermsAggregation().Field("f1").
				SubAggregation("a_0", elastic.NewTermsAggregation().Field("fa1")).
				SubAggregation("g1",
					elastic.NewTermsAggregation().Field("f2").
						SubAggregation("a_0", elastic.NewTermsAggregation().Field("fa1"))))
			require.NoError(t, err)

			agg1, err := elasticAggregationToJSON(elastic.NewTermsAggregation().Field("fa1"))
			require.NoError(t, err)

			aggregations := map[string]json.RawMessage{"g0": agg0, "a_0": agg1}

			now := time.Date(2025, 1, 2, 3, 4, 5, 6, time.UTC)
			repositoryQueryParams := newQueryParams(0)
			repositoryQueryParams.linseedQueryParams.TimeRange = &lmav1.TimeRange{
				From: time.Date(2023, 1, 2, 3, 4, 5, 6, time.UTC),
				To:   time.Date(2024, 1, 2, 3, 4, 5, 6, time.UTC),
				Now:  &now,
			}
			repositoryQueryParams.selector = "sel2 = sel2"
			// domain matches should be ignored for non-DNS collections
			repositoryQueryParams.domainMatches[lsv1.DomainMatchQname] = []string{"test-domain1.com", "test-domain2.com"}

			params, err := subject.Params(repositoryQueryParams, aggregations)
			require.NoError(t, err)
			require.Equal(t, &lsv1.FlowLogAggregationParams{
				FlowLogParams: lsv1.FlowLogParams{
					QueryParams: repositoryQueryParams.linseedQueryParams,
					LogSelectionParams: lsv1.LogSelectionParams{
						Selector: "sel2 = sel2",
					},
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
			}, params)
		})

		t.Run("query result", func(t *testing.T) {

			expectedAggregations := elastic.Aggregations{
				"agg1": json.RawMessage(`{"buckets":[]}`),
				"agg2": json.RawMessage(`{"buckets":[]}`),
			}

			mockClient.SetResults(rest.MockResult{
				Body: map[string]json.RawMessage{
					"agg1": json.RawMessage(`{"buckets":[]}`),
					"agg2": json.RawMessage(`{"buckets":[]}`)},
			})

			aggrResult, err := subject.Aggregations(ctx, "fake-cluster", &lsv1.FlowLogAggregationParams{
				Aggregations: elastic.Aggregations{
					"agg1": json.RawMessage(`{"terms":{"field":"f1"}}`),
					"agg2": json.RawMessage(`{"terms":{"field":"f2"}}`),
				},
			})
			require.NoError(t, err)
			require.Equal(t, expectedAggregations, aggrResult)
		})
	})
}
