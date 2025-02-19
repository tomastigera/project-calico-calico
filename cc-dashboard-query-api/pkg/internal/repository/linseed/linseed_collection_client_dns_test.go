package linseed

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/stretchr/testify/require"

	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/query/result"
	"github.com/tigera/tds-apiserver/lib/logging"
)

func TestLinseedCollectionClientDNS(t *testing.T) {

	tenantID := "fake-tenant"
	ctx := context.Background()
	logger := logging.New("TestLinseedCollectionClientDNS")

	mockClient := lsclient.NewMockClient(tenantID)
	subject := newLinseedCollectionClientDNS(logger, mockClient)

	t.Run("list", func(t *testing.T) {
		t.Run("params", func(t *testing.T) {
			now := time.Date(2025, 1, 2, 3, 4, 5, 6, time.UTC)
			repositoryQueryParams := newQueryParams(0)
			repositoryQueryParams.linseedQueryParams.TimeRange = &lmav1.TimeRange{
				From: time.Date(2023, 1, 2, 3, 4, 5, 6, time.UTC),
				To:   time.Date(2024, 1, 2, 3, 4, 5, 6, time.UTC),
				Now:  &now,
			}
			repositoryQueryParams.selector = "sel1 = sel1"
			repositoryQueryParams.domainMatches[lsv1.DomainMatchQname] = []string{"test-domain1.com", "test-domain2.com"}

			params, err := subject.Params(repositoryQueryParams, nil)
			require.NoError(t, err)
			require.Equal(t, &lsv1.DNSLogParams{
				QueryParams: repositoryQueryParams.linseedQueryParams,
				DomainMatches: []lsv1.DomainMatch{
					{Type: lsv1.DomainMatchQname, Domains: []string{"test-domain1.com", "test-domain2.com"}},
				},
				LogSelectionParams: lsv1.LogSelectionParams{
					Selector: "sel1 = sel1",
				},
				QuerySortParams: lsv1.QuerySortParams{
					Sort: []lsv1.SearchRequestSortBy{
						{Field: "start_time", Descending: true},
					},
				},
			}, params)
		})

		t.Run("query result", func(t *testing.T) {
			ip := net.ParseIP("1.2.3.4")
			dnsLogs := []lsv1.DNSLog{
				{QName: "test-domain1.com", RRSets: make(lsv1.DNSRRSets), StartTime: time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)},
				{QName: "test-domain2.com", RRSets: make(lsv1.DNSRRSets), StartTime: time.Date(2021, 1, 2, 3, 4, 5, 0, time.UTC), ClientIP: &ip},
			}

			mockClient.SetResults(rest.MockResult{
				Body: lsv1.List[lsv1.DNSLog]{
					Items:     dnsLogs,
					TotalHits: 22,
				},
			})
			queryResult, err := subject.List(ctx, "fake-cluster", &lsv1.QueryParams{})
			require.NoError(t, err)
			require.Equal(t, result.QueryResult{
				Hits: 22,
				Documents: []result.QueryResultDocument{
					{Content: dnsLogDocument{ClientIP: "0.0.0.0", Cluster: "fake-cluster", DNSLog: dnsLogs[0]}, Timestamp: time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)},
					{Content: dnsLogDocument{ClientIP: "1.2.3.4", Cluster: "fake-cluster", DNSLog: dnsLogs[1]}, Timestamp: time.Date(2021, 1, 2, 3, 4, 5, 0, time.UTC)},
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
			repositoryQueryParams.domainMatches[lsv1.DomainMatchQname] = []string{"test-domain1.com", "test-domain2.com"}

			params, err := subject.Params(repositoryQueryParams, aggregations)
			require.NoError(t, err)
			require.Equal(t, &lsv1.DNSAggregationParams{
				DNSLogParams: lsv1.DNSLogParams{
					QueryParams: repositoryQueryParams.linseedQueryParams,
					DomainMatches: []lsv1.DomainMatch{
						{Type: lsv1.DomainMatchQname, Domains: []string{"test-domain1.com", "test-domain2.com"}},
					},
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

			aggrResult, err := subject.Aggregations(ctx, "fake-cluster", &lsv1.QueryParams{})
			require.NoError(t, err)
			require.Equal(t, expectedAggregations, aggrResult)
		})
	})
}
