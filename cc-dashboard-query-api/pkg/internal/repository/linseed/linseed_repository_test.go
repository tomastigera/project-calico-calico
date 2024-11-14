package linseed

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/collections"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/query"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/query/result"
	"github.com/tigera/tds-apiserver/pkg/logging"
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

			queryResult := subject.Query(ctx, query.QueryRequest{
				CollectionName: collections.CollectionNameDNS,
				ClusterID:      "fake-cluster",
			})
			require.NoError(t, queryResult.Err)
			require.Equal(t, result.QueryResult{
				Documents: []result.QueryResultDocument{},
			}, queryResult)
		})

		t.Run("results include cluster name", func(t *testing.T) {
			mockClient.SetResults(rest.MockResult{
				Body: json.RawMessage(`{"items": null}`),
			})

			queryResult := subject.Query(ctx, query.QueryRequest{
				CollectionName: collections.CollectionNameDNS,
				ClusterID:      "fake-cluster",
			})
			require.NoError(t, queryResult.Err)
			require.Equal(t, result.QueryResult{
				Documents: []result.QueryResultDocument{},
			}, queryResult)
		})
	})
}
