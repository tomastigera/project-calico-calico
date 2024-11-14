package query

import (
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/aggregations"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/collections"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/filters"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/groups"
)

type ManagedClusterName string

type QueryRequest struct {
	Groups         groups.Groups
	Filters        filters.Criteria
	ClusterID      ManagedClusterName
	Aggregations   aggregations.Aggregations
	MaxDocuments   int
	CollectionName collections.CollectionName
}
