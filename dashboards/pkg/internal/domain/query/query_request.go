package query

import (
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/aggregations"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/collections"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/filters"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/groups"
)

type ManagedClusterName string

type QueryRequest struct {
	Groups         groups.Groups
	Filters        filters.Criteria
	ClusterIDs     []ManagedClusterName
	Aggregations   aggregations.Aggregations
	MaxDocuments   int
	PageNum        int
	CollectionName collections.CollectionName
}
