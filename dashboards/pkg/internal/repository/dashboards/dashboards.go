package dashboards

import (
	"embed"
	"time"

	"github.com/tigera/tds-apiserver/pkg/types"
)

//go:embed global
var GlobalDashboardsEmbed embed.FS

type Dashboard struct {
	ID     types.DashboardID
	Title  string
	Cards  []DashboardCard
	Layout []types.DashboardLayout

	DefaultFilters []types.DashboardFilter

	IsImmutable bool

	OrgID     types.OrganizationID
	ProjectID types.ProjectID

	Version   types.Version
	CreatedBy string
	CreatedAt time.Time
}

type DashboardCardQuery struct {
	MaxDocs        *int
	Filters        []map[string]any
	GroupBys       []map[string]any
	Aggregations   map[string]any
	CollectionName string
}
type DashboardCard struct {
	ID      types.DashboardCardID
	Title   string
	Chart   types.DashboardCardChart
	Query   DashboardCardQuery
	Mapping types.DashboardCardMapping
}

type DashboardCreateCommand struct {
	IDGenerator func() types.DashboardID

	OrgID     types.OrganizationID
	ProjectID types.ProjectID

	Title          string
	Cards          []DashboardCard
	Layout         []types.DashboardLayout
	DefaultFilters []types.DashboardFilter
}

type DashboardUpdateCommand struct {
	ID             types.DashboardID
	CurrentVersion types.Version

	Title          string
	Cards          []DashboardCard
	Layout         []types.DashboardLayout
	DefaultFilters []types.DashboardFilter
}
