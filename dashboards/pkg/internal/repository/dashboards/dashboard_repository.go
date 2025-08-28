package dashboards

import (
	"github.com/tigera/tds-apiserver/pkg/types"

	"github.com/projectcalico/calico/dashboards/pkg/internal/security"
)

type Repository interface {
	List(ctx security.Context, orgID types.OrganizationID, projectID types.ProjectID) ([]Dashboard, error)
	Count(ctx security.Context, orgID types.OrganizationID, projectID types.ProjectID) (int, error)
	Get(ctx security.Context, orgID types.OrganizationID, projectID types.ProjectID, dashboardID types.DashboardID) (Dashboard, error)
	Create(ctx security.Context, cmd DashboardCreateCommand) (Dashboard, error)
	Update(ctx security.Context, cmd DashboardUpdateCommand) (Dashboard, error)
	Delete(ctx security.Context, dashboardID types.DashboardID, currentVersion types.Version) error
}
