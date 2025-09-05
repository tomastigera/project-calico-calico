package metadata

import (
	"github.com/tigera/tds-apiserver/pkg/types"

	"github.com/projectcalico/calico/dashboards/pkg/client"
	"github.com/projectcalico/calico/dashboards/pkg/internal/security"
)

type Storer interface {
	Get(ctx security.Context, projectID types.ProjectID, dashboardID types.DashboardID) (client.Dashboard, error)
	List(ctx security.Context, projectID types.ProjectID) (client.DashboardListResponse, error)
	Create(ctx security.Context, projectID types.ProjectID, req client.DashboardCreateRequest) (client.Dashboard, error)
	Update(ctx security.Context, projectID types.ProjectID, dashboardID types.DashboardID, req client.DashboardUpdateRequest) (client.Dashboard, error)
	Delete(ctx security.Context, projectID types.ProjectID, dashboardID types.DashboardID) error
}
