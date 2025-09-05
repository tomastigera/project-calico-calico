package staticmetadata

import (
	"encoding/json"
	"io/fs"
	"maps"
	"net/http"
	"slices"

	"github.com/tigera/tds-apiserver/lib/httpreply"
	tdsslices "github.com/tigera/tds-apiserver/lib/slices"
	"github.com/tigera/tds-apiserver/pkg/types"

	"github.com/projectcalico/calico/dashboards/pkg/client"
	"github.com/projectcalico/calico/dashboards/pkg/internal/repository/dashboards"
	"github.com/projectcalico/calico/dashboards/pkg/internal/security"
)

type StaticMetadataService struct {
	dashboards map[client.DashboardID]client.Dashboard
}

func NewStaticMetadataService() (*StaticMetadataService, error) {
	globalDashboards, err := loadDashboards()
	if err != nil {
		return nil, err
	}

	return &StaticMetadataService{
		dashboards: globalDashboards,
	}, nil
}

func loadDashboards() (map[client.DashboardID]client.Dashboard, error) {
	globalDashboards := map[client.DashboardID]client.Dashboard{}
	return globalDashboards, fs.WalkDir(dashboards.GlobalDashboardsEmbed, ".", func(fsPath string, d fs.DirEntry, err error) error {
		if err != nil {
			// keep walking
			return nil
		}
		if d.IsDir() {
			return nil
		}

		dashboardBytes, err := dashboards.GlobalDashboardsEmbed.ReadFile(fsPath)
		if err != nil {
			return err
		}

		var dashboard client.Dashboard
		if err := json.Unmarshal(dashboardBytes, &dashboard); err != nil {
			return err
		}

		dashboard.IsImmutable = true
		globalDashboards[dashboard.ID] = dashboard

		return nil
	})
}

func (s *StaticMetadataService) Get(ctx security.Context, _ types.ProjectID, dashboardID types.DashboardID) (client.Dashboard, error) {
	dashboard, ok := s.dashboards[client.DashboardID(dashboardID)]
	if !ok {
		return client.Dashboard{}, httpreply.ReplyNotFound
	}

	return dashboard, nil
}

func (s *StaticMetadataService) List(ctx security.Context, _ types.ProjectID) (client.DashboardListResponse, error) {
	return client.DashboardListResponse{
		Dashboards: tdsslices.Map(slices.Collect(maps.Values(s.dashboards)), func(dashboard client.Dashboard) client.DashboardSummary {
			return client.DashboardSummary{
				ID:    dashboard.ID,
				Title: dashboard.Title,
			}
		}),
	}, nil
}

func (s *StaticMetadataService) Create(ctx security.Context, _ types.ProjectID, req client.DashboardCreateRequest) (client.Dashboard, error) {
	return client.Dashboard{}, httpreply.Reply{Status: http.StatusNotImplemented}
}

func (s *StaticMetadataService) Update(ctx security.Context, _ types.ProjectID, dashboardID types.DashboardID, req client.DashboardUpdateRequest) (client.Dashboard, error) {
	return client.Dashboard{}, httpreply.Reply{Status: http.StatusNotImplemented}
}

func (s *StaticMetadataService) Delete(ctx security.Context, _ types.ProjectID, dashboardID types.DashboardID) error {
	return httpreply.Reply{Status: http.StatusNotImplemented}
}
