package metadata

import (
	"fmt"
	"net/http"

	"github.com/tigera/tds-apiserver/lib/ghttp"
	"github.com/tigera/tds-apiserver/lib/httpreply"
	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/lib/slices"
	"github.com/tigera/tds-apiserver/pkg/types"

	"github.com/projectcalico/calico/dashboards/pkg/client"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/collections"
	"github.com/projectcalico/calico/dashboards/pkg/internal/map/orderedmap"
	"github.com/projectcalico/calico/dashboards/pkg/internal/security"
	staticmetadata "github.com/projectcalico/calico/dashboards/pkg/internal/svc/metadata/static"
)

type RemoteMetadataService struct {
	http.Client
	logger           logging.Logger
	collections      []collections.Collection
	metadataEndpoint string
	staticDashboards *orderedmap.OrderedMap[client.DashboardID, client.Dashboard]
}

const (
	packageNamePro  types.PackageName = "pro"
	packageNameFree types.PackageName = "free"
)

var (
	cloudPackagePathMap = map[types.PackageName]string{
		packageNamePro:  "global",
		packageNameFree: "global/free",
	}
)

func NewRemoteMetadataService(
	logger logging.Logger,
	cloudPackage types.PackageName,
	metadataEndpoint string,
	enabledCollections []collections.Collection,
	disabledDashboards map[string][]string,
) (*RemoteMetadataService, error) {

	staticDashboardsDirPrefix, ok := cloudPackagePathMap[cloudPackage]
	if !ok {
		return nil, fmt.Errorf("cloudPackage %s is not supported. must be one of [%s, %s]", cloudPackage, packageNamePro, packageNameFree)
	}

	staticDashboards, err := staticmetadata.LoadDashboards(staticDashboardsDirPrefix, disabledDashboards[staticDashboardsDirPrefix])
	if err != nil {
		return nil, err
	}

	return &RemoteMetadataService{
		logger:           logger,
		collections:      enabledCollections,
		metadataEndpoint: metadataEndpoint,
		staticDashboards: staticDashboards,
	}, nil
}

func (s *RemoteMetadataService) authorize(ctx security.Context) error {
	authorized, err := ctx.IsAnyPermitted(security.APIGroupLMATigera, slices.Map(s.collections, collections.Collection.LmaResourceName))
	if err != nil {
		return err
	} else if !authorized {
		return httpreply.ReplyAccessDenied
	}

	return nil
}

func (s *RemoteMetadataService) Get(ctx security.Context, projectID types.ProjectID, dashboardID types.DashboardID) (client.Dashboard, error) {
	dashboard, ok := s.staticDashboards.Get(client.DashboardID(dashboardID))
	if ok {
		return dashboard, nil
	}

	dashboard, err := executeRequest[ghttp.Nothing, client.Dashboard](ctx, s, projectID, http.MethodGet, dashboardID, ghttp.Nothing{})
	if err != nil {
		return client.Dashboard{}, err
	}

	return dashboard, nil
}

func (s *RemoteMetadataService) List(ctx security.Context, projectID types.ProjectID) (client.DashboardListResponse, error) {
	// Convert static dashboards to []client.DashboardSummary
	staticDashboards := slices.Map(s.staticDashboards.ValuesInOrder(), func(dashboard client.Dashboard) client.DashboardSummary {
		return client.DashboardSummary{
			ID:          dashboard.ID,
			Title:       dashboard.Title,
			IsImmutable: true,
		}
	})

	dashboardListResponse, err := executeRequest[ghttp.Nothing, client.DashboardListResponse](ctx, s, projectID, http.MethodGet, "", ghttp.Nothing{})
	if err != nil {
		return client.DashboardListResponse{}, err
	}

	return client.DashboardListResponse{
		Dashboards: append(staticDashboards, slices.FilterBy(dashboardListResponse.Dashboards, func(dashboardSummary client.DashboardSummary) bool {
			return !dashboardSummary.IsImmutable
		})...),
	}, nil
}

func (s *RemoteMetadataService) Create(ctx security.Context, projectID types.ProjectID, req client.DashboardCreateRequest) (client.Dashboard, error) {
	dashboard, err := executeRequest[client.DashboardCreateRequest, client.Dashboard](ctx, s, projectID, http.MethodPost, "", req)
	if err != nil {
		return client.Dashboard{}, err
	}

	return dashboard, nil
}

func (s *RemoteMetadataService) Update(ctx security.Context, projectID types.ProjectID, dashboardID types.DashboardID, req client.DashboardUpdateRequest) (client.Dashboard, error) {
	dashboard, err := executeRequest[client.DashboardUpdateRequest, client.Dashboard](ctx, s, projectID, http.MethodPut, dashboardID, req)
	if err != nil {
		return client.Dashboard{}, err
	}

	return dashboard, nil
}

func (s *RemoteMetadataService) Delete(ctx security.Context, projectID types.ProjectID, dashboardID types.DashboardID) error {
	_, err := executeRequest[ghttp.Nothing, ghttp.Nothing](ctx, s, projectID, http.MethodDelete, dashboardID, ghttp.Nothing{})
	if err != nil {
		return err
	}

	return nil
}

func executeRequest[Req any, Resp any](
	ctx security.Context,
	s *RemoteMetadataService,
	projectID types.ProjectID,
	httpMethod string,
	dashboardID types.DashboardID,
	req Req,
) (Resp, error) {
	err := s.authorize(ctx)
	if err != nil {
		var zero Resp
		return zero, err
	}

	url := s.metadataEndpoint
	if dashboardID != "" {
		url = fmt.Sprintf("%s/%s", s.metadataEndpoint, dashboardID)
	}

	return ghttp.Request[Req, Resp](
		ctx,
		&s.Client,
		httpMethod,
		url,
		req,
		ghttp.WithHeader("x-project-id", string(projectID)),
		ghttp.WithHeader("Authorization", ctx.Authorization()),
	)
}
