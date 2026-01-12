package metadata

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/stretchr/testify/require"
	"github.com/tigera/tds-apiserver/lib/httpreply"
	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/lib/slices"
	"github.com/tigera/tds-apiserver/lib/util"
	"github.com/tigera/tds-apiserver/pkg/http/handleradapters"
	"github.com/tigera/tds-apiserver/pkg/types"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/projectcalico/calico/dashboards/pkg/client"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/collections"
	"github.com/projectcalico/calico/dashboards/pkg/internal/map/orderedmap"
	"github.com/projectcalico/calico/dashboards/pkg/internal/security"
	"github.com/projectcalico/calico/dashboards/pkg/internal/testutils"
)

var (
	errMetadataNotFound = httpreply.Reply{
		Key:     "http_status_404",
		Status:  404,
		Message: `{"key":"error_not_found","message":"the entity was not found"}`,
	}
)

func TestMetadataService(t *testing.T) {

	logger := logging.New("TestMetadataService")

	fakeDashboards := orderedmap.New[types.DashboardID, *client.Dashboard]()
	for _, dashboard := range []client.Dashboard{
		{ID: "fake-dashboard-id1", Title: "fake-dashboard1", IsImmutable: true},
		{ID: "fake-dashboard-id2", Title: "fake-dashboard2"},
	} {
		fakeDashboards.Put(types.DashboardID(dashboard.ID), &dashboard)
	}

	withDashboardID := handleradapters.WithPathParam[types.DashboardID]("dashboardID", handleradapters.WithParamDescription("Dashboard ID"))
	withAuthorization := handleradapters.WithRequiredHeader[string]("Authorization")

	// mock (tds-apiserver) remote metadata api
	reg := handleradapters.NewRegistry("/api", httprouter.New())
	reg.Group("Metadata").Apply(func(reg handleradapters.Registry) {
		reg.GET("/metadata/:dashboardID", handleradapters.In2Out1(func(auth string, dashboardID types.DashboardID) (client.Dashboard, error) {
			if auth != "Bearer fake-token" {
				return client.Dashboard{}, httpreply.ReplyAccessDenied
			}

			dashboard, found := fakeDashboards.Get(dashboardID)
			if !found || dashboard == nil {
				return client.Dashboard{}, httpreply.ReplyNotFound
			}

			return *dashboard, nil
		},
			withAuthorization,
			withDashboardID,
			handleradapters.WithRespBody[client.Dashboard]()))

		reg.GET("/metadata", handleradapters.In1Out1(func(auth string) (client.DashboardListResponse, error) {
			if auth != "Bearer fake-token" {
				return client.DashboardListResponse{}, httpreply.ReplyAccessDenied
			}

			return client.DashboardListResponse{
				Dashboards: slices.Map(fakeDashboards.ValuesInOrder(), func(dashboard *client.Dashboard) client.DashboardSummary {
					return client.DashboardSummary{
						ID:          dashboard.ID,
						Title:       dashboard.Title,
						IsImmutable: dashboard.IsImmutable,
					}
				}),
			}, nil
		},
			withAuthorization,
			handleradapters.WithRespBody[client.DashboardListResponse]()))

		reg.POST("/metadata", handleradapters.In2Out1(func(auth string, req client.DashboardCreateRequest) (client.Dashboard, error) {
			if auth != "Bearer fake-token" {
				return client.Dashboard{}, httpreply.ReplyAccessDenied
			}
			dashboard := &client.Dashboard{
				ID:             client.DashboardID(fmt.Sprintf("fake-dashboard-id-%s", util.CryptoRandAlphaNum(8))),
				Title:          req.Title,
				Cards:          req.Cards,
				Layout:         req.Layout,
				DefaultFilters: req.DefaultFilters,
			}
			fakeDashboards.Put(types.DashboardID(dashboard.ID), dashboard)

			return *dashboard, nil
		},
			withAuthorization,
			handleradapters.WithReqBody[client.DashboardCreateRequest](),
			handleradapters.WithRespBody[client.Dashboard]()))

		reg.PUT("/metadata/:dashboardID", handleradapters.In3Out1(func(auth string, dashboardID types.DashboardID, req client.DashboardUpdateRequest) (client.Dashboard, error) {
			if auth != "Bearer fake-token" {
				return client.Dashboard{}, httpreply.ReplyAccessDenied
			}
			dashboard, found := fakeDashboards.Get(dashboardID)
			if !found || dashboard == nil {
				return client.Dashboard{}, httpreply.ReplyNotFound
			}

			dashboard.Title = req.Title
			dashboard.Cards = req.Cards
			dashboard.Layout = req.Layout
			dashboard.DefaultFilters = req.DefaultFilters

			return *dashboard, nil
		},
			withAuthorization,
			withDashboardID,
			handleradapters.WithReqBody[client.DashboardUpdateRequest](),
			handleradapters.WithRespBody[client.Dashboard]()))

		reg.DELETE("/metadata/:dashboardID", handleradapters.In2Out0(func(auth string, dashboardID types.DashboardID) error {
			if auth != "Bearer fake-token" {
				return httpreply.ReplyAccessDenied
			}
			dashboard, found := fakeDashboards.Get(dashboardID)
			if !found || dashboard == nil {
				return httpreply.ReplyNotFound
			}

			fakeDashboards.Put(dashboardID, nil)
			return nil
		},
			withAuthorization,
			withDashboardID))
	})

	httpServer := httptest.NewServer(reg.Handler())
	t.Cleanup(httpServer.Close)

	subject, err := NewRemoteMetadataService(logger, packageNamePro, httpServer.URL+"/api/metadata", collections.Collections(nil), nil)
	require.NoError(t, err)

	newUserAuthContextWithResourceRules := func(t *testing.T, resourceRules []authzv1.ResourceRule) security.Context {
		authorizer, err := security.NewAuthorizer(
			t.Context(),
			logger,
			time.Second,
			security.AuthorizerConfig{
				Namespace:                             "default",
				EnableNamespacedRBAC:                  false,
				AuthorizedVerbsCacheHardTTL:           time.Second,
				AuthorizedVerbsCacheSoftTTL:           time.Second,
				AuthorizedVerbsCacheReviewsTimeout:    time.Second,
				AuthorizedVerbsCacheRevalidateTimeout: time.Second,
			},
		)
		require.NoError(t, err)

		k8sClient := k8sfake.NewClientset()
		k8sClient.PrependReactor("create", "selfsubjectrulesreviews", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {

			createAction, ok := action.(k8stesting.CreateAction)
			require.True(t, ok, "invalid reactor action, expecting k8stesting.CreateAction but got", action)

			object := createAction.GetObject().DeepCopyObject()
			selfSubjectRulesReview, ok := object.(*authzv1.SelfSubjectRulesReview)
			require.True(t, ok, "invalid reactor object, expecting *SelfSubjectRulesReview but got", object)

			selfSubjectRulesReview.Status.ResourceRules = resourceRules

			return true, selfSubjectRulesReview, nil
		})

		return security.NewUserAuthContext(
			context.Background(),
			&user.DefaultInfo{Name: "fake-user"},
			authorizer,
			k8sClient,
			"Bearer fake-token",
			nil,
		)
	}

	ctx := newUserAuthContextWithResourceRules(t, []authzv1.ResourceRule{
		{Verbs: []string{"get"}, APIGroups: []string{security.APIGroupLMATigera}, ResourceNames: []string{"flows"}, Resources: []string{"dashboards"}},
	})

	t.Run("authorization", func(t *testing.T) {
		t.Run("success", func(t *testing.T) {
			_, err := subject.List(ctx, types.ProjectIDDefault)
			require.NoError(t, err)
		})

		t.Run("unauthorized", func(t *testing.T) {
			ctx := newUserAuthContextWithResourceRules(t, nil) // no rbac rules

			_, err := subject.List(ctx, types.ProjectIDDefault)
			require.Equal(t, httpreply.ReplyAccessDenied, err)
		})
	})

	t.Run("list", func(t *testing.T) {
		testCases := []struct {
			packageName types.PackageName
			goldenYaml  string
		}{
			{
				packageName: packageNamePro,
				goldenYaml:  "dashboard-list-pro",
			},
			{
				packageName: packageNameFree,
				goldenYaml:  "dashboard-list-free",
			},
		}

		for _, tc := range testCases {
			t.Run(string(tc.packageName), func(t *testing.T) {
				subject, err := NewRemoteMetadataService(logger, tc.packageName, httpServer.URL+"/api/metadata", collections.Collections(nil), nil)
				require.NoError(t, err)

				dashboards, err := subject.List(ctx, types.ProjectIDDefault)
				require.NoError(t, err)
				testutils.ExpectMatchesGoldenYaml(t, tc.goldenYaml, dashboards)
			})
		}

		t.Run("disabled dashboards", func(t *testing.T) {
			disabledDashboards := map[string][]string{"global": {"1"}}

			subject, err := NewRemoteMetadataService(logger, packageNamePro, httpServer.URL+"/api/metadata", collections.Collections(nil), nil)
			require.NoError(t, err)

			resp, err := subject.List(ctx, types.ProjectIDDefault)
			require.NoError(t, err)
			require.True(t, slices.AnyMatch(resp.Dashboards, func(summary client.DashboardSummary) bool {
				return summary.ID == "1"
			}))

			subject, err = NewRemoteMetadataService(logger, packageNamePro, httpServer.URL+"/api/metadata", collections.Collections(nil), disabledDashboards)
			require.NoError(t, err)

			resp, err = subject.List(ctx, types.ProjectIDDefault)
			require.NoError(t, err)
			require.False(t, slices.AnyMatch(resp.Dashboards, func(summary client.DashboardSummary) bool {
				return summary.ID == "1"
			}))
		})
	})

	t.Run("create", func(t *testing.T) {
		dashboard, err := subject.Create(ctx, types.ProjectIDDefault, client.DashboardCreateRequest{
			Title: "fake-dashboard-title-create",
		})
		require.NoError(t, err)

		require.Equal(t, "fake-dashboard-title-create", dashboard.Title)
		require.False(t, dashboard.IsImmutable)

		t.Run("get", func(t *testing.T) {

			testCases := []struct {
				name        string
				dashboardID types.DashboardID

				expected        client.Dashboard
				expectedError   error
				expectedURLPath string
			}{
				{
					name:            "static",
					dashboardID:     types.DashboardID("1"),
					expectedURLPath: "/server-path/1",
					expected: client.Dashboard{
						ID:          "1",
						Title:       "Traffic Volume",
						IsImmutable: true,
					},
				},
				{
					name:            "created",
					dashboardID:     types.DashboardID(dashboard.ID),
					expectedURLPath: fmt.Sprintf("/server-path/%s", dashboard.ID),
					expected: client.Dashboard{
						ID:    dashboard.ID,
						Title: "fake-dashboard-title-create",
					},
				},
				{
					name:            "not found",
					dashboardID:     types.DashboardID("unknown-dashboard-id"),
					expectedURLPath: "/server-path/unknown-dashboard-id",
					expectedError:   errMetadataNotFound,
				},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					resp, err := subject.Get(ctx, types.ProjectIDDefault, tc.dashboardID)
					require.Equal(t, tc.expectedError, err)

					require.Equal(t, tc.expected.ID, resp.ID)
					require.Equal(t, tc.expected.Title, resp.Title)
				})
			}
		})

		t.Run("update", func(t *testing.T) {
			dashboard, err := subject.Update(ctx, types.ProjectIDDefault, types.DashboardID(dashboard.ID), client.DashboardUpdateRequest{
				Title: "fake-dashboard-title-update",
			})
			require.NoError(t, err)
			require.Equal(t, client.Dashboard{
				ID:    dashboard.ID,
				Title: "fake-dashboard-title-update",
			}, dashboard)
		})

		t.Run("delete", func(t *testing.T) {
			err := subject.Delete(ctx, types.ProjectIDDefault, types.DashboardID(dashboard.ID))
			require.NoError(t, err)

			err = subject.Delete(ctx, types.ProjectIDDefault, types.DashboardID(dashboard.ID))
			require.ErrorIs(t, err, errMetadataNotFound)
		})
	})
}
