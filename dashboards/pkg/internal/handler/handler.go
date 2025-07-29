package handler

import (
	"net/http"
	"runtime/debug"

	jsoniter "github.com/json-iterator/go"
	"github.com/julienschmidt/httprouter"

	"github.com/projectcalico/calico/dashboards/pkg/client"
	"github.com/projectcalico/calico/dashboards/pkg/internal/handler/middleware/cors"
	"github.com/projectcalico/calico/dashboards/pkg/internal/security"
	"github.com/projectcalico/calico/dashboards/pkg/internal/svc/auth"
	"github.com/projectcalico/calico/dashboards/pkg/internal/svc/collections"
	"github.com/projectcalico/calico/dashboards/pkg/internal/svc/metadata"
	"github.com/projectcalico/calico/dashboards/pkg/internal/svc/query"
	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/pkg/http/handleradapters"
	"github.com/tigera/tds-apiserver/pkg/types"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

func NewHandler(
	logger logging.Logger,
	corsOrigins []string,
	authService *auth.AuthService,
	queryService *query.QueryService,
	metadataService *metadata.MetadataService,
	collectionsService *collections.CollectionsService,
) (handleradapters.RootRegistry, error) {

	router := httprouter.New()
	router.PanicHandler = func(w http.ResponseWriter, r *http.Request, err interface{}) {
		logger.WarnC(
			r.Context(),
			"a panic occurred in the http handler",
			logging.String("path", r.URL.Path),
			logging.String("method", r.Method),
			logging.Any("err", err),
			logging.String("stacktrace", string(debug.Stack())),
		)
		w.WriteHeader(http.StatusInternalServerError)
	}
	router.GlobalOPTIONS = cors.NewMiddleware(corsOrigins, router)

	// add a empty /health handler to keep external health checks happy
	router.Handle(http.MethodGet, "/health", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	withAuthContext := func() handleradapters.ReqMapper[security.Context] {
		return authService.NewUserAuthContextMapper()
	}

	reg := handleradapters.NewRegistry("/api", router,
		handleradapters.WithSpecTitle("Dashboard Query API"),
		handleradapters.WithSpecDescription("Dashboard Query API for Calico Cloud"),
	)

	withRequiredProjectIDHeader := handleradapters.WithRequiredHeader[types.ProjectID]("x-project-id",
		handleradapters.WithParamDescription("Organization Project ID"))

	reg.Group("Query").Apply(func(reg handleradapters.Registry) {

		reg.POST("/query", handleradapters.In2Out1(queryService.Query,
			withAuthContext(),
			handleradapters.WithReqBody[client.QueryRequest](),
			withQueryResponseWriter(logger),
		))
	})

	reg.Group("Collections").Apply(func(reg handleradapters.Registry) {

		reg.GET("/collections", handleradapters.In1Out1(collectionsService.Collections,
			withAuthContext(),
			handleradapters.WithRespBody[client.CollectionsResponse](),
		))
	})

	reg.Group("Metadata").Apply(func(reg handleradapters.Registry) {

		withDashboardID := handleradapters.WithPathParam[types.DashboardID]("dashboardID", handleradapters.WithParamDescription("Dashboard ID"))

		reg.GET("/metadata/:dashboardID", handleradapters.In3Out1(metadataService.Get,
			withAuthContext(),
			withRequiredProjectIDHeader,
			withDashboardID,
			handleradapters.WithRespBody[client.Dashboard]()))

		reg.GET("/metadata", handleradapters.In2Out1(metadataService.List,
			withAuthContext(),
			withRequiredProjectIDHeader,
			handleradapters.WithRespBody[client.DashboardListResponse]()))

		reg.POST("/metadata", handleradapters.In3Out1(metadataService.Create,
			withAuthContext(),
			withRequiredProjectIDHeader,
			handleradapters.WithReqBody[client.DashboardCreateRequest](),
			handleradapters.WithRespBody[client.Dashboard]()))

		reg.PUT("/metadata/:dashboardID", handleradapters.In4Out1(metadataService.Update,
			withAuthContext(),
			withRequiredProjectIDHeader,
			withDashboardID,
			handleradapters.WithReqBody[client.DashboardUpdateRequest](),
			handleradapters.WithRespBody[client.Dashboard]()))

		reg.DELETE("/metadata/:dashboardID", handleradapters.In3Out0(metadataService.Delete,
			withAuthContext(),
			withRequiredProjectIDHeader,
			withDashboardID))
	})

	return reg, nil
}
