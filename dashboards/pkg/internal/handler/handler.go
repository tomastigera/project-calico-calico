package handler

import (
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/julienschmidt/httprouter"
	"github.com/swaggest/openapi-go/openapi3"
	"github.com/tigera/tds-apiserver/lib/logging"
	tdsclient "github.com/tigera/tds-apiserver/pkg/client"
	"github.com/tigera/tds-apiserver/pkg/http/handleradapters"
	"github.com/tigera/tds-apiserver/pkg/types"

	"github.com/projectcalico/calico/dashboards/pkg/client"
	"github.com/projectcalico/calico/dashboards/pkg/internal/config"
	"github.com/projectcalico/calico/dashboards/pkg/internal/handler/middleware/cors"
	"github.com/projectcalico/calico/dashboards/pkg/internal/security"
	"github.com/projectcalico/calico/dashboards/pkg/internal/svc/auth"
	"github.com/projectcalico/calico/dashboards/pkg/internal/svc/collections"
	"github.com/projectcalico/calico/dashboards/pkg/internal/svc/metadata"
	"github.com/projectcalico/calico/dashboards/pkg/internal/svc/query"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

func NewHandler(
	cfg *config.Config,
	logger logging.Logger,
	corsOrigins []string,
	authService *auth.AuthService,
	queryService *query.QueryService,
	metadataService metadata.Storer,
	collectionsService *collections.CollectionsService,
) (handleradapters.RootRegistry, error) {

	router := httprouter.New()
	router.PanicHandler = func(w http.ResponseWriter, r *http.Request, err any) {
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

	projectIDHeader := "x-project-id"
	projectIDDocOpts := []handleradapters.ParamDocOption{handleradapters.WithParamDescription("Organization Project ID")}
	withVerifiedProjectHeader := handleradapters.NewReqMapper[types.ProjectID](
		func(w http.ResponseWriter, r *http.Request, p httprouter.Params) (types.ProjectID, bool) {
			value := r.Header.Get(projectIDHeader)
			if value == "" && cfg.ProductMode == config.ProductModeCloud {
				handleradapters.WriteErr(tdsclient.BadRequest("header-required", fmt.Sprintf("the '%s' header is required", projectIDHeader)), w, r)
				return "", false
			}
			return types.ProjectID(value), true
		},
		func(op *openapi3.Operation, specOps *handleradapters.SpecOps) {
			if cfg.ProductMode == config.ProductModeCloud {
				handleradapters.HeaderParameterDoc[types.ProjectID](op, projectIDHeader, cfg.ProductMode == config.ProductModeCloud, projectIDDocOpts)
			}
		},
	)

	reg.Group("Query").Apply(func(reg handleradapters.Registry) {

		reg.POST("/query", handleradapters.In2Out1(queryService.Query,
			withAuthContext(),
			withQueryRequest(),
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
			withVerifiedProjectHeader,
			withDashboardID,
			handleradapters.WithRespBody[client.Dashboard]()))

		reg.GET("/metadata", handleradapters.In2Out1(metadataService.List,
			withAuthContext(),
			withVerifiedProjectHeader,
			handleradapters.WithRespBody[client.DashboardListResponse]()))

		reg.POST("/metadata", handleradapters.In3Out1(metadataService.Create,
			withAuthContext(),
			withVerifiedProjectHeader,
			handleradapters.WithReqBody[client.DashboardCreateRequest](),
			handleradapters.WithRespBody[client.Dashboard]()))

		reg.PUT("/metadata/:dashboardID", handleradapters.In4Out1(metadataService.Update,
			withAuthContext(),
			withVerifiedProjectHeader,
			withDashboardID,
			handleradapters.WithReqBody[client.DashboardUpdateRequest](),
			handleradapters.WithRespBody[client.Dashboard]()))

		reg.DELETE("/metadata/:dashboardID", handleradapters.In3Out0(metadataService.Delete,
			withAuthContext(),
			withVerifiedProjectHeader,
			withDashboardID))
	})

	return reg, nil
}

func withQueryRequest() handleradapters.ReqMapper[client.QueryRequest] {
	return handleradapters.NewReqMapper[client.QueryRequest](
		func(w http.ResponseWriter, r *http.Request, p httprouter.Params) (client.QueryRequest, bool) {
			var req client.QueryRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				handleradapters.WriteErr(tdsclient.BadRequest("invalid-json", "Invalid JSON body"), w, r)
				return req, false
			}
			if strings.HasPrefix(r.Header.Get("Accept"), "text/csv") {
				req.IsExport = true
			}
			return req, true
		},
		func(op *openapi3.Operation, specOps *handleradapters.SpecOps) {
			// Delegate to WithReqBody's Document method to register the QueryRequest schema.
			handleradapters.WithReqBody[client.QueryRequest]().Document(op, specOps)
		},
	)
}
