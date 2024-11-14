package handler

import (
	"net/http"
	"runtime/debug"

	"github.com/julienschmidt/httprouter"

	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/client"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/handler/middleware/cors"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/security"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/svc/auth"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/svc/collections"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/svc/query"
	"github.com/tigera/tds-apiserver/pkg/http/handleradapters"
	"github.com/tigera/tds-apiserver/pkg/logging"
)

func NewHandler(
	logger logging.Logger,
	corsOrigins []string,
	authService *auth.AuthService,
	queryService *query.QueryService,
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
			logging.Any("stacktrace", debug.Stack()),
		)
		w.WriteHeader(http.StatusInternalServerError)
	}
	router.GlobalOPTIONS = cors.NewMiddleware(corsOrigins, router)

	// add a empty /health handler to keep external health checks happy
	router.Handle(http.MethodGet, "/health", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	withAuthContext := func() handleradapters.ReqMapper[security.AuthContext] {
		return authService.NewUserAuthContextMapper()
	}

	reg := handleradapters.NewRegistry("/api", router,
		handleradapters.WithSpecTitle("Dashboard Query API"),
		handleradapters.WithSpecDescription("Dashboard Query API for Calico Cloud"),
	)

	reg.Group("Query").Apply(func(reg handleradapters.Registry) {

		reg.POST("/query", handleradapters.In2Out1(queryService.Query,
			withAuthContext(),
			handleradapters.WithReqBody[client.QueryRequest](),
			handleradapters.WithRespBody[client.QueryResponse](),
		))
	})

	reg.Group("Collections").Apply(func(reg handleradapters.Registry) {

		reg.GET("/collections", handleradapters.In1Out1(collectionsService.Collections,
			withAuthContext(),
			handleradapters.WithRespBody[client.CollectionsResponse](),
		))
	})

	return reg, nil
}
