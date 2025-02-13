package handler

import (
	"fmt"
	"net/http"
	"regexp"
	"runtime/debug"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/julienschmidt/httprouter"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/client"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/handler/middleware/cors"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/security"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/svc/auth"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/svc/collections"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/svc/query"
	"github.com/tigera/tds-apiserver/lib/httpreply"
	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/pkg/http/handleradapters"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

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

	return reg, nil
}

func withQueryResponseWriter(logger logging.Logger) handleradapters.ResponseBodyMapper[client.QueryResponse] {
	defaultMapper := handleradapters.WithRespBody[client.QueryResponse]()
	return queryResponseWriterBodyMapper[client.QueryResponse]{logger: logger, defaultMapper: defaultMapper}
}

type queryResponseWriterBodyMapper[T client.QueryResponse] struct {
	logger        logging.Logger
	defaultMapper handleradapters.ResponseBodyMapper[client.QueryResponse]
}

var (
	reAcceptHeaderCSVColumns  = regexp.MustCompile(`;\s*columns="([^"]+)"`)
	reAcceptHeaderCSVFilename = regexp.MustCompile(`;\s*filename="([^"]+)"`)
)

func (m queryResponseWriterBodyMapper[T]) Map(resp client.QueryResponse, w http.ResponseWriter, r *http.Request) {
	acceptHeader := r.Header.Get("Accept")

	if strings.HasPrefix(acceptHeader, "text/csv") {
		matchColumns := reAcceptHeaderCSVColumns.FindStringSubmatch(acceptHeader)
		matchFilename := reAcceptHeaderCSVFilename.FindStringSubmatch(acceptHeader)

		if len(matchFilename) != 2 {
			message := "csv filename not set"
			err := httpreply.ToBadRequest(message).Send(w)

			m.logger.ErrorC(r.Context(), "failed to write CSV response", logging.String("message", message), logging.Error(err))
			return
		}

		if len(matchColumns) != 2 {
			message := "csv columns not set"
			err := httpreply.ToBadRequest(message).Send(w)

			m.logger.ErrorC(r.Context(), "failed to write CSV response", logging.String("message", message), logging.Error(err))
			return
		}

		columns := strings.Split(matchColumns[1], ",")

		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, matchFilename[1]))
		err := resp.WriteCSV(w, columns)
		if err != nil {
			m.logger.ErrorC(r.Context(), "failed to write CSV response", logging.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	} else {
		marshalled, err := json.Marshal(resp)
		if err != nil {
			m.logger.ErrorC(r.Context(), "failed to marshal response", logging.Error(err))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write(marshalled)
		if err != nil {
			m.logger.ErrorC(r.Context(), "failed to write response", logging.Error(err))
		}
	}
}

func (m queryResponseWriterBodyMapper[T]) Document(op *openapi3.Operation, specOps *handleradapters.SpecOps) {
	m.defaultMapper.Document(op, specOps)
}
