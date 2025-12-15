package handler

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/swaggest/openapi-go/openapi3"
	"github.com/tigera/tds-apiserver/lib/httpreply"
	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/pkg/http/handleradapters"

	"github.com/projectcalico/calico/dashboards/pkg/client"
)

type queryResponseWriterBodyMapper[T client.QueryResponse] struct {
	logger        logging.Logger
	defaultMapper handleradapters.ResponseBodyMapper[client.QueryResponse]
}

var (
	reAcceptHeaderCSVColumns  = regexp.MustCompile(`;\s*columns="([^"]+)"`)
	reAcceptHeaderCSVFilename = regexp.MustCompile(`;\s*filename="([^"]+)"`)
)

func withQueryResponseWriter(logger logging.Logger) handleradapters.ResponseBodyMapper[client.QueryResponse] {
	defaultMapper := handleradapters.WithRespBody[client.QueryResponse]()
	return queryResponseWriterBodyMapper[client.QueryResponse]{logger: logger, defaultMapper: defaultMapper}
}

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
		err := resp.WriteCSV(w, columns, 0)
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
