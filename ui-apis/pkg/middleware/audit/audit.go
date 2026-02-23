// Copyright (c) 2023 Tigera, Inc. All rights reserved.
package audit

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	auditv1 "k8s.io/apiserver/pkg/apis/audit"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/lma/pkg/httputils"
	"github.com/projectcalico/calico/ui-apis/pkg/middleware"
)

// Timeout for all requests to this API.
const timeout = 20 * time.Second

func NewHandler(lsclient client.Client, excludeDryRuns bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse the request.
		params, cluster, err := parseRequest(w, r, excludeDryRuns)
		if err != nil {
			httputils.EncodeError(w, err)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		items, err := lsclient.AuditLogs(cluster).List(ctx, params)
		if err != nil {
			httputils.EncodeError(w, err)
			return
		}

		// Write the response.
		httputils.Encode(w, items)
	})
}

func parseRequest(w http.ResponseWriter, r *http.Request, excludeDryRuns bool) (*v1.AuditLogParams, string, error) {
	if r.Method != http.MethodPost {
		logrus.WithError(middleware.ErrInvalidMethod).Info("Invalid http method.")
		return nil, "", &httputils.HttpStatusError{
			Status: http.StatusMethodNotAllowed,
			Msg:    middleware.ErrInvalidMethod.Error(),
			Err:    middleware.ErrInvalidMethod,
		}
	}

	type auditRequest struct {
		v1.AuditLogParams `json:",inline"`
		Page              int `json:"page"`
	}

	params := auditRequest{}
	if err := httputils.Decode(w, r, &params); err != nil {
		var e *httputils.HttpStatusError
		if errors.As(err, &e) {
			logrus.WithError(e.Err).Info(e.Msg)
			return nil, "", e
		} else {
			logrus.WithError(e.Err).Info("Error validating audit requests.")
			return nil, "", &httputils.HttpStatusError{
				Status: http.StatusBadRequest,
				Msg:    http.StatusText(http.StatusInternalServerError),
				Err:    err,
			}
		}
	}

	if params.Page > 0 {
		// Ideally, clients don't know the syntax of the after key, but
		// for paged lists we currently need this.
		params.SetAfterKey(map[string]any{
			"startFrom": params.Page * params.MaxPageSize,
		})
	}

	// Verify required fields.
	if params.Type == "" {
		return nil, "", &httputils.HttpStatusError{
			Status: http.StatusBadRequest,
			Msg:    "Missing log type parameter",
		}
	}

	// Set some constant fields. The UI always wants these set.
	params.Levels = []auditv1.Level{auditv1.LevelRequestResponse}
	params.Stages = []auditv1.Stage{auditv1.StageResponseComplete}
	params.Sort = []v1.SearchRequestSortBy{
		{
			Field:      "stageTimestamp",
			Descending: true,
		},
	}

	params.ExcludeDryRuns = excludeDryRuns

	// Extract the cluster ID header.
	cluster := middleware.MaybeParseClusterNameFromRequest(r)

	return &params.AuditLogParams, cluster, nil
}
