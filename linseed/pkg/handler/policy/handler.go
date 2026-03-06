// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package policy

import (
	"context"
	"net/http"

	"github.com/sirupsen/logrus"
	authzv1 "k8s.io/api/authorization/v1"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/handler"
	"github.com/projectcalico/calico/linseed/pkg/middleware"
	"github.com/projectcalico/calico/lma/pkg/httputils"
)

const (
	WriteLogPath = "/policy_activity/logs/bulk"
	ReadPath     = "/policy_activity"
)

type policy struct {
	logs    handler.RWHandler[v1.PolicyActivity, v1.PolicyActivityParams, v1.PolicyActivity]
	backend bapi.PolicyBackend
}

func New(b bapi.PolicyBackend) *policy {
	return &policy{
		logs:    handler.NewRWHandler[v1.PolicyActivity, v1.PolicyActivityParams](b.Create, nil),
		backend: b,
	}
}

func (h policy) APIS() []handler.API {
	return []handler.API{
		{
			Method:          "POST",
			URL:             WriteLogPath,
			Handler:         h.logs.Create(),
			AuthzAttributes: &authzv1.ResourceAttributes{Verb: handler.Create, Group: handler.APIGroup, Resource: "policyactivity"},
		},
		{
			Method:          "POST",
			URL:             ReadPath,
			Handler:         h.GetPolicyActivities(),
			AuthzAttributes: &authzv1.ResourceAttributes{Verb: handler.Get, Group: handler.APIGroup, Resource: "policyactivity"},
		},
	}
}

func (h policy) GetPolicyActivities() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		logCtx := logrus.WithFields(logrus.Fields{
			"path":   req.URL.Path,
			"method": req.Method,
		})

		reqParams, httpErr := handler.DecodeAndValidateReqParams[v1.PolicyActivityParams](w, req)
		if httpErr != nil {
			if logrus.IsLevelEnabled(logrus.DebugLevel) {
				body, err := handler.ReadBody(w, req)
				if err != nil {
					logrus.WithError(err).Warn("Failed to read request body")
				}
				logCtx = logCtx.WithField("body", body)
			}
			logCtx.WithError(httpErr).Error("Failed to decode/validate request parameters")
			httputils.JSONError(w, httpErr, httpErr.Status)
			return
		}

		if err := reqParams.Valid(); err != nil {
			logCtx.WithError(err).Error("Invalid request parameters")
			httputils.JSONError(w, &v1.HTTPError{
				Status: http.StatusBadRequest,
				Msg:    err.Error(),
			}, http.StatusBadRequest)
			return
		}

		clusterInfo := bapi.ClusterInfo{
			Cluster: middleware.ClusterIDFromContext(req.Context()),
			Tenant:  middleware.TenantIDFromContext(req.Context()),
		}

		if err := clusterInfo.Valid(); err != nil {
			logCtx.WithError(err).Error("Invalid cluster info")
			httputils.JSONError(w, &v1.HTTPError{
				Status: http.StatusBadRequest,
				Msg:    err.Error(),
			}, http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), v1.DefaultTimeOut)
		defer cancel()

		response, err := h.backend.GetPolicyActivities(ctx, clusterInfo, reqParams)
		if err != nil {
			logCtx.WithError(err).Error("Failed to get policy activity")
			httputils.JSONError(w, &v1.HTTPError{
				Status: http.StatusInternalServerError,
				Msg:    err.Error(),
			}, http.StatusInternalServerError)
			return
		}

		logCtx.Debugf("%s response is: %+v", ReadPath, response)
		httputils.Encode(w, response)
	}
}
