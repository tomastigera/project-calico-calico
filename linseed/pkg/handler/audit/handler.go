// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package audit

import (
	"context"
	"fmt"
	"net/http"

	"github.com/sirupsen/logrus"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/handler"
	"github.com/projectcalico/calico/linseed/pkg/middleware"
	"github.com/projectcalico/calico/lma/pkg/httputils"
)

const (
	LogPath            = "/audit/logs"
	AggsPath           = "/audit/logs/aggregation"
	LogPathBulkPattern = "/audit/logs/%s/bulk"
)

type audit struct {
	logs         bapi.AuditBackend
	aggregations handler.AggregationHandler[v1.AuditLogAggregationParams]
}

func New(logs bapi.AuditBackend) *audit {
	return &audit{
		logs:         logs,
		aggregations: handler.NewAggregationHandler(logs.Aggregations),
	}
}

func (h audit) APIS() []handler.API {
	return []handler.API{
		{
			Method:          "POST",
			URL:             LogPath,
			Handler:         h.GetLogs(),
			AuthzAttributes: &authzv1.ResourceAttributes{Verb: handler.Get, Group: handler.APIGroup, Resource: "auditlogs"},
		},
		{
			Method:          "POST",
			URL:             fmt.Sprintf(LogPathBulkPattern, v1.AuditLogTypeEE),
			Handler:         h.BulkAuditEE(),
			AuthzAttributes: &authzv1.ResourceAttributes{Verb: handler.Create, Group: handler.APIGroup, Resource: "ee_auditlogs"},
		},
		{
			Method:          "POST",
			URL:             fmt.Sprintf(LogPathBulkPattern, v1.AuditLogTypeKube),
			Handler:         h.BulkAuditKube(),
			AuthzAttributes: &authzv1.ResourceAttributes{Verb: handler.Create, Group: handler.APIGroup, Resource: "kube_auditlogs"},
		},
		{
			Method:          "POST",
			URL:             AggsPath,
			Handler:         h.aggregations.Aggregate(),
			AuthzAttributes: &authzv1.ResourceAttributes{Verb: handler.Get, Group: handler.APIGroup, Resource: "auditlogs"},
		},
	}
}

// BulkAuditEE handles bulk ingestion requests to add EE Audit logs, typically from fluentd.
func (h audit) BulkAuditEE() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		f := logrus.Fields{
			"path":   req.URL.Path,
			"method": req.Method,
		}
		logCtx := logrus.WithFields(f)

		decoded, httpErr := handler.DecodeAndValidateBulkParams[v1.AuditLog](w, req)
		if httpErr != nil {
			if logrus.IsLevelEnabled(logrus.DebugLevel) {
				// Include the request body in our logs.
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

		ctx, cancel := context.WithTimeout(context.Background(), v1.DefaultTimeOut)
		defer cancel()
		clusterInfo := bapi.ClusterInfo{
			Cluster: middleware.ClusterIDFromContext(req.Context()),
			Tenant:  middleware.TenantIDFromContext(req.Context()),
		}

		response, err := h.logs.Create(ctx, v1.AuditLogTypeEE, clusterInfo, decoded.Items)
		if err != nil {
			logCtx.WithError(err).Error("Failed to ingest EE audit logs")
			httputils.JSONError(w, &v1.HTTPError{
				Status: http.StatusInternalServerError,
				Msg:    err.Error(),
			}, http.StatusInternalServerError)
			return
		}
		response.Total += decoded.FailedCount
		response.Failed += decoded.FailedCount
		logCtx.Debugf("Bulk response is: %+v", response)
		httputils.Encode(w, response)
	}
}

// BulkAuditKube handles bulk ingestion requests to add Kube Audit logs, typically from fluentd.
func (h audit) BulkAuditKube() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		f := logrus.Fields{
			"path":   req.URL.Path,
			"method": req.Method,
		}
		logCtx := logrus.WithFields(f)

		decoded, httpErr := handler.DecodeAndValidateBulkParams[v1.AuditLog](w, req)
		if httpErr != nil {
			if logrus.IsLevelEnabled(logrus.DebugLevel) {
				// Include the request body in our logs.
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

		ctx, cancel := context.WithTimeout(context.Background(), v1.DefaultTimeOut)
		defer cancel()
		clusterInfo := bapi.ClusterInfo{
			Cluster: middleware.ClusterIDFromContext(req.Context()),
			Tenant:  middleware.TenantIDFromContext(req.Context()),
		}

		response, err := h.logs.Create(ctx, v1.AuditLogTypeKube, clusterInfo, decoded.Items)
		if err != nil {
			logCtx.WithError(err).Error("Failed to ingest Kube audit logs")
			httputils.JSONError(w, &v1.HTTPError{
				Status: http.StatusInternalServerError,
				Msg:    err.Error(),
			}, http.StatusInternalServerError)
			return
		}
		response.Total += decoded.FailedCount
		response.Failed += decoded.FailedCount
		logCtx.Debugf("Bulk response is: %+v", response)
		httputils.Encode(w, response)
	}
}

func (h audit) GetLogs() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		f := logrus.Fields{
			"path":   req.URL.Path,
			"method": req.Method,
		}
		logCtx := logrus.WithFields(f)

		reqParams, httpErr := handler.DecodeAndValidateReqParams[v1.AuditLogParams](w, req)
		if httpErr != nil {
			if logrus.IsLevelEnabled(logrus.DebugLevel) {
				// Include the request body in our logs.
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

		if reqParams.Timeout == nil {
			reqParams.Timeout = &metav1.Duration{Duration: v1.DefaultTimeOut}
		}

		clusterInfo := bapi.ClusterInfo{
			Cluster: middleware.ClusterIDFromContext(req.Context()),
			Tenant:  middleware.TenantIDFromContext(req.Context()),
		}

		ctx, cancel := context.WithTimeout(context.Background(), reqParams.Timeout.Duration)
		defer cancel()
		response, err := h.logs.List(ctx, clusterInfo, reqParams)
		if err != nil {
			logCtx.WithError(err).Error("Failed to list Audit logs")
			httputils.JSONError(w, &v1.HTTPError{
				Status: http.StatusInternalServerError,
				Msg:    err.Error(),
			}, http.StatusInternalServerError)
			return
		}

		logCtx.Debugf("%s response is: %+v", LogPath, response)
		httputils.Encode(w, response)
	}
}
