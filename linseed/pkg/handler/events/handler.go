// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package events

import (
	"context"
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
	EventsPath           = "/events"
	EventsPathBulk       = "/events/bulk"
	EventsPathStatistics = "/events/statistics"
)

func New(backend bapi.EventsBackend) *events {
	return &events{
		backend: backend,
	}
}

type events struct {
	backend bapi.EventsBackend
}

func (h events) APIS() []handler.API {
	return []handler.API{
		{
			// Base URL queries for events.
			Method:          "POST",
			URL:             EventsPath,
			Handler:         h.List(),
			AuthzAttributes: &authzv1.ResourceAttributes{Verb: handler.Get, Group: handler.APIGroup, Resource: "events"},
		},
		{
			// Bulk creation for events.
			Method:          "POST",
			URL:             EventsPathBulk,
			Handler:         h.Bulk(),
			AuthzAttributes: &authzv1.ResourceAttributes{Verb: handler.Create, Group: handler.APIGroup, Resource: "events"},
		},
		{
			// Bulk dismissal for events.
			Method:          "PUT",
			URL:             EventsPathBulk,
			Handler:         h.Bulk(),
			AuthzAttributes: &authzv1.ResourceAttributes{Verb: handler.Dismiss, Group: handler.APIGroup, Resource: "events"},
		},
		{
			// Bulk delete for events.
			Method:          "DELETE",
			URL:             EventsPathBulk,
			Handler:         h.Bulk(),
			AuthzAttributes: &authzv1.ResourceAttributes{Verb: handler.Delete, Group: handler.APIGroup, Resource: "events"},
		},
		{
			// Statistics for events.
			Method:          "POST",
			URL:             EventsPathStatistics,
			Handler:         h.Statistics(),
			AuthzAttributes: &authzv1.ResourceAttributes{Verb: handler.Get, Group: handler.APIGroup, Resource: "events"},
		},
	}
}

func (h events) List() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		f := logrus.Fields{
			"path":   req.URL.Path,
			"method": req.Method,
		}
		logCtx := logrus.WithFields(f)

		reqParams, httpErr := handler.DecodeAndValidateReqParams[v1.EventParams](w, req)
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
		response, err := h.backend.List(ctx, clusterInfo, reqParams)
		if err != nil {
			logCtx.WithError(err).Error("Failed to list events")
			httputils.JSONError(w, &v1.HTTPError{
				Status: http.StatusInternalServerError,
				Msg:    err.Error(),
			}, http.StatusInternalServerError)
			return
		}

		logCtx.Debugf("%s response is: %+v", EventsPath, response)
		httputils.Encode(w, response)
	}
}

func (h events) Bulk() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		f := logrus.Fields{
			"path":   req.URL.Path,
			"method": req.Method,
		}
		logCtx := logrus.WithFields(f)

		decoded, httpErr := handler.DecodeAndValidateBulkParams[v1.Event](w, req)
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

		// The bulk API supports multiple operations. Determine which backend
		// handler to use.
		type bulkHandler func(context.Context, bapi.ClusterInfo, []v1.Event) (*v1.BulkResponse, error)
		var handler bulkHandler
		switch req.Method {
		case http.MethodPost:
			// Create events.
			handler = h.backend.Create
		case http.MethodPut:
			// Dismiss events.
			handler = h.backend.UpdateDismissFlag
		case http.MethodDelete:
			// Delete events.
			handler = h.backend.Delete
		default:
			// Unsupported method.
			httputils.JSONError(w, &v1.HTTPError{
				Msg:    "unsupported method",
				Status: http.StatusMethodNotAllowed,
			}, http.StatusMethodNotAllowed)
			return
		}

		// Call the chosen handler.
		response, err := handler(ctx, clusterInfo, decoded.Items)
		if err != nil {
			logCtx.WithError(err).Error("Failed to perform bulk action on events")
			httputils.JSONError(w, &v1.HTTPError{
				Status: http.StatusInternalServerError,
				Msg:    err.Error(),
			}, http.StatusInternalServerError)
			return
		}
		response.Total += decoded.FailedCount
		response.Failed += decoded.FailedCount
		logCtx.Debugf("%s %s response is: %+v", req.Method, EventsPathBulk, response)
		httputils.Encode(w, response)
	}
}

func (h events) Statistics() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		f := logrus.Fields{
			"path":   req.URL.Path,
			"method": req.Method,
		}
		logCtx := logrus.WithFields(f)

		reqParams, httpErr := handler.DecodeAndValidateReqParams[v1.EventStatisticsParams](w, req)
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
		response, err := h.backend.Statistics(ctx, clusterInfo, reqParams)
		if err != nil {
			logCtx.WithError(err).Error("Failed get events statistics")
			httputils.JSONError(w, &v1.HTTPError{
				Status: http.StatusInternalServerError,
				Msg:    err.Error(),
			}, http.StatusInternalServerError)
			return
		}

		logCtx.Debugf("%s response is: %+v", EventsPath, response)
		httputils.Encode(w, response)
	}
}
