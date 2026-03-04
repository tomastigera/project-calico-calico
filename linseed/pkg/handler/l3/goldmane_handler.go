// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package l3

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/sirupsen/logrus"
	authzv1 "k8s.io/api/authorization/v1"

	"github.com/projectcalico/calico/goldmane/proto"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/handler"
	"github.com/projectcalico/calico/linseed/pkg/middleware"
	"github.com/projectcalico/calico/lma/pkg/httputils"
)

const (
	GoldmaneFlowPath = "/flows/bulk"
)

type GoldmaneFlows struct {
	hdlr *goldmaneFlowHandler
}

func NewGoldmane(logs bapi.FlowLogBackend) *GoldmaneFlows {
	return &GoldmaneFlows{
		hdlr: &goldmaneFlowHandler{
			logs: logs,
		},
	}
}

type goldmaneFlowHandler struct {
	logs bapi.FlowLogBackend
}

func (h goldmaneFlowHandler) Create() http.HandlerFunc {
	// Handler parses the inbound request from the OSS format, converts it to
	// the enterprise / cloud format, and then forwards it to the enterprise / cloud backend.
	return func(w http.ResponseWriter, req *http.Request) {
		f := logrus.Fields{
			"path":   req.URL.Path,
			"method": req.Method,
		}
		logCtx := logrus.WithFields(f)

		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			// Include the request body in our logs.
			body, err := handler.ReadBody(w, req)
			if err != nil {
				logrus.WithError(err).Warn("Failed to read request body")
			}
			logCtx = logCtx.WithField("body", body)
		}

		decoded, httpErr := handler.DecodeAndValidateBulkParams[*proto.Flow](w, req)
		if httpErr != nil {
			logCtx.WithError(httpErr).Error("Failed to decode/validate request parameters")
			httputils.JSONError(w, httpErr, httpErr.Status)
			return
		}

		// Bulk creation requests don't include a timeout, so use the default.
		ctx, cancel := context.WithTimeout(context.Background(), v1.DefaultTimeOut)
		defer cancel()
		clusterInfo := bapi.ClusterInfo{
			Cluster: middleware.ClusterIDFromContext(req.Context()),
			Tenant:  middleware.TenantIDFromContext(req.Context()),
		}

		// Convert the proto.Flow objects to v1.FlowLog objects.
		logs := make([]v1.FlowLog, 0, len(decoded.Items))
		for _, d := range decoded.Items {
			if f, err := convert(d); err == nil {
				logs = append(logs, f)
			} else {
				// This branch means we received a Flow object that we deem to be invalid. This
				// could be a bug, or it could be a malicious client.
				logCtx.WithField("log", d).WithError(err).Error("Invalid flow object received")
				decoded.FailedCount++
			}
		}

		if len(logs) == 0 {
			httputils.JSONError(w, &v1.HTTPError{
				Status: http.StatusBadRequest,
				Msg:    "Request body contains no valid flow logs",
			}, http.StatusBadRequest)
			return
		}

		// Call the creation function.
		response, err := h.logs.Create(ctx, clusterInfo, logs)
		if err != nil {
			logCtx.WithError(err).Error("Error performing bulk ingestion")
			httputils.JSONError(w, &v1.HTTPError{
				Status: http.StatusInternalServerError,
				Msg:    err.Error(),
			}, http.StatusInternalServerError)
			return
		}
		response.Total += decoded.FailedCount
		response.Failed += decoded.FailedCount
		logCtx.WithField("response", response).Debugf("Completed request")
		httputils.Encode(w, response)
	}
}

func (h GoldmaneFlows) APIS() []handler.API {
	return []handler.API{
		{
			Method:          "POST",
			URL:             GoldmaneFlowPath,
			Handler:         h.hdlr.Create(),
			AuthzAttributes: &authzv1.ResourceAttributes{Verb: handler.Create, Group: handler.APIGroup, Resource: "flowlogs"},
		},
	}
}

func convertType(t proto.EndpointType) (string, error) {
	switch t {
	case proto.EndpointType_WorkloadEndpoint:
		return "wep", nil
	case proto.EndpointType_HostEndpoint:
		return "hep", nil
	case proto.EndpointType_NetworkSet:
		return "ns", nil
	case proto.EndpointType_Network:
		return "net", nil
	}
	return "", fmt.Errorf("invalid endpoint type: %v", t)
}

func convertPolicies(p *proto.PolicyTrace) (*v1.FlowLogPolicy, error) {
	var ep, pp []string
	for _, p := range p.EnforcedPolicies {
		ps, err := p.ToString()
		if err != nil {
			return nil, err
		}
		ep = append(ep, ps)
	}
	for _, p := range p.PendingPolicies {
		ps, err := p.ToString()
		if err != nil {
			return nil, err
		}
		pp = append(pp, ps)
	}
	// Transit policies are not included in the FlowLogPolicy, as they are not present in the
	// Goldmane API
	return &v1.FlowLogPolicy{
		EnforcedPolicies: ep,
		PendingPolicies:  pp,
	}, nil
}

// validate validates the input. This allows us to check for flows that match the schema,
// but are known to not match what our code generates.
func validate(p *proto.Flow) error {
	// All Key fields are required.
	if p.Key == nil {
		return fmt.Errorf("key is required")
	}

	optionalKeyFields := map[string]bool{
		"SourceNamespace":      true,
		"DestNamespace":        true,
		"DestPort":             true,
		"DestServiceName":      true,
		"DestServiceNamespace": true,
		"DestServicePort":      true,
		"DestServicePortName":  true,
	}
	// Use reflection to check each Key field is set.
	structIterator := reflect.ValueOf(p.Key).Elem()
	for i := range structIterator.NumField() {
		field := structIterator.Type().Field(i)
		if field.IsExported() && !optionalKeyFields[field.Name] {
			val := structIterator.Field(i).Interface()
			if reflect.DeepEqual(val, reflect.Zero(structIterator.Field(i).Type()).Interface()) {
				return fmt.Errorf("key field %v is required", field.Name)
			}
		}
	}

	// Some fields have length limits. Enforce them here.
	return nil
}

func convert(p *proto.Flow) (v1.FlowLog, error) {
	if err := validate(p); err != nil {
		return v1.FlowLog{}, err
	}

	// Parse out enum types, rejecting any unexpected values.
	st, err := convertType(p.Key.SourceType)
	if err != nil {
		return v1.FlowLog{}, err
	}
	dt, err := convertType(p.Key.DestType)
	if err != nil {
		return v1.FlowLog{}, err
	}
	policies, err := convertPolicies(p.Key.Policies)
	if err != nil {
		return v1.FlowLog{}, err
	}

	return v1.FlowLog{
		SourceName:      p.Key.SourceName,
		SourceNameAggr:  p.Key.SourceName,
		SourceNamespace: p.Key.SourceNamespace,
		SourceType:      st,
		DestName:        p.Key.DestName,
		DestNameAggr:    p.Key.DestName,
		DestNamespace:   p.Key.DestNamespace,
		DestType:        dt,
		Protocol:        p.Key.Proto,
		DestPort:        &p.Key.DestPort,
		Reporter:        strings.ToLower(p.Key.Reporter.String()),
		Action:          strings.ToLower(p.Key.Action.String()),
		SourceLabels:    &v1.FlowLogLabels{Labels: p.SourceLabels},
		DestLabels:      &v1.FlowLogLabels{Labels: p.DestLabels},
		Policies:        policies,
		PacketsIn:       p.PacketsIn,
		PacketsOut:      p.PacketsOut,
		BytesIn:         p.BytesIn,
		BytesOut:        p.BytesOut,

		NumFlows:          p.NumConnectionsLive,
		NumFlowsStarted:   p.NumConnectionsStarted,
		NumFlowsCompleted: p.NumConnectionsCompleted,
		StartTime:         p.StartTime,
		EndTime:           p.EndTime,
	}, nil
}
