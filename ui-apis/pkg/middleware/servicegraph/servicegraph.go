// Copyright (c) 2021-2023 Tigera, Inc. All rights reserved.
package servicegraph

import (
	"context"
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/lma/pkg/auth"
	"github.com/projectcalico/calico/lma/pkg/httputils"
	"github.com/projectcalico/calico/lma/pkg/k8s"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
	"github.com/projectcalico/calico/ui-apis/pkg/middleware"
)

// This file implements the main HTTP handler factory for service graph. This is the main entry point for service
// graph in ui-apis. The handler pulls together various components to parse the request, query the flow data,
// filter and aggregate the flows. All HTTP request processing is handled here.

func NewServiceGraphHandler(
	authz auth.RBACAuthorizer,
	client ctrlclient.WithWatch,
	linseed lsclient.Client,
	clientSetFactory k8s.ClientSetFactory,
	cfg *Config,
) ServiceGraphHandler {
	return NewServiceGraphHandlerWithBackend(
		client,
		&realServiceGraphBackend{
			authz:            authz,
			linseed:          linseed,
			clientSetFactory: clientSetFactory,
			config:           cfg,
		},
		cfg,
	)
}

func NewServiceGraphHandlerWithBackend(
	client ctrlclient.WithWatch,
	backend ServiceGraphBackend,
	cfg *Config,
) ServiceGraphHandler {
	noServiceGroups := NewServiceGroups()
	noServiceGroups.FinishMappings()
	return &serviceGraph{
		sgCache:         NewServiceGraphCache(client, backend, cfg),
		noServiceGroups: noServiceGroups,
	}
}

type ServiceGraphHandler interface {
	http.Handler
	ServiceGraphCache() ServiceGraphCache
}

// serviceGraph implements the ServiceGraph interface.
type serviceGraph struct {
	// Flows cache.
	sgCache ServiceGraphCache

	// An empty service groups helper.  Used to initially validate the format of the view data.
	noServiceGroups ServiceGroups
}

// RequestData encapsulates data parsed from the request that is shared between the various components that construct
// the service graph.
type RequestData struct {
	ServiceGraphRequest *v1.ServiceGraphRequest
}

func (s *serviceGraph) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	start := time.Now()

	// Extract the request from the body.
	var sgr v1.ServiceGraphRequest
	if err := httputils.Decode(w, req, &sgr); err != nil {
		httputils.EncodeError(w, err)
		return
	}

	cluster := middleware.MaybeParseClusterNameFromRequest(req)
	sg, err := HandleServiceGraphRequest(req.Context(), cluster, &sgr, s.noServiceGroups, s.sgCache)
	if err != nil {
		httputils.EncodeError(w, err)
		return
	}
	httputils.Encode(w, sg)

	log.Infof("Service graph request took %s; returning %d nodes and %d edges", time.Since(start), len(sg.Nodes), len(sg.Edges))
}

func (s *serviceGraph) ServiceGraphCache() ServiceGraphCache {
	return s.sgCache
}

func HandleServiceGraphRequest(
	ctx context.Context,
	parsedClusterName string,
	sgr *v1.ServiceGraphRequest,
	emptyServiceGroups ServiceGroups,
	serviceGraphCache ServiceGraphCache,
	serviceGraphConstructorOpts ...ServiceGraphConstructorOption) (*v1.ServiceGraphResponse, error) {
	sgr, err := validateAndDefaultServiceGraphRequest(sgr, parsedClusterName)
	if err != nil {
		return nil, err
	}

	// Construct a context with timeout based on the service graph request.
	ctx, cancel := context.WithTimeout(ctx, sgr.Timeout.Duration)
	defer cancel()

	// Create the request data.
	rd := &RequestData{
		ServiceGraphRequest: sgr,
	}

	// Process the request:
	// - do a first parse of the view IDs (but with no service group info)
	// - get the filtered service graph raw data
	// - parse the view IDs, this time with service group info
	// - Compile the graph
	// - Write the response.
	if _, err := ParseViewIDs(rd, emptyServiceGroups); err != nil {
		return nil, err
	} else if f, err := serviceGraphCache.GetFilteredServiceGraphData(ctx, rd); err != nil {
		return nil, err
	} else if pv, err := ParseViewIDs(rd, f.ServiceGroups); err != nil {
		return nil, err
	} else if sg, err := GetServiceGraphResponse(f, pv, serviceGraphConstructorOpts...); err != nil {
		return nil, err
	} else {
		return sg, nil
	}
}

// validateAndDefaultServiceGraphRequest validates and processes a service graph request.
func validateAndDefaultServiceGraphRequest(sgr *v1.ServiceGraphRequest, parsedClusterName string) (*v1.ServiceGraphRequest, error) {
	// Validate parameters.
	if err := validator.Validate(sgr); err != nil {
		return nil, &httputils.HttpStatusError{
			Status: http.StatusBadRequest,
			Msg:    fmt.Sprintf("Request body contains invalid data: %v", err),
			Err:    err,
		}
	}

	if sgr.Timeout.Duration == 0 {
		sgr.Timeout.Duration = middleware.DefaultRequestTimeout
	}
	if sgr.Cluster == "" {
		sgr.Cluster = parsedClusterName
	}

	// Sanity check any user configuration that may potentially break the API. In particular all user defined names
	// that may be embedded in an ID should adhere to the IDValueRegex.
	allLayers := set.New[string]()
	for _, layer := range sgr.SelectedView.Layers {
		if !IDValueRegex.MatchString(layer.Name) {
			return nil, httputils.NewHttpStatusErrorBadRequest(fmt.Sprintf("Request body contains an invalid layer name: %s", layer.Name), nil)
		}
		if allLayers.Contains(layer.Name) {
			return nil, httputils.NewHttpStatusErrorBadRequest(fmt.Sprintf("Request body contains a duplicate layer name: %s", layer.Name), nil)
		}
		allLayers.Add(layer.Name)
	}

	allAggrHostnames := set.New[string]()
	for _, selector := range sgr.SelectedView.HostAggregationSelectors {
		if !IDValueRegex.MatchString(selector.Name) {
			return nil, httputils.NewHttpStatusErrorBadRequest(fmt.Sprintf("Request body contains an invalid aggregated host name: %s", selector.Name), nil)
		}
		if allAggrHostnames.Contains(selector.Name) {
			return nil, httputils.NewHttpStatusErrorBadRequest(fmt.Sprintf("Request body contains a duplicate aggregated host name: %s", selector.Name), nil)
		}
		allAggrHostnames.Add(selector.Name)
	}

	return sgr, nil
}
