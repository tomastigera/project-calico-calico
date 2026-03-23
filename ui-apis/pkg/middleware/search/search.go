// Copyright (c) 2021-2024 Tigera, Inc. All rights reserved.
package search

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/endpoints/request"

	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/validator/v3/query"
	lapi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/lma/pkg/elastic"
	"github.com/projectcalico/calico/lma/pkg/httputils"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
	"github.com/projectcalico/calico/ui-apis/pkg/math"
	"github.com/projectcalico/calico/ui-apis/pkg/middleware"
)

type SearchType int

const (
	SearchTypeFlows SearchType = iota
	SearchTypeDNS
	SearchTypeL7
	SearchTypeEvents
)

// SearchHandler is a handler for the /search endpoint.
//
// Validates request http method and calls different handlers based on the SearchType - flowLogTypeSearchHandler for
// SearchTypeFlows and commonTypeSearchHandler for other types.
func SearchHandler(
	t SearchType,
	authReview middleware.AuthorizationReview,
	k8sClientSetFactory lmak8s.ClientSetFactory,
	lsclient client.Client,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the request user
		user, ok := request.UserFrom(r.Context())
		if !ok {
			httputils.EncodeError(w, &httputils.HttpStatusError{
				Status: http.StatusUnauthorized,
				Msg:    "failed to extract user from request",
				Err:    nil,
			})
			return
		}

		// Get the request cluster.
		cluster := middleware.MaybeParseClusterNameFromRequest(r)

		// Get clientSet for the request user
		logrus.WithField("cluster", cluster).Debug("Cluster ID from request")
		k8sClient, err := k8sClientSetFactory.NewClientSetForUser(user, cluster)
		if err != nil {
			httputils.EncodeError(w, err)
			return
		}

		// Parse request body onto search parameters. If an error occurs while decoding define an http
		// error and return.
		var response *v1.SearchResponse

		// Validate http method.
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			logrus.WithError(middleware.ErrInvalidMethod).Info("Invalid http method.")

			httputils.EncodeError(w, &httputils.HttpStatusError{
				Status: http.StatusMethodNotAllowed,
				Msg:    middleware.ErrInvalidMethod.Error(),
				Err:    middleware.ErrInvalidMethod,
			})

			return
		}

		switch t {
		case SearchTypeFlows:
			response, err = flowlogTypeSearchHandler(authReview, lsclient, w, r)
		default:
			response, err = commonTypeSearchHandler(t, authReview, k8sClient, lsclient, w, r)
		}

		if err != nil {
			httputils.EncodeError(w, err)
			return
		}

		httputils.Encode(w, response)
	})
}

// flowlogTypeSearchHandler handles flowlog search requests.
//
// Uses a request body (JSON.blob) to extract parameters to build an elasticsearch query,
// executes it and returns the results.
func flowlogTypeSearchHandler(
	authReview middleware.AuthorizationReview,
	lsclient client.Client,
	w http.ResponseWriter,
	r *http.Request,
) (*v1.SearchResponse, error) {
	// Decode the request
	searchRequest, err := middleware.ParseBody[v1.FlowLogSearchRequest](w, r)
	if err != nil {
		return nil, err
	}

	// Validate request and set defaults
	err = defaultAndValidateCommonRequest(r, &searchRequest.CommonSearchRequest)
	if err != nil {
		return nil, err
	}

	// Create a context with timeout to ensure we don't block for too long with this query.
	// This releases timer resources if the operation completes before the timeout.
	ctx, cancel := context.WithTimeout(r.Context(), searchRequest.Timeout.Duration)
	defer cancel()

	// Perform the search.
	return searchFlowLogs(ctx, lsclient, searchRequest, authReview)
}

// commonTypeSearchHandler handles dnslogs, l7logs, and event search requests.
//
// Uses a request body (JSON.blob) to extract parameters to build an elasticsearch query,
// executes it and returns the results.
func commonTypeSearchHandler(
	t SearchType,
	authReview middleware.AuthorizationReview,
	k8sClient lmak8s.ClientSet,
	lsclient client.Client,
	w http.ResponseWriter,
	r *http.Request,
) (*v1.SearchResponse, error) {
	// Decode the request
	searchRequest, err := middleware.ParseBody[v1.CommonSearchRequest](w, r)
	if err != nil {
		return nil, err
	}

	// Validate request and set defaults
	err = defaultAndValidateCommonRequest(r, searchRequest)
	if err != nil {
		return nil, err
	}
	// Create a context with timeout to ensure we don't block for too long with this query.
	// This releases timer resources if the operation completes before the timeout.
	ctx, cancel := context.WithTimeout(r.Context(), searchRequest.Timeout.Duration)
	defer cancel()

	// Perform the search.
	switch t {
	case SearchTypeDNS:
		return searchDNSLogs(ctx, lsclient, searchRequest, authReview, k8sClient)
	case SearchTypeL7:
		return searchL7Logs(ctx, lsclient, searchRequest, authReview, k8sClient)
	case SearchTypeEvents:
		return searchEvents(ctx, lsclient, searchRequest, authReview, k8sClient)
	}
	return nil, errors.New("unhandled search type")
}

// defaultAndValidateCommonRequest validates CommonSearchRequest fields and defaults them where needed.
//
// Will define an http.Error if an error occurs.
func defaultAndValidateCommonRequest(r *http.Request, c *v1.CommonSearchRequest) error {
	// Initialize the search parameters to their default values.
	if c == nil {
		return fmt.Errorf("SearchRequest is not initialized before validation")
	}

	if c.PageSize == nil {
		size := elastic.DefaultPageSize
		c.PageSize = &size
	}

	if c.Timeout == nil {
		c.Timeout = &metav1.Duration{Duration: middleware.DefaultRequestTimeout}
	}

	// Validate parameters.
	if err := validator.Validate(c); err != nil {
		return &httputils.HttpStatusError{
			Status: http.StatusBadRequest,
			Msg:    err.Error(),
			Err:    err,
		}
	}

	// Set cluster name to default: "cluster", if empty.
	if c.ClusterName == "" {
		c.ClusterName = middleware.MaybeParseClusterNameFromRequest(r)
	}

	// Check that we are not attempting to enumerate more than the maximum number of results.
	if c.PageNum*(*c.PageSize) > middleware.MaxNumResults {
		return &httputils.HttpStatusError{
			Status: http.StatusBadRequest,
			Msg:    "page number overflow",
			Err:    errors.New("page number / Page size combination is too large"),
		}
	}

	// At the moment, we only support a single sort by field.
	// TODO(rlb): Need to check the fields are valid for the index type. Maybe something else for the
	// index helper.
	if len(c.SortBy) > 1 {
		return &httputils.HttpStatusError{
			Status: http.StatusBadRequest,
			Msg:    "too many sort fields specified",
			Err:    errors.New("too many sort fields specified"),
		}
	}

	// We want to allow user to be able to select using only From the UI
	if c.TimeRange != nil && c.TimeRange.To.IsZero() && !c.TimeRange.From.IsZero() {
		c.TimeRange.To = time.Now().UTC()
	}

	return nil
}

func validateSelector(selector string, t SearchType) error {
	q, err := query.ParseQuery(selector)
	if err != nil {
		return &httputils.HttpStatusError{
			Status: http.StatusBadRequest,
			Err:    err,
			Msg:    fmt.Sprintf("Invalid selector (%s) in request: %v", selector, err),
		}
	}

	// Validate the atoms in the selector.
	var validator query.Validator
	switch t {
	case SearchTypeL7:
		validator = query.IsValidL7LogsAtom
	case SearchTypeDNS:
		validator = query.IsValidDNSAtom
	case SearchTypeEvents:
		validator = query.IsValidEventsKeysAtom
	case SearchTypeFlows:
		validator = query.IsValidFlowsAtom
	default:
		return fmt.Errorf("invalid search type: %v", t)
	}

	if err := query.Validate(q, validator); err != nil {
		return &httputils.HttpStatusError{
			Status: http.StatusBadRequest,
			Err:    err,
			Msg:    fmt.Sprintf("Invalid selector (%s) in request: %v", selector, err),
		}
	}

	return nil
}

// intoLogParams converts a request into the given Linseed API parameters.
func intoLogParams(ctx context.Context, t SearchType, request *v1.CommonSearchRequest, params lapi.LogParams, authReview middleware.AuthorizationReview) error {
	// Add in the selector.
	if len(request.Selector) > 0 {
		// Validate the selector. Linseed performs the same check, but
		// better to short-circuit the request if we can avoid it.
		if err := validateSelector(request.Selector, t); err != nil {
			return err
		}
		params.SetSelector(request.Selector)
	}

	// Time range query.
	if request.TimeRange != nil {
		params.SetTimeRange(request.TimeRange)
	}

	if authReview != nil {
		// Get the user's permissions. We'll pass these to Linseed to filter out logs that
		// the user doens't have permission to view.
		verbs, err := authReview.PerformReview(ctx, request.ClusterName)
		if err != nil {
			return err
		}
		params.SetPermissions(verbs)
	}

	// Configure sorting, if set.
	for _, s := range request.SortBy {
		if s.Field == "" {
			continue
		}
		params.SetSortBy([]lapi.SearchRequestSortBy{
			{
				Field:      s.Field,
				Descending: s.Descending,
			},
		})
	}

	// if len(params.Filter) > 0 {
	// 	for _, filter := range params.Filter {
	// 		q := elastic.NewRawStringQuery(string(filter))
	// 		esquery = esquery.Filter(q)
	// 	}
	// }

	// Configure pagination, timeout, etc.
	params.SetTimeout(request.Timeout)
	params.SetMaxPageSize(*request.PageSize)
	if request.PageNum != 0 {
		// TODO: Ideally, clients don't know the format of the AfterKey. In order to satisfy
		// the exising UI API, we need to for now.
		params.SetAfterKey(map[string]any{
			"startFrom": request.PageNum * (*request.PageSize),
		})
	}

	return nil
}

// searchFlowLogs calls searchLogs, configured for flow logs.
func searchFlowLogs(
	ctx context.Context,
	lsclient client.Client,
	request *v1.FlowLogSearchRequest,
	authReview middleware.AuthorizationReview,
) (*v1.SearchResponse, error) {
	// build base params.
	params := &lapi.FlowLogParams{}

	if len(request.PolicyMatches) > 0 {
		params.PolicyMatches = request.PolicyMatches
	}

	// Merge in common search request parameters.
	err := intoLogParams(ctx, SearchTypeFlows, &request.CommonSearchRequest, params, authReview)
	if err != nil {
		return nil, err
	}

	listFn := lsclient.FlowLogs(request.ClusterName).List
	return searchLogs(ctx, listFn, params)
}

// searchFlowLogs calls searchLogs, configured for DNS logs.
func searchDNSLogs(
	ctx context.Context,
	lsclient client.Client,
	request *v1.CommonSearchRequest,
	authReview middleware.AuthorizationReview,
	k8sClient lmak8s.ClientSet,
) (*v1.SearchResponse, error) {
	params := &lapi.DNSLogParams{}
	err := intoLogParams(ctx, SearchTypeDNS, request, params, authReview)
	if err != nil {
		return nil, err
	}
	listFn := lsclient.DNSLogs(request.ClusterName).List
	return searchLogs(ctx, listFn, params)
}

// searchL7Logs calls searchLogs, configured for DNS logs.
func searchL7Logs(
	ctx context.Context,
	lsclient client.Client,
	request *v1.CommonSearchRequest,
	authReview middleware.AuthorizationReview,
	k8sClient lmak8s.ClientSet,
) (*v1.SearchResponse, error) {
	params := &lapi.L7LogParams{}
	err := intoLogParams(ctx, SearchTypeL7, request, params, authReview)
	if err != nil {
		return nil, err
	}
	listFn := lsclient.L7Logs(request.ClusterName).List
	return searchLogs(ctx, listFn, params)
}

// searchEvents calls searchLogs, configured for events.
func searchEvents(
	ctx context.Context,
	lsclient client.Client,
	request *v1.CommonSearchRequest,
	authReview middleware.AuthorizationReview,
	k8sClient lmak8s.ClientSet,
) (*v1.SearchResponse, error) {
	params := &lapi.EventParams{}
	err := intoLogParams(ctx, SearchTypeEvents, request, params, authReview)
	if err != nil {
		return nil, err
	}

	// For security event search requests, we need to modify the Elastic query
	// to exclude events which match exceptions created by users.
	eventExceptionList, err := k8sClient.ProjectcalicoV3().AlertExceptions().List(ctx, metav1.ListOptions{})
	if err != nil {
		logrus.WithError(err).Error("failed to list alert exceptions")
		return nil, &httputils.HttpStatusError{
			Status: http.StatusInternalServerError,
			Msg:    err.Error(),
			Err:    err,
		}
	}
	params.Selector = UpdateSelectorWithAlertExceptions(eventExceptionList, params.Selector)

	listFn := lsclient.Events(request.ClusterName).List
	return searchLogs(ctx, listFn, params)
}

// UpdateSelectorWithAlertExceptions() updates originalSelector so that it excludes events
// according to exception rules defined in alertExceptions.
func UpdateSelectorWithAlertExceptions(alertExceptions *v3.AlertExceptionList, originalSelector string) string {
	var selectors []string
	now := &metav1.Time{Time: time.Now()}
	for _, alertException := range alertExceptions.Items {
		if alertException.Spec.StartTime.Before(now) {
			if alertException.Spec.EndTime != nil && alertException.Spec.EndTime.Before(now) {
				// skip expired alert exceptions
				logrus.Debugf(`skipping expired alert exception="%s"`, alertException.GetName())
				continue
			}

			// Validate the selector first.
			err := validateSelector(alertException.Spec.Selector, SearchTypeEvents)
			if err != nil {
				logrus.WithError(err).Warnf(`ignoring alert exception="%s", failed to parse selector="%s"`,
					alertException.GetName(), alertException.Spec.Selector)
				continue
			}
			selectors = append(selectors, alertException.Spec.Selector)
		}
	}

	if len(selectors) > 0 {
		var exceptionsSelector string
		if len(selectors) == 1 {
			// Just one selector - invert it.
			exceptionsSelector = fmt.Sprintf("NOT ( %s )", selectors[0])
		} else {
			// Combine the selectors using OR, and then negate since we don't want
			// any alerts that match any of the selectors.
			// i.e., NOT ( (SEL1) OR (SEL2) OR (SEL3) )
			exceptionsSelector = fmt.Sprintf("NOT (( %s ))", strings.Join(selectors, " ) OR ( "))
		}

		if len(originalSelector) > 0 {
			// Combine exception selector with request selector
			return fmt.Sprintf("(%s) AND %s", originalSelector, exceptionsSelector)
		} else {
			// Use exception selector as request selector
			return exceptionsSelector
		}
	}
	return originalSelector
}

type Hit[T any] struct {
	ID     string `json:"id,omitempty"`
	Source T      `json:"source"`
}

// searchLogs performs a search against the Linseed API for logs that match the given
// parameters, using the provided client.ListFunc.
func searchLogs[T any](
	ctx context.Context,
	listFunc client.ListFunc[T],
	params lapi.LogParams,
) (*v1.SearchResponse, error) {
	pageSize := params.GetMaxPageSize()

	// Perform the query.
	start := time.Now()
	items, err := listFunc(ctx, params)
	if err != nil {
		if httpErr, ok := err.(lapi.HTTPError); ok {
			// It's an HTTP error.
			return nil, httpErr
		}

		return nil, &httputils.HttpStatusError{
			Status: http.StatusInternalServerError,
			Msg:    "error performing search",
			Err:    err,
		}
	}

	// Build the hits response. We want to keep track of errors, but still return
	// as many results as we can.
	var hits []json.RawMessage
	for _, item := range items.Items {
		// ID is only set when the UI needs it.
		var id string
		switch i := any(item).(type) {
		case lapi.Event:
			id = i.ID
		}
		hit := Hit[T]{
			ID:     id,
			Source: item,
		}
		hitJSON, err := json.Marshal(hit)
		if err != nil {
			logrus.WithError(err).WithField("hit", hit).Error("Error marshaling search result")
			return nil, &httputils.HttpStatusError{
				Status: http.StatusInternalServerError,
				Msg:    "error marshaling search result from linseed",
				Err:    err,
			}
		}
		hits = append(hits, json.RawMessage(hitJSON))
	}

	// Calculate the number of pages, given the request's page size.
	cappedTotalHits := math.MinInt(int(items.TotalHits), middleware.MaxNumResults)
	numPages := 0
	if pageSize > 0 {
		numPages = ((cappedTotalHits - 1) / pageSize) + 1
	}

	return &v1.SearchResponse{
		TimedOut:  false, // TODO: Is this used?
		Took:      metav1.Duration{Duration: time.Since(start)},
		NumPages:  numPages,
		TotalHits: int(items.TotalHits),
		Hits:      hits,
	}, nil
}
