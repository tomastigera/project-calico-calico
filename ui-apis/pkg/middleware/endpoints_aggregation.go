package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/utils/ptr"

	lapi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	lmaauth "github.com/projectcalico/calico/lma/pkg/auth"
	"github.com/projectcalico/calico/lma/pkg/httputils"
	querycacheclient "github.com/projectcalico/calico/queryserver/pkg/querycache/client"
	qsutils "github.com/projectcalico/calico/queryserver/pkg/querycache/utils"
	queryserverclient "github.com/projectcalico/calico/queryserver/queryserver/client"
	esauth "github.com/projectcalico/calico/ui-apis/pkg/auth"
)

const (
	TimeRangeError = "missing parameter: \"time_range.from\" and / or \"time_range.to\" is empty"
)

type EndpointsAggregationRequest struct {
	// ClusterName defines the name of the cluster a connection will be performed on.
	ClusterName string `json:"cluster"`

	// QueryServer params, inlined
	querycacheclient.QueryEndpointsReqBody

	// Enable filtering endpoints in denied traffic
	ShowDeniedEndpoints bool `json:"showDeniedEndpoints,omitempty" validate:"omitempty"`

	// Time range
	TimeRange *lmav1.TimeRange `json:"time_range" validate:"omitempty"`

	// Timeout for the request. Defaults to 60s.
	Timeout *metav1.Duration `json:"timeout" validate:"omitempty"`
}

type EndpointsAggregationResponse struct {
	Count int                  `json:"count"`
	Item  []AggregatedEndpoint `json:"endpoints"`
}

// AggregatedEndpoint contains endpoints object returned from queryserver with some additional properties listed below:
// HasDeniedTraffic: boolean pointer which can be nul (when user does not have access to flowlogs), true, or false.
// HasFlowAccess: boolean value which shows whether user has access to flowlogs or not
// Warnings: a string array which contains any warnings we want to share with consumer via the API.
type AggregatedEndpoint struct {
	querycacheclient.Endpoint
	HasDeniedTraffic *bool    `json:"hasDeniedTraffic"`
	HasFlowAccess    bool     `json:"hasFlowAccess"`
	Warnings         []string `json:"warnings"`
}

var (
	flowAccessWarning = `user is missing required rbac verbs ("get") to resource "flows"`
)

// EndpointsAggregationHandler is a handler for /endpoints/aggregation api
//
// returns a http handler function for getting list of endpoints (and filtering them by a set of parameters including:
// 1. network traffic (retrieved from flowlogs), and 2. static info (from endpoints, policies,
// nodes, and labels which are retrieved from queryserver cache))
//
// *note: this handler aggregates endpoints info with denied flowlogs - If timerange.from is provided from the client,
// linseed will return denied flowlogs from the provided time until now (linseed) time. timerange.to is set to Now()
// when linseed is processing the request and is different from when client is calling this api or when results are back
// to the client. So in very rare cases, results might be missing denied flowlog information if it happens in the very
// small timeframe between the call to linseed and response getting back to client. In this case, the api has to be called
// again (maybe just refreshing a page from user's point of view).
func EndpointsAggregationHandler(authz lmaauth.RBACAuthorizer, authreview AuthorizationReview, qsConfig *queryserverclient.QueryServerConfig,
	lsclient client.Client) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		start := time.Now()
		logrus.Debug("[Endpoints] Processing Endpoints Aggregation request")
		// Validate http method.
		if r.Method != http.MethodPost {
			logrus.WithError(ErrInvalidMethod).Error("Invalid http method.")

			err := &httputils.HttpStatusError{
				Status: http.StatusMethodNotAllowed,
				Msg:    ErrInvalidMethod.Error(),
				Err:    ErrInvalidMethod,
			}

			httputils.EncodeError(w, err)
			return
		}

		// Parse request body.
		endpointsAggregationRequest, err := ParseBody[EndpointsAggregationRequest](w, r)
		if err != nil {
			logrus.WithError(err).Error("call to ParseBody failed.")
			httputils.EncodeError(w, err)
			return
		}

		// Validate parameters.
		err = validateEndpointsAggregationRequest(r, endpointsAggregationRequest)
		if err != nil {
			logrus.WithError(err).Error("call to validateEndpointsAggregationRequest failed.")
			httputils.EncodeError(w, err)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), endpointsAggregationRequest.Timeout.Duration)
		defer cancel()

		logrus.Debug("[Endpoints] Check flow log permissions")
		// Check access to flowlogs
		flowAccess, err := hasFlowLogsPermission(authz, r)
		if err != nil {
			logrus.WithError(err).Error("call to hasFlowLogsPermission failed.")
			httputils.EncodeError(w, &httputils.HttpStatusError{
				Status: http.StatusInternalServerError,
				Msg:    "request to authorize user for access to flowlogs has failed",
				Err:    errors.New("user authorization has failed"),
			})
			return
		}
		logrus.Debugf("[Endpoints] Done checking flow log permissions, hasFlowAcces=%v", flowAccess)

		grp, ctx := errgroup.WithContext(ctx)

		var deniedEndpoints []string
		var qsEndpointsResp *querycacheclient.QueryEndpointsResp

		if endpointsAggregationRequest.ShowDeniedEndpoints {
			grp.Go(func() error {
				// Call will be made sequentially since the denied endpoints regex is used to query denied endpoints
				// from query server

				var err error
				if flowAccess {
					// Build a denied endpoints regex based on denied flow logs (retrieved via linseed)
					deniedEndpoints, err = deniedEndpointsRegex(ctx, endpointsAggregationRequest, lsclient, authreview)
					if err != nil {
						return err
					}
				}
				// Filter deniedEndpoints via queryserver
				qsEndpointsResp, err = endpoints(r, qsConfig, endpointsAggregationRequest, deniedEndpoints)
				if err != nil {
					return err
				}
				return nil
			})
		} else {
			// Calls can be made in parallel since we need all endpoints and,
			// we do not need to build the denied endpoints regex from Linseed queries
			grp.Go(func() error {
				var err error
				if flowAccess {
					// Build a denied endpoints regex based on denied flow logs (retrieved via linseed)
					deniedEndpoints, err = deniedEndpointsRegex(ctx, endpointsAggregationRequest, lsclient, authreview)
				}
				return err
			})
			grp.Go(func() error {
				var err error
				// Get endpoints via queryserver
				qsEndpointsResp, err = endpoints(r, qsConfig, endpointsAggregationRequest, nil)
				return err
			})

		}

		if err := grp.Wait(); err != nil {
			var httpStatusErr *httputils.HttpStatusError
			if errors.As(err, &httpStatusErr) {
				httputils.EncodeError(w, httpStatusErr)
				return
			} else {
				logrus.WithError(err).Error("call to grp.Wait() failed.")
			}
			return
		}

		// Enrich deniedEndpoints results with denied traffic info
		respBodyUpdated, err := updateResults(qsEndpointsResp, deniedEndpoints, flowAccess)
		if err != nil {
			logrus.WithError(err).Error("call to updateResults failed.")
			httputils.EncodeError(w, &httputils.HttpStatusError{
				Status: http.StatusInternalServerError,
				Msg:    "failed to update deniedEndpoints with denied traffic info",
				Err:    errors.New("failed to update deniedEndpoints with denied traffic info"),
			})
			return
		}
		logrus.Debugf("[Endpoints] Done processing endpoints aggregation request, duration=%s", time.Since(start))
		httputils.Encode(w, respBodyUpdated)
	})
}

// endpoints queries queryserver to retrieve endpoints for a cluster
//
// returns QueryEndpointsResp: list of endpoints from queryserver based on the search parameters provided.
func endpoints(r *http.Request, qsConfig *queryserverclient.QueryServerConfig, params *EndpointsAggregationRequest,
	deniedEndpoints []string) (*querycacheclient.QueryEndpointsResp, error) {

	start := time.Now()
	logrus.Debug("[Endpoints] Fetch endpoints from Query Server")
	// build queryserver getEndpoints api params
	qsReqParams := getQueryServerRequestParams(params, deniedEndpoints)

	// Update queryserver config with logged-in user's token
	qsConfig.QueryServerToken = r.Header.Get("Authorization")[7:]

	// Create queryServerClient client.
	queryServerClient, err := queryserverclient.NewQueryServerClient(qsConfig)
	if err != nil {
		logrus.WithError(err).Error("call to create NewQueryServerClient failed.")
		return nil, &httputils.HttpStatusError{
			Status: http.StatusInternalServerError,
			Msg:    "failed to get endpoints from queryserver",
			Err:    errors.New("failed to get endpoints from queryserver"),
		}
	}

	// call to queryserver client to get deniedEndpoints
	qsEndpointsResp, err := queryServerClient.SearchEndpoints(qsConfig, qsReqParams, params.ClusterName)
	logrus.Debugf("[Endpoints] Done fetching endpoints from Query Server. duration=%s", time.Since(start))
	if err != nil {
		logrus.WithError(err).Error("call to endpoints failed.")
		if strings.ContainsAny(strings.ToLower(err.Error()), "not authorized") {
			return qsEndpointsResp, &httputils.HttpStatusError{
				Status: http.StatusForbidden,
				Msg:    "failed authorization to queryserver/endpoints",
				Err:    err,
			}
		} else {
			return qsEndpointsResp, &httputils.HttpStatusError{
				Status: http.StatusInternalServerError,
				Msg:    "failed to get endpoints from queryserver",
				Err:    errors.New("failed to get endpoints from queryserver"),
			}
		}
	}

	return qsEndpointsResp, nil
}

// updateResults enriches list of endpoints with denied traffic information
//
// return EndpointsAggregationResponse
func updateResults(endpointsResp *querycacheclient.QueryEndpointsResp,
	deniedEndpoints []string, flowAccess bool) (*EndpointsAggregationResponse, error) {

	epAggrList := []AggregatedEndpoint{}

	var epPatterns *regexp.Regexp

	if len(deniedEndpoints) > 0 {
		var err error
		epPatterns, err = qsutils.BuildSubstringRegexMatcher(deniedEndpoints)
		if err != nil {
			logrus.WithError(err).Error("call to BuildSubstringRegexMatcher failed.")
			return nil, err
		}
	}

	for _, item := range endpointsResp.Items {
		epAggregate := AggregatedEndpoint{
			Endpoint: item,
		}

		epKey := fmt.Sprintf("%s/%s", item.Namespace, item.Name)

		if !flowAccess {
			epAggregate.HasDeniedTraffic = nil
			epAggregate.HasFlowAccess = false
			epAggregate.Warnings = append(epAggregate.Warnings, flowAccessWarning)
		} else if epPatterns != nil && epPatterns.MatchString(epKey) {
			epAggregate.HasDeniedTraffic = ptr.To(true)
			epAggregate.HasFlowAccess = true
		} else {
			epAggregate.HasDeniedTraffic = ptr.To(false)
			epAggregate.HasFlowAccess = true
		}

		epAggrList = append(epAggrList, epAggregate)
	}

	epAggrResponse := EndpointsAggregationResponse{
		Count: endpointsResp.Count,
		Item:  epAggrList,
	}
	return &epAggrResponse, nil
}

// validateEndpointsAggregationRequest validates the request params for /endpoints/aggregation api
//
// return error if an unacceptable set of parameters are provided
func validateEndpointsAggregationRequest(r *http.Request, endpointReq *EndpointsAggregationRequest) error {
	// Set cluster name to default: "cluster", if empty.
	if endpointReq.ClusterName == "" {
		endpointReq.ClusterName = MaybeParseClusterNameFromRequest(r)
	}

	if endpointReq.ShowDeniedEndpoints {
		// validate queryserver params to not include endpoints list when ShowDeniedEndpoints is set to true
		if endpointReq.EndpointsList != nil {
			return &httputils.HttpStatusError{
				Status: http.StatusBadRequest,
				Msg:    "both ShowDeniedEndpoints and endpointList can not be provided in the same request",
				Err:    errors.New("invalid combination of parameters are provided: \"ShowDeniedEndpoints\" and / or \"endpointsList\""),
			}
		}
	}

	if endpointReq.Timeout == nil {
		endpointReq.Timeout = &metav1.Duration{Duration: DefaultRequestTimeout}
	}

	// validate time range to not be empty
	if endpointReq.TimeRange == nil || endpointReq.TimeRange.From.IsZero() || endpointReq.TimeRange.To.IsZero() {
		return &httputils.HttpStatusError{
			Status: http.StatusBadRequest,
			Msg:    "time_range should not be empty",
			Err:    errors.New(TimeRangeError),
		}

	}

	return nil
}

// buildFlowLogParamsForDeniedTrafficSearch prepares the parameters for flowlog search call to linseed to get denied flowlogs.
//
// returns FlowLogParams to be passed to linseed client, and an error.
func buildFlowLogParamsForDeniedTrafficSearch(ctx context.Context, authReview AuthorizationReview, params *EndpointsAggregationRequest,
	pageNumber, pageSize int) (*lapi.FlowLogParams, error) {
	fp := &lapi.FlowLogParams{}

	if params.TimeRange != nil {
		fp.SetTimeRange(params.TimeRange)
	}

	// set policy match to filter denied flowlogs
	action := lapi.FlowActionDeny
	fp.PolicyMatches = []lapi.PolicyMatch{
		{
			Action: &action,
		},
	}

	// Get the user's permissions. We'll pass these to Linseed to filter out logs that
	// the user doens't have permission to view.
	verbs, err := authReview.PerformReview(ctx, params.ClusterName)
	if err != nil {
		logrus.WithError(err).Error("call to authorization PerformReview failed.")
		return nil, err
	}
	fp.SetPermissions(verbs)

	// Configure pagination, timeout, etc.
	fp.SetTimeout(params.Timeout)

	fp.SetMaxPageSize(pageSize)
	if pageNumber != 0 {
		fp.SetAfterKey(map[string]any{
			"startFrom": pageNumber * (fp.GetMaxPageSize()),
		})
	}

	return fp, nil
}

// deniedEndpointsRegex extracts a regex of endpoints from denied flowlogs.
//
// It calls linseed.FlowLogs().List to fetch denied flowlogs.
// returns:
// 1. []string that includes a regex based extracted endpoints (src or dst) from denied flowlogs. Endpoint formatting is
// compatible with endpoint keys in datastore (used in queryserver).
//
//	example : ["(.*?tigera-compliance)/(.*?-compliance--controller--6769fc95b4--gslxr)"]
//
// 2. error
func deniedEndpointsRegex(ctx context.Context, endpointsAggregationRequest *EndpointsAggregationRequest,
	lsclient client.Client, authreview AuthorizationReview) ([]string, error) {

	var endpoints []string
	var endpointsSet = make(map[string]bool)
	pageNumber := 0
	pageSize := 1000
	var afterKey map[string]any
	deniedFlowLogsParams, err := buildFlowLogParamsForDeniedTrafficSearch(ctx, authreview, endpointsAggregationRequest, pageNumber, pageSize)
	if err != nil {
		logrus.WithError(err).Error("call to buildFlowLogParamsForDeniedTrafficSearch failed.")
		return nil, &httputils.HttpStatusError{
			Status: http.StatusInternalServerError,
			Msg:    "error preparing flowlog search parameters",
			Err:    err,
		}
	}

	start := time.Now()
	logrus.Debug("[Endpoints] Fetch data from Linseed")
	// iterate over all the page to get all flowlogs returned by flowlogs search
	for pageNumber == 0 || afterKey != nil {
		listFn := lsclient.FlowLogs(endpointsAggregationRequest.ClusterName).List

		items, err := listFn(ctx, deniedFlowLogsParams)
		if err != nil {
			logrus.WithError(err).Error("call to get flowLogs list from linseed failed.")
			return nil, &httputils.HttpStatusError{
				Status: http.StatusInternalServerError,
				Msg:    "error performing flowlog search",
				Err:    err,
			}
		}

		for _, item := range items.Items {

			// Extract endpoints from flowlog item: both src and dst.
			sourcePattern := buildQueryServerEndpointKeyString(item.SourceNamespace, item.SourceName, item.SourceNameAggr)
			endpointsSet[sourcePattern] = true

			destPattern := buildQueryServerEndpointKeyString(item.DestNamespace, item.DestName, item.DestNameAggr)
			endpointsSet[destPattern] = true
		}
		pageNumber++

		afterKey = items.AfterKey
		deniedFlowLogsParams.SetAfterKey(items.AfterKey)
	}
	logrus.Debugf("[Endpoints] Done fetching data from Linseed, duration=%s", time.Since(start))

	for k := range endpointsSet {
		endpoints = append(endpoints, k)
	}

	return endpoints, nil
}

// buildQueryServerEndpointKeyString is building endpoints key in the format expected by queryserver.
//
// Here is one example of an endpoint key in queryserver:
// WorkloadEndpoint(tigera-fluentd/afra--bz--vaxb--kadm--ms-k8s-fluentd--node--dfpzf-eth0)
// In this code, we create the following string that will be a match for the above endpoint:
//
//	.*tigera-fluentd/afra--bz--vaxb--kadm--ms-k8s-fluentd--node--*
func buildQueryServerEndpointKeyString(ns, name, nameaggr string) string {
	if name == "-" {
		return fmt.Sprintf("(.*?%s/.*?-%s)",
			ns,
			strings.ReplaceAll(nameaggr, "-", "--"))

	} else {
		return fmt.Sprintf("(.*?%s/.*?-%s)",
			ns,
			strings.ReplaceAll(name, "-", "--"))

	}
}

// getQueryServerRequestParams prepare the queryserver params
//
// return *querycacheclient.QueryEndpointsReq
func getQueryServerRequestParams(params *EndpointsAggregationRequest, deniedEndpoints []string) *querycacheclient.QueryEndpointsReqBody {
	// don't copy endpointsList initially from params.
	qsReqParams := querycacheclient.QueryEndpointsReqBody{
		Policy:              params.Policy,
		RuleDirection:       params.RuleDirection,
		RuleIndex:           params.RuleIndex,
		RuleEntity:          params.RuleEntity,
		RuleNegatedSelector: params.RuleNegatedSelector,
		Selector:            params.Selector,
		Endpoint:            params.Endpoint,
		Unprotected:         params.Unprotected,
		Node:                params.Node,
		Namespace:           params.Namespace,
		PodNamePrefix:       params.PodNamePrefix,
		Unlabelled:          params.Unlabelled,
		Page:                params.Page,
		Sort:                params.Sort,
	}

	if params.ShowDeniedEndpoints {

		if deniedEndpoints == nil {
			qsReqParams.EndpointsList = []string{}
		} else {
			logrus.Debugf("[Endpoints] Specifying denied endpoints to be queried (%v).", deniedEndpoints)
			qsReqParams.EndpointsList = deniedEndpoints
		}
	}

	return &qsReqParams
}

// hasFlowLogsPermission checks to see if user is authorized to call linseed flowlog API.
func hasFlowLogsPermission(authz lmaauth.RBACAuthorizer, r *http.Request) (bool, error) {
	// Extract the cluster name from the request body.
	// Note: DecodeIgnoreUnknownFields maintains the request body's data to pass on to the next handler.
	var params = struct {
		ClusterName string `json:"cluster,omitempty"`
	}{}

	clusterName := params.ClusterName
	if clusterName == "" {
		clusterName = MaybeParseClusterNameFromRequest(r)
	}

	res := esauth.CreateLMAResourceAttributes(clusterName, "flows")
	usr, _ := request.UserFrom(r.Context())

	return authz.Authorize(usr, res, nil)
}
