// Copyright (c) 2019-2025 Tigera, Inc. All rights reserved.

package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8srequest "k8s.io/apiserver/pkg/endpoints/request"

	"github.com/projectcalico/calico/compliance/pkg/datastore"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	lapi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	v1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	lmaauth "github.com/projectcalico/calico/lma/pkg/auth"
	lmaelastic "github.com/projectcalico/calico/lma/pkg/elastic"
	"github.com/projectcalico/calico/lma/pkg/rbac"
	"github.com/projectcalico/calico/lma/pkg/timeutils"
	pippkg "github.com/projectcalico/calico/ui-apis/pkg/pip"
)

type FlowLogsParams struct {
	ClusterName          string          `json:"cluster"`
	Limit                int32           `json:"limit"`
	SourceType           []string        `json:"srcType"`
	SourceLabels         []LabelSelector `json:"srcLabels"`
	DestType             []string        `json:"dstType"`
	DestLabels           []LabelSelector `json:"dstLabels"`
	StartDateTime        string          `json:"startDateTime"`
	EndDateTime          string          `json:"endDateTime"`
	Actions              []string        `json:"actions"`
	Namespace            string          `json:"namespace"`
	SourceDestNamePrefix string          `json:"srcDstNamePrefix"`
	PolicyPreviews       []PolicyPreview `json:"policyPreviews"`
	Unprotected          bool            `json:"unprotected"`
	ImpactedOnly         bool            `json:"impactedOnly"`

	// Parsed timestamps
	startDateTime       *time.Time
	endDateTime         *time.Time
	startDateTimeESParm any
	endDateTimeESParm   any
}

type LabelSelector struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

type PolicyPreview struct {
	Verb          string             `json:"verb"`
	NetworkPolicy resources.Resource `json:"networkPolicy"`
}

// policyPreviewTrial is used to temporarily unmarshal the PolicyPreviews so that we can extract the TypeMeta from
// the resource definition.
type policyPreviewTrial struct {
	NetworkPolicy metav1.TypeMeta `json:"networkPolicy"`
}

// Defined an alias for the ResourceChange so that we can json unmarshal it from the PolicyPreviews.UnmarshalJSON
// without causing recursion (since aliased types do not inherit methods).
type AliasedPolicyPreview *PolicyPreview

// UnmarshalJSON allows unmarshalling of a PolicyPreviews from JSON bytes. This is required because the Resource
// field is an interface, and so it needs to be set with a concrete type before it can be unmarshalled.
func (c *PolicyPreview) UnmarshalJSON(b []byte) error {
	// Unmarshal into the "trial" struct that allows us to easily extract the TypeMeta of the resource.
	var r policyPreviewTrial
	if err := json.Unmarshal(b, &r); err != nil {
		return err
	}
	c.NetworkPolicy = resources.NewResource(r.NetworkPolicy)

	// Decode the policy preview JSON data. We should fail if there are unhandled fields in the request. Validation of
	// the actual data is done within PIP as part of the xrefcache population.
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(AliasedPolicyPreview(c)); err != nil {
		return err
	}
	if decoder.More() {
		return errPreviewResourceExtraData
	}

	// If this is a Calico tiered network policy, configure an empty tier to be default and verify the name matches
	// the tier.
	var tier *string
	var name string
	switch np := c.NetworkPolicy.(type) {
	case *v3.NetworkPolicy:
		tier = &np.Spec.Tier
		name = np.Name
	case *v3.GlobalNetworkPolicy:
		tier = &np.Spec.Tier
		name = np.Name
	default:
		// Not a calico tiered policy, so just exit now, no need to do the extra checks.
		return nil
	}

	// Calico tiered policy. The tier in the spec should also be the prefix of the policy name.
	if *tier == "" {
		// The tier is not set, so set it to be default.
		*tier = "default"
	}
	if !strings.HasPrefix(name, *tier+".") {
		return errors.New("policy name '" + name + "' is not correct for the configured tier '" + *tier + "'")
	}
	return nil
}

// A handler for the /flowLogs endpoint, uses url parameters to build an elasticsearch query,
// executes it and returns the results.
func FlowLogsHandler(
	k8sClientFactory datastore.ClusterCtxK8sClientFactory,
	lsclient client.Client,
	pip pippkg.PIP,
	impersonate bool,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Validate Request
		params, err := validateFlowLogsRequest(req)
		if err != nil {
			log.WithError(err).Info("Error validating flowLogs request")
			switch err {
			case ErrInvalidMethod:
				http.Error(w, err.Error(), http.StatusMethodNotAllowed)
			case ErrParseRequest:
				http.Error(w, err.Error(), http.StatusBadRequest)
			case errInvalidAction:
				http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			case errInvalidFlowType:
				http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			case errInvalidLabelSelector:
				http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			case errInvalidPolicyPreview:
				http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			}
			return
		}

		// Create a context to use.
		ctx, cancel := context.WithTimeout(req.Context(), 60*time.Second)
		defer cancel()

		k8sCli, err := k8sClientFactory.ClientSetForCluster(params.ClusterName)
		if err != nil {
			log.WithError(err).Error("failed to get k8s cli")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		user, ok := k8srequest.UserFrom(req.Context())
		if !ok {
			log.Error("user not found in context")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// If impersonation in managed clusters is enabled, we can use the original user's identity to
		// perform the RBAC checks.
		flowHelper := rbac.NewCachedFlowHelper(user, lmaauth.NewRBACAuthorizer(k8sCli))
		flowFilter := lmaelastic.NewFlowFilterUserRBAC(flowHelper)
		if !impersonate {
			// Otherwise, we cannot perform the RBAC checks, so we will include all flows.
			flowFilter = lmaelastic.NewFlowFilterIncludeAll()
		}

		var response any
		var stat int
		flowParams := buildFlowParams(params)
		opts := []client.ListPagerOption[lapi.L3Flow]{client.WithMaxResults[lapi.L3Flow](int(params.Limit))}
		pager := client.NewListPager(flowParams, opts...)
		if len(params.PolicyPreviews) == 0 {
			response, stat, err = getFlowLogsFromLinseed(ctx, flowFilter, params.Unprotected, pager, lsclient, params.ClusterName)
		} else {
			rbacHelper := NewPolicyImpactRbacHelper(user, lmaauth.NewRBACAuthorizer(k8sCli))
			response, stat, err = getPIPFlowLogsFromLinseed(ctx, pager, flowFilter, params, pip, rbacHelper)
		}

		if err != nil {
			log.WithError(err).Info("Error getting search results from Linseed")
			http.Error(w, err.Error(), stat)
		}

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(response)
		if err != nil {
			log.WithError(err).Info("Encoding search results failed")
			http.Error(w, errGeneric.Error(), http.StatusInternalServerError)
			return
		}
	})
}

// extracts query parameters from url and validates them
func validateFlowLogsRequest(req *http.Request) (*FlowLogsParams, error) {
	// Validate http method
	if req.Method != http.MethodGet {
		return nil, ErrInvalidMethod
	}

	// extract params from request
	url := req.URL.Query()
	cluster := strings.ToLower(url.Get("cluster"))
	limit, err := extractLimitParam(url)
	if err != nil {
		log.WithError(err).Info("Error extracting limit")
		return nil, ErrParseRequest
	}
	srcType := lowerCaseParams(url["srcType"])
	srcLabels, err := getLabelSelectors(url["srcLabels"])
	if err != nil {
		log.WithError(err).Info("Error extracting srcLabels")
		return nil, ErrParseRequest
	}
	dstType := lowerCaseParams(url["dstType"])
	dstLabels, err := getLabelSelectors(url["dstLabels"])
	if err != nil {
		log.WithError(err).Info("Error extracting dstLabels")
		return nil, ErrParseRequest
	}
	startDateTimeString := url.Get("startDateTime")
	endDateTimeString := url.Get("endDateTime")
	actions := lowerCaseParams(url["actions"])
	namespace := strings.ToLower(url.Get("namespace"))
	srcDstNamePrefix := strings.ToLower(url.Get("srcDstNamePrefix"))
	policyPreviews, err := getPolicyPreviews(url["policyPreview"])
	if err != nil {
		log.WithError(err).Info("Error extracting policyPreview")
		return nil, ErrParseRequest
	}
	unprotected := false
	if unprotectedValue := url.Get("unprotected"); unprotectedValue != "" {
		if unprotected, err = strconv.ParseBool(unprotectedValue); err != nil {
			return nil, ErrParseRequest
		}
	}
	impactedOnly := false
	if impactedOnlyValue := url.Get("impactedOnly"); impactedOnlyValue != "" {
		if impactedOnly, err = strconv.ParseBool(impactedOnlyValue); err != nil {
			return nil, ErrParseRequest
		}
	}

	now := time.Now()
	startDateTime, startDateTimeESParm, err := timeutils.ParseTime(now, &startDateTimeString)
	if err != nil {
		log.WithError(err).Info("Error extracting start date time")
		return nil, ErrParseRequest
	}
	endDateTime, endDateTimeESParm, err := timeutils.ParseTime(now, &endDateTimeString)
	if err != nil {
		log.WithError(err).Info("Error extracting end date time")
		return nil, ErrParseRequest
	}

	params := &FlowLogsParams{
		ClusterName:          cluster,
		Limit:                limit,
		SourceType:           srcType,
		SourceLabels:         srcLabels,
		DestType:             dstType,
		DestLabels:           dstLabels,
		StartDateTime:        startDateTimeString,
		EndDateTime:          endDateTimeString,
		Actions:              actions,
		Namespace:            namespace,
		SourceDestNamePrefix: srcDstNamePrefix,
		PolicyPreviews:       policyPreviews,
		ImpactedOnly:         impactedOnly,
		Unprotected:          unprotected,
		startDateTime:        startDateTime,
		endDateTime:          endDateTime,
		startDateTimeESParm:  startDateTimeESParm,
		endDateTimeESParm:    endDateTimeESParm,
	}

	if params.ClusterName == "" {
		params.ClusterName = MaybeParseClusterNameFromRequest(req)
	}
	srcTypeValid := validateFlowTypes(params.SourceType)
	if !srcTypeValid {
		return nil, errInvalidFlowType
	}
	dstTypeValid := validateFlowTypes(params.DestType)
	if !dstTypeValid {
		return nil, errInvalidFlowType
	}
	srcLabelsValid := validateLabelSelector(params.SourceLabels)
	if !srcLabelsValid {
		return nil, errInvalidLabelSelector
	}
	dstLabelsValid := validateLabelSelector(params.DestLabels)
	if !dstLabelsValid {
		return nil, errInvalidLabelSelector
	}
	actionsValid := validateActions(params.Actions)
	if !actionsValid {
		return nil, errInvalidAction
	}
	valid := validateActionsAndUnprotected(params.Actions, params.Unprotected)
	if !valid {
		return nil, errInvalidActionUnprotected
	}
	policyPreviewValid := validatePolicyPreviews(params.PolicyPreviews)
	if !policyPreviewValid {
		return nil, errInvalidPolicyPreview
	}

	return params, nil
}

func buildFlowParams(params *FlowLogsParams) *lapi.L3FlowParams {
	fp := lapi.L3FlowParams{}

	// We will limit the entire response later, but
	// don't increase the page size above 1000.
	fp.MaxPageSize = int(params.Limit)
	if params.Limit > 1000 {
		fp.MaxPageSize = 1000
	}
	if len(params.Actions) > 0 {
		fp.Actions = []lapi.FlowAction{}
		for _, a := range params.Actions {
			fp.Actions = append(fp.Actions, lapi.FlowAction(a))
		}
	}
	if len(params.SourceType) > 0 {
		fp.SourceTypes = []lapi.EndpointType{}
		for _, t := range params.SourceType {
			fp.SourceTypes = append(fp.SourceTypes, lapi.EndpointType(t))
		}
	}
	if len(params.DestType) > 0 {
		fp.DestinationTypes = []lapi.EndpointType{}
		for _, t := range params.DestType {
			fp.DestinationTypes = append(fp.DestinationTypes, lapi.EndpointType(t))
		}
	}
	if len(params.SourceLabels) > 0 {
		fp.SourceSelectors = []lapi.LabelSelector{}
		for _, sel := range params.SourceLabels {
			fp.SourceSelectors = append(fp.SourceSelectors, lapi.LabelSelector{
				Key:      sel.Key,
				Operator: sel.Operator,
				Values:   sel.Values,
			})
		}
	}
	if len(params.DestLabels) > 0 {
		fp.DestinationSelectors = []lapi.LabelSelector{}
		for _, sel := range params.DestLabels {
			fp.DestinationSelectors = append(fp.DestinationSelectors, lapi.LabelSelector{
				Key:      sel.Key,
				Operator: sel.Operator,
				Values:   sel.Values,
			})
		}
	}
	if params.startDateTime != nil || params.endDateTime != nil {
		tr := v1.TimeRange{}
		if params.startDateTime != nil {
			tr.From = *params.startDateTime
		}
		if params.endDateTime != nil {
			tr.To = *params.endDateTime
		}
		fp.TimeRange = &tr
	}

	if params.Namespace != "" {
		fp.NamespaceMatches = []lapi.NamespaceMatch{
			{
				Type:       lapi.MatchTypeAny,
				Namespaces: []string{params.Namespace},
			},
		}
	}

	if params.SourceDestNamePrefix != "" {
		fp.NameAggrMatches = []lapi.NameMatch{
			{
				Type:  lapi.MatchTypeAny,
				Names: []string{params.SourceDestNamePrefix},
			},
		}
	}
	return &fp
}

type bucket struct {
	DocCount                 int64             `json:"doc_count"`
	Key                      key               `json:"key"`
	SourceLabels             map[string]string `json:"source_labels,omitempty"`
	DestinationLabels        map[string]string `json:"destination_labels,omitempty"`
	SumBytesIn               map[string]int64  `json:"sum_bytes_in"`
	SumBytesOut              map[string]int64  `json:"sum_bytes_out"`
	SumHttpRequestsAllowedIn map[string]int64  `json:"sum_http_requests_allowed_in"`
	SumHttpRequestsDeniedIn  map[string]int64  `json:"sum_http_requests_denied_in"`
	SumNumFlowsCompleted     map[string]int64  `json:"sum_num_flows_completed"`
	SumNumFlowsStarted       map[string]int64  `json:"sum_num_flows_started"`
	SumPacketsIn             map[string]int64  `json:"sum_packets_in"`
	SumPacketsOut            map[string]int64  `json:"sum_packets_out"`
}

type key struct {
	Action          string `json:"action"`
	DestName        string `json:"dest_name"`
	DestNamespace   string `json:"dest_namespace"`
	DestType        string `json:"dest_type"`
	Reporter        string `json:"reporter"`
	SourceName      string `json:"source_name"`
	SourceNamespace string `json:"source_namespace"`
	SourceType      string `json:"source_type"`
}

// This is temporary logic to mimic the response we used to receive from
// elasticsearch. Ultimately, we should update the UI to expect the new format, but for now
// we will just convert the Linseed results into a format the UI understands.
// Alternatively, maybe we should adjust the Linseed response format so that it matches
// what a flow used to look like from ES.
func convertToBuckets(items []lapi.L3Flow, unprotectedOnly bool, filter lmaelastic.FlowFilter) []bucket {
	buckets := []bucket{}
	for _, f := range items {
		if unprotectedOnly {
			// If this is an unprotected query, filter out any flows that have a policy.
			// We might want to add this as a query parameter to Linseed, but for now we can
			// filter them here since we need to iterate for conversion anyway.
			hasPolicy := false
			for _, p := range f.Policies {
				if !p.IsProfile {
					hasPolicy = true
					break
				}
			}
			if hasPolicy {
				continue
			}
		}

		// Check that this flow is allowed by the filter.
		if include, err := filter.IncludeLinseedFlow(&f); err != nil {
			log.WithError(err).Warn("Failed to check flow, skipping")
			continue
		} else if !include {
			log.Debugf("Skipping flow: %#v", f)
			continue
		}

		bucket := bucket{
			Key: key{
				Action:          string(f.Key.Action),
				DestName:        f.Key.Destination.AggregatedName,
				DestNamespace:   lmaelastic.EmptyToDash(f.Key.Destination.Namespace),
				DestType:        string(f.Key.Destination.Type),
				Reporter:        string(f.Key.Reporter),
				SourceName:      f.Key.Source.AggregatedName,
				SourceNamespace: lmaelastic.EmptyToDash(f.Key.Source.Namespace),
				SourceType:      string(f.Key.Source.Type),
			},
			SourceLabels:      make(map[string]string),
			DestinationLabels: make(map[string]string),
		}
		if f.TrafficStats != nil {
			bucket.SumBytesIn = map[string]int64{"value": f.TrafficStats.BytesIn}
			bucket.SumBytesOut = map[string]int64{"value": f.TrafficStats.BytesOut}
			bucket.SumPacketsIn = map[string]int64{"value": f.TrafficStats.PacketsIn}
			bucket.SumPacketsOut = map[string]int64{"value": f.TrafficStats.PacketsOut}
		}
		if f.HTTPStats != nil {
			bucket.SumHttpRequestsAllowedIn = map[string]int64{"value": f.HTTPStats.AllowedIn}
			bucket.SumHttpRequestsDeniedIn = map[string]int64{"value": f.HTTPStats.DeniedIn}

		}
		if f.LogStats != nil {
			bucket.DocCount = f.LogStats.FlowLogCount
			bucket.SumNumFlowsStarted = map[string]int64{"value": f.LogStats.Started}
			bucket.SumNumFlowsCompleted = map[string]int64{"value": f.LogStats.Completed}
		}
		// Propagate labels from the HostEndpoint resource to the bucket so that Flow Visualizer
		// can categorize and display them under pseudo-namespaces "hosts" or "cluster nodes".
		if f.Key.Source.Type == lapi.HEP {
			for _, label := range f.SourceLabels {
				if label.Key == names.HostEndpointTypeLabelKey && len(label.Values) > 0 {
					// Only the first label value is used when extracting the host endpoint type.
					// It is a programming error if there are multiple values for this label.
					bucket.SourceLabels[label.Key] = label.Values[0].Value
					break
				}
			}
		}
		if f.Key.Destination.Type == lapi.HEP {
			for _, label := range f.DestinationLabels {
				if label.Key == names.HostEndpointTypeLabelKey && len(label.Values) > 0 {
					// Only the first label value is used when extracting the host endpoint type.
					// It is a programming error if there are multiple values for this label.
					bucket.DestinationLabels[label.Key] = label.Values[0].Value
					break
				}
			}
		}
		buckets = append(buckets, bucket)
	}
	return buckets
}

// This method will take a look at the request parameters made to the /flowLogs endpoint and return the results.
func getFlowLogsFromLinseed(
	ctx context.Context,
	filter lmaelastic.FlowFilter,
	unprotected bool,
	pager client.ListPager[lapi.L3Flow],
	lsc client.Client,
	cluster string,
) (*lmaelastic.CompositeAggregationResults, int, error) {
	start := time.Now()

	// Perform the paginated list.
	pages, errors := pager.Stream(ctx, lsc.L3Flows(cluster).List)
	result := []lapi.L3Flow{}
	for page := range pages {
		result = append(result, page.Items...)
	}

	// Check for errors.
	if err := <-errors; err != nil {
		return nil, http.StatusInternalServerError, err
	}

	response := lmaelastic.CompositeAggregationResults{
		Took:     time.Since(start).Milliseconds(),
		TimedOut: false,
		Aggregations: map[string]any{
			"flog_buckets": map[string]any{
				"buckets": convertToBuckets(result, unprotected, filter),
			},
		},
	}
	return &response, http.StatusOK, nil
}

func getPIPParams(params *FlowLogsParams) *pippkg.PolicyImpactParams {
	// Convert the input format to the PIP format.
	// TODO(rlb): We don't need both formats, and the PIP format has the more generically named "Resource" field rather
	//            than limiting to network policies.
	resourceChanges := make([]pippkg.ResourceChange, len(params.PolicyPreviews))
	for i, pp := range params.PolicyPreviews {
		resourceChanges[i] = pippkg.ResourceChange{
			Action:   pp.Verb,
			Resource: pp.NetworkPolicy,
		}
	}

	return &pippkg.PolicyImpactParams{
		ClusterName:     params.ClusterName,
		ResourceActions: resourceChanges,
		Limit:           params.Limit,
		ImpactedOnly:    params.ImpactedOnly,
		FromTime:        params.startDateTime,
		ToTime:          params.endDateTime,
	}
}

// This method will take a look at the request parameters made to the /flowLogs endpoint with pip settings,
// verify RBAC based on the previewed settings and return the results from Linseed.
func getPIPFlowLogsFromLinseed(
	ctx context.Context,
	pager client.ListPager[lapi.L3Flow],
	flowFilter lmaelastic.FlowFilter,
	params *FlowLogsParams,
	pip pippkg.PIP,
	rbacHelper PolicyImpactRbacHelper,
) (any, int, error) {
	// Check a NP is supplied in every request.
	if len(params.PolicyPreviews) == 0 {
		// Expect the policy preview to contain a network policy.
		return nil, http.StatusBadRequest, errors.New("no network policy specified in preview request")
	}
	for i := range params.PolicyPreviews {
		if params.PolicyPreviews[i].NetworkPolicy == nil {
			return nil, http.StatusBadRequest, errors.New("no network policy specified in preview request")
		}
	}

	// This is a PIP request. Extract the PIP parameters.
	pipParams := getPIPParams(params)

	// Check for RBAC
	for _, action := range pipParams.ResourceActions {
		if action.Resource == nil {
			return nil, http.StatusBadRequest, fmt.Errorf("invalid resource actions syntax: resource is missing from request")
		}
		if err := validateAction(action.Action); err != nil {
			return nil, http.StatusBadRequest, err
		}
		if authorized, err := rbacHelper.CheckCanPreviewPolicyAction(action.Action, action.Resource); err != nil {
			return nil, http.StatusInternalServerError, err
		} else if !authorized {
			return nil, http.StatusForbidden, fmt.Errorf("Forbidden")
		}
	}

	// Fetch results from Linseed.
	response, err := pip.GetFlows(ctx, pager, pipParams, flowFilter)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	return response, http.StatusOK, nil
}

// validateAction checks that the action in a resource update is one of the expected actions. Any deviation from these
// actions is considered a bad request (even if it is strictly a valid k8s action).
func validateAction(action string) error {
	switch strings.ToLower(action) {
	case "create", "update", "delete":
		return nil
	}
	return fmt.Errorf("invalid action '%s' in preview request", action)
}
