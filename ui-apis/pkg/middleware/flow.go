package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	k8srequest "k8s.io/apiserver/pkg/endpoints/request"

	"github.com/projectcalico/calico/compliance/pkg/datastore"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/lma/pkg/api"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	"github.com/projectcalico/calico/lma/pkg/rbac"
	"github.com/projectcalico/calico/lma/pkg/timeutils"
)

const (
	HttpErrUnauthorizedFlowAccess = "User is not authorised to view this flow."
)

// flowRequestParams is the representation of the parameters sent to the "flow" endpoint. An http.Request object should
// be validated and parsed with the parseAndValidateFlowRequest function.
//
// Note that if srcType or dstType are global endpoint types, HEP or global NS, the the srcNamespace and / or dstNamespace
// must be "-". srcNamespace and dstNamespace are always required.
type flowRequestParams struct {
	// Required parameters used to uniquely define a "flow".
	clusterName  string
	srcType      api.EndpointType
	srcNamespace string
	srcName      string
	dstType      api.EndpointType
	dstNamespace string
	dstName      string

	// Optional parameters used to filter flow logs evaluated for a "flow".
	srcLabels []LabelSelector
	dstLabels []LabelSelector

	// The format is either RFC3339 or a relative time like now-15m, now-1h.
	startDateTime *time.Time
	endDateTime   *time.Time
}

// parseAndValidateFlowRequest parses the fields in the request query, validating that required parameters are set and or the
// correct format, then setting them to the appropriate values in a flowRequest.
//
// Any error returned is of a format and contains information that can be returned in the response body. Any errors that
// are not to be returned in the response are logged as an error.
func parseAndValidateFlowRequest(req *http.Request) (*flowRequestParams, error) {
	var err error
	query := req.URL.Query()

	requiredParams := []string{"srcType", "srcName", "dstType", "dstName", "srcNamespace", "dstNamespace"}
	for _, param := range requiredParams {
		if query.Get(param) == "" {
			return nil, fmt.Errorf("missing required parameter '%s'", param)
		}
	}

	flowParams := &flowRequestParams{
		clusterName:  strings.ToLower(query.Get("cluster")),
		srcType:      api.StringToEndpointType(strings.ToLower(query.Get("srcType"))),
		srcNamespace: strings.ToLower(query.Get("srcNamespace")),
		srcName:      strings.ToLower(query.Get("srcName")),
		dstType:      api.StringToEndpointType(strings.ToLower(query.Get("dstType"))),
		dstNamespace: strings.ToLower(query.Get("dstNamespace")),
		dstName:      strings.ToLower(query.Get("dstName")),
	}

	if flowParams.clusterName == "" {
		flowParams.clusterName = MaybeParseClusterNameFromRequest(req)
	}

	if flowParams.srcType == api.EndpointTypeInvalid {
		return nil, fmt.Errorf("srcType value '%s' is not a valid endpoint type", flowParams.srcType)
	} else if flowParams.dstType == api.EndpointTypeInvalid {
		return nil, fmt.Errorf("dstType value '%s' is not a valid endpoint type", flowParams.dstType)
	}

	// As part of PMREQ-649, UI will categorize non-cluster hosts under a pseudo-namespace
	// labeled "hosts". To simplify the UI implementation, Flow Visualizer requests
	// will include this value in the namespace parameter for host endpoints. As HostEndpoints
	// are not namespaced, we will ignore the namespace parameter and reset it back to "-".
	if flowParams.srcType == api.EndpointTypeHep {
		flowParams.srcNamespace = api.GlobalEndpointType
	}
	if flowParams.dstType == api.EndpointTypeHep {
		flowParams.dstNamespace = api.GlobalEndpointType
	}

	if dateTimeStr := query.Get("startDateTime"); len(dateTimeStr) > 0 {
		flowParams.startDateTime, _, err = timeutils.ParseTime(time.Now(), &dateTimeStr)
		if err != nil {
			errMsg := fmt.Sprintf("failed to parse 'startDateTime' value '%s' as RFC3339 datetime or relative time", dateTimeStr)
			return nil, errors.New(errMsg)
		}
	}

	if dateTimeStr := query.Get("endDateTime"); len(dateTimeStr) > 0 {
		flowParams.endDateTime, _, err = timeutils.ParseTime(time.Now(), &dateTimeStr)
		if err != nil {
			errMsg := fmt.Sprintf("failed to parse 'endDateTime' value '%s' as RFC3339 datetime or relative time", dateTimeStr)
			return nil, errors.New(errMsg)
		}
	}

	if labels, exists := query["srcLabels"]; exists {
		srcLabels, err := getLabelSelectors(labels)
		if err != nil {
			return nil, err
		}

		flowParams.srcLabels = srcLabels
	}

	if labels, exists := query["dstLabels"]; exists {
		dstLabels, err := getLabelSelectors(labels)
		if err != nil {
			return nil, err
		}

		flowParams.dstLabels = dstLabels
	}

	return flowParams, nil
}

type PolicyReport struct {
	// AllowedFlowPolicies contains the policies from the allowed flow. Policies that the user is not authorized to view
	// are obfuscated.
	AllowedFlowPolicies []*FlowResponsePolicy `json:"allowedFlowPolicies"`

	// DeniedFlowPolicies contains the policies from the denied flow. Policies that the user is not authorized to view
	// are obfuscated.
	DeniedFlowPolicies []*FlowResponsePolicy `json:"deniedFlowPolicies"`
}

// FlowResponse is the response that will be returned json marshaled and written in the flowHandler's ServeHTTP.
type FlowResponse struct {
	// Count is the total number of documents that were included in the flow log.
	Count int64 `json:"count"`

	// DstLabels contains all the labels the flows destination had, if applicable, in the given time frame for the flow query.
	DstLabels FlowResponseLabels `json:"dstLabels"`

	// SrcLabels contains all the labels the flow's source had, if applicable, in the given time frame for the flow query.
	SrcLabels FlowResponseLabels `json:"srcLabels"`

	// SrcPolicyReport contains the policies that were applied and reported by the source of the flow.
	SrcPolicyReport *PolicyReport `json:"srcPolicyReport"`

	// DstPolicyReport contains the policies that were applied and reported by the destination of the flow.
	DstPolicyReport *PolicyReport `json:"dstPolicyReport"`

	// SrcPendingPolicyReport contains the expected policy trace at the source when including staged policies.
	// This may contain enforced policies, staged policies, or a mix of both.
	SrcPendingPolicyReport *PolicyReport `json:"srcPendingPolicyReport,omitempty"`

	// DstPendingPolicyReport contains the expected policy trace at the destination when including staged policies.
	// This may contain enforced policies, staged policies, or a mix of both.
	DstPendingPolicyReport *PolicyReport `json:"dstPendingPolicyReport,omitempty"`
}

// MergeDestLabels merges in the given destination labels.
func (r *FlowResponse) MergeDestLabels(labels []v1.FlowLabels) {
	if len(labels) != 0 && r.DstLabels == nil {
		r.DstLabels = map[string][]FlowResponseLabelValue{}
	}

	for _, label := range labels {
		k := label.Key
		vals := label.Values

		if _, ok := r.DstLabels[k]; !ok {
			// No key currently known for this label. Add it.
			r.DstLabels[k] = []FlowResponseLabelValue{}
		}

		// Iterate the values for the key, and increment the FlowResponse
		// keys accordingly.
		for _, v := range vals {
			found := false
			for _, lv := range r.DstLabels[k] {
				if lv.Value == v.Value {
					// Found a match, increment it.
					lv.Count += v.Count
					found = true
				}
			}

			if !found {
				// Didn't already exist - add it.
				r.DstLabels[k] = append(r.DstLabels[k], FlowResponseLabelValue{
					Value: v.Value,
					Count: v.Count,
				})
			}
		}
	}
}

// MergeSourceLabels merges in the given source labels.
func (r *FlowResponse) MergeSourceLabels(labels []v1.FlowLabels) {
	if len(labels) != 0 && r.SrcLabels == nil {
		r.SrcLabels = map[string][]FlowResponseLabelValue{}
	}
	for _, label := range labels {
		k := label.Key
		vals := label.Values
		if _, ok := r.SrcLabels[k]; !ok {
			// No key currently known for this label. Add it.
			r.SrcLabels[k] = []FlowResponseLabelValue{}
		}

		// Iterate the values for the key, and increment the FlowResponse
		// keys accordingly.
		for _, v := range vals {
			found := false
			for _, lv := range r.SrcLabels[k] {
				if lv.Value == v.Value {
					// Found a match, increment it.
					lv.Count += v.Count
					found = true
				}
			}

			if !found {
				// Didn't already exist - add it.
				r.SrcLabels[k] = append(r.SrcLabels[k], FlowResponseLabelValue{
					Value: v.Value,
					Count: v.Count,
				})
			}
		}
	}
}

type FlowResponseLabels map[string][]FlowResponseLabelValue

type FlowResponseLabelValue struct {
	Count int64  `json:"count"`
	Value string `json:"value"`
}

type FlowResponsePolicy struct {
	Index        int    `json:"index"`
	Tier         string `json:"tier"`
	Namespace    string `json:"namespace"`
	Name         string `json:"name"`
	Kind         string `json:"kind,omitempty"`
	Action       string `json:"action"`
	IsStaged     bool   `json:"isStaged"`
	IsKubernetes bool   `json:"isKubernetes"`
	IsProfile    bool   `json:"isProfile"`
	Count        int64  `json:"count"`
}

type flowHandler struct {
	k8sCliFactory datastore.ClusterCtxK8sClientFactory
	client        client.Client
}

func NewFlowHandler(client client.Client, k8sClientFactory datastore.ClusterCtxK8sClientFactory) http.Handler {
	return &flowHandler{
		k8sCliFactory: k8sClientFactory,
		client:        client,
	}
}

func (handler *flowHandler) ServeHTTP(w http.ResponseWriter, rawRequest *http.Request) {
	logrus.Debug("GET Flow request received.")

	req, err := parseAndValidateFlowRequest(rawRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	logrus.WithField("Request", req).Debug("Request validated.")

	logrus.Debug("Retrieving user from context.")
	user, ok := k8srequest.UserFrom(rawRequest.Context())
	if !ok {
		logrus.WithError(err).Error("user not found in context")
		http.Error(w, HttpErrUnauthorizedFlowAccess, http.StatusUnauthorized)
		return
	}
	logrus.WithField("user", user).Debug("User retrieved from context.")

	authorizer, err := handler.k8sCliFactory.RBACAuthorizerForCluster(req.clusterName)
	if err != nil {
		logrus.WithError(err).Errorf("failed to get k8s client for cluster %s", req.clusterName)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	flowHelper := rbac.NewCachedFlowHelper(user, authorizer)

	srcAuthorized, err := flowHelper.CanListEndpoint(req.srcType, req.srcNamespace)
	if err != nil {
		logrus.WithError(err).Error("Failed to check authorization status of flow log")

		switch err.(type) {
		case *rbac.ErrUnknownEndpointType:
			http.Error(w, "Unknown srcType", http.StatusInternalServerError)
		default:
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}

		return
	}
	logrus.Debugf("User has source endpoint authorization: %t", srcAuthorized)

	dstAuthorized, err := flowHelper.CanListEndpoint(req.dstType, req.dstNamespace)
	if err != nil {
		logrus.WithError(err).Error("Failed to check authorization status of flow log")

		switch err.(type) {
		case *rbac.ErrUnknownEndpointType:
			http.Error(w, "Unknown srcType", http.StatusInternalServerError)
		default:
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}

		return
	}
	logrus.Debugf("User has destination endpoint authorization: %t", srcAuthorized)

	// If the user is not authorized to access the source or destination endpoints then they are not authorized to access
	// the flow.
	if !srcAuthorized && !dstAuthorized {
		http.Error(w, HttpErrUnauthorizedFlowAccess, http.StatusUnauthorized)
		return
	}
	logrus.Debug("User is authorised to view flow.")

	// Build the query to send.
	params := v1.L3FlowParams{
		SourceTypes:      []v1.EndpointType{v1.EndpointType(req.srcType)},
		DestinationTypes: []v1.EndpointType{v1.EndpointType(req.dstType)},
		NameAggrMatches:  []v1.NameMatch{},      // Filled in below.
		NamespaceMatches: []v1.NamespaceMatch{}, // Filled in below.
	}

	if len(req.srcName) > 0 {
		params.NameAggrMatches = append(params.NameAggrMatches, v1.NameMatch{
			Type:  v1.MatchTypeSource,
			Names: []string{req.srcName},
		})
	}
	if len(req.dstName) > 0 {
		params.NameAggrMatches = append(params.NameAggrMatches, v1.NameMatch{
			Type:  v1.MatchTypeDest,
			Names: []string{req.dstName},
		})
	}

	if len(req.srcNamespace) > 0 {
		params.NamespaceMatches = append(params.NamespaceMatches, v1.NamespaceMatch{
			Type:       v1.MatchTypeSource,
			Namespaces: []string{req.srcNamespace},
		})
	}
	if len(req.dstNamespace) > 0 {
		params.NamespaceMatches = append(params.NamespaceMatches, v1.NamespaceMatch{
			Type:       v1.MatchTypeDest,
			Namespaces: []string{req.dstNamespace},
		})
	}

	for _, sel := range req.srcLabels {
		params.SourceSelectors = append(params.SourceSelectors, v1.LabelSelector{
			Key:      sel.Key,
			Operator: sel.Operator,
			Values:   sel.Values,
		})
	}

	for _, sel := range req.dstLabels {
		params.DestinationSelectors = append(params.DestinationSelectors, v1.LabelSelector{
			Key:      sel.Key,
			Operator: sel.Operator,
			Values:   sel.Values,
		})
	}

	if req.startDateTime != nil || req.endDateTime != nil {
		if params.TimeRange == nil {
			params.TimeRange = &lmav1.TimeRange{}
		}

		if req.startDateTime != nil {
			params.TimeRange.From = *req.startDateTime
		}
		if req.endDateTime != nil {
			params.TimeRange.To = *req.endDateTime
		}
	}

	logrus.Debug("Querying Linseed for flow(s).")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	flows, err := handler.client.L3Flows(req.clusterName).List(ctx, &params)
	if err != nil {
		logrus.WithError(err).Error("failed to get flows")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	logrus.Debugf("Total matching flow logs for flow: %d", len(flows.Items))
	if len(flows.Items) == 0 {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// Build a response. Above, we received a list of flows as reported by the source and destination,
	// and with different actions. Here, we build a policy report by aggregating information
	// from these flows.
	response := FlowResponse{
		// The UI expects these to be non-nil, so always default them to empty values.
		SrcLabels: make(FlowResponseLabels),
		DstLabels: make(FlowResponseLabels),
	}
	totalHits := int64(0)
	for _, item := range flows.Items {
		if item.LogStats != nil {
			// Increment stats.
			totalHits += item.LogStats.FlowLogCount

			// Build labels into the response.
			response.MergeSourceLabels(item.SourceLabels)
			response.MergeDestLabels(item.DestinationLabels)
		}

		// Build up enforced policy report.
		policyReport, err := newPolicyReportFromFlow(item, flowHelper)
		if err != nil {
			logrus.WithError(err).Error("failed to read policy report for flow")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		logrus.WithField("policies", policyReport).Debug("Policies parsed.")
		mergePolicyReport(item.Key, policyReport, &response.SrcPolicyReport, &response.DstPolicyReport)

		// Build up pending policy report. The pending trace contains the full set of policies
		// (enforced, staged, or a mix) that would apply when including staged policies.
		pendingPolicyReport, err := newPendingPolicyReportFromFlow(item, flowHelper)
		if err != nil {
			logrus.WithError(err).Error("failed to read pending policy report for flow")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		mergePolicyReport(item.Key, pendingPolicyReport, &response.SrcPendingPolicyReport, &response.DstPendingPolicyReport)
	}

	response.Count = totalHits

	// Send the response back to the client.
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logrus.WithError(err).Error("failed to json encode response")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func newPolicyReportFromFlow(flow v1.L3Flow, flowHelper rbac.FlowHelper) (*PolicyReport, error) {
	return newPolicyReport(flow.Key.Action, flow.Policies, flowHelper)
}

func newPendingPolicyReportFromFlow(flow v1.L3Flow, flowHelper rbac.FlowHelper) (*PolicyReport, error) {
	return newPolicyReport(flow.Key.Action, flow.PendingPolicies, flowHelper)
}

// newPolicyReport builds a PolicyReport from the given policies, splitting them into allowed/denied
// based on the flow action. Returns nil if the policy slice is empty or all policies are filtered by RBAC.
func newPolicyReport(action v1.FlowAction, policies []v1.Policy, flowHelper rbac.FlowHelper) (*PolicyReport, error) {
	if len(policies) == 0 {
		return nil, nil
	}

	parsed, err := getPoliciesFromFlow(policies, flowHelper)
	if err != nil {
		return nil, err
	}

	policyReport := &PolicyReport{}
	switch action {
	case "allow":
		policyReport.AllowedFlowPolicies = parsed
	case "deny":
		policyReport.DeniedFlowPolicies = parsed
	}

	// Don't return a policy report if there are neither allowed nor denied policies, since this means a policy report
	// doesn't exist.
	if policyReport.DeniedFlowPolicies == nil && policyReport.AllowedFlowPolicies == nil {
		return nil, nil
	}

	return policyReport, nil
}

// mergePolicyReport merges the given policy report into the appropriate src/dst report pointer based on the flow key's
// reporter and action.
func mergePolicyReport(key v1.L3FlowKey, report *PolicyReport, srcReport, dstReport **PolicyReport) {
	if report == nil {
		return
	}
	target := dstReport
	if key.Reporter == "src" {
		target = srcReport
	}
	if *target == nil {
		*target = &PolicyReport{}
	}
	switch key.Action {
	case "allow":
		(*target).AllowedFlowPolicies = report.AllowedFlowPolicies
	case "deny":
		(*target).DeniedFlowPolicies = report.DeniedFlowPolicies
	}
}

// getPoliciesFromFlow converts the provided slice of v1.Policy objects into FlowResponsePolicy entries that can be
// returned in the API response. The given flowHelper is used to apply RBAC, obfuscating or omitting policies that the
// user is not authorized to view.
func getPoliciesFromFlow(flowPolicies []v1.Policy, flowHelper rbac.FlowHelper) ([]*FlowResponsePolicy, error) {
	var policies []*FlowResponsePolicy
	var obfuscatedPolicy *FlowResponsePolicy
	var policyIdx int

	// Loop through the flow's policies. Check RBAC on each and obfuscate those which the user doesn't have
	// permissions to see. Convert the others to the proper response format expected by the UI.
	// TODO: It would be nice to change the response format expected by the UI to match Linseed's API, so we don't need
	// to maintain multiple structures representing a policy hit.
	for _, p := range flowPolicies {
		// Create a PolicyHit object to help with RBAC decisions.
		policyHit, err := api.NewPolicyHit(api.Action(p.Action), policyIdx, p.Name, p.Namespace, p.Kind, p.Tier, p.RuleID)
		if err != nil {
			logrus.WithField("policy", p).Warn("Failed to parse policy, skipping")
			continue
		}

		if canListPolicy, err := flowHelper.CanListPolicy(policyHit); err != nil {
			// An error here may mean that the request needs to be retried, i.e. a temporary error, so we should fail
			// the request so the user knows to try again.
			return nil, err
		} else if canListPolicy {
			logrus.WithFields(logrus.Fields{"name": p.Name}).Debug("User is authorized to view policy.")
			if obfuscatedPolicy != nil {
				obfuscatedPolicy.Index = policyIdx
				policies = append(policies, obfuscatedPolicy)

				obfuscatedPolicy = nil
				policyIdx++
			}

			policies = append(policies, &FlowResponsePolicy{
				Index:        policyIdx,
				Action:       p.Action,
				Tier:         p.Tier,
				Namespace:    p.Namespace,
				Name:         p.Name,
				Kind:         policyHit.Kind(),
				IsStaged:     p.IsStaged,
				IsKubernetes: p.IsKubernetes,
				IsProfile:    p.IsProfile,
				Count:        p.Count,
			})

			policyIdx++
		} else if api.IsStaged(policyHit.Kind()) {
			// Ignore staged policies the use is not authorized to view
			continue
		} else {
			if obfuscatedPolicy != nil {
				obfuscatedPolicy.Action = string(policyHit.Action())
				obfuscatedPolicy.Count += p.Count
			} else {
				obfuscatedPolicy = &FlowResponsePolicy{
					Namespace: "*",
					Tier:      "*",
					Name:      "*",
					Action:    string(policyHit.Action()),
					Count:     p.Count,
				}
			}
		}
	}

	if obfuscatedPolicy != nil {
		obfuscatedPolicy.Index = policyIdx
		policies = append(policies, obfuscatedPolicy)
	}

	return policies, nil
}
