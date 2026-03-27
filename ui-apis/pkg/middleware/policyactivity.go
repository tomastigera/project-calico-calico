// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
	linseedv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/lma/pkg/httputils"
	uiapi "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
)

// namespacedPolicyKinds are policy kinds that require a namespace.
var namespacedPolicyKinds = map[string]bool{
	"NetworkPolicy":       true,
	"StagedNetworkPolicy": true,
}

// clusterScopedPolicyKinds are policy kinds that must not have a namespace.
var clusterScopedPolicyKinds = map[string]bool{
	"GlobalNetworkPolicy":       true,
	"StagedGlobalNetworkPolicy": true,
}

// validatePolicyActivityRequest validates the parsed request body fields.
func validatePolicyActivityRequest(req *uiapi.PolicyActivityRequest) *httputils.HttpStatusError {
	if err := validator.Validate(req); err != nil {
		return &httputils.HttpStatusError{Status: http.StatusBadRequest, Msg: fmt.Sprintf("invalid request: %v", err), Err: err}
	}

	for _, p := range req.Policies {
		if namespacedPolicyKinds[p.Kind] && p.Namespace == "" {
			msg := fmt.Sprintf("missing required field: namespace (required for %s %q)", p.Kind, p.Name)
			return &httputils.HttpStatusError{Status: http.StatusBadRequest, Msg: msg, Err: errors.New(msg)}
		}
		if clusterScopedPolicyKinds[p.Kind] && p.Namespace != "" {
			msg := fmt.Sprintf("namespace must not be set for cluster-scoped kind %s %q", p.Kind, p.Name)
			return &httputils.HttpStatusError{Status: http.StatusBadRequest, Msg: msg, Err: errors.New(msg)}
		}
	}

	return nil
}

// NewPolicyActivityHandler returns an http.Handler for POST /policies/activities.
// It queries Linseed for policy activity data and returns simplified lastEvaluated timestamps.
func NewPolicyActivityHandler(linseedClient lsclient.Client) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httputils.EncodeError(w, &httputils.HttpStatusError{Status: http.StatusMethodNotAllowed, Msg: fmt.Sprintf("method(%s) not allowed", r.Method)})
			return
		}

		var parsed uiapi.PolicyActivityRequest
		if err := httputils.Decode(w, r, &parsed); err != nil {
			httputils.EncodeError(w, err)
			return
		}

		if err := validatePolicyActivityRequest(&parsed); err != nil {
			httputils.EncodeError(w, err)
			return
		}

		// Build a single Linseed request with Generation: nil so that
		// Linseed returns activity across all generations in one round-trip.
		// We split results client-side by comparing rule.Generation against
		// the caller's requested generation.
		linseedPolicies := make([]linseedv1.PolicyActivityQueryPolicy, 0, len(parsed.Policies))
		requestedGen := make(map[uiapi.PolicyKey]int64, len(parsed.Policies))
		for _, p := range parsed.Policies {
			key := uiapi.PolicyKey{Kind: p.Kind, Namespace: p.Namespace, Name: p.Name}
			requestedGen[key] = p.Generation
			linseedPolicies = append(linseedPolicies, linseedv1.PolicyActivityQueryPolicy{
				Kind:      p.Kind,
				Namespace: p.Namespace,
				Name:      p.Name,
				// Generation is nil — fetch activity across all generations.
			})
		}

		// Determine the cluster from the request header.
		clusterID := MaybeParseClusterNameFromRequest(r)
		policyActivityClient := linseedClient.PolicyActivity(clusterID)

		resp, err := policyActivityClient.GetPolicyActivities(r.Context(), &linseedv1.PolicyActivityParams{
			Policies: linseedPolicies,
		})
		if err != nil {
			log.WithError(err).Error("Failed to get policy activities from Linseed")
			httputils.EncodeError(w, &httputils.HttpStatusError{Status: http.StatusInternalServerError, Msg: "failed to retrieve policy activity data", Err: err})
			return
		}

		activityByPolicy := make(map[uiapi.PolicyKey]*uiapi.PolicyActivity, len(resp.Items))
		for _, result := range resp.Items {
			key := uiapi.PolicyKey{Kind: result.Policy.Kind, Namespace: result.Policy.Namespace, Name: result.Policy.Name}
			pa := &uiapi.PolicyActivity{}
			wantGen := requestedGen[key]

			// Find the generation and timestamp of the most recently evaluated rule.
			var latestRuleTime time.Time
			var latestRuleGen int64
			for _, rule := range result.Rules {
				if rule.LastEvaluated.After(latestRuleTime) {
					latestRuleTime = rule.LastEvaluated
					latestRuleGen = rule.Generation
				}
			}

			if latestRuleGen >= wantGen {
				// Activity exists at the requested or a newer generation.
				// The latest rule's timestamp is always >= any timestamp at
				// the requested generation, so use it directly.
				pa.LastEvaluated = &latestRuleTime
				pa.LastEvaluatedGeneration = &latestRuleGen
			} else if result.LastEvaluated != nil {
				// Only older generation activity exists.
				pa.LastEvaluatedAnyGeneration = result.LastEvaluated
				if len(result.Rules) > 0 {
					pa.LastEvaluatedGeneration = &latestRuleGen
				}
			}
			activityByPolicy[key] = pa
		}

		// Build response — one item per requested policy, in request order.
		items := make([]uiapi.PolicyActivityItem, 0, len(parsed.Policies))
		for _, p := range parsed.Policies {
			key := uiapi.PolicyKey{Kind: p.Kind, Namespace: p.Namespace, Name: p.Name}
			item := uiapi.PolicyActivityItem{PolicyKey: key}
			if pa, ok := activityByPolicy[key]; ok {
				item.PolicyActivity = *pa
			}
			items = append(items, item)
		}

		httputils.Encode(w, uiapi.PolicyActivityResponse{Items: items})
	})
}
