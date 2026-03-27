// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package middleware

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lma/pkg/httputils"
	"github.com/projectcalico/calico/lma/pkg/timeutils"
	querycacheclient "github.com/projectcalico/calico/queryserver/pkg/querycache/client"
	queryserverclient "github.com/projectcalico/calico/queryserver/queryserver/client"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
)

// policiesSearcher is a narrow interface covering the single queryserver method we need.
// It lets tests inject a mock without requiring a full QueryServerClient implementation.
type policiesSearcher interface {
	SearchPolicies(cfg *queryserverclient.QueryServerConfig, from, to *time.Time, clusterID string) (*querycacheclient.QueryPoliciesResp, error)
}

// UnusedPoliciesHandler handles GET /policies/unused.
// It fetches all policies (with lastEvaluated timestamps) from queryserver
// for the requested time window, then classifies them as entirely unused
// or partially unused (some rules have no activity).
func UnusedPoliciesHandler(qsConfig *queryserverclient.QueryServerConfig) http.Handler {
	qsClient, err := queryserverclient.NewQueryServerClient(qsConfig)
	if err != nil {
		logrus.WithError(err).Fatal("failed to create queryserver client for /policies/unused")
	}
	return unusedPoliciesHandler(qsConfig, qsClient)
}

// unusedPoliciesHandler is the testable implementation of UnusedPoliciesHandler.
// It accepts a pre-built client so tests can inject a mock.
func unusedPoliciesHandler(qsConfig *queryserverclient.QueryServerConfig, qsClient policiesSearcher) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			httputils.EncodeError(w, &httputils.HttpStatusError{
				Status: http.StatusMethodNotAllowed,
				Msg:    ErrInvalidMethod.Error(),
				Err:    ErrInvalidMethod,
			})
			return
		}

		from, to, err := parseUnusedTimeRange(r)
		if err != nil {
			httputils.EncodeError(w, &httputils.HttpStatusError{
				Status: http.StatusBadRequest,
				Msg:    err.Error(),
				Err:    err,
			})
			return
		}

		authHeader := r.Header.Get("Authorization")
		if len(authHeader) <= 7 {
			httputils.EncodeError(w, &httputils.HttpStatusError{
				Status: http.StatusUnauthorized,
				Msg:    "missing authorization token",
				Err:    fmt.Errorf("missing authorization token"),
			})
			return
		}
		localCfg := *qsConfig
		localCfg.QueryServerToken = authHeader[7:]
		clusterID := MaybeParseClusterNameFromRequest(r)

		resp, err := qsClient.SearchPolicies(&localCfg, from, to, clusterID)
		if err != nil {
			logrus.WithError(err).Error("failed to fetch policies from queryserver")
			httputils.EncodeError(w, &httputils.HttpStatusError{
				Status: http.StatusInternalServerError,
				Msg:    "failed to fetch policies from queryserver",
				Err:    err,
			})
			return
		}

		httputils.Encode(w, classifyUnusedPolicies(resp.Items))
	})
}

// parseUnusedTimeRange parses optional "from" and "to" query params.
// Supports both RFC3339 and relative formats (e.g. "now-90d") via timeutils.ParseTime.
// Returns an error if a param is present but unparseable.
func parseUnusedTimeRange(r *http.Request) (from, to *time.Time, err error) {
	now := time.Now()
	if s := r.URL.Query().Get("from"); s != "" {
		from, _, err = timeutils.ParseTime(now, &s)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid 'from' query param %q: %w", s, err)
		}
	}
	if s := r.URL.Query().Get("to"); s != "" {
		to, _, err = timeutils.ParseTime(now, &s)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid 'to' query param %q: %w", s, err)
		}
	}
	return
}

// classifyUnusedPolicies splits policies into entirely-unused and partially-unused (by rules).
func classifyUnusedPolicies(policies []querycacheclient.Policy) *v1.UnusedPoliciesResponse {
	resp := &v1.UnusedPoliciesResponse{
		Policies: []v1.UnusedPolicyEntry{},
		Rules:    []v1.UnusedRuleEntry{},
	}
	for _, p := range policies {
		// A policy was evaluated at a previous generation if it has no activity
		// at the current generation but does have activity at any generation.
		evalAtPrevGen := p.LastEvaluated == nil && p.LastEvaluatedAnyGeneration != nil

		if p.LastEvaluated == nil {
			resp.Policies = append(resp.Policies, v1.UnusedPolicyEntry{
				PolicyKey:                     v1.PolicyKey{Kind: p.Kind, Namespace: p.Namespace, Name: p.Name},
				Generation:                    p.Generation,
				CreationTime:                  p.CreationTime,
				EvaluatedAtPreviousGeneration: evalAtPrevGen,
			})
			continue
		}

		var unusedRules []v1.UnusedRule
		for i, rule := range p.IngressRules {
			if rule.LastEvaluated == nil {
				unusedRules = append(unusedRules, v1.UnusedRule{Direction: "ingress", Index: strconv.Itoa(i)})
			}
		}
		for i, rule := range p.EgressRules {
			if rule.LastEvaluated == nil {
				unusedRules = append(unusedRules, v1.UnusedRule{Direction: "egress", Index: strconv.Itoa(i)})
			}
		}
		if len(unusedRules) > 0 {
			resp.Rules = append(resp.Rules, v1.UnusedRuleEntry{
				Kind:         p.Kind,
				Namespace:    p.Namespace,
				Name:         p.Name,
				Generation:   p.Generation,
				CreationTime: p.CreationTime,
				UnusedRules:  unusedRules,
			})
		}
	}
	return resp
}
