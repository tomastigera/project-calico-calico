package waf

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/apiserver/pkg/endpoints/request"

	"github.com/projectcalico/calico/lma/pkg/httputils"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
	"github.com/projectcalico/calico/ui-apis/pkg/middleware"
	"github.com/projectcalico/calico/ui-apis/pkg/middleware/waf/ruleset"
)

// WAFRulesetsHandler handles requests related to WAF Rulesets.
func WAFRulesetsHandler(k8sClientSetFactory lmak8s.ClientSetFactory) http.Handler {
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

		rs := ruleset.Ruleset{
			Client: k8sClient,
		}

		handleWAFRulesetsRequest(w, r, rs)
	})
}

func handleWAFRulesetsRequest(w http.ResponseWriter, r *http.Request, rulesets ruleset.Ruleset) {
	// Create a context with timeout to ensure we don't block for too long with this query.
	// This releases timer resources if the operation completes before the timeout.
	ctx, cancel := context.WithTimeout(r.Context(), middleware.DefaultRequestTimeout)
	defer cancel()

	// Handle the query
	switch r.Method {
	case http.MethodGet:
		var results []*v1.WAFRuleset
		// List will give an overview of all the WAF rulesets
		results, err := rulesets.GetRulesets(ctx)
		if err != nil {
			httputils.EncodeError(w, err)
		} else {
			httputils.Encode(w, results)
		}
	default:
		err := fmt.Errorf("unsupported http method")
		httputils.EncodeError(w, err)
	}
}

// WAFRulesetHandler handles requests related to a specific WAF Ruleset.
func WAFRulesetHandler(k8sClientSetFactory lmak8s.ClientSetFactory) http.Handler {
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

		rs := ruleset.Ruleset{
			Client: k8sClient,
		}

		handleWAFRulesetRequest(w, r, rs)
	})
}

func handleWAFRulesetRequest(w http.ResponseWriter, r *http.Request, rulesets ruleset.Ruleset) {
	rulesetID := r.PathValue("rulesetID")

	// Create a context with timeout to ensure we don't block for too long with this query.
	// This releases timer resources if the operation completes before the timeout.
	ctx, cancel := context.WithTimeout(r.Context(), middleware.DefaultRequestTimeout)
	defer cancel()

	// Handle the query
	switch r.Method {
	case http.MethodGet:
		var results *v1.WAFRuleset
		// List will give an overview of all the WAF rulesets
		results, err := rulesets.GetRuleset(ctx, rulesetID)
		if err != nil {
			httputils.EncodeError(w, err)
		} else {
			httputils.Encode(w, results)
		}
	default:
		err := fmt.Errorf("unsupported http method")
		httputils.EncodeError(w, err)
	}
}

// WAFRulesetHandler handles requests related to WAF Rulesets.
func WAFRuleDetailsHandler(k8sClientSetFactory lmak8s.ClientSetFactory) http.Handler {
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

		rs := ruleset.Ruleset{
			Client: k8sClient,
		}

		handleWAFRuleDetails(w, r, rs)
	})
}

func handleWAFRuleDetails(w http.ResponseWriter, r *http.Request, ruleset ruleset.Ruleset) {
	rulesetID := r.PathValue("rulesetID")
	ruleID := r.PathValue("ruleID")

	// Create a context with timeout to ensure we don't block for too long with this query.
	// This releases timer resources if the operation completes before the timeout.
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()

	// Handle the query
	switch r.Method {
	case http.MethodGet:
		var results *v1.Rule
		results, err := ruleset.GetRule(ctx, rulesetID, ruleID)
		if err != nil {
			httputils.EncodeError(w, err)
		} else {
			httputils.Encode(w, results)
		}
	default:
		err := fmt.Errorf("unsupported http method")
		httputils.EncodeError(w, err)
	}
}
