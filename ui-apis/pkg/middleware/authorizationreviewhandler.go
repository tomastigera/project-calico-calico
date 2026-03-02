// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package middleware

import (
	"encoding/json"
	"net/http"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	authnv1 "k8s.io/api/authentication/v1"
	"k8s.io/apiserver/pkg/endpoints/request"

	"github.com/projectcalico/calico/ui-apis/pkg/authzreview"
)

// authorizationReviewHandler is an HTTP handler that computes RBAC permissions via the Reviewer.
// For the local (management) cluster, it uses the Calculator directly. For managed clusters, it creates
// a per-cluster calculator and falls back to the API server implementation through the Voltron tunnel.
type authorizationReviewHandler struct {
	reviewer authzreview.Reviewer
}

// NewAuthorizationReviewHandler returns an http.Handler that accepts a bare AuthorizationReview JSON POST,
// computes permissions using the RBAC calculator, and returns the result.
//
// This handler exists to be used by the UI only, as a drop-in replacement for the older v3.AuthorizationReview API which is no longer supported.
// It is not intended for general use and should not be used by external clients. Internal Calico components should use
// the Reviewer directly instead of going through this HTTP handler.
func NewAuthorizationReviewHandler(reviewer authzreview.Reviewer) http.Handler {
	return &authorizationReviewHandler{reviewer: reviewer}
}

func (h *authorizationReviewHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// This endpoint is only for the UI. Reject any request that carries impersonation headers,
	// since the UI never sets them and their presence would indicate a misconfigured or
	// malicious client trying to check permissions for a different user.
	if req.Header.Get(authnv1.ImpersonateUserHeader) != "" || req.Header.Get(authnv1.ImpersonateGroupHeader) != "" {
		http.Error(w, "Impersonation headers are not allowed on this endpoint", http.StatusForbidden)
		return
	}

	// Decode the AuthorizationReview from the request body.
	in := &v3.AuthorizationReview{}
	if err := json.NewDecoder(req.Body).Decode(in); err != nil {
		log.WithError(err).Debug("Failed to decode AuthorizationReview request body")
		http.Error(w, "Failed to decode request body", http.StatusBadRequest)
		return
	}

	// Reject requests that attempt to specify explicit user info in the Spec. User identity
	// must come from the authenticated request context, not from the request body. The Spec fields are only used
	// for the API server fallback path on managed clusters, and we populate them from the request context before forwarding.
	if in.Spec.User != "" || in.Spec.UID != "" || len(in.Spec.Groups) > 0 || len(in.Spec.Extra) > 0 {
		http.Error(w, "Spec.User, Spec.UID, Spec.Groups, and Spec.Extra must not be set; user identity is determined from the authenticated request", http.StatusBadRequest)
		return
	}

	// Extract user info from the authenticated request context.
	ctxUser, ok := request.UserFrom(req.Context())
	if !ok {
		http.Error(w, "No user information on request", http.StatusInternalServerError)
		return
	}
	userInfo := ctxUser
	// Populate spec so it's available for the API server fallback path on managed clusters.
	in.Spec.User = ctxUser.GetName()
	in.Spec.UID = ctxUser.GetUID()
	in.Spec.Groups = ctxUser.GetGroups()
	in.Spec.Extra = ctxUser.GetExtra()

	// Determine the target cluster from the x-cluster-id header.
	clusterID := MaybeParseClusterNameFromRequest(req)

	verbs, err := h.reviewer.Review(
		req.Context(),
		userInfo,
		clusterID,
		in.Spec.ResourceAttributes,
	)
	if err != nil {
		log.WithError(err).WithField("cluster", clusterID).Error("Failed to perform authorization review")
		http.Error(w, "Failed to perform authorization review", http.StatusInternalServerError)
		return
	}

	out := &v3.AuthorizationReview{
		TypeMeta:   in.TypeMeta,
		ObjectMeta: in.ObjectMeta,
		Spec:       in.Spec,
		Status: v3.AuthorizationReviewStatus{
			AuthorizedResourceVerbs: verbs,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		log.WithError(err).Error("Failed to encode AuthorizationReview response")
	}
}
