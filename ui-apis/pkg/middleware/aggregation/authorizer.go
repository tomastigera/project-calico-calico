// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package aggregation

import (
	"context"
	"net/http"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apiserver/pkg/endpoints/request"

	"github.com/projectcalico/calico/lma/pkg/httputils"
	"github.com/projectcalico/calico/ui-apis/pkg/authzreview"
)

// Sanity check the satisfies the interface.
var _ Authorizer = &realAuthorizer{}

// Authorizer provides the backend function for stats queries.
type Authorizer interface {
	PerformUserAuthorizationReview(ctx context.Context, rd *RequestData) ([]v3.AuthorizedResourceVerbs, error)
}

// realAuthorizer implements the real backend for stats queries.
type realAuthorizer struct {
	reviewer authzreview.Reviewer
}

// PerformUserAuthorizationReview performs a user authorization check.
func (r *realAuthorizer) PerformUserAuthorizationReview(ctx context.Context, rd *RequestData) ([]v3.AuthorizedResourceVerbs, error) {
	// Get the RBAC portion of the query to limit the documents the user can request.
	user, ok := request.UserFrom(ctx)
	if !ok {
		// There should be user info on the request context. If not this is is server error since an earlier handler
		// should have authenticated.
		log.Debug("No user information on request")
		return nil, &httputils.HttpStatusError{
			Status: http.StatusInternalServerError,
			Msg:    "No user information on request",
		}
	}
	return r.reviewer.ReviewForLogs(ctx, user, rd.AggregationRequest.Cluster)
}
