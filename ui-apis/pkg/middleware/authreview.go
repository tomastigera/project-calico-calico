// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package middleware

import (
	"context"
	"net/http"

	log "github.com/sirupsen/logrus"
	libcalv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apiserver/pkg/endpoints/request"

	"github.com/projectcalico/calico/lma/pkg/httputils"
	"github.com/projectcalico/calico/ui-apis/pkg/authzreview"
)

type AuthorizationReview interface {
	PerformReview(ctx context.Context, cluster string) ([]libcalv3.AuthorizedResourceVerbs, error)
}

// The user authentication review struct implementing the authentication review interface.
type userAuthorizationReview struct {
	reviewer authzreview.Reviewer
}

// NewAuthorizationReview creates an implementation of the AuthorizationReview.
func NewAuthorizationReview(reviewer authzreview.Reviewer) AuthorizationReview {
	return &userAuthorizationReview{reviewer: reviewer}
}

// PerformReview performs an authorization review on behalf of the user specified in
// the HTTP request using the RBAC calculator.
func (a userAuthorizationReview) PerformReview(ctx context.Context, cluster string) ([]libcalv3.AuthorizedResourceVerbs, error) {
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

	return a.reviewer.ReviewForLogs(ctx, user, cluster)
}
