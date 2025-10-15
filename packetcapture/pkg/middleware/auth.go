// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package middleware

import (
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apiserver/pkg/endpoints/request"

	"github.com/projectcalico/calico/lma/pkg/auth"
	"github.com/projectcalico/calico/packetcapture/pkg/cache"
)

// AuthZ is used to authorize requests for PacketCapture files access
type AuthZ struct {
	cache cache.ClientCache
}

// NewAuthZ will return an *AuthZ based on the passed in configuration and multi-cluster setup
// Authorization can be checked against the management cluster or the managed cluster
// cache.ClientCache will create/return specialized authorizer based on the request given
func NewAuthZ(cache cache.ClientCache) *AuthZ {
	return &AuthZ{cache: cache}
}

// AuthenticationHandler is a middleware handler that authenticates a request
func AuthenticationHandler(authn auth.JWTAuth, handlerFunc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		// Authenticate the user/service account based on the Authorization token
		// For a standalone and a management cluster, the Authorization token will
		// authenticate the initiator of the request. For a managed cluster, it
		// will authenticate the service account that tries to impersonate the initiator
		// of the request
		usr, stat, err := authn.Authenticate(req)
		if err != nil {
			log.WithError(err).Error("failed to authenticate user")
			http.Error(w, err.Error(), stat)
			return
		}
		req = req.WithContext(request.WithUser(req.Context(), usr))
		handlerFunc.ServeHTTP(w, req)
	}
}

// Authorize is a middleware handler that authorizes a request for access or delete to
// subresource packet captures/files in a given namespace
func (authz *AuthZ) Authorize(handlerFunc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		resAtr := &authzv1.ResourceAttributes{
			Verb:        ActionIDFromContext(req.Context()),
			Group:       "projectcalico.org",
			Resource:    "packetcaptures",
			Subresource: "files",
			Name:        CaptureNameFromContext(req.Context()),
			Namespace:   NamespaceFromContext(req.Context()),
		}

		status, err := authz.authorize(req, resAtr)
		if err != nil {
			http.Error(w, err.Error(), status)
			return
		}

		handlerFunc.ServeHTTP(w, req)
	}
}

func (authz *AuthZ) authorize(req *http.Request, resAtr *authzv1.ResourceAttributes) (int, error) {
	var clusterID = ClusterIDFromContext(req.Context())
	var authorizer, err = authz.cache.GetAuthorizer(clusterID)
	if err != nil {
		log.WithError(err).Error("Failed to create authorizer")
		return http.StatusInternalServerError, err
	}
	usr, ok := request.UserFrom(req.Context())
	if !ok {
		var err = fmt.Errorf("missing user from request")
		log.WithError(err).Error("no user found in request context")
		return http.StatusBadRequest, err
	}

	isAuthorized, err := authorizer.Authorize(usr, resAtr, nil)
	if err != nil {
		log.WithError(err).Error("Kubernetes authorization failure")
		return http.StatusUnauthorized, err
	}

	if !isAuthorized {
		var err error
		if len(resAtr.Subresource) == 0 {
			err = fmt.Errorf("%s is not authorized to %s for %s", usr.GetName(), resAtr.Verb, resAtr.Resource)
		} else {
			err = fmt.Errorf("%s is not authorized to %s for %s/%s", usr.GetName(), resAtr.Verb, resAtr.Resource, resAtr.Subresource)
		}
		log.WithError(err).Error("User is not authorized")
		return http.StatusUnauthorized, err
	}

	return 0, nil
}
