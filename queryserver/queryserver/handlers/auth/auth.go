// Copyright (c) 2022 Tigera, Inc. All rights reserved.
package authhandler

import (
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apiserver/pkg/endpoints/request"

	"github.com/projectcalico/calico/lma/pkg/auth"
)

type HTTPMethod string

const (
	MethodGET  HTTPMethod = http.MethodGet
	MethodPOST HTTPMethod = http.MethodPost
)

// The RBAC permissions that allow a user to perform an HTTP GET to Queryserver.
var resourceGET = &authzv1.ResourceAttributes{
	Verb:     "get",
	Resource: "services/proxy",
	Name:     "https:calico-api:8080",
}

// The RBAC permissions that allow a user to perform an HTTP POST to Queryserver.
var resourcePOST = &authzv1.ResourceAttributes{
	Verb:     "create",
	Resource: "services/proxy",
	Name:     "https:calico-api:8080",
}

type AuthHandler interface {
	AuthenticationHandler(handlerFunc http.HandlerFunc, httpMethodAllowed HTTPMethod) http.HandlerFunc
}

type authHandler struct {
	authJWT auth.JWTAuth
}

// NewAuthHandler returns a new AuthHandler.
func NewAuthHandler(a auth.JWTAuth) AuthHandler {
	return &authHandler{
		authJWT: a,
	}
}

// AuthenticationHandler is a handler that authenticates a request. Supports GET and POST
// returns an error for other methods.
func (ah *authHandler) AuthenticationHandler(handlerFunc http.HandlerFunc, httpMethodAllowed HTTPMethod) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if ah.authJWT == nil {
			log.Warnf("Authentication checks for request to path %s are skipped", req.URL.RawPath)
			return
		}
		// Authentication.
		usr, stat, err := ah.authJWT.Authenticate(req)
		if err != nil {
			name := ""
			if usr != nil {
				name = usr.GetName()
			}
			log.WithError(err).Errorf("failed to authenticate user: %s", name)
			http.Error(w, err.Error(), stat)
			w.WriteHeader(stat)
			_, err := w.Write([]byte(err.Error()))
			if err != nil {
				log.WithError(err).Error("failed to write body to response")
			}
			return
		}

		req = req.WithContext(request.WithUser(req.Context(), usr))

		// Authorization.
		// TODO(dimitri): Replace simple with query result authorization [EV-2033].

		if req.Method != string(httpMethodAllowed) {
			// Operation not allowed
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, err := w.Write([]byte("Method Not Allowed"))
			if err != nil {
				log.WithError(err).Error("failed to write body to response")
			}
			return
		}

		// Generate resource based on httpMethod
		var resource *authzv1.ResourceAttributes

		switch req.Method {
		case http.MethodGet:
			resource = resourceGET
		case http.MethodPost:
			resource = resourcePOST
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, err := w.Write([]byte("Method Not Allowed"))
			if err != nil {
				log.Errorf("error when writing body to response: %v", err)
			}
			return
		}

		authorized := false
		// Check if either of the permissions are allowed, then the user is authorized.
		ok, err := ah.authJWT.Authorize(usr, resource, nil)
		if err != nil {
			// Respond with 500.
			w.WriteHeader(http.StatusInternalServerError)
			_, err := w.Write([]byte(err.Error()))
			if err != nil {
				log.Errorf("error when writing body to response: %v", err)
			}
			return
		}
		if ok {
			authorized = true
		}

		if !authorized {
			// Respond with 403.
			w.WriteHeader(http.StatusForbidden)
			_, err := fmt.Fprintf(w, "user %v is not authorized to perform %v https:calico-api:8080", usr, req.Method)
			if err != nil {
				log.Errorf("error when writing body to response: %v", err)
			}
			return
		}

		handlerFunc.ServeHTTP(w, req)
	}
}
