// Copyright (c) 2021 Tigera. All rights reserved.
package handler

import (
	"fmt"
	"net/http"
	"net/http/httputil"

	log "github.com/sirupsen/logrus"
	authzv1 "k8s.io/api/authorization/v1"

	"github.com/projectcalico/calico/lma/pkg/auth"
)

var (
	// The RBAC permissions that allow a user to perform an HTTP GET to Prometheus.
	getResources = []*authzv1.ResourceAttributes{
		{
			Verb:     "get",
			Resource: "services/proxy",
			Name:     "https:calico-api:8080",
		},
		{
			Verb:     "get",
			Resource: "services/proxy",
			Name:     "calico-node-prometheus:9090",
		},
	}
	// The RBAC permissions that allow a user to perform an HTTP POST to Prometheus.
	createResources = []*authzv1.ResourceAttributes{
		{
			Verb:     "create",
			Resource: "services/proxy",
			Name:     "https:calico-api:8080",
		},
		{
			Verb:     "create",
			Resource: "services/proxy",
			Name:     "calico-node-prometheus:9090",
		},
	}
)

// Proxy sends the received query to the forwarded host registered in ReverseProxy param
func Proxy(proxy *httputil.ReverseProxy, authn auth.JWTAuth) (http.HandlerFunc, error) {

	return func(w http.ResponseWriter, req *http.Request) {
		if authn == nil {
			proxy.ServeHTTP(w, req)
			return
		}

		usr, stat, err := authn.Authenticate(req)
		if err != nil {
			w.WriteHeader(stat)
			_, err := w.Write([]byte(err.Error()))
			if err != nil {
				log.Errorf("Error when writing body to response: %v", err)
			}
			return
		}

		// Perform AuthZ checks
		var resources []*authzv1.ResourceAttributes
		if req.Method == http.MethodGet {
			resources = getResources
		} else if req.Method == http.MethodPost {
			resources = createResources
		} else {
			// At this time only HTTP GET/POST are allowed
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, err := w.Write([]byte("Method Not Allowed"))
			if err != nil {
				log.Errorf("Error when writing body to response: %v", err)
			}
			return
		}

		authorized := false
		// Check if either of the permissions are allowed, then the user is authorized.
		for _, res := range resources {
			ok, err := authn.Authorize(usr, res, nil)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_, err := w.Write([]byte(err.Error()))
				if err != nil {
					log.Errorf("Error when writing body to response: %v", err)
				}
				return
			}
			if ok {
				authorized = true
				break
			}
		}

		if !authorized {
			w.WriteHeader(http.StatusForbidden)
			_, err := w.Write([]byte(fmt.Sprintf("user %v is not authorized to perform %v https:calico-api:8080", usr, req.Method)))
			if err != nil {
				log.Errorf("Error when writing body to response: %v", err)
			}
			return
		}

		proxy.ServeHTTP(w, req)
	}, nil
}
