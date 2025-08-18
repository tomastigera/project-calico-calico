// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/linseed/pkg/config"
	"github.com/projectcalico/calico/linseed/pkg/handler"
	"github.com/projectcalico/calico/linseed/pkg/middleware"
	"github.com/projectcalico/calico/lma/pkg/auth"
	"github.com/projectcalico/calico/lma/pkg/httputils"
)

// Route defines the server response based on the method and pattern of the request
type Route struct {
	method  string
	pattern string
	handler http.Handler
}

// UnpackRoutes will create routes based on the methods supported for the provided handlers
func UnpackRoutes(handlers ...handler.Handler) []Route {
	var routes []Route

	for _, h := range handlers {
		for _, m := range h.APIS() {
			if m.AuthzAttributes != nil {
				routes = append(routes, []Route{{m.Method, m.URL, m.Handler}}...)
			} else {
				logrus.WithField("api", m).Warn("Skipping API with no authorization configured")
			}
		}
	}

	return routes
}

// UtilityRoutes defines all available utility routes
func UtilityRoutes() []Route {
	return []Route{
		{"GET", "/version", handler.VersionCheck()},
	}
}

// Middlewares defines all available intermediary handlers
func Middlewares(cfg config.Config, authn auth.Authenticator, authz *middleware.KubernetesAuthzTracker) []func(http.Handler) http.Handler {
	clusterInfo := middleware.ClusterInfo{}
	metrics := middleware.Metrics{}
	tokenAuth := middleware.NewTokenAuth(authn, authz, cfg.ExpectedTenantID)
	return []func(http.Handler) http.Handler{
		// Track an in-flight request. Do this first so that we count requests even if they encounter issues
		// in a subsequent middleware.
		metrics.TrackInflightRequest(),
		// LogRequestHeaders needs to be placed before any middlewares that mutate the request.
		httputils.LogRequestHeaders,
		// Recoverer recovers from panics, logs the panic and returns 500.
		chimiddleware.Recoverer,
		// AllowContentType allows only specific content types for the requests.
		chimiddleware.AllowContentType("application/json", "application/x-ndjson"),
		// ClusterInfo will extract cluster and tenant information from the request to identify the caller.
		clusterInfo.Extract(),
		// Authenticate tokens.
		tokenAuth.Do(),
		// Metrics will track all relevant information for requests.
		metrics.Track(),
	}
}

// Option will configure a Server with different options
type Option func(*Server) error

// WithAPIVersionRoutes will add to the internal router the desired routes to the api version
func WithAPIVersionRoutes(apiVersion string, routes ...Route) Option {
	return func(s *Server) error {
		if s.router == nil {
			return fmt.Errorf("default server is missing a router")
		}

		s.router.Route(apiVersion, func(r chi.Router) {
			for _, route := range routes {
				r.Method(route.method, route.pattern, route.handler)
			}
		})

		return nil
	}
}

// WithRoutes will add to the internal router the desired routes
func WithRoutes(routes ...Route) Option {
	return func(s *Server) error {
		if s.router == nil {
			return fmt.Errorf("default server is missing a router")
		}

		for _, route := range routes {
			s.router.Method(route.method, route.pattern, route.handler)
		}

		return nil
	}
}

// WithMiddlewares will instruct the internal router to make use of the desired middlewares
func WithMiddlewares(middlewares []func(http.Handler) http.Handler) Option {
	return func(s *Server) error {
		if s.router == nil {
			return fmt.Errorf("default server is missing a router")
		}

		s.router.Use(middlewares...)

		return nil
	}
}

// WithClientCACerts configures the server to enable mTLS, using the certificates located at the
// provided paths to authenticate clients.
func WithClientCACerts(certPaths ...string) Option {
	return func(s *Server) error {
		if s.srv == nil || s.srv.TLSConfig == nil {
			return fmt.Errorf("server is not initialized")
		}

		// Build a cert pool with the provided paths.
		certPool := x509.NewCertPool()
		for _, certPath := range certPaths {
			caCert, err := os.ReadFile(certPath)
			if err != nil {
				return err
			}
			certPool.AppendCertsFromPEM(caCert)
		}

		// Require client certificate verification using the generated
		// certificate pool.
		s.srv.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
		s.srv.TLSConfig.ClientCAs = certPool

		return nil
	}
}
