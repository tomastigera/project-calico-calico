// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package server

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/projectcalico/calico/es-gateway/pkg/cache"
	"github.com/projectcalico/calico/es-gateway/pkg/clients/elastic"
	"github.com/projectcalico/calico/es-gateway/pkg/clients/kibana"
	"github.com/projectcalico/calico/es-gateway/pkg/clients/kubernetes"
	"github.com/projectcalico/calico/es-gateway/pkg/handlers"
	"github.com/projectcalico/calico/es-gateway/pkg/handlers/health"
	"github.com/projectcalico/calico/es-gateway/pkg/metrics"
	mid "github.com/projectcalico/calico/es-gateway/pkg/middlewares"
	"github.com/projectcalico/calico/es-gateway/pkg/proxy"
)

const (
	DefaultReadTimeout = 45 * time.Second
)

// Server is the ES Gateway server that accepts requests from various components that require
// access to Elasticsearch (& Kibana). It serves HTTP requests and proxies them Elasticsearch
// and Kibana.
type Server struct {
	ctx    context.Context
	cancel context.CancelFunc

	http         *http.Server     // Server to accept incoming ES/Kibana requests
	addr         string           // Address for server to listen on
	internalCert *tls.Certificate // Certificate chain used for all external requests

	esTarget     *proxy.Target // Proxy target for Elasticsearch API
	kibanaTarget *proxy.Target // Proxy target for Kibana API
	dummyRoutes  proxy.Routes  // Routes specified will responded to with a StatusOK and not forwarded

	esClient  elastic.Client    // Elasticsearch client for making API calls required by ES Gateway
	kbClient  kibana.Client     // Kibana client for making API calls required by ES Gateway
	k8sClient kubernetes.Client // K8s client for retrieving K8s resources related to ES users

	adminESUsername string // Used to store the username for a real ES admin user
	adminESPassword string // Used to store the password for a real ES admin user

	cache     cache.SecretsCache // Used to store secrets related authN and credential swapping
	collector metrics.Collector  // Used to collect prometheus metrics.

	middlewareMap mid.HandlerMap
}

// New returns a new ES Gateway server. Validate and set the server options. Set up the Elasticsearch and Kibana
// related routes and HTTP handlers.
func New(opts ...Option) (*Server, error) {
	var err error
	srv := &Server{}

	// -----------------------------------------------------------------------------------------------------
	// Parse server options
	// -----------------------------------------------------------------------------------------------------
	for _, o := range opts {
		if err := o(srv); err != nil {
			return nil, errors.WithMessage(err, "applying option failed")
		}
	}

	if srv.ctx == nil {
		// Use a default context if one was not provided
		srv.ctx, srv.cancel = context.WithCancel(context.Background())
	}

	cfg, err := calicotls.NewTLSConfig()
	if err != nil {
		return nil, err
	}
	if srv.internalCert != nil {
		cfg.Certificates = append(cfg.Certificates, *srv.internalCert)
	}

	// -----------------------------------------------------------------------------------------------------
	// Set up all routing for ES Gateway server (using Gorilla Mux).
	// -----------------------------------------------------------------------------------------------------
	router := mux.NewRouter()

	// Route Handling #1: Handle the ES Gateway health check endpoint
	if srv.k8sClient != nil {
		healthHandler := health.GetHealthHandler(srv.k8sClient)
		router.HandleFunc("/health", healthHandler).Name("health")
	}
	if srv.esClient != nil {
		healthCheckES := health.GetESHealthHandler(srv.esClient)
		router.HandleFunc("/es-health", healthCheckES).Name("es-health")
	}
	if srv.kbClient != nil {
		healthCheckKB := health.GetKBHealthHandler(srv.kbClient)
		router.HandleFunc("/kb-health", healthCheckKB).Name("kb-health")
	}

	if srv.kibanaTarget != nil {
		// Route Handling #2: Handle any Kibana request, which we expect will have a common path prefix.
		kibanaHandler, err := handlers.GetProxyHandler(srv.kibanaTarget, nil)
		if err != nil {
			return nil, err
		}
		// The below path prefix syntax provides us a wildcard to specify that kibanaHandler will handle all
		// requests with a path that begins with the given path prefix.
		err = addRoutes(
			router,
			srv.kibanaTarget.Routes,
			srv.kibanaTarget.CatchAllRoute,
			srv.middlewareMap,
			kibanaHandler,
		)
		if err != nil {
			return nil, err
		}
	}

	if len(srv.dummyRoutes) > 0 {
		// Connect the dummy routes to the IgnoreHandler which returns success without forwarding the traffic
		err = addRoutes(
			router,
			srv.dummyRoutes,
			nil, // No catch all with the dummy route
			nil, // No middleware needed
			handlers.GetIgnoreHandler(),
		)
		if err != nil {
			return nil, err
		}
	}

	if srv.esTarget != nil {
		// Route Handling #3: Handle any Elasticsearch request. We do the Elasticsearch section last because
		// these routes do not have a universally common path prefix.
		esHandler, err := handlers.GetProxyHandler(srv.esTarget, handlers.ElasticModifyResponseFunc(srv.collector))
		if err != nil {
			return nil, err
		}
		err = addRoutes(
			router,
			srv.esTarget.Routes,
			srv.esTarget.CatchAllRoute,
			srv.middlewareMap,
			esHandler,
		)
		if err != nil {
			return nil, err
		}
	}

	// Add common middlewares to the router.
	router.Use(srv.middlewareMap[mid.TypeLog])

	// -----------------------------------------------------------------------------------------------------
	// Return configured ES Gateway server.
	// -----------------------------------------------------------------------------------------------------
	srv.http = &http.Server{
		Addr:        srv.addr,
		Handler:     router,
		TLSConfig:   cfg,
		ReadTimeout: DefaultReadTimeout,
	}

	return srv, nil
}

// ListenAndServeHTTPS starts listening and serving HTTPS requests
func (s *Server) ListenAndServeHTTPS() error {
	return s.http.ListenAndServeTLS("", "")
}

// ListenAndServeHTTP starts listening and serving HTTP requests
func (s *Server) ListenAndServeHTTP() error {
	return s.http.ListenAndServe()
}

// addRoutes sets up the given Routes for the provided mux.Router.
func addRoutes(router *mux.Router, routes proxy.Routes, catchAllRoute *proxy.Route, h mid.HandlerMap, f http.Handler) error {
	// Set up provided list of Routes
	for _, route := range routes {
		muxRoute := router.NewRoute()

		// If this Route has HTTP methods to filter on, then add those.
		if len(route.HTTPMethods) > 0 {
			muxRoute.Methods(route.HTTPMethods...)
		}

		handlerChain := buildMiddlewareChain(&route, h, f)
		if route.IsPathPrefix {
			muxRoute.PathPrefix(route.Path).Handler(handlerChain).Name(route.Name)
		} else {
			muxRoute.Path(route.Path).Handler(handlerChain).Name(route.Name)
		}
	}

	// Set up provided catch-all Route
	if catchAllRoute != nil {
		if !catchAllRoute.IsPathPrefix {
			return errors.New("catch-all route must be marked as a path prefix")
		}

		handlerChain := buildMiddlewareChain(catchAllRoute, h, f)
		router.PathPrefix(catchAllRoute.Path).Handler(handlerChain).Name(catchAllRoute.Name)
	}

	return nil
}

// getLogRouteMatchHandler returns a function that wraps a http.Handler in order to log the Mux route that was
// matched. This is useful for troubleshooting and debugging.
func getLogRouteMatchHandler(routeName string) func(h http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Debugf("%s %s as been matched with route \"%s\"", r.Method, r.RequestURI, routeName)
			h.ServeHTTP(w, r)
		})
	}
}

// buildMiddlewareChain takes a proxy.Route and builds a chain of middleware handlers including the final
// HTTP handler f to be executed for the given route r. Which middlewares are included depends on r's
// configuration flags.
// When applying the chain, the last handler is applied to f first (since the chain is built outwards).
// This will ensure that the handlers are executed in the correct order for a request (ending with f).
// So if chain = {m1, m2, m3}, then we apply them on f, like this m1(m2(m3(f))). And the order of execution
// will be m1, m2, m3, f.
func buildMiddlewareChain(r *proxy.Route, h mid.HandlerMap, f http.Handler) http.Handler {
	chain := []mux.MiddlewareFunc{}

	// Add a wrapping handler that will log the route name when executed.
	wrapper := getLogRouteMatchHandler(r.Name)
	chain = append(chain, wrapper)

	// Add auth middleware to the chain for this Route, if the flag is enabled.
	if r.RequireAuth {
		chain = append(chain, h[mid.TypeAuth])

		// Alongside auth, add credential swapping middlware to the Handler chain for this
		// Route
		chain = append(chain, h[mid.TypeSwap])
	}

	if r.RejectUnacceptableContentType {
		chain = append(chain, h[mid.TypeContentType])
	}

	if r.EnforceTenancy {
		chain = append(chain, h[mid.TypeMultiTenant])
	}

	// Now apply the chain of middleware handlers on the given route handler f, starting with the last one.
	finalHandler := f
	for i := range chain {
		finalHandler = chain[len(chain)-1-i](finalHandler)
	}

	return finalHandler
}
