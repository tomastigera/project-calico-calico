// Copyright (c) 2023-2025 Tigera, Inc. All rights reserved.

package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/crypto/pkg/tls"
)

// Server defines a custom http server that can be configured to respond to different routes
// and make use of multiple  and serves only HTTPS traffic
type Server struct {
	srv    *http.Server
	router *chi.Mux
}

// NewServer creates a new Server that binds on addr and applies different customizations
func NewServer(addr string, opts ...Option) *Server {
	const (
		defaultIdleTimeout = 120 * time.Second
		defaultReadTimeout = 60 * time.Second
	)

	mux := chi.NewRouter()

	srv := &http.Server{
		Addr:        addr,
		TLSConfig:   tls.NewTLSConfig(),
		Handler:     mux,
		IdleTimeout: defaultIdleTimeout,
		ReadTimeout: defaultReadTimeout,
		// Don't impose a WriteTimeout on Linseed's server side.  Instead we have a timeout
		// (defaulting to 60s) in the Elastic backend.
	}

	server := &Server{
		srv:    srv,
		router: mux,
	}

	for _, opt := range opts {
		err := opt(server)
		if err != nil {
			log.WithError(err).Fatal("invalid options applied to server")
			return nil
		}
	}

	return server
}

// ListenAndServeTLS is a blocking request that will listen on the provided network address
// and serves incoming TLS requests. All traffic will be encrypted with certFile, keyFile provided
func (s *Server) ListenAndServeTLS(certFile, keyFile string) error {
	if s.srv == nil {
		return fmt.Errorf("no server is currently configured")
	}
	return s.srv.ListenAndServeTLS(certFile, keyFile)
}

// Shutdown gracefully shutdowns the server
func (s *Server) Shutdown(ctx context.Context) error {
	if s.srv == nil {
		return fmt.Errorf("no server is currently configured")
	}
	return s.srv.Shutdown(ctx)
}
