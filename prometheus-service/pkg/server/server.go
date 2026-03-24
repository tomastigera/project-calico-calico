// Copyright (c) 2021 Tigera. All rights reserved.
package server

import (
	"context"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/projectcalico/calico/lma/pkg/auth"
	health "github.com/projectcalico/calico/prometheus-service/pkg/handler/health"
	proxy "github.com/projectcalico/calico/prometheus-service/pkg/handler/proxy"
	"github.com/projectcalico/calico/prometheus-service/pkg/middleware"
)

var (
	server *http.Server
	wg     sync.WaitGroup
)

func Start(config *Config) {
	sm := http.NewServeMux()

	reverseProxy := getReverseProxy(config.PrometheusUrl)

	var authn auth.JWTAuth
	if config.AuthenticationEnabled {

		restConfig, err := rest.InClusterConfig()
		if err != nil {
			log.Fatal("Unable to create client config", err)
		}
		//restConfig.
		k8sCli, err := kubernetes.NewForConfig(restConfig)
		if err != nil {
			log.Fatal("Unable to create kubernetes interface", err)
		}

		var options []auth.JWTAuthOption
		if config.DexEnabled {
			log.Debug("Configuring Dex for authentication")
			opts := []auth.DexOption{
				auth.WithGroupsClaim(config.OIDCAuthGroupsClaim),
				auth.WithJWKSURL(config.OIDCAuthJWKSURL),
				auth.WithUsernamePrefix(config.OIDCAuthUsernamePrefix),
				auth.WithGroupsPrefix(config.OIDCAuthGroupsPrefix),
			}
			dex, err := auth.NewDexAuthenticator(
				config.OIDCAuthIssuer,
				config.OIDCAuthClientID,
				config.OIDCAuthUsernameClaim,
				opts...)
			if err != nil {
				log.Fatal("Unable to add an issuer to the authenticator", err)
			}
			options = append(options, auth.WithAuthenticator(config.OIDCAuthIssuer, dex))
		}
		authn, err = auth.NewJWTAuth(restConfig, k8sCli, options...)
		if err != nil {
			log.Fatal("Unable to create authenticator", err)
		}
	}

	proxyHandler, err := proxy.Proxy(reverseProxy, authn)
	if err != nil {
		log.Fatal("Unable to create proxy handler", err)
	}

	sm.Handle("/health", health.HealthCheck())

	sm.Handle("/", proxyHandler)
	tlsConfig, err := tls.NewTLSConfig()
	if err != nil {
		log.Fatal(err)
	}
	server = &http.Server{
		Addr:      config.ListenAddr,
		Handler:   middleware.LogRequestHeaders(sm),
		TLSConfig: tlsConfig,
	}

	wg.Go(func() {
		log.Infof("Starting server on %v", config.ListenAddr)
		err := server.ListenAndServeTLS(config.TLSCert, config.TLSKey)
		if err != nil {
			log.WithError(err).Error("Error when starting server.")
		}
	})
}

func getReverseProxy(target *url.URL) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		// applies the prometheus target URL to the request
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
		},
	}
}

func Wait() {
	wg.Wait()
}

func Stop() {
	if err := server.Shutdown(context.Background()); err != nil {
		log.WithError(err).Error("Error when stopping server")
	}
}
