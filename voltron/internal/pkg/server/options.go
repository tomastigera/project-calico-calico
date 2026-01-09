// Copyright (c) 2020 Tigera, Inc. All rights reserved.

package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/projectcalico/calico/lma/pkg/auth"
	"github.com/projectcalico/calico/lma/pkg/cache"
	"github.com/projectcalico/calico/voltron/internal/pkg/proxy"
	"github.com/projectcalico/calico/voltron/internal/pkg/server/accesslog"
	"github.com/projectcalico/calico/voltron/internal/pkg/server/metrics"
	"github.com/projectcalico/calico/voltron/internal/pkg/utils/cors"
)

// Option is a common format for New() options
type Option func(*Server) error

// WithDefaultAddr changes the default address where the server accepts
// connections when Listener is not provided.
func WithDefaultAddr(addr string) Option {
	return func(s *Server) error {
		s.addr = addr
		return nil
	}
}

// WithInternalAddr changes the internal address where the server accepts
// connections. This address is used for internal-only endpoints such as /metrics
func WithInternalAddr(addr string) Option {
	return func(s *Server) error {
		s.internalAddr = addr
		return nil
	}
}

// ProxyTarget represents a target for WithProxyTargets. It defines where a
// request should be redirected based on patter that matches its path.
type ProxyTarget struct {
	Pattern string
	Dest    string
}

// WithExternalCredFiles sets the default cert and key to be used for the TLS
// connections for external traffic (UI).
func WithExternalCredFiles(certFile, keyFile string) Option {
	return func(s *Server) error {
		var err error

		certPEMBlock, err := os.ReadFile(certFile)
		if err != nil {
			return err
		}
		keyPEMBlock, err := os.ReadFile(keyFile)
		if err != nil {
			return err
		}

		return WithExternalCreds(certPEMBlock, keyPEMBlock)(s)
	}
}

// WithExternalCreds creates the default cert and key from the given pem bytes to be used for the TLS connections for
// external traffic (UI).
func WithExternalCreds(certBytes []byte, keyBytes []byte) Option {
	return func(s *Server) error {
		var err error
		s.externalCert, err = tls.X509KeyPair(certBytes, keyBytes)
		return err
	}
}

// WithInternalCredsFiles sets the default cert and key to be used for the TLS
// connections within the management cluster.
func WithInternalCredFiles(certFile, keyFile string) Option {
	return func(s *Server) error {
		certPEMBlock, err := os.ReadFile(certFile)
		if err != nil {
			return err
		}
		keyPEMBlock, err := os.ReadFile(keyFile)
		if err != nil {
			return err
		}

		return WithInternalCreds(certPEMBlock, keyPEMBlock)(s)
	}
}

// WithTunnelInnerProxy adds an inner proxier to use for all connections received from managed clusters
// that are targeting Voltron itself, rather than using SNI routing. For example,
// managed cluster connections to Linseed.
func WithTunnelInnerProxy(p *proxy.Proxy) Option {
	return func(s *Server) error {
		s.clusters.innerProxy = p
		return nil
	}
}

// WithInternalCreds creates the default cert and key from the given pem bytes to be used for the TLS connections within
// the management cluster.
func WithInternalCreds(certBytes []byte, keyBytes []byte) Option {
	return func(s *Server) error {
		var err error
		s.internalCert, err = tls.X509KeyPair(certBytes, keyBytes)
		return err
	}
}

// WithTunnelSigningCreds sets the credentials to be used to to generate creds for guardians.
func WithTunnelSigningCreds(cert *x509.Certificate) Option {
	return func(s *Server) error {
		s.tunnelSigningCert = cert
		return nil
	}
}

// WithTunnelCert sets the credentials to be used for the tunnel server
func WithTunnelCert(tlsCert tls.Certificate) Option {
	return func(s *Server) error {
		s.tunnelCert = tlsCert
		return nil
	}
}

// WithKeepAliveSettings sets the Keep Alive settings for the tunnel.
func WithKeepAliveSettings(enable bool, intervalMs int) Option {
	return func(s *Server) error {
		s.tunnelEnableKeepAlive = enable
		s.tunnelKeepAliveInterval = time.Duration(intervalMs) * time.Millisecond
		return nil
	}
}

// WithDefaultProxy sets the default proxy which is used for requests that do not specify an x-cluster-id header.
// It primarily handles requests from the user's browser which are destined to the
// management cluster (or standalone).
//
// it is optional. If this option is not set, then the server will returns a 400
// error when a request does not have the x-cluster-id header set.
func WithDefaultProxy(p *proxy.Proxy) Option {
	return func(s *Server) error {
		s.defaultProxy = p
		return nil
	}
}

func WithAuthAttributesMap(authMap map[string]*proxy.AuthorizationDetails) Option {
	return func(s *Server) error {
		s.authDetailsMap = authMap
		return nil
	}
}

// WithTunnelTargetWhitelist sets a whitelist of regex representing potential target paths
// that should go through tunnel proxying in the server. This happens within the server
// clusterMux handler.
func WithTunnelTargetWhitelist(tgts []regexp.Regexp) Option {
	return func(s *Server) error {
		s.tunnelTargetWhitelist = tgts
		return nil
	}
}

// WithForwardingEnabled sets if we should allow forwarding to another server
func WithForwardingEnabled(forwardingEnabled bool) Option {
	return func(s *Server) error {
		s.clusters.forwardingEnabled = forwardingEnabled
		return nil
	}
}

// WithDefaultForwardServer sets the server that requests from guardian should be sent to by default
func WithDefaultForwardServer(serverName string, dialRetryAttempts int, dialRetryInterval time.Duration) Option {
	return func(s *Server) error {
		s.clusters.defaultForwardServerName = serverName
		s.clusters.defaultForwardDialRetryAttempts = dialRetryAttempts
		s.clusters.defaultForwardDialRetryInterval = dialRetryInterval
		return nil
	}
}

// WithKubernetesAPITargets sets a whitelist of regex representing target paths
// that target the kube (a)api server
func WithKubernetesAPITargets(tgts []regexp.Regexp) Option {
	return func(s *Server) error {
		s.kubernetesAPITargets = tgts
		return nil
	}
}

// WithUnauthenticatedTargets sets a whitelist target paths that do not need authentication
func WithUnauthenticatedTargets(tgts []string) Option {
	return func(s *Server) error {
		s.unauthenticatedTargetPaths = tgts
		return nil
	}
}

// WithSNIServiceMap sets the service map used by the SNI proxy to say where to proxy traffic from a specific host to.
func WithSNIServiceMap(serviceMap map[string]string) Option {
	return func(s *Server) error {
		s.clusters.sniServiceMap = serviceMap
		return nil
	}
}

func WithCheckManagedClusterAuthorizationBeforeProxy(enabled bool, cacheTTL time.Duration, authorizer auth.RBACAuthorizer) Option {
	return func(s *Server) error {
		if enabled && cacheTTL > 0 {
			if cacheTTL > AuthzCacheMaxTTL {
				return fmt.Errorf("configured cacheTTL of %v exceeds maximum permitted of %v", cacheTTL, AuthzCacheMaxTTL)
			}
			authCache, err := cache.NewExpiring[string, bool](cache.ExpiringConfig{
				Context: s.ctx,
				Name:    "managedcluster-access-authorizer",
				TTL:     cacheTTL,
			})
			if err != nil {
				return err
			}
			authorizer = auth.NewCachingAuthorizer(authCache, authorizer)
		}
		s.checkManagedClusterAuthorizationBeforeProxy = enabled
		s.checkManagedClusterAuthorizer = authorizer
		return nil
	}
}

// WithHTTPAccessLogging enables writing of http access logs to stdout
func WithHTTPAccessLogging(options ...accesslog.Option) Option {
	return func(s *Server) error {
		logger, err := accesslog.New(options...)
		if err != nil {
			return err
		}

		s.accessLogger = logger
		return nil
	}
}

// WithInternalMetricsEndpointEnabled enables the `/metrics` endpoint in the internal mux
func WithInternalMetricsEndpointEnabled(enabled bool) Option {
	return func(s *Server) error {
		if enabled {
			if s.internalMux == nil {
				s.internalMux = http.NewServeMux()
			}

			s.internalMux.Handle("/metrics", metrics.NewHandler())
		}

		return nil
	}
}

// WithCalicoCloudCORS enables calico cloud CORS handler for all paths except specified ignorePaths.
func WithCalicoCloudCORS(expr string, ignorePaths ...string) Option {
	return func(s *Server) error {
		c, err := cors.New(expr, ignorePaths...)
		if err != nil {
			return fmt.Errorf("failed to initialize cors: %v", err)
		}
		s.cors = c
		return nil
	}
}
