// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.

package server

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/textproto"
	"regexp"
	"strings"
	"time"

	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
	"github.com/felixge/httpsnoop"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"golang.org/x/oauth2"
	authnv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/apiserver/pkg/authentication"
	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/projectcalico/calico/lma/pkg/auth"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	"github.com/projectcalico/calico/voltron/internal/pkg/bootstrap"
	"github.com/projectcalico/calico/voltron/internal/pkg/config"
	"github.com/projectcalico/calico/voltron/internal/pkg/proxy"
	"github.com/projectcalico/calico/voltron/internal/pkg/server/accesslog"
	"github.com/projectcalico/calico/voltron/internal/pkg/server/metrics"
	"github.com/projectcalico/calico/voltron/internal/pkg/utils"
	"github.com/projectcalico/calico/voltron/internal/pkg/utils/cors"
	"github.com/projectcalico/calico/voltron/pkg/tunnel"
	"github.com/projectcalico/calico/voltron/pkg/tunnelmgr"
)

const (
	DefaultReadTimeout = 45 * time.Second

	// CalicoCloudTenantIDClaimName is the name of the tenantID claim in Calico Cloud issued bearer tokens
	CalicoCloudTenantIDClaimName = "https://calicocloud.io/tenantID"

	AuthzCacheMaxTTL = 20 * time.Second
)

// ClusterHeaderFieldCanon represents the request header key used to determine which
// cluster to proxy for (Canonical)
var ClusterHeaderFieldCanon = textproto.CanonicalMIMEHeaderKey(utils.ClusterHeaderField)

var authorizationHeaderKey = http.CanonicalHeaderKey("Authorization")

// Server is the voltron server that accepts tunnels from the app clusters. It
// serves HTTP requests and proxies them to the tunnels.
type Server struct {
	ctx      context.Context
	cancel   context.CancelFunc
	http     *http.Server
	proxyMux *http.ServeMux

	// a http mux for endpoints that should not be exposed to the outside, e.g. `/metrics`
	//
	// lazily initialized, any handler registration function must create it if it is nil
	internalMux *http.ServeMux

	internalAddr string

	// internalHTTP only created & started if the lazily initialized internalMux is not nil
	internalHTTP *http.Server

	k8s bootstrap.K8sClient
	// When impersonating a user we use the tigera-manager sa bearer token from this config.
	config        *rest.Config
	authenticator auth.JWTAuth

	// defaultProxy handles requests received by voltron which are destined to the management cluster itself.
	// this primarily serves requests made by the user's browser.
	// when nil, the server will returns a 400 error for requests that do not have the x-cluster-id header set.
	//
	// defaultProxy has its own ServeMux, separate from proxyMux and internalMux.
	defaultProxy *proxy.Proxy

	// tunnelTargetWhitelist contains a list of url paths which are allowed to go down the tunnel to the managed cluster.
	// requests that do not match this whitelist will be diverted to the management cluster even if the request has specified
	// the x-cluster-id header.
	//
	// this can be used to move services to the management cluster without needing any update to the client making the request.
	tunnelTargetWhitelist      []regexp.Regexp
	kubernetesAPITargets       []regexp.Regexp
	unauthenticatedTargetPaths []string

	clusters *clusters
	health   *health

	tunSrv *tunnel.Server

	externalCert tls.Certificate
	internalCert tls.Certificate

	addr string

	// tunnelSigningCert is the cert that was used to generate creds for the tunnel clients a.k.a guardians and
	// thus the cert that can be used to verify its identity
	tunnelSigningCert *x509.Certificate

	// tunnelCert is the cert to be used for the tunnel endpoint
	tunnelCert tls.Certificate

	tunnelEnableKeepAlive   bool
	tunnelKeepAliveInterval time.Duration

	sniServiceMap map[string]string

	// checkManagedClusterAuthorizationBeforeProxy
	checkManagedClusterAuthorizationBeforeProxy bool

	// specific `auth.RBACAuthorizer` for `checkManagedClusterAuthorizationBeforeProxy` which may have caching enabled
	checkManagedClusterAuthorizer auth.RBACAuthorizer

	accessLogger *accesslog.Logger

	cors *cors.CORS

	// The token that Voltron uses has an exp of 1h by default and is periodically refreshed in the rest config
	// BearerTokenFile location by the kubelet (k8s 1.22+). This token source uses client-go's tokenSource.
	tokenSource oauth2.TokenSource
}

// New returns a new Server. k8s may be nil and options must check if it is nil
// or not if they set its user and return an error if it is nil
func New(k8s bootstrap.K8sClient, client ctrlclient.WithWatch, config *rest.Config, vcfg config.Config, authenticator auth.JWTAuth, opts ...Option) (*Server, error) {
	srv := &Server{
		k8s:           k8s,
		config:        config,
		authenticator: authenticator,
		clusters: &clusters{
			clusters:   make(map[string]*cluster),
			voltronCfg: &vcfg,
			k8sCLI:     k8s,
			client:     client,
			// Dummy function that will be overwritten if voltron is accepting
			// managed cluster connections.
			statusUpdateFunc: func(string, v3.ManagedClusterStatusValue) {},
		},
		tunnelEnableKeepAlive:   true,
		tunnelKeepAliveInterval: 100 * time.Millisecond,
	}

	// Apply options to the server first.
	srv.ctx, srv.cancel = context.WithCancel(context.Background())
	for _, o := range opts {
		if err := o(srv); err != nil {
			return nil, errors.WithMessage(err, "applying option failed")
		}
	}

	// Generate TLS configuration for the per-cluster HTTPS server that
	// handles incoming requests from connected managed clusters.
	if err := srv.clusters.makeInnerTLSConfig(); err != nil {
		return nil, err
	}
	srv.clusters.sniServiceMap = srv.sniServiceMap

	// Create an HTTP server to handle incoming requests.
	srv.proxyMux = http.NewServeMux()
	srv.proxyMux.HandleFunc("/", wrapInMetricsAndLoggingAwareHandler(vcfg.MetricsEnabled, srv.accessLogger, wrapInCORSHandler(srv.cors, srv.clusterMuxer)))
	srv.proxyMux.HandleFunc("/voltron/api/health", srv.health.apiHandle)

	cfg := calicotls.NewTLSConfig()
	cfg.Certificates = append(cfg.Certificates, srv.externalCert)
	if len(srv.internalCert.Certificate) > 0 {
		cfg.Certificates = append(cfg.Certificates, srv.internalCert)
	}
	srv.http = &http.Server{
		Addr:        srv.addr,
		Handler:     srv.proxyMux,
		TLSConfig:   cfg,
		ReadTimeout: DefaultReadTimeout,
	}

	if srv.internalMux != nil {
		if len(srv.internalCert.Certificate) == 0 {
			return nil, fmt.Errorf("no internal certificates configured")
		}
		internalTlsCfg := calicotls.NewTLSConfig()
		internalTlsCfg.Certificates = append(internalTlsCfg.Certificates, srv.internalCert)

		srv.internalHTTP = &http.Server{
			Addr:        srv.internalAddr,
			Handler:     srv.internalMux,
			TLSConfig:   internalTlsCfg,
			ReadTimeout: DefaultReadTimeout,
		}
	}

	if srv.tunnelSigningCert != nil {
		var tunOpts []tunnel.ServerOption
		tunOpts = append(tunOpts,
			tunnel.WithClientCert(srv.tunnelSigningCert),
			tunnel.WithServerCert(srv.tunnelCert),
		)

		var err error
		srv.tunSrv, err = tunnel.NewServer(tunOpts...)
		if err != nil {
			return nil, errors.WithMessage(err, "tunnel server")
		}
		go srv.acceptTunnels(
			tunnel.WithKeepAliveSettings(srv.tunnelEnableKeepAlive, srv.tunnelKeepAliveInterval),
		)

		x := NewStatusUpdater(srv.ctx, client, vcfg, nil)
		srv.clusters.statusUpdateFunc = x.SetStatus

		srv.clusters.clientCertificatePool = srv.tunSrv.GetClientCertificatePool()
	}

	srv.tokenSource = transport.NewCachedFileTokenSource(config.BearerTokenFile)
	return srv, nil
}

// ServeHTTPS starts serving HTTPS requests
func (s *Server) ServeHTTPS(lis net.Listener, certFile, keyFile string) error {
	logrus.Debug("ServeHTTPS")
	defer logrus.Debug("ServeHTTPS done")
	return s.http.ServeTLS(lis, certFile, keyFile)
}

func (s *Server) ServeInternalHTTPS(lis net.Listener, certFile, keyFile string) error {
	if s.internalHTTP != nil {
		return s.internalHTTP.ServeTLS(lis, certFile, keyFile)
	}
	return nil
}

// ListenAndServeHTTPS starts listening and serving HTTPS requests
func (s *Server) ListenAndServeHTTPS() error {
	return s.http.ListenAndServeTLS("", "")
}

// ListenAndServeInternalHTTPS starts listening and serving the internalHTTP server
func (s *Server) ListenAndServeInternalHTTPS() error {
	if s.internalHTTP != nil {
		logrus.Infof("Voltron listens for Internal HTTP requests at %s", s.internalAddr)
		return s.internalHTTP.ListenAndServeTLS("", "")
	}
	return nil
}

// Close stop the server
func (s *Server) Close() error {
	defer logrus.Infof("Voltron Server closed")

	s.cancel()
	if s.tunSrv != nil {
		s.tunSrv.Stop()
	}

	var internalCloseErr error
	if s.internalHTTP != nil {
		internalCloseErr = s.internalHTTP.Close()
	}

	if publicCloseErr := s.http.Close(); publicCloseErr != nil {
		return publicCloseErr
	}

	return internalCloseErr
}

// ServeTunnelsTLS start serving TLS secured tunnels using the provided listener and
// the TLS configuration of the Server
func (s *Server) ServeTunnelsTLS(lis net.Listener) error {
	logrus.Debugf("ServeTunnelsTLS")
	defer logrus.Debugf("ServeTunnelsTLS exited")

	if s.tunSrv == nil {
		return errors.New("no tunnel server was initiated")
	}
	err := s.tunSrv.ServeTLS(lis)
	if err != nil {
		return errors.WithMessage(err, "ServeTunnels")
	}

	return nil
}

func (s *Server) acceptTunnels(opts ...tunnel.Option) {
	logrus.Debugf("Accepting tunnel connections")
	defer logrus.Debugf("acceptTunnels exited")

	for {
		t, err := s.tunSrv.AcceptTunnel(opts...)
		if err != nil {
			select {
			case <-s.ctx.Done():
				// N.B. When s.ctx.Done() AcceptTunnel will return with an
				// error, will not block
				return
			default:
				logrus.Warnf("accepting tunnel failed: %s", err)
				continue
			}
		}
		logrus.Debugf("tunnel accepted")

		clusterID, fingerprint, tunnelCert := s.extractIdentity(t)

		c := s.clusters.get(clusterID)
		if c == nil {
			logrus.Errorf("cluster %q does not exist", clusterID)
			t.Close()
			continue
		}
		managedCertificate := c.Certificate

		// Needs a lock for both reading and writing (if assignTunnel is called).
		c.Lock()

		// we call this function so that we can return and unlock on any failed
		// check
		func() {
			defer c.Unlock()

			if len(managedCertificate) != 0 {
				if err := validateCertificate(tunnelCert, managedCertificate); err != nil {
					logrus.WithError(err).Errorf("failed to verify certificate for cluster %s", clusterID)
					closeTunnel(t)
					return
				}
			} else {
				if len(c.ActiveFingerprint) == 0 {
					logrus.Error("no fingerprint has been stored against the current connection")
					closeTunnel(t)
					return
				}
				// Before Calico Enterprise v3.15, we use md5 hash algorithm for the managed cluster
				// certificate fingerprint. md5 is known to cause collisions and it is not approved in
				// FIPS mode. From v3.15, we are upgrading the active fingerprint to use sha256 hash algorithm.
				if hex.DecodedLen(len(c.ActiveFingerprint)) == sha256.Size {
					if fingerprint != c.ActiveFingerprint {
						logrus.Error("stored fingerprint does not match provided fingerprint")
						closeTunnel(t)
						return
					}
				} else {
					// check pre-v3.15 fingerprint (md5)
					if s.extractMD5Identity(t) != c.ActiveFingerprint {
						logrus.Error("stored fingerprint does not match provided fingerprint")
						closeTunnel(t)
						return
					}

					// update to v3.15 fingerprint hash (sha256) when matched
					if err := c.updateActiveFingerprint(fingerprint); err != nil {
						logrus.WithError(err).Errorf("failed to update cluster %s stored fingerprint", clusterID)
						closeTunnel(t)
						return
					}

					logrus.Infof("Cluster %s stored fingerprint is successfully updated", clusterID)
				}
			}

			if err := c.assignTunnel(t); err != nil {
				if err == tunnelmgr.ErrTunnelSet {
					logrus.Errorf("opening a second tunnel ID %s rejected", clusterID)
				} else {
					logrus.WithError(err).Errorf("failed to open the tunnel for cluster %s", clusterID)
				}

				if err := t.Close(); err != nil {
					logrus.WithError(err).Errorf("failed closed tunnel after failing to assign it to cluster %s", clusterID)
				}
			}

			logrus.Debugf("Accepted a new tunnel from %s", clusterID)
		}()
	}
}

func closeTunnel(t *tunnel.Tunnel) {
	err := t.Close()
	if err != nil {
		logrus.WithError(err).Error("Could not close tunnel")
	}
}

func (s *Server) extractIdentity(t *tunnel.Tunnel) (clusterID, fingerprint string, certificate *x509.Certificate) {
	switch id := t.Identity().(type) {
	case *x509.Certificate:
		// N.B. By now, we know that we signed this certificate as these checks
		// are performed during TLS handshake. We need to extract the common name
		// and fingerprint of the certificate to check against our internal records
		// We expect to have a cluster registered with this ID and matching fingerprint
		// for the cert.
		clusterID = id.Subject.CommonName
		fingerprint = utils.GenerateFingerprint(id)
		certificate = id
	default:
		logrus.Errorf("unknown tunnel identity type %T", id)
	}
	return
}

func (s *Server) extractMD5Identity(t *tunnel.Tunnel) (fingerprint string) {
	switch id := t.Identity().(type) {
	case *x509.Certificate:
		fingerprint = fmt.Sprintf("%x", md5.Sum(id.Raw))
	default:
		logrus.Errorf("unknown tunnel identity type %T", id)
	}
	return
}

// validateCertificate validates the certificate of the tunnel against the certificate of the
// managed cluster it is connecting to (if any) and returns an error if they don't match or if the
// certificate of the managed cluster is not provided. It is assumed that the certificate PEM
// is a single block.
func validateCertificate(tunnelCert *x509.Certificate, certPEM []byte) error {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		err := errors.New("failed to decode PEM block containing certificate")
		logrus.WithError(err).Error("failed to validate certificate")
		return err
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	if !tunnelCert.Equal(cert) {
		return errors.New("certificates don't match")
	}
	return nil
}

func wrapInMetricsAndLoggingAwareHandler(metricsEnabled bool, logger *accesslog.Logger, delegate http.HandlerFunc) http.HandlerFunc {
	loggingEnabled := logger != nil
	if !metricsEnabled && !loggingEnabled {
		// neither enabled so no need to wrap
		return delegate
	}

	return func(w http.ResponseWriter, r *http.Request) {
		var httpSnoopMetrics httpsnoop.Metrics

		var authToken jwt.JWT
		var authTokenErr error
		if rawAuthToken := authorizationHeaderBearerToken(r); rawAuthToken != "" {
			authToken, authTokenErr = jws.ParseJWT([]byte(rawAuthToken))
		}

		if metricsEnabled {
			metricsEnd := metrics.OnRequestStart(r, authToken)
			defer metricsEnd(&httpSnoopMetrics)
		}

		if loggingEnabled {
			wrappedWriter, loggerEnd := logger.OnRequest(w, r, authToken, authTokenErr)
			defer loggerEnd(&httpSnoopMetrics)

			w = wrappedWriter
		}

		httpSnoopMetrics = httpsnoop.CaptureMetricsFn(w, func(w http.ResponseWriter) {
			delegate(w, r)
		})
	}
}

func wrapInCORSHandler(cors *cors.CORS, delegate http.HandlerFunc) http.HandlerFunc {
	if cors != nil {
		return cors.NewHandlerFunc(delegate)
	}
	return delegate
}

// clusterMuxer is the main handler for all requests coming into voltron. It determines
// if the request should be proxied to a managed cluster, or the local cluster itself and performs
// the necessary authentication and impersonation.
func (s *Server) clusterMuxer(w http.ResponseWriter, r *http.Request) {
	chdr, hasClusterHeader := r.Header[ClusterHeaderFieldCanon]
	isK8sRequest := requestPathMatches(r, s.kubernetesAPITargets)
	shouldUseTunnel := requestPathMatches(r, s.tunnelTargetWhitelist) && hasClusterHeader

	if requestTargetPathMatches(r, s.defaultProxy, s.unauthenticatedTargetPaths) {
		// This request is to a target that can be unauthenticated
		s.defaultProxy.ServeHTTP(w, r)
		return
	}

	// For everything else we authenticate before forwarding on a request

	if len(chdr) > 1 {
		msg := fmt.Sprintf("multiple %q headers", utils.ClusterHeaderField)
		logrus.Errorf("clusterMuxer: %s", msg)
		http.Error(w, msg, 400)
		return
	}

	usr, status, err := s.authenticator.Authenticate(r)
	if err != nil {
		logrus.Errorf("Could not authenticate user from request: %s", err)
		http.Error(w, err.Error(), status)
		return
	}

	// If shouldUseTunnel=true, we do impersonation and the request will be sent to guardian.
	// If isK8sRequest=true, we do impersonation.
	// If neither is true, we proxy the request without impersonation. Authn will also be handled there.
	if (!shouldUseTunnel || !hasClusterHeader) && !isK8sRequest {
		// This is a request for the backend servers in the management cluster, like ui-apis or compliance.
		logrus.Debug("Request is for the management cluster backing services")
		s.defaultProxy.ServeHTTP(w, r)
		return
	}

	// There are two cases where we want to propagate the authenticated user info via impersonation headers:
	// 1. The request is going to a managed cluster, and Guardian has impersonation capabilities.
	// 2. The request is going to the management cluster.
	if s.clusters.voltronCfg.ManagedClusterSupportsImpersonation || !shouldUseTunnel {
		// Don't overwrite impersonation headers set by clients.
		if len(r.Header.Get(authnv1.ImpersonateUserHeader)) == 0 {
			addImpersonationHeaders(r, usr)
		}
	}

	if shouldUseTunnel && !s.clusters.voltronCfg.ManagedClusterSupportsImpersonation {
		// If the request is going to a managed cluster, but the managed cluster does not support impersonation,
		// remove impersonation headers. This isn't strictly necessary - the managed cluster will ignore the headers
		// if they are present - but it's cleaner to remove them.
		logrus.Debug("Removing impersonation headers")
		r.Header.Del(authnv1.ImpersonateUserHeader)
		r.Header.Del(authnv1.ImpersonateGroupHeader)
	}

	// Always remove the auth headers before proxying the request. Management cluster requests will
	// use impersonation, and tunneled requests will either use impersonation or Guardian's AuthN.
	removeAuthHeaders(r)

	// Note, we expect the value passed in the request header field to be the resource
	// name for a ManagedCluster resource (which will be human-friendly and unique)
	clusterID := r.Header.Get(utils.ClusterHeaderField)

	// DefaultClusterID is the name of the management cluster. No tunnel is necessary for
	// requests with this value in the ClusterHeaderField.
	if isK8sRequest && (!hasClusterHeader || clusterID == lmak8s.DefaultCluster) {
		token, err := s.tokenSource.Token()
		var voltronSAToken string
		if err != nil {
			logrus.Errorf("Failed to read the container's JWT from disk, defaulting to the config.BearerToken which" +
				"was read at startup. This token may expire.")
			voltronSAToken = s.config.BearerToken
		} else {
			voltronSAToken = token.AccessToken
		}

		r.Header.Set(authentication.AuthorizationHeader, fmt.Sprintf("Bearer %s", voltronSAToken))
		s.defaultProxy.ServeHTTP(w, r)
		return
	}

	c := s.clusters.get(clusterID)

	if c == nil {
		msg := fmt.Sprintf("Unknown target cluster %q", clusterID)
		logrus.Errorf("clusterMuxer: %s", msg)
		writeHTTPError(w, clusterNotFoundError(clusterID))
		return
	}

	// perform an authorization to make sure this user can get this cluster
	if s.checkManagedClusterAuthorizationBeforeProxy {
		ok, err := s.checkManagedClusterAuthorizer.Authorize(usr, &authorizationv1.ResourceAttributes{
			Verb:     "get",
			Group:    "projectcalico.org",
			Version:  "v3",
			Resource: "managedclusters",
			Name:     clusterID,
		}, nil)
		if err != nil {
			logrus.Errorf("Could not authenticate user for cluster: %s", err)
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if !ok {
			http.Error(w, "not authorized for managed cluster", http.StatusForbidden)
			return
		}
	}

	// We proxy through a secure tunnel, therefore we only enforce https for HTTP/2
	// XXX What if we set http2.Transport.AllowHTTP = true ?
	r.URL.Scheme = "http"
	if r.ProtoMajor == 2 {
		r.URL.Scheme = "https"
	}

	// N.B. Host is only set to make the ReverseProxy happy, DialContext ignores
	// this as the destinatination has been decided by choosing the tunnel.
	r.URL.Host = "voltron-tunnel"
	r.Header.Del(utils.ClusterHeaderField)
	c.ServeHTTP(w, r)
}

// Determine whether or not the given request should use the tunnel proxying
// by comparing its URL path against the provide list of regex expressions
// (representing paths for targets that the request might be going to).
func requestPathMatches(r *http.Request, targetPaths []regexp.Regexp) bool {
	for _, p := range targetPaths {
		if p.MatchString(r.URL.Path) {
			return true
		}
	}
	return false
}

// Determine whether or not the given request should use the tunnel proxying
// by getting the TargetPath the prxy would select for the provided r *http.Request
// and comparing it against the provided list of targetPaths
// (representing paths for targets that the request might be going to).
func requestTargetPathMatches(r *http.Request, prxy *proxy.Proxy, targetPaths []string) bool {
	if prxy == nil {
		return false
	}
	path := prxy.GetTargetPath(r)
	for _, p := range targetPaths {
		if p == path {
			return true
		}
	}
	return false
}

func removeAuthHeaders(r *http.Request) {
	r.Header.Del("Authorization")
	r.Header.Del("Auth")
}

func addImpersonationHeaders(r *http.Request, user user.Info) {
	r.Header.Add(authnv1.ImpersonateUserHeader, user.GetName())
	for _, group := range user.GetGroups() {
		r.Header.Add(authnv1.ImpersonateGroupHeader, group)
	}
	logrus.Debugf("Adding impersonation headers")
}

// WatchK8s starts watching k8s resources, always exits with an error
func (s *Server) WatchK8s() error {
	return s.WatchK8sWithSync(nil)
}

// WatchK8sWithSync is a variant of WatchK8s for testing. Every time a watch
// event is handled its result is posted on the syncC channel
func (s *Server) WatchK8sWithSync(syncC chan<- error) error {
	logrus.Debug("WatchK8sWithSync")
	defer logrus.Debug("WatchK8sWithSync done")

	if s.k8s == nil {
		return errors.New("no k8s interface")
	}

	return s.clusters.watchK8s(s.ctx, syncC)
}

// FlushAccessLogs exposed for testing
func (s *Server) FlushAccessLogs() {
	if s.accessLogger != nil {
		s.accessLogger.Flush()
	}
}

func authorizationHeaderBearerToken(r *http.Request) string {
	if value := r.Header.Get(authorizationHeaderKey); len(value) > 7 && strings.EqualFold(value[0:7], "bearer ") {
		return value[7:]
	}
	return ""
}
