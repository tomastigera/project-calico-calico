// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
	"github.com/coreos/go-semver/semver"
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
	"github.com/projectcalico/calico/voltron/internal/pkg/config"
	"github.com/projectcalico/calico/voltron/internal/pkg/proxy"
	"github.com/projectcalico/calico/voltron/internal/pkg/server/accesslog"
	"github.com/projectcalico/calico/voltron/internal/pkg/server/metrics"
	"github.com/projectcalico/calico/voltron/internal/pkg/utils"
	"github.com/projectcalico/calico/voltron/internal/pkg/utils/cors"
	"github.com/projectcalico/calico/voltron/pkg/tunnel"
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

	// When impersonating a user we use the tigera-manager sa bearer token from this config.
	config        *rest.Config
	authenticator auth.JWTAuth

	authDetailsMap map[string]*proxy.AuthorizationDetails

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

	tunSrv tunnel.Server

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

	// checkManagedClusterAuthorizationBeforeProxy
	checkManagedClusterAuthorizationBeforeProxy bool

	// specific `auth.RBACAuthorizer` for `checkManagedClusterAuthorizationBeforeProxy` which may have caching enabled
	checkManagedClusterAuthorizer auth.RBACAuthorizer

	accessLogger *accesslog.Logger

	cors *cors.CORS

	// The token that Voltron uses has an exp of 1h by default and is periodically refreshed in the rest config
	// BearerTokenFile location by the kubelet (k8s 1.22+). This token source uses client-go's tokenSource.
	tokenSource               oauth2.TokenSource
	waitForStatusManagerClose func()

	impersonationSupported bool
}

// New returns a new Server. k8s may be nil and options must check if it is nil
// or not if they set its user and return an error if it is nil
func New(client ctrlclient.WithWatch, config *rest.Config, vcfg config.Config, authenticator auth.JWTAuth, mcQuerierFactory ManagedClusterQuerierFactory, opts ...Option) (*Server, error) {
	srv := &Server{
		config:                 config,
		authenticator:          authenticator,
		impersonationSupported: vcfg.ManagedClusterSupportsImpersonation,
		clusters: &clusters{
			clusters:        make(map[string]*cluster),
			tenantID:        vcfg.TenantID,
			tenantNamespace: vcfg.TenantNamespace,
			goldmaneEnabled: vcfg.GoldmaneEnabled,
			client:          client,
			// Dummy function that will be overwritten if voltron is accepting
			// managed cluster connections.
			statusUpdateFunc:             func(string, v3.ManagedClusterStatusValue) {},
			managedClusterQuerierFactory: mcQuerierFactory,
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
	tlsConfig, err := makeInnerTLSConfig(vcfg)
	if err != nil {
		return nil, err
	}
	srv.clusters.tlsConfig = tlsConfig

	// Create an HTTP server to handle incoming requests.
	srv.proxyMux = http.NewServeMux()
	srv.proxyMux.HandleFunc("/", wrapInMetricsAndLoggingAwareHandler(vcfg.MetricsEnabled, srv.accessLogger, wrapInCORSHandler(srv.cors, srv.clusterMuxer)))
	srv.proxyMux.HandleFunc("/voltron/api/health", srv.health.apiHandle)

	cfg, err := calicotls.NewTLSConfig()
	if err != nil {
		return nil, err
	}
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
		internalTlsCfg, err := calicotls.NewTLSConfig()
		if err != nil {
			return nil, err
		}
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
		srv.waitForStatusManagerClose = x.WaitForClose
		srv.clusters.clientCertificatePool = srv.tunSrv.GetClientCertificatePool()
	}

	srv.tokenSource = transport.NewCachedFileTokenSource(config.BearerTokenFile)
	return srv, nil
}

func makeInnerTLSConfig(voltronCfg config.Config) (*tls.Config, error) {
	cfg, err := calicotls.NewTLSConfig()
	if err != nil {
		return nil, err
	}
	if voltronCfg.LinseedServerKey != "" && voltronCfg.LinseedServerCert != "" {
		certBytes, err := os.ReadFile(voltronCfg.LinseedServerCert)
		if err != nil {
			return nil, err
		}
		keyBytes, err := os.ReadFile(voltronCfg.LinseedServerKey)
		if err != nil {
			return nil, err
		}
		cert, err := tls.X509KeyPair(certBytes, keyBytes)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = append(cfg.Certificates, cert)
	}

	return cfg, nil
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

	if s.waitForStatusManagerClose != nil {
		s.waitForStatusManagerClose()
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

		c := s.clusters.get(t.ClusterID())
		if c == nil {
			logrus.Errorf("cluster %q does not exist", t.ClusterID())
			_ = t.Close()
			continue
		}

		if err := c.assignTunnel(t); err != nil {
			if errors.Is(err, tunnel.ErrTunnelSet) {
				logrus.Errorf("opening a second tunnel ID %s rejected", t.ClusterID())
			} else {
				logrus.WithError(err).Errorf("failed to open the tunnel for cluster %s", t.ClusterID())
			}

			if err := t.Close(); err != nil {
				logrus.WithError(err).Errorf("failed closed tunnel after failing to assign it to cluster %s", t.ClusterID())
			}
		}

		logrus.Debugf("Accepted a new tunnel from %s", t.ClusterID())
	}
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
	clusterIDs := r.Header.Values(utils.ClusterHeaderField)
	if len(clusterIDs) > 1 {
		msg := fmt.Sprintf("multiple %q headers", utils.ClusterHeaderField)
		logrus.Errorf("clusterMuxer: %s", msg)
		http.Error(w, msg, 400)
		return
	}
	var tunnelClusterID string
	if len(clusterIDs) == 1 {
		if id := clusterIDs[0]; id != lmak8s.DefaultCluster { // the default cluster is not tunneled
			tunnelClusterID = id
		}
	}
	isK8sRequest := requestPathMatches(r, s.kubernetesAPITargets)
	shouldUseTunnel := requestPathMatches(r, s.tunnelTargetWhitelist) && tunnelClusterID != ""

	if requestTargetPathMatches(r, s.defaultProxy, s.unauthenticatedTargetPaths) {
		// This request is to a target that can be unauthenticated
		s.defaultProxy.ServeHTTP(w, r)
		return
	}

	// For everything else we authenticate before forwarding on a request
	usr, status, err := s.authenticator.Authenticate(r)
	if err != nil {
		logrus.Errorf("Could not authenticate user from request: %s", err)
		http.Error(w, err.Error(), status)
		return
	}

	// Perform authorization if an authorizer has been registered for the path.
	authorizationDetails := s.getAuthorizationDetails(r)
	if authorizationDetails != nil && authorizationDetails.FullySet() {
		resAttrs, nonResAttrs, err := authorizationDetails.AttributesFunc(r)
		if err != nil {
			logrus.Errorf("Failed to resolve authorization attributes from request: %s", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		authorized, err := authorizationDetails.Authorizer.Authorize(usr, resAttrs, nonResAttrs)
		if err != nil {
			logrus.Errorf("Failed to authorize user from request: %s", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if !authorized {
			msg := "User was not authorized to perform request at this path"
			logrus.Error(msg)
			http.Error(w, msg, http.StatusUnauthorized)
			return
		}
	}

	// If shouldUseTunnel=true, we do impersonation and the request will be sent to guardian.
	// If isK8sRequest=true, we do impersonation.
	// If neither is true, we proxy the request without impersonation. Authn will also be handled there.
	if !shouldUseTunnel && !isK8sRequest {
		// This is a request for the backend servers in the management cluster, like ui-apis or compliance.
		logrus.Debug("Request is for the management cluster backing services")
		s.defaultProxy.ServeHTTP(w, r)
		return
	}

	// There are two cases where we want to propagate the authenticated user info via impersonation headers:
	// 1. The request is going to a managed cluster, and Guardian has impersonation capabilities.
	// 2. The request is going to the management cluster.
	// 3. The request is from non-cluster hosts using Tigera signed JWT tokens.
	if s.impersonationSupported || !shouldUseTunnel {
		// Don't overwrite impersonation headers set by clients.
		if len(r.Header.Get(authnv1.ImpersonateUserHeader)) == 0 {
			addImpersonationHeaders(r, usr)
		}
	}

	// Always remove the auth headers before proxying the request. Management cluster requests will
	// use impersonation, and tunneled requests will either use impersonation or Guardian's AuthN.
	removeAuthHeaders(r)

	if shouldUseTunnel {
		tunnelCluster := s.clusters.get(tunnelClusterID)

		if tunnelCluster == nil {
			msg := fmt.Sprintf("Unknown target cluster %q", tunnelClusterID)
			logrus.Errorf("clusterMuxer: %s", msg)
			writeHTTPError(w, clusterNotFoundError(tunnelClusterID))
			return
		}

		isOlderCluster := isOlderManagedCluster(tunnelCluster)
		userName := usr.GetName()

		// Strip impersonation headers if the request is destined for a managed cluster and either:
		// - The cluster is a newer version (v3.22+) that uses consolidated Guardian RBAC,
		//   and the request originates from a management cluster backend component
		// - The cluster does not support impersonation at all (e.g., free tier)
		if !isOlderCluster &&
			(strings.HasPrefix(userName, "system:serviceaccount:tigera-") ||
				strings.HasPrefix(userName, "system:serviceaccount:calico-") ||
				strings.HasPrefix(userName, "system:serviceaccount:cc-tenant-")) ||
			!s.impersonationSupported {
			logrus.Debugf("Removing impersonation headers from request (%s)", userName)
			r.Header.Del(authnv1.ImpersonateUserHeader)
			r.Header.Del(authnv1.ImpersonateGroupHeader)
		}

		// TODO: Clean up this logic in v3.25+, since we only support two minor versions back.
		// For older managed clusters that still support impersonation, replace the impersonation header
		// to refer to the older policy recommendation service account.
		// Apply the impersonation header only to non–free-tier clusters that support impersonation;
		// free-tier clusters do not support impersonation.
		if isOlderCluster && s.impersonationSupported {
			switch userName {
			case "system:serviceaccount:calico-system:tigera-policy-recommendation":
				r.Header.Set(authnv1.ImpersonateUserHeader, "system:serviceaccount:tigera-policy-recommendation:tigera-policy-recommendation")
				r.Header.Add(authnv1.ImpersonateGroupHeader, "system:serviceaccount:tigera-policy-recommendation")
			case "system:serviceaccount:calico-system:calico-manager":
				r.Header.Set(authnv1.ImpersonateUserHeader, "system:serviceaccount:tigera-manager:tigera-manager")
				r.Header.Add(authnv1.ImpersonateGroupHeader, "system:serviceaccount:tigera-manager")
			}
		}

		// perform an authorization to make sure this user can get this cluster
		if s.checkManagedClusterAuthorizationBeforeProxy {
			ok, err := s.checkManagedClusterAuthorizer.Authorize(usr, &authorizationv1.ResourceAttributes{
				Verb:     "get",
				Group:    "projectcalico.org",
				Version:  "v3",
				Resource: "managedclusters",
				Name:     tunnelClusterID,
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

		// Older managed clusters still run the API server in the "tigera-system" namespace.
		// To support UI requests to the queryserver, we must point to the correct service in the old namespace.
		// TODO: Remove this in v3.24 or v3.25. We only support up to two minor version skews.
		if strings.Contains(r.URL.Path, "/namespaces/calico-system/services/https:calico-api") {
			if isOlderCluster {
				logrus.Debugf("Redirecting request path for older managed cluster: %s", tunnelClusterID)
				re := regexp.MustCompile(`/namespaces/calico-system/services/https:calico-api`)
				r.URL.Path = re.ReplaceAllString(r.URL.Path, `/namespaces/tigera-system/services/https:tigera-api`)
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
		tunnelCluster.ServeHTTP(w, r)

	} else { // must be a local K8S API request

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
	}
}

func isOlderManagedCluster(cluster *cluster) bool {
	if len(cluster.version) == 0 {
		logrus.Debugf("ManagedCluster %s has no version info; treating as older cluster", cluster.ID)
		return true
	}
	// ignore the prerelease version for semver compare
	version := strings.Split(cluster.version, "-")
	if len(version) == 0 {
		logrus.Debugf("Managed cluster version length is zero for cluster ID: %s. Version info: %s", cluster.ID, cluster.version)
		// Treat it as a new cluster for now; this behavior may change in the future.
		return false
	}

	clusterVersion, err := semver.NewVersion(strings.TrimPrefix(version[0], "v"))
	if err != nil {
		logrus.Debugf("Failed to parse semantic version for cluster ID: %s. Version info: %s", cluster.ID, cluster.version)
		// Treat it as a new cluster for now; this behavior may change in the future.
		return false
	}

	featureVersion, _ := semver.NewVersion("3.22.0")
	return clusterVersion.LessThan(*featureVersion)
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
	return slices.Contains(targetPaths, path)
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
	logrus.Debug("WatchK8sWithSync")
	defer logrus.Debug("WatchK8sWithSync done")

	if s.clusters.client == nil {
		return errors.New("no k8s interface")
	}

	return s.clusters.watchK8s(s.ctx)
}

// FlushAccessLogs exposed for testing
func (s *Server) FlushAccessLogs() {
	if s.accessLogger != nil {
		s.accessLogger.Flush()
	}
}

func (s *Server) getAuthorizationDetails(r *http.Request) *proxy.AuthorizationDetails {
	if s.authDetailsMap == nil || s.defaultProxy == nil {
		return nil
	}

	return s.authDetailsMap[s.defaultProxy.GetTargetPath(r)]
}

func authorizationHeaderBearerToken(r *http.Request) string {
	if value := r.Header.Get(authorizationHeaderKey); len(value) > 7 && strings.EqualFold(value[0:7], "bearer ") {
		return value[7:]
	}
	return ""
}
