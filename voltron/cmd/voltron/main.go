// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/lma/pkg/auth"
	"github.com/projectcalico/calico/lma/pkg/cache"
	"github.com/projectcalico/calico/voltron/internal/pkg/bootstrap"
	"github.com/projectcalico/calico/voltron/internal/pkg/config"
	"github.com/projectcalico/calico/voltron/internal/pkg/proxy"
	"github.com/projectcalico/calico/voltron/internal/pkg/regex"
	"github.com/projectcalico/calico/voltron/internal/pkg/server"
	"github.com/projectcalico/calico/voltron/internal/pkg/server/accesslog"
	"github.com/projectcalico/calico/voltron/internal/pkg/utils"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())

	cfg, err := config.Parse()
	if err != nil {
		log.WithError(err).Fatal("Failed to load voltron configuration.")
	}

	bootstrap.ConfigureLogging(cfg.LogLevel)
	log.Infof("Starting %s with %s", config.EnvConfigPrefix, cfg)

	if cfg.PProf {
		go func() {
			err := bootstrap.StartPprof()
			log.WithError(err).Fatal("PProf exited.")
		}()
	}

	addr := fmt.Sprintf("%v:%v", cfg.Host, cfg.Port)

	kubernetesAPITargets, err := regex.CompileRegexStrings([]string{
		`^/api/?`,
		`^/apis/?`,
	})
	if err != nil {
		log.WithError(err).Fatalf("Failed to parse tunnel target whitelist.")
	}

	// Paths served by management cluster backends rather than the k8s API server.
	// AuthorizationReviews are handled by ui-apis, which performs the managed
	// cluster RBAC calculation itself. This must be set unconditionally (not just
	// in MCM mode) because ui-apis serves this endpoint in standalone as well.
	managementBackendTargets, err := regex.CompileRegexStrings([]string{
		`^/apis/projectcalico.org/v3/authorizationreviews$`,
	})
	if err != nil {
		log.WithError(err).Fatalf("Failed to parse management backend targets.")
	}

	opts := []server.Option{
		server.WithDefaultAddr(addr),
		server.WithInternalAddr(fmt.Sprintf("%v:%v", cfg.Host, cfg.InternalPort)),
		server.WithKeepAliveSettings(cfg.KeepAliveEnable, cfg.KeepAliveInterval),
		server.WithExternalCredFiles(cfg.HTTPSCert, cfg.HTTPSKey),
		server.WithKubernetesAPITargets(kubernetesAPITargets),
		server.WithManagementBackendTargets(managementBackendTargets),
		server.WithInternalMetricsEndpointEnabled(cfg.MetricsEnabled),
	}

	k8sConfig := bootstrap.NewRestConfig(cfg.K8sConfigPath)
	if cfg.K8sClientQPS > 0 {
		k8sConfig.QPS = cfg.K8sClientQPS
	}
	if cfg.K8sClientBurst > 0 {
		k8sConfig.Burst = cfg.K8sClientBurst
	}

	k8s := bootstrap.NewK8sClientWithConfig(k8sConfig)

	var client ctrlclient.WithWatch
	scheme := runtime.NewScheme()
	if err = v3.AddToScheme(scheme); err != nil {
		log.WithError(err).Fatal("Failed to configure controller runtime client")
	}
	client, err = ctrlclient.NewWithWatch(k8sConfig, ctrlclient.Options{Scheme: scheme})
	if err != nil {
		log.WithError(err).Fatal("Failed to configure controller runtime client with watch")
	}

	if cfg.EnableMultiClusterManagement {
		// the cert used to sign guardian certs is required no matter what to verify inbound connections
		tunnelSigningX509Cert, err := utils.LoadX509Cert(cfg.TunnelCert)
		if err != nil {
			log.WithError(err).Fatal("couldn't load tunnel X509 key pair")
		}

		if cfg.UseHTTPSCertOnTunnel {
			// if a tunnelCert and tunnelKey was specified, use those for the voltron server cert.
			// this uses a different certificate chain for guardian and voltron, but allows use of
			// a separate, public CA to verify voltron certificates instead of relying on self-signed certs.
			tlsCert, err := tls.LoadX509KeyPair(cfg.HTTPSCert, cfg.HTTPSKey)
			if err != nil {
				log.WithError(err).Fatal("couldn't load tunnel X509 key pair")
			}

			opts = append(opts, server.WithTunnelCert(tlsCert))
		} else if cfg.TunnelKey != "" {
			// otherwise, use the signing chain
			tlsCert, err := tls.LoadX509KeyPair(cfg.TunnelCert, cfg.TunnelKey)
			if err != nil {
				log.WithError(err).Fatal("couldn't load tunnel X509 key pair")
			}
			opts = append(opts, server.WithTunnelCert(tlsCert))
		} else {
			log.Fatal("must specify either a tunnel cert & key or a signing key")
		}

		// With the introduction of Centralized ElasticSearch for Multi-cluster Management,
		// certain categories of requests related to a specific cluster will be proxied
		// within the Management cluster (instead of being sent down a secure tunnel to the
		// actual Managed cluster).
		// In the setup below, we create a list of URI paths that should still go through the
		// tunnel down to a Managed cluster. Requests that do not match this whitelist, will
		// instead be proxied locally (within the Management cluster itself using the
		// defaultProxy that is set up later on in this function). The whitelist is used
		// within the server's clusterMuxer handler.
		tunnelTargetWhitelist, err := regex.CompileRegexStrings([]string{
			`^/api/?`,
			`^/apis/?`,
			`^/packet-capture/?`,
			`^/goldmane.Statistics/List?`,
		})
		if err != nil {
			log.WithError(err).Fatalf("Failed to parse tunnel target whitelist.")
		}

		kibanaURL, err := url.Parse(cfg.KibanaEndpoint)
		if err != nil {
			log.WithError(err).Fatalf("failed to parse Kibana endpoint %s", cfg.KibanaEndpoint)
		}

		sniServiceMap := map[string]string{
			kibanaURL.Hostname(): kibanaURL.Host, // Host includes the port, Hostname does not
		}

		if cfg.EnableImageAssurance && cfg.ImageAssuranceEndpoint != "" && cfg.ImageAssuranceCABundlePath != "" {
			bastURL, err := url.Parse(cfg.ImageAssuranceEndpoint)
			if err != nil {
				log.WithError(err).Fatalf("failed to parse Bast API endpoint %s", cfg.ImageAssuranceEndpoint)
			}

			sniServiceMap[bastURL.Hostname()] = bastURL.Host
		}

		if cfg.UpstreamTunnelTLSPassThroughRoutesPath != nil {
			for _, route := range loadTLSPassThroughRoutesFromFile(*cfg.UpstreamTunnelTLSPassThroughRoutesPath) {
				sniServiceMap[route.ServerName] = route.Destination
			}
		}

		log.WithField("map", sniServiceMap).Info("SNI map")

		// Create a proxy to use as the "inner proxy" - handling connections _from_ managed clusters to
		// services in the management cluster handled directly by Voltron.
		targetList := []bootstrap.Target{
			{
				// All Linseed APIs start with this prefix. In practice, only Linseed connections should ever
				// hit this handler anyway because we use the server field in the TLS header to direct connections
				// to this handler.
				Path:           "/api/v1/",
				Dest:           cfg.LinseedEndpoint,
				CABundlePath:   cfg.LinseedCABundlePath,
				ClientKeyPath:  cfg.InternalHTTPSKey,
				ClientCertPath: cfg.InternalHTTPSCert,
			},
		}

		if cfg.UpstreamTunnelTLSTerminatedRoutesPath != nil {
			targetList = append(targetList, loadTLSTerminatedRoutesFromFile(*cfg.UpstreamTunnelTLSTerminatedRoutesPath)...)
		}

		targets, err := bootstrap.ProxyTargets(targetList)
		if err != nil {
			log.WithError(err).Fatal("failed to parse Linseed proxy targets")
		}

		innerProxy, err := proxy.New(targets)
		if err != nil {
			log.WithError(err).Fatalf("failed to create proxier for tunneled connections from a managed cluster")
		}

		opts = append(opts,
			server.WithInternalCredFiles(cfg.InternalHTTPSCert, cfg.InternalHTTPSKey),
			server.WithTunnelSigningCreds(tunnelSigningX509Cert),
			server.WithForwardingEnabled(cfg.ForwardingEnabled),
			server.WithDefaultForwardServer(cfg.DefaultForwardServer, cfg.DefaultForwardDialRetryAttempts, cfg.DefaultForwardDialInterval),
			server.WithTunnelTargetWhitelist(tunnelTargetWhitelist),
			server.WithSNIServiceMap(sniServiceMap),
			server.WithCheckManagedClusterAuthorizationBeforeProxy(
				cfg.CheckManagedClusterAuthorizationBeforeProxy,
				cfg.CheckManagedClusterAuthorizationCacheTTL,
				auth.NewNamespacedRBACAuthorizer(k8s, cfg.TenantNamespace),
			),
			server.WithTunnelInnerProxy(innerProxy),
		)
	}

	if cfg.HTTPAccessLoggingEnabled {
		logOpts := []accesslog.Option{
			accesslog.WithRequestHeader(server.ClusterHeaderFieldCanon, "xClusterID"),
			accesslog.WithRequestHeader("User-Agent", "userAgent"),
			accesslog.WithRequestHeader("Impersonate-User", "impersonateUser"),
			accesslog.WithRequestHeader("Impersonate-Group", "impersonateGroup"),
			accesslog.WithErrorResponseBodyCaptureSize(250),
		}

		if cfg.OIDCAuthEnabled {
			logOpts = append(logOpts, accesslog.WithStandardJWTClaims())
			logOpts = append(logOpts, accesslog.WithStringJWTClaim(cfg.OIDCAuthUsernameClaim, "username"))
			if cfg.HTTPAccessLoggingIncludeAuthGroups {
				logOpts = append(logOpts, accesslog.WithStringArrayJWTClaim(cfg.OIDCAuthGroupsClaim, "groups"))
			}
			if cfg.CalicoCloudRequireTenantClaim || cfg.RequireTenantClaim {
				logOpts = append(logOpts, accesslog.WithStringJWTClaim(server.CalicoCloudTenantIDClaimName, "ccTenantID"))
			}
		}

		opts = append(opts, server.WithHTTPAccessLogging(logOpts...))
	}

	// Create a shared authorizer for targets to use.
	var authorizer auth.RBACAuthorizer
	if cfg.TargetAuthorizerCacheTTL > 0 {
		authCache, err := cache.NewExpiring[string, bool](cache.ExpiringConfig{
			Context: ctx,
			Name:    "target-authorizer",
			TTL:     cfg.TargetAuthorizerCacheTTL,
		})
		if err != nil {
			log.WithError(err).Panic("Unable to create target authorizer")
		}
		authorizer = auth.NewCachingAuthorizer(authCache, auth.NewNamespacedRBACAuthorizer(k8s, cfg.TenantNamespace))
	}

	targetList := bootstrap.Targets{
		{
			Path:         "/api/",
			Dest:         cfg.K8sEndpoint,
			CABundlePath: "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
		},
		{
			// Route the legacy CRD-style AuthorizationReview path to ui-apis,
			// which now serves this endpoint directly instead of the API server.
			Path:             "/apis/projectcalico.org/v3/authorizationreviews",
			Dest:             cfg.UIBackendEndpoint,
			PathRegexp:       []byte("^/apis/projectcalico.org/v3/authorizationreviews$"),
			PathReplace:      []byte("/authorizationreviews"),
			AllowInsecureTLS: true,
		},
		{
			Path:         "/apis/",
			Dest:         cfg.K8sEndpoint,
			CABundlePath: "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
		},
		{
			Path:             "/ui-apis/",
			Dest:             cfg.UIBackendEndpoint,
			PathRegexp:       []byte("^/ui-apis/?"),
			PathReplace:      []byte("/"),
			AllowInsecureTLS: true,
		},
		{
			Path:             "/ui-apis/version",
			Dest:             cfg.UIBackendEndpoint,
			PathRegexp:       []byte("^/ui-apis/version$"),
			PathReplace:      []byte("/version"),
			AllowInsecureTLS: true,
			Unauthenticated:  true,
		},
		{
			// Legacy route kept for backwards compatibility with older UI versions.
			Path:             "/tigera-elasticsearch/",
			Dest:             cfg.UIBackendEndpoint,
			PathRegexp:       []byte("^/tigera-elasticsearch/?"),
			PathReplace:      []byte("/"),
			AllowInsecureTLS: true,
		},
		{
			Path:             "/tigera-elasticsearch/version",
			Dest:             cfg.UIBackendEndpoint,
			PathRegexp:       []byte("^/tigera-elasticsearch/version$"),
			PathReplace:      []byte("/version"),
			AllowInsecureTLS: true,
			Unauthenticated:  true,
		},
		{
			Path:         "/packet-capture/",
			Dest:         cfg.PacketCaptureEndpoint,
			PathRegexp:   []byte("^/packet-capture/?"),
			PathReplace:  []byte("/"),
			CABundlePath: cfg.PacketCaptureCABundlePath,
		},
		{
			Path:         cfg.PrometheusPath,
			Dest:         cfg.PrometheusEndpoint,
			PathRegexp:   fmt.Appendf(nil, "^%v/?", cfg.PrometheusPath),
			PathReplace:  []byte("/"),
			CABundlePath: cfg.PrometheusCABundlePath,
		},
		{
			Path:         cfg.QueryserverPath,
			Dest:         cfg.QueryserverEndpoint,
			PathRegexp:   fmt.Appendf(nil, "^%v/?", cfg.QueryserverPath),
			PathReplace:  []byte("/"),
			CABundlePath: cfg.QueryserverCABundlePath,
		},
		{
			Path:         cfg.KibanaBasePath,
			Dest:         cfg.KibanaEndpoint,
			CABundlePath: cfg.KibanaCABundlePath,
			// We use special token authentication with Kibana so it doesn't need to be
			// authenticated.
			Unauthenticated: true,
		},
		{
			Path:             "/",
			Dest:             cfg.NginxEndpoint,
			AllowInsecureTLS: true,
			// Need this unauthenticated so a browser can download the manager UI webcode.
			Unauthenticated: true,
		},
	}

	if cfg.EnterpriseDashboardEndpoint != "" {
		targetList = append(targetList, bootstrap.Target{
			Dest:             cfg.EnterpriseDashboardEndpoint,
			Path:             fmt.Sprintf("%s/", cfg.EnterpriseDashboardBasePath),
			PathRegexp:       fmt.Appendf(nil, "^%s/?", cfg.EnterpriseDashboardBasePath),
			PathReplace:      []byte("/api/"),
			AllowInsecureTLS: true,
		})
	}

	if cfg.GoldmaneEnabled {
		// We need to add a Target to the default proxy so that these requests don't fallthrough to
		// the default "/" target.
		targetList = append(targetList, bootstrap.Target{
			Path:         "/goldmane.Statistics/List",
			Dest:         cfg.GoldmaneEndpoint,
			CABundlePath: cfg.GoldmaneCABundlePath,
		})
	}

	if cfg.EnableCompliance {
		targetList = append(targetList, bootstrap.Target{
			Path:             "/compliance/",
			Dest:             cfg.ComplianceEndpoint,
			CABundlePath:     cfg.ComplianceCABundlePath,
			AllowInsecureTLS: cfg.ComplianceInsecureTLS,
		})
	}

	if cfg.EnableImageAssurance && cfg.ImageAssuranceEndpoint != "" && cfg.ImageAssuranceCABundlePath != "" {
		targetList = append(targetList, bootstrap.Target{
			Path:         "/bast/",
			Dest:         cfg.ImageAssuranceEndpoint,
			PathRegexp:   []byte("^/bast/?"),
			PathReplace:  []byte("/"),
			CABundlePath: cfg.ImageAssuranceCABundlePath,
		})
	}

	if cfg.EnableCalicoCloudRbacApi && cfg.CalicoCloudRbacApiEndpoint != "" && cfg.CalicoCloudRbacApiCABundlePath != "" {
		targetList = append(targetList, bootstrap.Target{
			Path:         "/cloud-rbac/",
			Dest:         cfg.CalicoCloudRbacApiEndpoint,
			PathRegexp:   []byte("^/cloud-rbac/?"),
			PathReplace:  []byte("/"),
			CABundlePath: cfg.CalicoCloudRbacApiCABundlePath,
		})
	}

	if cfg.EnableNonclusterHost {
		targetList = append(targetList, bootstrap.Target{
			Path:           "/ingestion/api/v1/",
			PathRegexp:     []byte("^/ingestion/api/v1/flows/logs/bulk"),
			PathReplace:    []byte("/non-cluster-flows"),
			Dest:           cfg.FluentdHTTPPath,
			CABundlePath:   cfg.FluentdCABundlePath,
			ClientKeyPath:  cfg.InternalHTTPSKey,
			ClientCertPath: cfg.InternalHTTPSCert,
			Authorizer:     authorizer,
			AuthorizationAttributesFunc: func(request *http.Request) (*authzv1.ResourceAttributes, *authzv1.NonResourceAttributes, error) {
				return &authzv1.ResourceAttributes{
					Verb:     "create",
					Group:    "linseed.tigera.io",
					Resource: "flowlogs",
				}, nil, nil
			},
		})
	}

	if cfg.CalicoCloudCorsHost != "" {
		// pass prometheus path as a path to ignore because prometheus already sets cors headers in responses.
		opts = append(opts, server.WithCalicoCloudCORS(cfg.CalicoCloudCorsHost, cfg.PrometheusPath))
	}

	var jwtAuthOpts []auth.JWTAuthOption
	if cfg.OIDCAuthEnabled {
		// If dex is enabled we need to add the CA Bundle, otherwise the default trusted certs from the image will
		// suffice.
		if cfg.DexEnabled {
			targetList = append(targetList, bootstrap.Target{
				Path:         cfg.DexBasePath,
				Dest:         cfg.DexURL,
				CABundlePath: cfg.DexCABundlePath,
				// Dex endpoints setup auth tokens, so we can't authenticate access.
				Unauthenticated: true,
			})
		}

		authOpts := []auth.DexOption{
			auth.WithGroupsClaim(cfg.OIDCAuthGroupsClaim),
			auth.WithJWKSURL(cfg.OIDCAuthJWKSURL),
			auth.WithUsernamePrefix(cfg.OIDCAuthUsernamePrefix),
			auth.WithGroupsPrefix(cfg.OIDCAuthGroupsPrefix),
		}
		if cfg.CalicoCloudRequireTenantClaim || cfg.RequireTenantClaim {
			// CALICO_CLOUD_TENANT_CLAIM is deprecated in favour of TENANT_CLAIM
			// We will read both set of environment variables for a grace period
			if cfg.TenantClaim != "" {
				authOpts = append(authOpts, auth.WithCalicoCloudTenantClaim(cfg.TenantClaim))
			} else if cfg.CalicoCloudTenantClaim != "" {
				// Fallback using deprecated values in case the new ones are not set
				authOpts = append(authOpts, auth.WithCalicoCloudTenantClaim(cfg.CalicoCloudTenantClaim))
			} else {
				log.Panic("Tenant ID not specified")
			}
		}

		oidcAuth, err := auth.NewDexAuthenticator(
			cfg.OIDCAuthIssuer,
			cfg.OIDCAuthClientID,
			cfg.OIDCAuthUsernameClaim,
			authOpts...)
		if err != nil {
			log.WithError(err).Panic("Unable to create dex authenticator")
		}

		jwtAuthOpts = append(jwtAuthOpts, auth.WithAuthenticator(cfg.OIDCAuthIssuer, oidcAuth))
	}

	jwtAuthOpts = append(jwtAuthOpts,
		auth.WithTokenReviewCacheTTL(ctx, cfg.OIDCTokenReviewCacheTTL),
		auth.WithAuthzCacheTTL(ctx, cfg.LMAAuthorizationCacheTTL),
		auth.WithTigeraIssuerPublicKey(cfg.TigeraIssuerCABundlePath),
	)

	authn, err := auth.NewJWTAuth(k8sConfig, k8s, jwtAuthOpts...)
	if err != nil {
		log.Fatal("Unable to create authenticator", err)
	}

	if cfg.UITlsTerminatedRoutesPath != nil {
		targetList = append(targetList, loadTLSTerminatedRoutesFromFile(*cfg.UITlsTerminatedRoutesPath)...)
	}

	opts = append(opts, server.WithUnauthenticatedTargets(targetList.UnauthenticatedPaths()))

	targets, err := bootstrap.ProxyTargets(targetList)
	if err != nil {
		log.WithError(err).Fatal("Failed to parse default proxy targets.")
	}

	defaultProxy, err := proxy.New(targets)
	if err != nil {
		log.WithError(err).Fatalf("Failed to create a default k8s proxy.")
	}
	opts = append(opts, server.WithDefaultProxy(defaultProxy))

	authorizationDetailsByPath := bootstrap.AuthorizationDetailsByPath(targetList)
	opts = append(opts, server.WithAuthAttributesMap(authorizationDetailsByPath))

	srv, err := server.New(
		client,
		k8sConfig,
		*cfg,
		authn,
		&server.DefaultManagedClusterQuerierFactory{},
		opts...,
	)
	if err != nil {
		log.WithError(err).Fatal("Failed to create server.")
	}

	if cfg.EnableMultiClusterManagement {
		lisTun, err := net.Listen("tcp", fmt.Sprintf("%s:%d", cfg.TunnelHost, cfg.TunnelPort))
		if err != nil {
			log.WithError(err).Fatal("Failed to create tunnel listener.")
		}

		go func() {
			err := srv.ServeTunnelsTLS(lisTun)
			log.WithError(err).Fatal("Tunnel server exited.")
		}()

		go func() {
			err := srv.WatchK8s()
			log.WithError(err).Fatal("K8s watcher exited.")
		}()

		log.Infof("Voltron listens for tunnels at %s", lisTun.Addr().String())
	}

	go func() {
		if err := srv.ListenAndServeInternalHTTPS(); err != nil {
			log.WithError(err).Fatal("internal http server exited.")
		}
	}()

	log.Infof("Voltron listens for HTTP request at %s", addr)
	if err := srv.ListenAndServeHTTPS(); err != nil {
		cancel()
		log.Fatal(err)
	}
}

func loadTLSTerminatedRoutesFromFile(filePath string) []bootstrap.Target {
	log.Infof("Loading tls terminated routes from %s.", filePath)

	routes, err := bootstrap.TLSTerminatedRoutesFromFile(filePath)
	if err != nil {
		log.WithError(err).Fatalf("Failed to load routes from file %s.", filePath)
	}

	log.WithField("routes", routes).Infof("Loaded %d tls terminated routes from file", len(routes))

	return routes
}

func loadTLSPassThroughRoutesFromFile(filePath string) []bootstrap.TLSPassThroughRoute {
	log.Infof("Loading tls pass through routes from %s.", filePath)

	routes, err := bootstrap.TLSPassThroughRoutesFromFile(filePath)
	if err != nil {
		log.WithError(err).Fatalf("Failed to load tunnel pass through routes from %s", filePath)
	}

	log.WithField("routes", routes).Infof("Loaded %d tls passthrough routes from file", len(routes))

	return routes
}
