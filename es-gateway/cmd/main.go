// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/es-gateway/pkg/cache"
	"github.com/projectcalico/calico/es-gateway/pkg/clients/elastic"
	"github.com/projectcalico/calico/es-gateway/pkg/clients/kibana"
	"github.com/projectcalico/calico/es-gateway/pkg/clients/kubernetes"
	"github.com/projectcalico/calico/es-gateway/pkg/config"
	"github.com/projectcalico/calico/es-gateway/pkg/metrics"
	"github.com/projectcalico/calico/es-gateway/pkg/middlewares"
	"github.com/projectcalico/calico/es-gateway/pkg/proxy"
	"github.com/projectcalico/calico/es-gateway/pkg/server"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

var (
	versionFlag    = flag.Bool("version", false, "Print version information")
	challengerFlag = flag.Bool("run-as-challenger", false, "Run as a traffic interceptor between Kibana and Elasticsearch")

	// Configuration object for ES Gateway server.
	cfg *config.Config

	// Catch-all Route for Elasticsearch and Kibana.
	elasticCatchAllRoute, kibanaCatchAllRoute *proxy.Route
)

// Initialize ES Gateway configuration.
func init() {
	// Parse all command-line flags.
	flag.Parse()

	// For --version use case (display version information and exit program).
	if *versionFlag {
		buildinfo.PrintVersion()
		os.Exit(0)
	}

	cfg = &config.Config{}
	if err := envconfig.Process(config.EnvConfigPrefix, cfg); err != nil {
		log.WithError(err).Warn("failed to initialize environment variables")
		log.Fatal(err)
	}

	// Setup logging. Default to WARN log level.
	cfg.SetupLogging()

	// Print out configuration (minus sensitive fields)
	printCfg := &config.Config{}
	*printCfg = *cfg
	printCfg.ElasticPassword = "" // wipe out sensitive field

	log.Infof("Starting %s with %s", config.EnvConfigPrefix, printCfg)

	if !*challengerFlag {
		if len(cfg.ElasticCatchAllRoute) > 0 {
			// Catch-all route should ...
			elasticCatchAllRoute = &proxy.Route{
				Name:                          "es-catch-all",
				Path:                          cfg.ElasticCatchAllRoute,
				IsPathPrefix:                  true,       // ... always be a prefix route.
				HTTPMethods:                   []string{}, // ... not filter on HTTP methods.
				RequireAuth:                   true,
				RejectUnacceptableContentType: true,
			}
		}

		if len(cfg.KibanaCatchAllRoute) > 0 {
			// Catch-all route should ...
			kibanaCatchAllRoute = &proxy.Route{
				Name:         "kb-catch-all",
				Path:         cfg.KibanaCatchAllRoute,
				IsPathPrefix: true,       // ... always be a prefix route.
				HTTPMethods:  []string{}, // ... not filter on HTTP methods.
				RequireAuth:  false,
			}
		}

		if len(cfg.KibanaEndpoint) == 0 {
			log.Fatal("Kibana endpoint cannot be empty")
		}

		if len(cfg.ElasticUsername) == 0 || len(cfg.ElasticPassword) == 0 {
			log.Fatal("Elastic credentials cannot be empty")
		}
	}

	if len(cfg.ElasticEndpoint) == 0 {
		log.Fatal("Elastic endpoint cannot be empty")
	}
}

// Start up HTTPS server for ES Gateway.
func main() {
	if *challengerFlag {
		runChallenger()
	} else {
		runESGateway()
	}
}

func runESGateway() {
	addr := fmt.Sprintf("%v:%v", cfg.Host, cfg.Port)

	// Create Kibana target that will be used to configure all routing to Kibana target.
	kibanaTarget, err := proxy.CreateTarget(
		kibanaCatchAllRoute,
		config.KibanaRoutes,
		cfg.KibanaEndpoint,
		cfg.KibanaCABundlePath,
		cfg.KibanaClientCertPath,
		cfg.KibanaClientKeyPath,
		cfg.EnableKibanaMutualTLS,
		false,
	)
	if err != nil {
		log.WithError(err).Fatal("failed to configure Kibana target for ES Gateway.")
	}

	// Create Elasticsearch target that will be used to configure all routing to ES target.
	esTarget, err := proxy.CreateTarget(
		elasticCatchAllRoute,
		config.ElasticsearchRoutes,
		cfg.ElasticEndpoint,
		cfg.ElasticCABundlePath,
		cfg.ElasticClientCertPath,
		cfg.ElasticClientKeyPath,
		cfg.EnableElasticMutualTLS,
		false,
	)
	if err != nil {
		log.WithError(err).Fatal("failed to configure ES target for ES Gateway.")
	}

	// Create client for Elasticsearch API calls.
	esClient, err := elastic.NewClient(
		cfg.ElasticEndpoint,
		cfg.ElasticUsername,
		cfg.ElasticPassword,
		cfg.ElasticCABundlePath,
		cfg.ElasticClientCertPath,
		cfg.ElasticClientKeyPath,
		cfg.EnableElasticMutualTLS,
	)
	if err != nil {
		log.WithError(err).Fatal("failed to configure ES client for ES Gateway.")
	}

	// Create client for Kibana API calls.
	kbClient, err := kibana.NewClient(
		cfg.KibanaEndpoint,
		cfg.ElasticUsername,
		cfg.ElasticPassword,
		cfg.KibanaCABundlePath,
		cfg.KibanaClientCertPath,
		cfg.KibanaClientKeyPath,
		cfg.EnableKibanaMutualTLS,
	)
	if err != nil {
		log.WithError(err).Fatal("failed to configure Kibana client for ES Gateway.")
	}

	// Create client for Kube API calls.
	k8sClient, err := kubernetes.NewClient(cfg.K8sConfigPath)
	if err != nil {
		log.WithError(err).Fatal("failed to configure Kibana client for ES Gateway.")
	}

	ctx, cancel := context.WithCancel(context.Background())
	// -----------------------------------------------------------------------------------------------------
	// Load all k8s secrets required for authN and credential swapping and keep it in sync.
	// -----------------------------------------------------------------------------------------------------
	secretCache, err := cache.NewSecretCache(ctx, k8sClient)
	if err != nil {
		log.Fatal(err)
	}

	opts := []server.Option{
		server.WithAddr(addr),
		server.WithCancelableContext(ctx, cancel),
		server.WithESTarget(esTarget),
		server.WithKibanaTarget(kibanaTarget),
		server.WithInternalTLSFiles(cfg.HTTPSCert, cfg.HTTPSKey),
		server.WithESClient(esClient),
		server.WithKibanaClient(kbClient),
		server.WithK8sClient(k8sClient),
		server.WithAdminUser(cfg.ElasticUsername, cfg.ElasticPassword),
		server.WithSecretCache(secretCache),
		server.WithMiddlewareMap(middlewares.GetHandlerMap(secretCache)),
	}

	var collector metrics.Collector

	if cfg.MetricsEnabled {
		log.Debugf("starting a metrics server on port %v", cfg.MetricsPort)
		collector, err = metrics.NewCollector()
		if err != nil {
			log.Fatal(err)
		}
		opts = append(opts, server.WithCollector(collector))
	}

	if cfg.ILMDummyRouteEnabled {
		log.Debugf("ElasticSearch ILM dummy endpoint is enabled, PUTs or POSTs to ILM will be ignored")
		opts = append(opts, server.WithILMDummyRoutes(config.DummyRoutes))
	}

	srv, err := server.New(opts...)
	if err != nil {
		log.WithError(err).Fatal("failed to create ES Gateway server.")
	}

	if cfg.MetricsEnabled {
		metricsAddr := fmt.Sprintf("%v:%v", cfg.Host, cfg.MetricsPort)
		go func() {
			log.Infof("ES Gateway listening for metrics requests at %s", metricsAddr)
			log.Fatal(collector.Serve(metricsAddr))
		}()
	}

	log.Infof("ES Gateway listening for HTTPS requests at %s", addr)
	log.Fatal(srv.ListenAndServeHTTPS())
}

func runChallenger() {
	challengerAddr := fmt.Sprintf("%v:%v", cfg.Host, cfg.ChallengerPort)
	challengerRoutes := proxy.Routes{
		proxy.Route{
			Name:        "kb-all",
			Path:        "/",
			HTTPMethods: []string{"POST", "PUT", "DELETE", "GET", "OPTIONS", "PATCH"},
		},
	}
	challengerCatchAllRoute := &proxy.Route{
		Name:           "kb-catch-all",
		Path:           cfg.KibanaCatchAllRoute,
		IsPathPrefix:   true,       // ... always be a prefix route.
		HTTPMethods:    []string{}, // ... not filter on HTTP methods.
		EnforceTenancy: true,
	}
	// Create Challenger target that will be used to configure all routing to Elasticsearch.
	challengerTarget, err := proxy.CreateTarget(
		challengerCatchAllRoute,
		challengerRoutes,
		cfg.ElasticEndpoint,
		cfg.ElasticCABundlePath,
		cfg.ElasticClientCertPath,
		cfg.ElasticClientKeyPath,
		cfg.EnableElasticMutualTLS,
		false,
	)
	if err != nil {
		log.WithError(err).Fatal("failed to create Challenger target.")
	}
	if cfg.TenantID == "" {
		log.Fatal("Missing Tenant ID configuration")
	}
	challengerOpts := []server.Option{
		server.WithAddr(challengerAddr),
		server.WithKibanaTarget(challengerTarget),
		server.WithMiddlewareMap(middlewares.GetChallengerHandlerMap(middlewares.NewKibanaTenancy(cfg.TenantID))),
	}
	challenger, err := server.New(challengerOpts...)
	if err != nil {
		log.WithError(err).Fatal("failed to create Challenger.")
	}
	log.Infof("Challenger listening for HTTPS requests at %s", challengerAddr)
	log.Fatal(challenger.ListenAndServeHTTP())
}
