package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
	"github.com/tigera/api/pkg/client/clientset_generated/clientset"
	"github.com/tigera/tds-apiserver/lib/logging"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/projectcalico/calico/dashboards/pkg/internal/config"
	"github.com/projectcalico/calico/dashboards/pkg/internal/security"
	"github.com/projectcalico/calico/dashboards/pkg/internal/server"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	"github.com/projectcalico/calico/ui-apis/pkg/authzreview"
)

var (
	logger = logging.New("dashboard-query-api")
	ready  bool
)

func init() {
	flag.BoolVar(&ready, "ready", false, "readiness check")
}

func main() {
	flag.Parse()

	// Setup a context with cancel for informerFactory.Start(ctx.Done())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &config.Config{}
	if err := envconfig.Process("", cfg); err != nil {
		logger.Error("failed to process config", logging.Error(err))
		os.Exit(1)
	}

	if cfg.ProductMode != config.ProductModeEnterprise && cfg.ProductMode != config.ProductModeCloud {
		logger.Error("invalid product mode", logging.String("productMode", cfg.ProductMode))
		os.Exit(1)
	}

	if ready {
		os.Exit(doHealthCheck(cfg.HealthPort))
		return
	}

	logger.Info("starting", logging.String("config", cfg.String()))

	// Library logger
	// The calico lma auth library uses logrus std
	// Note: use logrus.SetFormatter or logrus.SetOutput to ensure logrus output matches the main logger
	logLevelLogrus, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		logger.ErrorC(ctx, "failed to parse log level. Using INFO", logging.Error(err))
		logLevelLogrus = logrus.InfoLevel
	}
	logrus.SetLevel(logLevelLogrus)

	var k8sRestConfig *rest.Config
	if cfg.Kubeconfig == "" {
		k8sRestConfig, err = rest.InClusterConfig()
	} else {
		k8sRestConfig, err = clientcmd.BuildConfigFromFlags("", cfg.Kubeconfig)
	}
	if err != nil {
		logger.Error("failed to build kubernetes rest config", logging.Error(err))
		os.Exit(1)
	}

	k8sClient, err := kubernetes.NewForConfig(k8sRestConfig)
	if err != nil {
		logger.Error("failed to create kubernetes client", logging.Error(err))
		os.Exit(1)
	}

	dynamicClient, err := dynamic.NewForConfig(k8sRestConfig)
	if err != nil {
		logger.Error("failed to create calico client", logging.Error(err))
		os.Exit(1)
	}

	// Create a Calico clientset for the RBAC calculator.
	calicoClient, err := clientset.NewForConfig(k8sRestConfig)
	if err != nil {
		logger.Error("failed to create calico clientset", logging.Error(err))
		os.Exit(1)
	}

	// Create an RBAC Reviewer for performing authorization reviews directly as a library call,
	// avoiding the extra hop to ui-apis.
	calculator := authzreview.NewCalculator(k8sClient, calicoClient)
	csFactory := lmak8s.NewClientSetFactoryWithConfig(k8sRestConfig, cfg.MultiClusterForwardingCA, cfg.MultiClusterForwardingEndpoint)
	reviewer := authzreview.NewAuthzReviewer(calculator, csFactory)

	authorizer, err := security.NewAuthorizer(
		ctx,
		logger,
		cfg.LMAAuthorizationCacheTTL,
		security.AuthorizerConfig{
			Namespace:                             cfg.TenantNamespace,
			ProductMode:                           cfg.ProductMode,
			EnableNamespacedRBAC:                  cfg.NamespacedRBAC,
			AuthorizedVerbsCacheHardTTL:           cfg.AuthorizedVerbsCacheHardTTL,
			AuthorizedVerbsCacheSoftTTL:           cfg.AuthorizedVerbsCacheSoftTTL,
			AuthorizedVerbsCacheReviewsTimeout:    cfg.AuthorizedVerbsCacheReviewsTimeout,
			AuthorizedVerbsCacheRevalidateTimeout: cfg.AuthorizedVerbsCacheRevalidateTimeout,
		},
		reviewer,
	)
	if err != nil {
		logger.Error("failed to create authorizer", logging.Error(err))
		os.Exit(1)
	}

	if err := server.Start(ctx, cfg, logger, authorizer, k8sClient, k8sRestConfig, dynamicClient); err != nil {
		logger.Error("server start failed", logging.Error(err))
		os.Exit(1)
	}
}

// doHealthCheck checks the local readiness or liveness endpoint and prints its status.
// It exits with a status code based on the status.
func doHealthCheck(port int) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	url := fmt.Sprintf("http://localhost:%d/health", port)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		logger.Error("failed to build request", logging.Error(err))
		return 1
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Error("healthcheck failed", logging.Error(err))
		return 1
	}
	if resp.StatusCode != http.StatusOK {
		logger.Error("bad status code from healthcheck endpoint", logging.Int("statusCode", resp.StatusCode))
		return 1
	}

	return 0
}
