package main

import (
	"context"
	"os"

	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/config"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/security"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/server"
	"github.com/tigera/tds-apiserver/lib/logging"
)

var logger = logging.New("cc-dashboard-query-api")

func main() {
	// Setup a context with cancel for informerFactory.Start(ctx.Done())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &config.Config{}
	if err := envconfig.Process("CC_DASHBOARD_QUERY_API", cfg); err != nil {
		logger.Error("failed to process config", logging.Error(err))
		os.Exit(1)
	}

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

	authorizer, err := security.NewAuthorizer(
		ctx,
		logger,
		cfg.TenantNamespace,
		cfg.LMAAuthorizationCacheTTL,
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
