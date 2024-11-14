package main

import (
	"context"

	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap/zapcore"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	lmaauth "github.com/projectcalico/calico/lma/pkg/auth"
	"github.com/projectcalico/calico/lma/pkg/cache"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/config"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/server"
	"github.com/tigera/tds-apiserver/pkg/logging"
)

var logger = logging.New("cc-dashboard-query-api")

func main() {
	// Setup a context with cancel for informerFactory.Start(ctx.Done())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &config.Config{}
	if err := envconfig.Process("CC_DASHBOARD_QUERY_API", cfg); err != nil {
		logger.Fatal("failed to process config", logging.Error(err))
	}

	// Setup logging
	// Main logger
	logLevelZapcore, err := zapcore.ParseLevel(cfg.LogLevel)
	if err != nil {
		logger.ErrorC(ctx, "failed to parse log level. Using INFO", logging.Error(err))
		logLevelZapcore = zapcore.InfoLevel
	}
	logger = logger.WithEventLevel(logLevelZapcore)

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
		logger.Fatal("failed to build kubernetes rest config", logging.Error(err))
	}

	k8sClient, err := kubernetes.NewForConfig(k8sRestConfig)
	if err != nil {
		logger.Fatal("failed to create kubernetes client", logging.Error(err))
	}

	dynamicClient, err := dynamic.NewForConfig(k8sRestConfig)
	if err != nil {
		logger.Fatal("failed to create calico client", logging.Error(err))
	}

	// Create an authorizer to use for lma.tigera.io resources. If a tenant namespace is configured, the authorizer
	// will use LocalSubjectAccessReviews to check access to the tenant namespace. Otherwise, it will use SubjectAccessReviews
	// to check access at the cluster scope.
	rbacAuthorizer := lmaauth.NewNamespacedRBACAuthorizer(k8sClient, cfg.TenantNamespace)

	if cfg.LMAAuthorizationCacheTTL > 0 {
		authCache, err := cache.NewExpiring[string, bool](cache.ExpiringConfig{
			Context: ctx,
			Name:    "lma-access-authorizer",
			TTL:     cfg.LMAAuthorizationCacheTTL,
		})
		if err != nil {
			logger.Fatal("failed to create authorization cache", logging.Error(err))
		}

		rbacAuthorizer = lmaauth.NewCachingAuthorizer(authCache, rbacAuthorizer)
	}

	if err := server.Start(ctx, cfg, logger, k8sRestConfig, k8sClient, dynamicClient, rbacAuthorizer); err != nil {
		logger.Fatal("server start failed", logging.Error(err))
	}
}
