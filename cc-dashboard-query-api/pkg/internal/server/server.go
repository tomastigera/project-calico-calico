package server

import (
	"context"
	"net/http"
	"strings"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/config"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/handler"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/repository/linseed"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/security"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/svc/auth"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/svc/collections"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/svc/managedclusters"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/svc/query"
	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/pkg/otel"
)

// Start starts the HTTPS server.
func Start(
	ctx context.Context,
	cfg *config.Config,
	logger logging.Logger,
	authorizer security.Authorizer,
	k8sClient *kubernetes.Clientset,
	k8sRestConfig *rest.Config,
	dynamicClient dynamic.Interface,
) error {
	authService, err := auth.NewAuthService(
		cfg,
		logger,
		authorizer,
		k8sClient,
		k8sRestConfig,
	)
	if err != nil {
		return err
	}

	linseedRepository, err := linseed.NewLinseedRepository(
		logger,
		cfg.TenantID,
		cfg.LinseedURL,
		cfg.LinseedCA,
		cfg.LinseedClientCert,
		cfg.LinseedClientKey,
		cfg.LinseedToken,
	)
	if err != nil {
		return err
	}

	managedClusterNameLister, err := managedclusters.NewNameLister(ctx, logger, dynamicClient, cfg.TenantNamespace)
	if err != nil {
		return err
	}

	queryService := query.NewQueryService(
		logger,
		linseedRepository,
		managedClusterNameLister,
		query.Config{
			QueryTimeout:           time.Duration(2) * time.Minute,
			MaxRequestFilters:      cfg.MaxRequestFilters,
			MaxRequestAggregations: cfg.MaxRequestAggregations,
		},
	)

	collectionsService := collections.NewCollectionsService(logger)

	handlerRegistry, err := handler.NewHandler(
		logger,
		strings.Split(cfg.CorsOrigins, ","),
		authService,
		queryService,
		collectionsService,
	)
	if err != nil {
		return err
	}

	rootHandler := otel.NewHandlerIfEnabled(cfg.OpenTelemetryEnabled, handlerRegistry.Handler())

	httpServer := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: rootHandler,
	}

	return httpServer.ListenAndServeTLS(cfg.HTTPSCert, cfg.HTTPSKey)
}
