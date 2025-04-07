package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/config"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/handler"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/repository/linseed"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/security"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/svc/auth"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/svc/collections"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/svc/managedclusters"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/svc/metadata"
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

	metadataService := metadata.NewMetadataService(logger, cfg.MetadataAPIEndpoint)
	collectionsService := collections.NewCollectionsService(logger)

	handlerRegistry, err := handler.NewHandler(
		logger,
		strings.Split(cfg.CorsOrigins, ","),
		authService,
		queryService,
		metadataService,
		collectionsService,
	)
	if err != nil {
		return err
	}

	rootHandler := otel.NewHandlerIfEnabled(cfg.OpenTelemetryEnabled, handlerRegistry.Handler())

	tlsConfig, err := getTLSConfig(cfg.HttpsCACert)
	if err != nil {
		return err
	}

	errCh := make(chan error)
	go func() {
		healthServer := &http.Server{
			// We only want the health url to be accessible from within the container.
			// Kubelet will use an exec probe to get status.
			Addr: fmt.Sprintf("localhost:%d", cfg.HealthPort),
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health" {
					w.WriteHeader(http.StatusOK)
				} else {
					w.WriteHeader(http.StatusNotFound)
				}
			}),
		}
		errCh <- healthServer.ListenAndServe()
	}()

	go func() {
		httpServer := &http.Server{
			Addr:      cfg.ListenAddr,
			Handler:   rootHandler,
			TLSConfig: tlsConfig,
		}

		errCh <- httpServer.ListenAndServeTLS(cfg.HttpsCert, cfg.HttpsKey)
	}()

	return <-errCh
}

func getTLSConfig(caCertFilename string) (*tls.Config, error) {
	tlsConfig := calicotls.NewTLSConfig()
	if caCertFilename != "" {
		caCert, err := os.ReadFile(caCertFilename)
		if err != nil {
			return nil, err
		}

		tlsConfig.ClientCAs = x509.NewCertPool()
		tlsConfig.ClientCAs.AppendCertsFromPEM(caCert)
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsConfig, nil
}
