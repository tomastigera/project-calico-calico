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

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/pkg/otel"
	"github.com/tigera/tds-apiserver/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/projectcalico/calico/dashboards/pkg/internal/config"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/collections"
	"github.com/projectcalico/calico/dashboards/pkg/internal/handler"
	"github.com/projectcalico/calico/dashboards/pkg/internal/metrics"
	"github.com/projectcalico/calico/dashboards/pkg/internal/repository/linseed"
	"github.com/projectcalico/calico/dashboards/pkg/internal/security"
	"github.com/projectcalico/calico/dashboards/pkg/internal/svc/auth"
	svccollections "github.com/projectcalico/calico/dashboards/pkg/internal/svc/collections"
	"github.com/projectcalico/calico/dashboards/pkg/internal/svc/managedclusters"
	"github.com/projectcalico/calico/dashboards/pkg/internal/svc/metadata"
	staticmetadata "github.com/projectcalico/calico/dashboards/pkg/internal/svc/metadata/static"
	"github.com/projectcalico/calico/dashboards/pkg/internal/svc/query"
)

func Start(
	ctx context.Context,
	cfg *config.Config,
	logger logging.Logger,
	authorizer security.Authorizer,
	k8sClient *kubernetes.Clientset,
	k8sRestConfig *rest.Config,
	dynamicClient dynamic.Interface,
) error {
	var tenantClaim string
	if cfg.ProductMode == config.ProductModeCloud {
		tenantClaim = cfg.CalicoCloudTenantClaim
		if tenantClaim == "" {
			tenantClaim = cfg.TenantID
		}
	}

	authService, err := auth.NewAuthService(
		cfg,
		logger,
		cfg.TenantID,
		tenantClaim,
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

	enabledCollections := collections.Collections(collections.ToCollectionNames(strings.Split(cfg.DisabledCollections, ",")))

	queryService := query.NewQueryService(
		logger,
		linseedRepository,
		enabledCollections,
		managedClusterNameLister,
		query.Config{
			QueryTimeout:           time.Duration(2) * time.Minute,
			MaxRequestFilters:      cfg.MaxRequestFilters,
			MaxRequestAggregations: cfg.MaxRequestAggregations,
		},
	)

	var metadataService metadata.Storer
	if cfg.ProductMode == config.ProductModeCloud {
		metadataService, err = metadata.NewRemoteMetadataService(
			logger,
			types.PackageName(cfg.CalicoCloudPackage),
			cfg.MetadataAPIEndpoint,
			enabledCollections,
			cfg.DisabledDashboards,
		)
	} else {
		metadataService, err = staticmetadata.NewStaticMetadataService()
	}
	if err != nil {
		return err
	}

	collectionsService := svccollections.NewCollectionsService(logger, enabledCollections)

	handlerRegistry, err := handler.NewHandler(
		cfg,
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

	var tlsConfig *tls.Config
	if cfg.HttpsCert != "" && cfg.HttpsKey != "" {
		tlsConfig, err = getTLSConfig(cfg.HttpsCACert)
		if err != nil {
			return err
		}
	} else if cfg.ProductMode == config.ProductModeCloud {
		return fmt.Errorf("https cert and key must be provided in cloud product mode")
	}

	errCh := make(chan error)
	if cfg.EnableMetrics {
		rootHandler = metrics.Wrap(ctx, logger, rootHandler, cfg.TenantID)

		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())
			metricsServer := &http.Server{
				Addr:    cfg.MetricsAddr,
				Handler: mux,
			}
			errCh <- metricsServer.ListenAndServeTLS(cfg.MetricsCert, cfg.MetricsKey)
		}()
	}

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

		var err error
		if tlsConfig != nil {
			err = httpServer.ListenAndServeTLS(cfg.HttpsCert, cfg.HttpsKey)
		} else {
			err = httpServer.ListenAndServe()
		}
		errCh <- err
	}()

	return <-errCh
}

func getTLSConfig(caCertFilename string) (*tls.Config, error) {
	tlsConfig, err := calicotls.NewTLSConfig()
	if err != nil {
		return nil, err
	}

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
