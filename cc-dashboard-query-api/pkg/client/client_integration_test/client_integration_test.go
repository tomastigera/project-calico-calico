package client_integration_test

import (
	"context"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/handler"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/svc/collections"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/svc/query"
	"github.com/tigera/tds-apiserver/pkg/http/handleradapters"
	"github.com/tigera/tds-apiserver/pkg/logging"
)

var (
	logger = logging.New("client_integration_test")

	handlerRegistry handleradapters.RootRegistry
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	handleError := func(msg string, err error) {
		logger.ErrorC(ctx, "error", zap.String("message", msg), zap.Error(err))
		os.Exit(1)
	}

	queryService := query.NewQueryService(logger, nil, nil, time.Duration(2)*time.Minute, "")
	collectionsService := collections.NewCollectionsService(logger)

	var err error
	handlerRegistry, err = handler.NewHandler(
		logger,
		nil,
		nil,
		queryService,
		collectionsService,
	)
	if err != nil {
		handleError("failed to create handler registry", err)
	}

	exitCode := m.Run()

	// any cleanup should go here...
	// cleanup()

	os.Exit(exitCode)
}
