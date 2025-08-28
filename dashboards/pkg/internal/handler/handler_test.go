package handler

import (
	"context"
	"os"
	"testing"

	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/pkg/http/handleradapters"

	staticmetadata "github.com/projectcalico/calico/dashboards/pkg/internal/svc/metadata/static"
)

var (
	logger = logging.New("client_integration_test")

	handlerRegistry handleradapters.RootRegistry
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	handleError := func(msg string, err error) {
		logger.ErrorC(ctx, "error", logging.String("message", msg), logging.Error(err))
		os.Exit(1)
	}

	metadataService, err := staticmetadata.NewStaticMetadataService()
	if err != nil {
		handleError("failed to create metadata service", err)
	}

	handlerRegistry, err = NewHandler(
		logger,
		nil,
		nil,
		nil,
		metadataService,
		nil,
	)
	if err != nil {
		handleError("failed to create handler registry", err)
	}

	exitCode := m.Run()

	// any cleanup should go here...
	// cleanup()

	os.Exit(exitCode)
}
