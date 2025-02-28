package handler

import (
	"context"
	"os"
	"testing"

	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/pkg/http/handleradapters"
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

	var err error
	handlerRegistry, err = NewHandler(
		logger,
		nil,
		nil,
		nil,
		nil,
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
