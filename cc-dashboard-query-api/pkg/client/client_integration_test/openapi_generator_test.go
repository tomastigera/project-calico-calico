package client_integration_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateOpenAPI(t *testing.T) {
	yaml, err := handlerRegistry.OpenAPIYaml()
	require.NoError(t, err)

	err = os.WriteFile("../../../openapi.yaml", yaml, 0644)
	require.NoError(t, err)
}
