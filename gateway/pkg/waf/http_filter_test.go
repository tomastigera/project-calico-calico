package waf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUpdateWAFConfig(t *testing.T) {
	f := NewWAFHTTPFilter(ServerOptions{
		TcpPort:  9002,
		HttpPort: 8080,
	}, DebugLogger)

	require.NotNil(t, f.wafServer)

	err := f.UpdateWAFConfig(Directives)
	require.NoError(t, err)
	require.NotNil(t, f.wafServer)
}
