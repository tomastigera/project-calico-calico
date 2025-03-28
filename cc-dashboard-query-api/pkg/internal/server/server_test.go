package server

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServer(t *testing.T) {

	t.Run("mTLS configuration", func(t *testing.T) {
		certContent := []byte("-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----")
		expectedCertPool := x509.NewCertPool()
		expectedCertPool.AppendCertsFromPEM(certContent)

		caCertFilename := filepath.Join(t.TempDir(), "cacert.pem")
		require.NoError(t, os.WriteFile(caCertFilename, certContent, 0o600))

		testCases := []struct {
			name           string
			caCertFilename string
			expected       *tls.Config
		}{
			{
				name:     "disabled",
				expected: nil,
			},
			{
				name:           "enabled",
				caCertFilename: caCertFilename,
				expected: &tls.Config{
					ClientCAs:  expectedCertPool,
					ClientAuth: tls.RequireAndVerifyClientCert,
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				tlsConfig, err := getTLSConfig(tc.caCertFilename)

				require.NoError(t, err)
				require.Equal(t, tc.expected, tlsConfig)
			})
		}
	})
}
