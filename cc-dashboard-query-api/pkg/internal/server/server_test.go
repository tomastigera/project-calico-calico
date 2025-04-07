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
			name               string
			caCertFilename     string
			expectedCAs        *x509.CertPool
			expectedClientAuth tls.ClientAuthType
		}{
			{
				name:               "disabled",
				caCertFilename:     "",
				expectedCAs:        nil,
				expectedClientAuth: 0,
			},
			{
				name:               "enabled",
				caCertFilename:     caCertFilename,
				expectedCAs:        expectedCertPool,
				expectedClientAuth: tls.RequireAndVerifyClientCert,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				tlsConfig, err := getTLSConfig(tc.caCertFilename)

				require.NoError(t, err)
				require.Equal(t, tc.expectedCAs, tlsConfig.ClientCAs)
				require.Equal(t, tc.expectedClientAuth, tlsConfig.ClientAuth)
			})
		}
	})
}
