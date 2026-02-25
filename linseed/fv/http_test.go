// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package fv_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type httpReqSpec struct {
	method  string
	url     string
	body    []byte
	headers map[string]string
}

func (h *httpReqSpec) AddHeaders(headers map[string]string) {
	if h.headers == nil {
		h.headers = make(map[string]string)
	}
	maps.Copy(h.headers, headers)
}

func (h *httpReqSpec) SetBody(body string) {
	h.body = []byte(body)
}

func noBodyHTTPReqSpec(method, url, tenant, cluster string, token []byte) httpReqSpec {
	s := httpReqSpec{
		method: method,
		url:    url,
		headers: map[string]string{
			"x-cluster-id": cluster,
			"x-tenant-id":  tenant,
		},
	}
	if len(token) > 0 {
		s.headers["Authorization"] = fmt.Sprintf("Bearer %s", string(token))
	}
	return s
}

func xndJSONPostHTTPReqSpec(url, tenant, cluster string, token, body []byte) httpReqSpec {
	s := httpReqSpec{
		method: "POST",
		url:    url,
		headers: map[string]string{
			"x-cluster-id": cluster,
			"x-tenant-id":  tenant,
			"Content-Type": "application/x-ndjson",
		},
		body: body,
	}
	if len(token) > 0 {
		s.headers["Authorization"] = fmt.Sprintf("Bearer %s", string(token))
	}
	return s
}

func doRequest(t *testing.T, client *http.Client, spec httpReqSpec) (*http.Response, []byte) {
	req, err := http.NewRequest(spec.method, spec.url, bytes.NewBuffer(spec.body))
	require.NoError(t, err)
	for k, v := range spec.headers {
		req.Header.Set(k, v)
	}

	res, err := client.Do(req)
	require.NoError(t, err)
	defer func() {
		_ = res.Body.Close()
	}()

	var resBody []byte
	resBody, err = io.ReadAll(res.Body)
	require.NoError(t, err)
	return res, resBody
}

func mTLSClient(t *testing.T) *http.Client {
	caCert, err := os.ReadFile("cert/RootCA.crt")
	require.NoError(t, err)

	// Get client  for mTLS.
	cert := mustReadTLSKeyPair(t, "cert/localhost.crt", "cert/localhost.key")

	tlsConfig := &tls.Config{
		RootCAs:      certPool(caCert),
		Certificates: []tls.Certificate{cert},
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}
	return client
}

func mTLSClientWithCerts(certPool *x509.CertPool, certificate tls.Certificate) *http.Client {
	tlsConfig := &tls.Config{
		RootCAs:      certPool,
		Certificates: []tls.Certificate{certificate},
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}
	return client
}

func mustReadTLSKeyPair(t *testing.T, certPath, keyPath string) tls.Certificate {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)
	return cert
}

func mustGetTLSKeyPair(t *testing.T, certPEM, keyPEM []byte) tls.Certificate {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	return cert
}

func tlsClient(t *testing.T) *http.Client {
	caCert, err := os.ReadFile("cert/RootCA.crt")
	require.NoError(t, err)

	tlsConfig := &tls.Config{
		RootCAs: certPool(caCert),
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}
	return client
}

func certPool(caCert []byte) *x509.CertPool {
	// Get root CA for TLS verification of the server cert.
	certPool, _ := x509.SystemCertPool()
	if certPool == nil {
		certPool = x509.NewCertPool()
	}
	certPool.AppendCertsFromPEM(caCert)

	return certPool
}

func mustCreateCAKeyPair(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	// Create a x509 template for the mustCreateCAKeyPair
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization: []string{"Tigera"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Generate a private key
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	return template, key
}

func mustCreateClientKeyPair(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	// Create a x509 template for the mustCreateCAKeyPair
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization: []string{"Tigera"},
		},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	// Generate a private key
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	return template, key
}

func signAndEncodeCert(t *testing.T, ca *x509.Certificate, caPrivateKey *rsa.PrivateKey,
	cert *x509.Certificate, key *rsa.PrivateKey,
) []byte {
	// Sign the certificate with the provided CA
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, caPrivateKey)
	require.NoError(t, err)

	// Encode the certificate
	certPEM := bytes.Buffer{}
	err = pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	require.NoError(t, err)

	return certPEM.Bytes()
}

func encodeKey(t *testing.T, key *rsa.PrivateKey) []byte {
	// Encode the private key
	keyPEM := bytes.Buffer{}
	privateBytes, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	err = pem.Encode(&keyPEM, &pem.Block{Type: "PRIVATE KEY", Bytes: privateBytes})
	require.NoError(t, err)

	return keyPEM.Bytes()
}
