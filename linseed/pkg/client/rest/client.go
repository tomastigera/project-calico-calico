// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package rest

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/sirupsen/logrus"

	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
)

const LinseedServerName = "tigera-linseed"

// RESTClient is a helper for building HTTP requests for the Linseed API.
type RESTClient interface {
	BaseURL() string
	Tenant() string
	Token() ([]byte, error)
	HTTPClient() *http.Client
	Verb(string) Request
	Post() Request
	Put() Request
	Delete() Request
}

type restClient struct {
	// Configuration, input by caller.
	config    Config
	client    *http.Client
	tenantID  string
	tokenPath string
}

type Config struct {
	// The base URL of the server
	URL string

	// CACertPath is the path to the CA cert for verifying
	// the server certificate provided by Linseed.
	CACertPath string

	// ClientCertPath is the path to the client certificate this client
	// should present to Linseed for mTLS authentication.
	ClientCertPath string

	// ClientKeyPath is the path to the client key used for mTLS.
	ClientKeyPath string

	// ServerName is the hostname used to validate the server’s certificate during the TLS handshake.
	ServerName string
}

type ClientOption func(*restClient) error

// WithTokenPath sets the token path to use for this client.
// The client will load this token on each request to allow for token rotation.
func WithTokenPath(path string) ClientOption {
	return func(c *restClient) error {
		if path == "" {
			return fmt.Errorf("token path cannot be empty")
		}
		c.tokenPath = path
		return nil
	}
}

// NewClient returns a new restClient.
func NewClient(tenantID string, cfg Config, opts ...ClientOption) (RESTClient, error) {
	httpClient, err := newHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	rc := &restClient{
		config:   cfg,
		tenantID: tenantID,
		client:   httpClient,
	}
	for _, opt := range opts {
		if err = opt(rc); err != nil {
			return nil, err
		}
	}
	return rc, nil
}

func newHTTPClient(cfg Config) (*http.Client, error) {
	tlsConfig := calicotls.NewTLSConfig()
	tlsConfig.ServerName = LinseedServerName
	if len(cfg.ServerName) > 0 {
		tlsConfig.ServerName = cfg.ServerName
	}
	if cfg.CACertPath != "" {
		caCertPool := x509.NewCertPool()
		caCert, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("error reading CA file: %s", err)
		}
		ok := caCertPool.AppendCertsFromPEM(caCert)
		if !ok {
			return nil, fmt.Errorf("failed to parse root certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	// Create a custom dialer so that we can configure a dial timeout.
	// If we can't connect to Linseed within 10 seconds, something is up.
	// Note: this is not the same as the request timeout, which is handled via the
	// provided context on a per-request basis.
	dialWithTimeout := func(network, addr string) (net.Conn, error) {
		return net.DialTimeout(network, addr, 10*time.Second)
	}
	httpTransport := &http.Transport{
		Dial:            dialWithTimeout,
		TLSClientConfig: tlsConfig,
	}

	if cfg.ClientKeyPath != "" && cfg.ClientCertPath != "" {
		clientCert, err := tls.LoadX509KeyPair(cfg.ClientCertPath, cfg.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("error load cert key pair for linseed client: %s", err)
		}
		httpTransport.TLSClientConfig.Certificates = []tls.Certificate{clientCert}
		logrus.Info("Using provided client certificates for mTLS")
	}
	return &http.Client{
		Transport: httpTransport,
	}, nil
}

func (c *restClient) Verb(verb string) Request {
	return NewRequest(c).Verb(verb)
}

func (c *restClient) Post() Request {
	return c.Verb(http.MethodPost)
}

func (c *restClient) Put() Request {
	return c.Verb(http.MethodPut)
}

func (c *restClient) Delete() Request {
	return c.Verb(http.MethodDelete)
}

func (c *restClient) BaseURL() string {
	return c.config.URL
}

func (c *restClient) Tenant() string {
	return c.tenantID
}

func (c *restClient) HTTPClient() *http.Client {
	return c.client
}

func (c *restClient) Token() ([]byte, error) {
	if c.tokenPath == "" {
		return nil, nil
	}
	token, err := os.ReadFile(c.tokenPath)
	if err != nil {
		return nil, fmt.Errorf("unable to load Linseed token from %s: %s", c.tokenPath, err)
	}
	return token, nil
}
