// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package kibana

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
)

const kibanaRequestTimeout = time.Second * 10

// client is a wrapper for a simple HTTP client. We'll use this since there is no
// official Golang Kibana client library and we only need to call Kibana API for
// the health check.
type client struct {
	httpClient *http.Client
	baseURL    string
	username   string
	password   string
}

// Client is an interface that exposes the required Kibana API operations for ES Gateway.
type Client interface {
	GetKibanaStatus() error
}

// NewClient returns a newly configured ES client.
func NewClient(url, username, password, caCertPath, clientCertPath, clientKeyPath string, mTLS bool) (Client, error) {
	// Load CA cert
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		log.Fatal(err)
	}

	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM(caCert)
	if !ok {
		return nil, fmt.Errorf("failed to parse root certificate")
	}

	// Set up default HTTP transport config.
	tlsConfig, err := calicotls.NewTLSConfig()
	if err != nil {
		return nil, err
	}
	tlsConfig.RootCAs = caCertPool
	httpTransport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	// Determine whether mTLS is enabled for Kibana.
	if mTLS {
		clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		if err != nil {
			return nil, err
		}
		httpTransport.TLSClientConfig.Certificates = []tls.Certificate{clientCert}
	}

	httpClient := &http.Client{
		Transport: httpTransport,
		Timeout:   kibanaRequestTimeout,
	}

	return &client{
		httpClient: httpClient,
		baseURL:    url,
		username:   username,
		password:   password,
	}, nil
}

// GetKibanaStatus checks the status of the Kibana API that the client is connected to.
// If the response is anything other than HTTP 200, an error is returned.
// Otherwise, we return nil.
// https://www.elastic.co/guide/en/kibana/master/access.html#status
func (c *client) GetKibanaStatus() error {
	url := fmt.Sprintf("%s%s", c.baseURL, "/tigera-kibana/api/status")
	req, _ := http.NewRequest("GET", url, nil)
	req.SetBasicAuth(c.username, c.password)

	res, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}

	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		// Dump response
		defer func() { _ = res.Body.Close() }()
		data, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}
		return errors.New(string(data))
	}

	return nil
}
