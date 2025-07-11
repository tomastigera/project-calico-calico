// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package elastic

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"

	es7 "github.com/elastic/go-elasticsearch/v7"

	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
	httpCommon "github.com/projectcalico/calico/es-gateway/pkg/clients/internal/http"
)

// client is a wrapper for the ES client.
type client struct {
	*es7.Client
}

// Client is an interface that exposes the required ES API operations for ES Gateway.
type Client interface {
	GetClusterHealth() error
}

// NewClient returns a newly configured ES client.
func NewClient(url, username, password, caCertPath, clientCertPath, clientKeyPath string, mTLS bool) (Client, error) {
	// Attempt to load CA cert.
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, err
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

	// Determine whether mTLS is enabled for Elasticsearch.
	if mTLS {
		clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		if err != nil {
			return nil, err
		}
		httpTransport.TLSClientConfig.Certificates = []tls.Certificate{clientCert}
	}

	// Configure the ES client.
	config := es7.Config{
		Addresses: []string{
			url,
		},
		Username:  username,
		Password:  password,
		Transport: httpTransport,
	}

	esClient, err := es7.NewClient(config)
	if err != nil {
		return nil, err
	}

	return &client{esClient}, nil
}

// GetClusterHealth checks the health of the ES cluster that the client is connected to.
// If the response is anything other than HTTP 200, then an error is returned.
// Otherwise, we return nil.
// http://www.elastic.co/guide/en/elasticsearch/reference/master/cluster-health.html
func (es *client) GetClusterHealth() error {
	health := es.API.Cluster.Health

	res, err := health(health.WithTimeout(httpCommon.HealthCheckTimeout))
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return errors.New(res.String())
	}

	return nil
}
