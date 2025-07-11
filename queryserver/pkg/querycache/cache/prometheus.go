// Copyright (c) 2023 Tigera, Inc. All rights reserved.
package cache

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/api"
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/config"
	"github.com/prometheus/common/model"
	log "github.com/sirupsen/logrus"

	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
)

func NewPrometheusClient(address, token string) (*PrometheusClient, error) {
	tlsConfig, err := getTLSConfig()
	if err != nil {
		log.WithError(err).Warn("failed to get TLS config for Prometheus client")
		return nil, err
	}

	client, err := api.NewClient(api.Config{
		Address: address,
		RoundTripper: config.NewAuthorizationCredentialsRoundTripper(
			"Bearer", config.NewInlineSecret(token),
			&http.Transport{TLSClientConfig: tlsConfig},
		),
	})

	if err != nil {
		log.WithError(err).Warn("failed to create Prometheus client")
		return nil, err
	}
	return &PrometheusClient{client: client}, nil
}

func getTLSConfig() (*tls.Config, error) {
	// don't create the TLS config if the env variable isn't set
	caBundle, err := os.ReadFile(os.Getenv("TRUSTED_BUNDLE_PATH"))
	if err != nil {
		return nil, nil
	}

	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM(caBundle)
	if !ok {
		return nil, fmt.Errorf("failed to parse root certificate")
	}

	tlsConfig, err := calicotls.NewTLSConfig()
	if err != nil {
		return nil, err
	}
	tlsConfig.RootCAs = caCertPool

	return tlsConfig, nil
}

type PrometheusClient struct {
	client api.Client
}

func (c *PrometheusClient) Query(query string, ts time.Time) (model.Value, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	v1api := v1.NewAPI(c.client)
	res, _, err := v1api.Query(ctx, query, ts, v1.WithTimeout(5*time.Second))
	return res, err
}
