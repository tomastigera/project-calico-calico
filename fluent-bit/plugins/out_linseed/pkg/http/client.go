// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

package http

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/projectcalico/calico/fluent-bit/plugins/out_linseed/pkg/config"
)

const (
	// This is the default network configuration suggested by the fluent-bit documentation.
	// https://docs.fluentbit.io/manual/administration/networking#configuration-options
	defaultConnectTimeout     = 10 * time.Second
	defaultConnectIdleTimeout = 15 * time.Second
	defaultTimeout            = 30 * time.Second
)

type Client struct {
	*http.Client

	tokenProvider TokenProvider
}

func NewClient(cfg *config.Config) (*Client, error) {
	tk, err := NewToken(cfg)
	if err != nil {
		return nil, err
	}

	return &Client{
		Client: &http.Client{
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: defaultConnectTimeout,
				}).DialContext,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: cfg.InsecureSkipVerify,
					RootCAs:            certPool(cfg),
				},
				IdleConnTimeout: defaultConnectIdleTimeout,
			},
			Timeout: defaultTimeout,
		},
		tokenProvider: tk,
	}, nil
}

func (c *Client) Do(endpoint, tag string, ndjsonBuffer *bytes.Buffer) error {
	url := ""
	switch tag {
	case "flows":
		url = fmt.Sprintf("%s/ingestion/api/v1/%s/logs/bulk", endpoint, tag)
	default:
		return fmt.Errorf("unknown log type %q", tag)
	}

	logrus.WithField("tag", tag).Debugf("sending logs to %q", url)
	req, err := http.NewRequest("POST", url, bytes.NewReader(ndjsonBuffer.Bytes()))
	if err != nil {
		return err
	}

	token, err := c.tokenProvider.Token()
	if err != nil {
		logrus.WithError(err).Error("failed to get token")
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/x-ndjson")

	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		// Drain the body before closing so the underlying TCP connection can be
		// reused by the transport's connection pool.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			// We got a 401 Unauthorized, so the token is probably expired or invalid.
			// Force a token refresh for the next request.
			logrus.Info("received 401 Unauthorized, refreshing token")
			if _, err := c.tokenProvider.Refresh(); err != nil {
				logrus.WithError(err).Warn("failed to refresh token")
			}
		}

		// Read a truncated excerpt of the response body for diagnostics.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		if len(body) > 0 {
			return fmt.Errorf("error response from server %q: %s", resp.Status, string(body))
		}
		return fmt.Errorf("error response from server %q", resp.Status)
	}
	return nil
}

func certPool(cfg *config.Config) *x509.CertPool {
	systemPool, err := x509.SystemCertPool()
	if err != nil {
		logrus.WithError(err).Warn("failed to load system cert pool, creating a new one")
		systemPool = x509.NewCertPool()
	}

	kcfg, err := clientcmd.LoadFromFile(cfg.Kubeconfig)
	if err != nil {
		logrus.WithError(err).Warn("failed to load kubeconfig, using system cert pool only")
		return systemPool
	}

	ctx, ok := kcfg.Contexts[kcfg.CurrentContext]
	if !ok {
		logrus.WithField("context", kcfg.CurrentContext).Warn("failed to find current context in kubeconfig, using system cert pool only")
		return systemPool
	}

	cluster, ok := kcfg.Clusters[ctx.Cluster]
	if !ok {
		logrus.WithField("cluster", ctx.Cluster).Warn("failed to find current cluster in kubeconfig, using system cert pool only")
		return systemPool
	}

	if len(cluster.CertificateAuthorityData) > 0 {
		if ok := systemPool.AppendCertsFromPEM(cluster.CertificateAuthorityData); !ok {
			logrus.Warn("failed to append certificate authority data from kubeconfig, using system cert pool only")
		}
		logrus.Info("appended certificate-authority-data from kubeconfig")
	} else if cluster.CertificateAuthority != "" {
		caData, err := os.ReadFile(cluster.CertificateAuthority)
		if err != nil {
			logrus.WithError(err).WithField("ca", cluster.CertificateAuthority).Warn("failed to read certificate authority file, using system cert pool only")
		} else {
			if ok := systemPool.AppendCertsFromPEM(caData); !ok {
				logrus.WithField("ca", cluster.CertificateAuthority).Warn("failed to append certificate authority data from file, using system cert pool only")
			}
			logrus.Info("appended certificate-authority from kubeconfig")
		}
	}
	return systemPool
}
