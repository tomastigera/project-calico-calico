// Copyright (c) 2018-2019 Tigera, Inc. All rights reserved.

package security

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"

	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
)

// Serve Prometheus metrics from the specified gatherer at /metrics.
// The service is TLS-secured (HTTPS) if certFile, keyFile and caFile
// are all specified, in that (a) it only accepts connection from a
// client with a certificate signed by a trusted CA, and (b) data is
// sent to that client encrypted, and cannot be snooped.  Otherwise it
// is insecure (HTTP).
func ServePrometheusMetrics(gatherer prometheus.Gatherer, host string, port int, certFile, keyFile, caFile string) (err error) {
	mux := http.NewServeMux()
	handler := promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{})
	mux.Handle("/metrics", handler)
	if certFile != "" && keyFile != "" && caFile != "" {
		var caCert []byte
		caCert, err = os.ReadFile(caFile)
		if err != nil {
			return
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig, tlsErr := calicotls.NewTLSConfig()
		if tlsErr != nil {
			err = fmt.Errorf("failed to create TLS Config: %w", tlsErr)
			return
		}
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConfig.ClientCAs = caCertPool
		srv := &http.Server{
			Addr:      fmt.Sprintf("[%v]:%v", host, port),
			Handler:   handler,
			TLSConfig: tlsConfig,
		}
		err = srv.ListenAndServeTLS(certFile, keyFile)
	} else {
		err = http.ListenAndServe(fmt.Sprintf("[%v]:%v", host, port), mux)
	}
	return
}

func ServePrometheusMetricsForever(gatherer prometheus.Gatherer, host string, port int, certFile, keyFile, caFile string) {
	for {
		err := ServePrometheusMetrics(gatherer, host, port, certFile, keyFile, caFile)
		logrus.WithError(err).Error(
			"Prometheus metrics endpoint failed, trying to restart it...")
		time.Sleep(1 * time.Second)
	}
}
