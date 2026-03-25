// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package fv_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("Prometheus Proxy Test", func() {

	const (
		httpScheme               = "https://"
		mockPrometheuServicesUrl = "localhost:9090"
		proxyServicesUrl         = "localhost:8090"

		testPrometheusQuery = "sum(http_requests_total{method=\"GET\"} offset 5m)"
		testStep            = "15s"

		caCert = "./tls.crt"
	)

	var mockPrometheusService *http.Server
	var client *http.Client
	BeforeEach(func() {
		caCert, err := os.ReadFile(caCert)
		if err != nil {
			log.Fatal(err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: caCertPool,
				},
			},
		}

		// setup mock prometheus service
		mockPrometheusServiceMux := http.NewServeMux()
		mockPrometheusServiceMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			requestParam := struct {
				Host           string
				Method         string
				Path           string
				XForwardedHost string
			}{
				r.Host,
				r.Method,
				r.URL.Path,
				r.Header.Get("X-Forwarded-Host"),
			}

			err := json.NewEncoder(w).Encode(requestParam)
			if err != nil {
				log.Errorf("JSON Encoder error: %s", err)
			}
		})
		mockPrometheusService = &http.Server{
			Addr:    mockPrometheuServicesUrl,
			Handler: mockPrometheusServiceMux,
		}
		go func() {
			err := mockPrometheusService.ListenAndServe()
			if err != nil {
				log.Warnf("Mock Prometheus Service: %s", err)
			}
		}()
	})

	AfterEach(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := mockPrometheusService.Shutdown(ctx); err != nil {
			Fail("Unable to continue, server does not shutdown")
		}
	})

	It("should proxy http requests to the prometheus service as it was received", func() {
		http_proxy_url, err := url.Parse(httpScheme + proxyServicesUrl)
		Expect(err).NotTo(HaveOccurred())
		http_proxy_url.Path = "/api/v1/query_range"

		req, err := http.NewRequest("GET", http_proxy_url.String(), nil)
		Expect(err).NotTo(HaveOccurred())

		req_query := req.URL.Query()
		req_query.Add("query", testPrometheusQuery)
		t := time.Now()
		start := strconv.FormatInt(t.Unix(), 10)
		end := strconv.FormatInt(t.Unix()+60, 10)
		req_query.Add("start", start)
		req_query.Add("end", end)
		req_query.Add("step", testStep)

		log.Infof("Making request to: %v", req.URL.String())
		resp, err := client.Do(req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(200))

		var data map[string]string
		err = json.NewDecoder(resp.Body).Decode(&data)
		Expect(err).NotTo(HaveOccurred())
		Expect(data["Method"]).To(Equal(req.Method))
		Expect(data["Path"]).To(Equal(req.URL.Path))
		// SetURL sets the Host header to the upstream target
		Expect(data["Host"]).To(Equal(mockPrometheuServicesUrl))
		// The original proxy host is preserved in X-Forwarded-Host
		Expect(data["XForwardedHost"]).To(Equal(proxyServicesUrl))
	})
})
