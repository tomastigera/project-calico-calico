// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	ctls "github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/config"
)

var (
	//go:embed data/api-kibana-dashboard.json
	apiDashboard string
	//go:embed data/tor-vpn-dashboard.json
	torVpnDashBoard string
	//go:embed data/dns-dashboard.json
	dnsDashboard string
	//go:embed data/kubernetes-api-dashboard.json
	k8sApiDashboard string
	//go:embed data/l7-dashboard.json
	l7Dashboard string
)

func main() {
	cfg, err := config.GetDashboardInstallerConfig()
	if err != nil {
		log.Fatal(err)
	}

	// Attempt to load CA cert.
	caCert, err := os.ReadFile(cfg.KibanaCAPath)
	if err != nil {
		log.Panicf("unable to read certificate for Kibana: %v", err)
	}

	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM(caCert)
	if !ok {
		log.Panicf("failed to add certificate to the pool: %v", err)
	}

	// Set up default HTTP transport config.
	tlsConfig, err := ctls.NewTLSConfig()
	if err != nil {
		log.Fatal(err)
	}
	tlsConfig.RootCAs = caCertPool

	// Determine whether mTLS is enabled for Kibana.
	if cfg.KibanaMTLSEnabled {
		clientCert, err := tls.LoadX509KeyPair(cfg.KibanaClientCert, cfg.KibanaClientKey)
		if err != nil {
			log.Fatalf("could not load client certificates for mtls. %v", err)
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	var kibanaURL string
	if cfg.KibanaSpaceID == "" {
		kibanaURL = fmt.Sprintf("%s://%s:%s/tigera-kibana/", cfg.KibanaScheme, cfg.KibanaHost, cfg.KibanaPort)
	} else {
		kibanaURL = fmt.Sprintf("%s://%s:%s/tigera-kibana/s/%s/", cfg.KibanaScheme, cfg.KibanaHost, cfg.KibanaPort, cfg.KibanaSpaceID)
	}
	bulkCreateURL := fmt.Sprintf("%sapi/saved_objects/_bulk_create", kibanaURL)
	postDashboard(client, bulkCreateURL, cfg.ElasticUsername, cfg.ElasticPassword, "apiDashboard", apiDashboard)
	postDashboard(client, bulkCreateURL, cfg.ElasticUsername, cfg.ElasticPassword, "torVpnDashBoard", torVpnDashBoard)
	postDashboard(client, bulkCreateURL, cfg.ElasticUsername, cfg.ElasticPassword, "dnsDashboard", dnsDashboard)
	postDashboard(client, bulkCreateURL, cfg.ElasticUsername, cfg.ElasticPassword, "k8sApiDashboard", k8sApiDashboard)
	postDashboard(client, bulkCreateURL, cfg.ElasticUsername, cfg.ElasticPassword, "l7Dashboard", l7Dashboard)

	importURL := fmt.Sprintf("%sapi/saved_objects/_import", kibanaURL)
	uploadDashboardNDJSON(client, importURL, cfg.ElasticUsername, cfg.ElasticPassword, "flowlog-dashboard", "/etc/dashboards/flowlog-dashboard.ndjson")
}

// uploadDashboardNDJSON uploads an NDJSON file and posts it as a multipart upload.
func uploadDashboardNDJSON(client *http.Client, url, username, password, dashboardName, dashboard string) {
	log.Infof("Creating dashboard %s...", dashboardName)
	err := performRequest(client, func() *http.Request {
		file, err := os.Open(dashboard)
		defer func(file *os.File) {
			err := file.Close()
			if err != nil {
				log.Fatalf("unable to create dashboard %s: %v ", dashboardName, err)
			}
		}(file)
		if err != nil {
			log.Fatalf("unable to create dashboard %s: %v ", dashboardName, err)
		}
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		part, err := writer.CreateFormFile("file", filepath.Base(file.Name()))
		if err != nil {
			log.Fatalf("unable to create dashboard %s: %v ", dashboardName, err)
		}
		_, err = io.Copy(part, file)
		_ = writer.Close()
		if err != nil {
			log.Fatalf("unable to create dashboard %s: %v ", dashboardName, err)
		}
		req, err := http.NewRequest(http.MethodPost, url, body)
		if err != nil {
			log.Fatalf("unable to create dashboard %s: %v ", dashboardName, err)
		}
		req.SetBasicAuth(username, password)
		req.Header.Add("Content-Type", writer.FormDataContentType())
		req.Header.Add("kbn-xsrf", "reporting")
		return req
	})
	if err != nil {
		log.Fatalf("unable to create dashboard %s: %v ", dashboardName, err)
	}
}

// postDashboard makes a performRequest request with a JSON body to create objects in Kibana.
func postDashboard(client *http.Client, url, username, password, dashboardName, dashboard string) {
	log.Infof("Creating dashboard %s...", dashboardName)
	err := performRequest(client, func() *http.Request {
		req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(dashboard))
		if err != nil {
			log.Fatalf("unable to create dashboard %s: %v ", dashboardName, err)
		}
		req.SetBasicAuth(username, password)
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("kbn-xsrf", "reporting")
		return req
	})
	if err != nil {
		log.Fatalf("unable to create dashboard %s: %v ", dashboardName, err)
	}
}

// performRequest makes a POST request to Kibana. If a 409 error occurs, it will retry once.
func performRequest(client *http.Client, requestFn func() *http.Request) error {
	resp, err := client.Do(requestFn())
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusConflict {
		log.Info("Conflict, trying again")
		req := requestFn()
		req.Method = http.MethodPut
		resp, err = client.Do(req)
		if err != nil {
			return err
		}
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("unable to setup dashboard. Status code: %d , body: %s", resp.StatusCode, body)
	}
	log.Info(resp.Status)
	return nil
}
