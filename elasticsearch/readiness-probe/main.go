package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	esHttp "github.com/elastic/cloud-on-k8s/v3/pkg/controller/common/http"
	"github.com/elastic/cloud-on-k8s/v3/pkg/controller/elasticsearch/label"
	"github.com/elastic/cloud-on-k8s/v3/pkg/controller/elasticsearch/volume"
	"github.com/sirupsen/logrus"
)

// This is the golang version of the bash script written for ECK version 2.5.0, located here
// https://github.com/elastic/cloud-on-k8s/blob/2.5.0/pkg/controller/elasticsearch/nodespec/readiness_probe.go#L33
//
// The readiness probe was re written in golang so that curl can be removed from the Elasticsearch image.
func main() {
	labelsFilePath := volume.DownwardAPIMountPath + "/" + volume.LabelsFile

	version := ""
	if exists, err := fileExists(labelsFilePath); err != nil {
		fail(fmt.Sprintf("failed to check if file %s exists", labelsFilePath), err)
	} else if exists {
		// Get Elasticsearch version from the downward API
		contents, err := os.ReadFile(labelsFilePath)
		if err != nil {
			fail(fmt.Sprintf("failed to read contents of %s", labelsFilePath), err)
		}

		r := regexp.MustCompile(fmt.Sprintf("%s=(.*)$", label.VersionLabelName))
		if matches := r.FindStringSubmatch(string(contents)); len(matches) == 2 {
			version = strings.Trim(matches[1], "\"")
		}
	}

	rpTimeoutSeconds, err := strconv.Atoi(getEnv("READINESS_PROBE_TIMEOUT", "3"))
	if err != nil {
		fail("invalid readiness probe timeout value", err)
	}

	// Check if PROBE_PASSWORD_PATH is set, otherwise fall back to its former name in 1.0.0.beta-1: PROBE_PASSWORD_FILE
	probePasswordPath := getEnv("PROBE_PASSWORD_FILE", "")
	if len(probePasswordPath) == 0 {
		probePasswordPath = getEnv("PROBE_PASSWORD_PATH", "")
	}

	// setup basic auth if credentials are available
	basicAuth := ""
	probeUserName := getEnv("PROBE_USERNAME", "")
	if len(probeUserName) > 0 {
		if exists, err := fileExists(probePasswordPath); err != nil {
			fail("failed to check if password file exists (error message omitted)", nil)
		} else if exists {
			probePassword, err := os.ReadFile(probePasswordPath)
			if err != nil {
				fail("failed to read password (error message omitted)", nil)
			}

			basicAuth = fmt.Sprintf("%s:%s@", probeUserName, probePassword)
		}
	}

	// Request Elasticsearch on /
	endpoint := fmt.Sprintf("%s://%s127.0.0.1:9200/", getEnv("READINESS_PROBE_PROTOCOL", "https"), basicAuth)

	client := &http.Client{
		Timeout: time.Duration(rpTimeoutSeconds) * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		}},
	}

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		fail("failed to construct readiness probe request", err)
	}
	req.Header.Add(esHttp.InternalProductRequestHeaderKey, esHttp.InternalProductRequestHeaderValue)

	resp, err := client.Do(req)
	if err != nil {
		fail("readiness probe failed", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fail("failed to read readiness probe response body", err)
	}
	if resp.StatusCode != 200 || (resp.StatusCode == 503 && len(version) > 1 && version[0:2] == ".6") {
		fail(fmt.Sprintf("status: %d, body: %s", resp.StatusCode, string(body)), nil)
	}

	os.Exit(0)
}

func fileExists(path string) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func getEnv(key, fallback string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		return fallback
	}
	return value
}

func fail(message string, err error) {
	entry := logrus.NewEntry(logrus.New())
	if err != nil {
		entry = entry.WithError(err)
	}

	entry.Error(message)
	os.Exit(1)
}
