// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package fv

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/gateway/pkg/license"
	"github.com/projectcalico/calico/gateway/pkg/waf"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

var wafEvents []*proto.WAFEvent
var l *license.FakeGatewayLicense

func InMemoryLogger(wafEvent *proto.WAFEvent) {
	logrus.Warnf("New WAF event! Need to do something about that! %v", wafEvent)
	wafEvents = append(wafEvents, wafEvent)
}

func setupServer(t *testing.T, opts waf.ServerOptions) func() {
	l = &license.FakeGatewayLicense{IsLicenseEnabled: true}
	srv := waf.NewWAFHTTPFilter(opts, l, InMemoryLogger)

	// We keep track of whether we're stopping the server to catch errors on startup
	stopping := false

	// Start the server. It will block until the listen socket is closed,
	// so run it in a goroutine.
	go func() {
		err := srv.Start()
		if !stopping {
			require.NoError(t, err)
		}
	}()

	return func() {
		stopping = true
		wafEvents = nil
		err := srv.Stop()
		require.NoError(t, err)
	}
}

func waitForConfigChange(t require.TestingT, tests func(tt require.TestingT, body string)) {
	transport := &http.Transport{
		DialContext: dialContextFromLocalPort(8001),
	}
	client := &http.Client{
		Transport: transport,
	}

	// Wait until the envoy config has changed
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		req, err := http.NewRequest("GET", "http://example.com:8001/config_dump", nil)
		require.NoError(c, err)

		resp, err := client.Do(req)
		require.NoError(c, err)

		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		require.NoError(c, err)

		tests(c, string(body))

	}, 30*time.Second, 1*time.Second)

	// Close idle connection so that we use a new connection and use the latest envoy config.
	// This is needed because the default http.Client use http.DefaultTransport.
	client.CloseIdleConnections()
}
func setupTest(t *testing.T, opts waf.ServerOptions, filesToBackup []string) {
	logrus.SetLevel(logrus.DebugLevel)
	logCancel := logutils.RedirectLogrusToTestingT(t)

	teardownServer := setupServer(t, opts)

	for _, file := range filesToBackup {
		cmd := exec.Command("cp", file, file+".backup")
		_, err := cmd.Output()
		require.NoError(t, err)
	}

	t.Cleanup(func() {
		for _, file := range filesToBackup {
			cmd := exec.Command("mv", file+".backup", file)
			_, err := cmd.Output()
			require.NoError(t, err)
		}

		waitForConfigChange(t, func(t require.TestingT, config string) {
			require.Contains(t, config, "type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor")
		})

		teardownServer()
		logCancel()
	})

	// Make sure the filter is ready
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		transport := &http.Transport{
			DialContext: dialContextFromLocalPort(opts.HttpPort),
		}
		client := &http.Client{
			Transport: transport,
		}
		healthUrl := fmt.Sprintf("http://example.com:%d/healthz", opts.HttpPort)
		req, err := http.NewRequest("GET", healthUrl, nil)
		require.NoError(c, err)

		resp, err := client.Do(req)
		require.NoError(c, err)

		require.Equal(c, 200, resp.StatusCode)
	}, 10*time.Second, 200*time.Millisecond)

	require.Empty(t, wafEvents)
}

func testRequest(t *testing.T, client *http.Client, verb string, url string, headers map[string]string, description string, tests func(tt require.TestingT, resp *http.Response, body string)) {
	t.Run(description, func(t *testing.T) {
		req, err := http.NewRequest(verb, url, nil)
		require.NoError(t, err)

		for key, value := range headers {
			req.Header.Set(key, value)
		}

		resp, err := client.Do(req)
		require.NoError(t, err)

		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		tests(t, resp, string(body))
	})
}

func testRequestEventually(t *testing.T, client *http.Client, verb string, url string, headers map[string]string, description string, tests func(tt require.TestingT, resp *http.Response, body string)) {
	t.Run(description, func(t *testing.T) {
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			req, err := http.NewRequest(verb, url, nil)
			require.NoError(c, err)

			for key, value := range headers {
				req.Header.Set(key, value)
			}

			resp, err := client.Do(req)
			require.NoError(c, err)

			defer func() { _ = resp.Body.Close() }()

			body, err := io.ReadAll(resp.Body)
			require.NoError(c, err)

			tests(c, resp, string(body))
		}, 30*time.Second, 1*time.Second)

	})
}

// Test request against and envoy instance configured to use the waf-http-filter
func TestRequests(t *testing.T) {

	setupTest(t, waf.ServerOptions{
		TcpPort:  9002,
		HttpPort: 8080,
	}, nil)

	transport := &http.Transport{
		DialContext: dialContextFromLocalPort(8000),
	}
	client := &http.Client{
		Transport: transport,
	}

	testRequest(t, client, "GET", "http://example.com:8000/nothing-suspicious", nil, "not WAF'ed", func(t require.TestingT, resp *http.Response, body string) {
		require.Equal(t, 200, resp.StatusCode)
		require.Contains(t, body, "/nothing-suspicious")
		require.Empty(t, wafEvents)
	})

	testRequest(t, client, "GET", "http://example.com:8000/subpath?artist=0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user", nil, "WAF'ed (detection-only)", func(t require.TestingT, resp *http.Response, body string) {
		require.Equal(t, 200, resp.StatusCode)
		require.Contains(t, body, "/subpath?artist=")
		require.Len(t, wafEvents, 1)
	})
}

func TestDisablingWAFHTTPFilter(t *testing.T) {
	setupTest(t, waf.ServerOptions{
		TcpPort:  9002,
		HttpPort: 8080,
	}, []string{"testdata/lds-no-filter.yaml", "testdata/lds.yaml"})

	client := &http.Client{}

	require.Len(t, wafEvents, 0)
	testRequest(t, client, "GET", "http://127.0.0.1:8000/subpath?artist=0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user", nil, "WAF'ed (detection-only)", func(t require.TestingT, resp *http.Response, body string) {
		require.Equal(t, 200, resp.StatusCode)
		require.Contains(t, body, "/subpath?artist=")
		require.Len(t, wafEvents, 1)
	})

	// Replace config with one that does not use the waf-http-filter.
	// We need to use a file move operation so that envoy picks up the config change: https://www.envoyproxy.io/docs/envoy/latest/start/quick-start/configuration-dynamic-filesystem
	cmd := exec.Command("mv", "testdata/lds-no-filter.yaml", "testdata/lds.yaml")
	_, err := cmd.Output()
	require.NoError(t, err)

	waitForConfigChange(t, func(t require.TestingT, config string) {
		require.NotContains(t, config, "type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor")
	})

	// First request with the new config still uses the old config because update happens in the background so that we don't hold up traffic.
	testRequest(t, client, "GET", "http://127.0.0.1:8000/subpath?artist=0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user", nil, "WAF'ed (detection-only) using old config", func(t require.TestingT, resp *http.Response, body string) {
		require.Equal(t, 200, resp.StatusCode)
		require.Contains(t, body, "/subpath?artist=")
		require.Len(t, wafEvents, 2)
	})

	// By now the new config should be used.
	testRequest(t, client, "GET", "http://127.0.0.1:8000/subpath?artist=0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user", nil, "No active WAF", func(t require.TestingT, resp *http.Response, body string) {
		require.Equal(t, 200, resp.StatusCode)
		require.Contains(t, body, "/subpath?artist=")
		// The previous event in the same test
		require.Len(t, wafEvents, 2)
	})
}

func TestWAFConfig(t *testing.T) {
	setupTest(t, waf.ServerOptions{
		TcpPort:  9002,
		HttpPort: 8080,
	}, []string{"testdata/lds.yaml", "testdata/lds-blocking.yaml"})

	transport := &http.Transport{
		DialContext: dialContextFromLocalPort(8000),
	}
	client := &http.Client{
		Transport: transport,
	}

	testRequest(t, client, "GET", "http://example.com:8000/subpath?artist=0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user", nil, "WAF'ed (detection-only)", func(t require.TestingT, resp *http.Response, body string) {
		require.Equal(t, 200, resp.StatusCode)
		require.Contains(t, body, "subpath?artist=")
		require.Len(t, wafEvents, 1)
	})
	time.Sleep(2 * time.Second)

	// Replace the waf-http-filter config with a blocking WAF.
	cmd := exec.Command("mv", "testdata/lds-blocking.yaml", "testdata/lds.yaml")
	_, err := cmd.Output()
	require.NoError(t, err)

	waitForConfigChange(t, func(t require.TestingT, config string) {
		require.Contains(t, config, "SecRuleEngine On")
	})

	testRequestEventually(t, client, "GET", "http://example.com:8000/subpath?artist=0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user", nil, "WAF'ed (blocking)", func(t require.TestingT, resp *http.Response, body string) {
		require.Equal(t, 403, resp.StatusCode)
		require.Contains(t, body, "deny (403)")
	})

	// Initial sanity test with non-blocking WAF
	require.Equal(t, wafEvents[0].Action, "pass")
	// First request with new config (but used old config because update happens in the background so that we don't hold up traffic)
	require.Equal(t, wafEvents[1].Action, "pass")
	// Eventually the new config is used
	require.Equal(t, wafEvents[len(wafEvents)-1].Action, "deny")
}

func TestUnlicensedBehaviour(t *testing.T) {
	setupTest(t, waf.ServerOptions{
		TcpPort:  9002,
		HttpPort: 8080,
	}, []string{"testdata/lds.yaml", "testdata/lds-blocking.yaml"})

	transport := &http.Transport{
		DialContext: dialContextFromLocalPort(8000),
	}
	client := &http.Client{
		Transport: transport,
	}

	// Setup the waf-http-filter config with a blocking WAF.
	cmd := exec.Command("mv", "testdata/lds-blocking.yaml", "testdata/lds.yaml")
	_, err := cmd.Output()
	require.NoError(t, err)

	waitForConfigChange(t, func(t require.TestingT, config string) {
		require.Contains(t, config, "SecRuleEngine On")
	})

	testRequestEventually(t, client, "GET", "http://example.com:8000/subpath?artist=0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user", nil, "WAF'ed (blocking)", func(t require.TestingT, resp *http.Response, body string) {
		require.Equal(t, 403, resp.StatusCode)
		require.Contains(t, body, "deny (403)")
	})

	// Eventually the new config is used
	require.Equal(t, wafEvents[len(wafEvents)-1].Action, "deny")

	// Keep track of reference index
	initialNumEvents := len(wafEvents)

	// Disable license
	l.IsLicenseEnabled = false

	// Make sure WAF is inactive
	testRequest(t, client, "GET", "http://example.com:8000/subpath?artist=0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user", nil, "WAF'ed (blocking)", func(t require.TestingT, resp *http.Response, body string) {
		require.Equal(t, 200, resp.StatusCode)
		require.Contains(t, body, "subpath?artist=")
		require.Len(t, wafEvents, initialNumEvents)
	})

	// Re-enable license
	l.IsLicenseEnabled = true

	// Make sure WAF is active
	testRequest(t, client, "GET", "http://example.com:8000/subpath?artist=0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user", nil, "WAF'ed (blocking)", func(t require.TestingT, resp *http.Response, body string) {
		require.Equal(t, 403, resp.StatusCode)
		require.Contains(t, body, "deny (403)")
		require.Len(t, wafEvents, initialNumEvents+1)
	})
}

func TestFileLogger(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	logCancel := logutils.RedirectLogrusToTestingT(t)

	opts := waf.ServerOptions{
		TcpPort:              9002,
		HttpPort:             8080,
		LogFileDirectory:     "testdata",
		LogFileName:          "waf.log",
		LogAggregationPeriod: 100 * time.Millisecond,
		MustKeepFields:       []string{"rules"},
	}

	// Create a file logger that writes to a file in the testdata directory.
	fileLogger, stopAggController, err := waf.NewFileLogger(opts.LogFileDirectory, opts.LogFileName, opts.LogAggregationPeriod, opts.MustKeepFields)
	require.NoError(t, err)

	l = &license.FakeGatewayLicense{IsLicenseEnabled: true}
	logFilePath := fmt.Sprintf("%s/%s", opts.LogFileDirectory, opts.LogFileName)

	srv := waf.NewWAFHTTPFilter(opts, l, fileLogger)

	// We keep track of whether we're stopping the server to catch errors on startup
	stopping := false

	// Start the server. It will block until the listen socket is closed,
	// so run it in a goroutine.
	go func() {
		err := srv.Start()
		if !stopping {
			require.NoError(t, err)
		}
	}()

	teardownServer := func() {
		stopping = true
		err := srv.Stop()
		require.NoError(t, err)
	}

	t.Cleanup(func() {
		teardownServer()
		stopAggController()
		logCancel()
		_ = os.Remove(logFilePath)
	})

	// Make sure the filter is ready
	require.EventuallyWithT(t, func(t *assert.CollectT) {
		client := &http.Client{}
		healthUrl := fmt.Sprintf("http://127.0.0.1:%d/healthz", opts.HttpPort)
		req, err := http.NewRequest("GET", healthUrl, nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)

		require.Equal(t, 200, resp.StatusCode)
	}, 10*time.Second, 200*time.Millisecond)

	transport := &http.Transport{
		DialContext: dialContextFromLocalPort(8000),
	}
	client := &http.Client{
		Transport: transport,
	}

	testRequest(t, client, "GET", "http://example.com:8000/subpath?artist=0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user", nil, "WAF'ed (detection-only)", func(t require.TestingT, resp *http.Response, body string) {
		require.Equal(t, 200, resp.StatusCode)
		require.Contains(t, body, "subpath?artist=")
	})

	// Second request to cover log aggreagation too
	testRequest(t, client, "POST", "http://example.com:8000/subpath?artist=0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user", nil, "WAF'ed (detection-only)", func(t require.TestingT, resp *http.Response, body string) {
		require.Equal(t, 200, resp.StatusCode)
		require.Contains(t, body, "subpath?artist=")
	})

	// Check that the log file is eventually created and contains the WAF event.
	require.EventuallyWithT(t, func(t *assert.CollectT) {
		data, err := os.ReadFile(logFilePath)
		require.NoError(t, err)

		lines := strings.Split(string(data), "\n")
		// In the vast majority of cases, the files will contain 2 lines: 1 aggregated WAF log and an empty line.
		if len(lines) == 2 {
			require.Contains(t, lines[0], "WAF detected 3 violations [pass]")
			require.Contains(t, lines[0], "SQL Injection Attack Detected via libinjection")
			require.Contains(t, lines[0], `"count":2`)
			require.Empty(t, lines[1])
			// Rarely (flakes on CI), we get 2 logs that are not aggregated, likely because the aggregation period
			// ended between the 2 requests are being generated.
		} else {
			require.Len(t, lines, 3) // 2 non-aggregated WAF logs and 1 empty line
			require.Contains(t, lines[0], "WAF detected 3 violations [pass]")
			require.Contains(t, lines[0], "SQL Injection Attack Detected via libinjection")
			require.Contains(t, lines[0], `"method":"GET"`)
			require.Contains(t, lines[0], `"count":1`)

			require.Contains(t, lines[1], "WAF detected 3 violations [pass]")
			require.Contains(t, lines[1], "SQL Injection Attack Detected via libinjection")
			require.Contains(t, lines[1], `"method":"POST"`)
			require.Contains(t, lines[1], `"count":1`)

			require.Empty(t, lines[2])
		}

	}, 30*time.Second, 1*time.Second)
}
