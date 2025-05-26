package fv

import (
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/gateway/pkg/waf"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

var wafEvents []*proto.WAFEvent

func InMemoryLogger(wafEvent *proto.WAFEvent) {
	logrus.Warnf("New WAF event! Need to do something about that! %v", wafEvent)
	wafEvents = append(wafEvents, wafEvent)
}

func setupServer(t *testing.T, opts waf.ServerOptions) func() {
	srv := waf.NewWAFHTTPFilter(opts, InMemoryLogger)

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

		teardownServer()
		logCancel()
	})

	// Make sure the filter is ready
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		client := &http.Client{}
		healthUrl := fmt.Sprintf("http://127.0.0.1:%d/healthz", opts.HttpPort)
		req, err := http.NewRequest("GET", healthUrl, nil)
		require.NoError(c, err)

		resp, err := client.Do(req)
		require.NoError(c, err)

		require.Equal(c, 200, resp.StatusCode)
	}, 10*time.Second, 200*time.Millisecond)
}

func testRequest(t *testing.T, client *http.Client, verb string, url string, headers map[string]string, description string, tests func(resp *http.Response, body string)) {
	t.Run(description, func(t *testing.T) {
		req, err := http.NewRequest(verb, url, nil)
		require.NoError(t, err)

		for key, value := range headers {
			req.Header.Set(key, value)
		}

		resp, err := client.Do(req)
		require.NoError(t, err)

		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		tests(resp, string(body))
	})
}

// Test request against and envoy instance configured to use the waf-http-filter
func TestRequests(t *testing.T) {

	setupTest(t, waf.ServerOptions{
		TcpPort:  9002,
		HttpPort: 8080,
	}, nil)

	client := &http.Client{}

	testRequest(t, client, "GET", "http://127.0.0.1:8000/nothing-suspicious", nil, "not WAF'ed", func(resp *http.Response, body string) {
		require.Equal(t, 200, resp.StatusCode)
		require.Contains(t, body, "/nothing-suspicious")
		require.Empty(t, wafEvents)
	})

	testRequest(t, client, "GET", "http://127.0.0.1:8000/subpath?artist=0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user", nil, "WAF'ed (blocking)", func(resp *http.Response, body string) {
		require.Equal(t, 403, resp.StatusCode)
		require.Contains(t, body, "deny (403)")
		require.Len(t, wafEvents, 1)
	})
}

func TestDisablingWAFHTTPFilter(t *testing.T) {
	setupTest(t, waf.ServerOptions{
		TcpPort:  9002,
		HttpPort: 8080,
	}, []string{"testdata/lds.yaml", "testdata/lds-no-filter.yaml"})

	client := &http.Client{}

	testRequest(t, client, "GET", "http://127.0.0.1:8000/subpath?artist=0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user", nil, "WAF'ed (blocking)", func(resp *http.Response, body string) {
		require.Equal(t, 403, resp.StatusCode)
		require.Contains(t, body, "deny (403)")
		require.Len(t, wafEvents, 1)
	})

	// Replace config with one that does not use the waf-http-filter.
	// We need to use a file move operation so that envoy picks up the config change: https://www.envoyproxy.io/docs/envoy/latest/start/quick-start/configuration-dynamic-filesystem
	cmd := exec.Command("mv", "testdata/lds-no-filter.yaml", "testdata/lds.yaml")
	_, err := cmd.Output()
	require.NoError(t, err)

	// Wait until the envoy config has changed (i.e. the ext_proc filter is no longer used)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		req, err := http.NewRequest("GET", "http://127.0.0.1:8001/config_dump", nil)
		require.NoError(c, err)

		resp, err := client.Do(req)
		require.NoError(c, err)

		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(c, err)

		require.NotContains(c, body, "type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor")
	}, 30*time.Second, 1*time.Second)

	// Close idle connection so that we use a new connection and use the latest envoy config
	client.CloseIdleConnections()

	testRequest(t, client, "GET", "http://127.0.0.1:8000/subpath?artist=0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user", nil, "No active WAF", func(resp *http.Response, body string) {
		require.Equal(t, 200, resp.StatusCode)
		require.Contains(t, body, "/subpath?artist=")
		// The previous event in the same test
		require.Len(t, wafEvents, 1)
	})
}
