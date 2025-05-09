package fv

import (
	"io"
	"net/http"
	"testing"

	"github.com/projectcalico/calico/gateway/pkg/waf"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func setupServer(t *testing.T, opts waf.ServerOptions) func() {
	srv := waf.NewWafHTTPFilter(opts, waf.DebugLogger)

	// Start the server. It will block until the listen socket is closed,
	// so run it in a goroutine.
	go func() {
		err := srv.Start()
		require.NoError(t, err)
	}()

	return func() {
		err := srv.Stop()
		require.NoError(t, err)
	}
}

func setupTest(t *testing.T, opts waf.ServerOptions) func() {
	logrus.SetLevel(logrus.DebugLevel)
	logCancel := logutils.RedirectLogrusToTestingT(t)

	teardownServer := setupServer(t, opts)

	return func() {
		teardownServer()
		logCancel()
	}
}

// Test request against and envoy instance configured to use the waf-http-filter
func TestRequests(t *testing.T) {

	setupTest(t, waf.ServerOptions{
		TcpPort:  9002,
		HttpPort: 8080,
	})

	client := &http.Client{}

	testRequest := func(t *testing.T, verb string, url string, headers map[string]string, description string, tests func(resp *http.Response, body string)) {
		t.Run(description, func(t *testing.T) {
			req, err := http.NewRequest(verb, url, nil)
			require.NoError(t, err)

			// req.Header.Add("Content-Type", contentType)
			// req.Header.Add("Authorization", "Bearer YOUR_ACCESS_TOKEN")

			resp, err := client.Do(req)
			require.NoError(t, err)

			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			tests(resp, string(body))
		})
	}

	testRequest(t, "GET", "http://127.0.0.1:8000/nothing-suspicious", nil, "not WAF'ed", func(resp *http.Response, body string) {
		require.Equal(t, 200, resp.StatusCode)
		require.Contains(t, body, "/nothing-suspicious")
	})

	testRequest(t, "GET", "http://127.0.0.1:8000/subpath?artist=0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user", nil, "WAF'ed (blocking)", func(resp *http.Response, body string) {
		require.Equal(t, 403, resp.StatusCode)
		require.Contains(t, body, "Sorry you've been WAF'ed!")
	})
}
