package waf_test

import (
	"net/http"
	"testing"

	"github.com/projectcalico/calico/gateway/pkg/waf"
	"github.com/sirupsen/logrus"
)

func TestHealthCheckService(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel) // Set log level to debug for detailed output
	//sockPath := filepath.Join(t.TempDir(), "waf.sock")
	opts := waf.ServerOptions{
		TcpPort:           5555,
		HttpPort:          8080,
		SocketPath:        "",
		WafRulesetRootDir: "",
		LogToFile:         false,
	}
	readyCh := make(chan struct{})
	errorCh := make(chan error, 1)
	wf := waf.NewWAFHTTPFilter(opts, waf.DebugLogger)
	go func() {
		if err := wf.Start(readyCh); err != nil {
			errorCh <- err
		}
	}()
	select {
	case <-readyCh:
		t.Log("WAF HTTP filter is ready")
	case err := <-errorCh:
		t.Fatalf("Failed to start WAF HTTP filter: %v", err)
	}
	// Perform health check with http
	resp, err := http.Get("http://localhost:8080/healthz")
	if err != nil {
		t.Fatalf("Failed to perform health check: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected HTTP status 200 OK, got %d", resp.StatusCode)
	}
	t.Logf("Health check passed with status: %d", resp.StatusCode)
	if err := wf.Stop(); err != nil { // Stop the WAF HTTP filter after tests
		t.Fatalf("Failed to stop WAF HTTP filter: %v", err)
	}

}
