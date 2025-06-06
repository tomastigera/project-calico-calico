package waf_test

import (
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/gateway/pkg/waf"
)

func TestHealthCheckService(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel) // Set log level to debug for detailed output

	opts := waf.ServerOptions{
		TcpPort:  5555,
		HttpPort: 8080,
	}

	readyCh := make(chan struct{})
	errorCh := make(chan error, 1)
	wf := waf.NewWAFHTTPFilter(opts, waf.DebugLogger)
	go func() {
		if err := wf.Start(); err != nil {
			errorCh <- err
		}
	}()

	// Wait for the WAF HTTP filter to be listening on the TCP port
	go func() {
		for {
			// Attempt to connect to the WAF HTTP filter
			conn, err := net.DialTCP("tcp", nil, &net.TCPAddr{
				Port: opts.TcpPort,
			})
			if err != nil {
				<-time.After(100 * time.Millisecond) // Wait before retrying
				continue                             // If connection fails, retry
			}
			conn.Close()   // Close the connection if successful
			close(readyCh) // Signal that the WAF HTTP filter is ready
			return
		}
	}()

	// Wait for the WAF HTTP filter to be ready or to encounter an error
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
