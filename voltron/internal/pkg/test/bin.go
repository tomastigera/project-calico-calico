package test

import (
	"crypto/tls"
	"net/http"
	"sync"

	"github.com/onsi/ginkgo"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/voltron/pkg/tunnel"
)

// HTTPSBin is a bin server that listens on the other end of the tunnel.
type HTTPSBin struct {
	srv *http.Server
	wg  sync.WaitGroup
}

// Close stops the HTTPSBin
func (h *HTTPSBin) Close() {
	_ = h.srv.Close()
	h.wg.Wait()
}

// NewHTTPSBin starts a new HTTPSBin. Its parameters can be used to inspect
// the requests and make assertion on it. HTTPSBin will return 200 OK for every request
func NewHTTPSBin(t tunnel.Tunnel, xCert tls.Certificate,
	inspectRequest func(r *http.Request)) *HTTPSBin {

	mux := http.NewServeMux()
	bin := &HTTPSBin{
		srv: &http.Server{
			Handler: mux,
		},
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		defer ginkgo.GinkgoRecover()
		log.Infof("Received request %v", r)
		inspectRequest(r)
	})

	lisTLS := tls.NewListener(t, &tls.Config{
		Certificates: []tls.Certificate{xCert},
		NextProtos:   []string{"h2"},
	})

	bin.wg.Add(1)
	go func() {
		defer bin.wg.Done()
		_ = bin.srv.Serve(lisTLS)
	}()

	return bin
}
