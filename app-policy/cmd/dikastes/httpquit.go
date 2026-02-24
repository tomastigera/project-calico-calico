package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"

	log "github.com/sirupsen/logrus"
)

type httpTerminationHandler struct {
	termChan chan struct{}
}

func (h *httpTerminationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	close(h.termChan)
	if _, err := io.WriteString(w, "terminating Dikastes\n"); err != nil {
		log.Fatalf("error writing HTTP response: %v", err)
	}
}

func (h *httpTerminationHandler) RunHTTPServer(addr string, port string) (*http.Server, *sync.WaitGroup, error) {
	if i, err := strconv.Atoi(port); err != nil {
		err = fmt.Errorf("error parsing provided HTTP listen port: %v", err)
		return nil, nil, err
	} else if i < 1 {
		err = fmt.Errorf("please provide non-zero, non-negative port number for HTTP listening port")
		return nil, nil, err
	}

	if addr != "" {
		if ip := net.ParseIP(addr); ip == nil {
			err := fmt.Errorf("invalid HTTP bind address \"%v\"", addr)
			return nil, nil, err
		}
	}

	httpServerSockAddr := fmt.Sprintf("%s:%s", addr, port)
	httpServerMux := http.NewServeMux()
	httpServerMux.Handle("/terminate", h)
	httpServer := &http.Server{Addr: httpServerSockAddr, Handler: httpServerMux}
	httpServerWg := &sync.WaitGroup{}

	httpServerWg.Go(func() {
		log.Infof("starting HTTP server on %v", httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("HTTP server closed unexpectedly: %v", err)
		}
	})
	return httpServer, httpServerWg, nil
}
