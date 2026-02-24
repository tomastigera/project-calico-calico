package server

import (
	"context"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/bmizerany/pat"
	log "github.com/sirupsen/logrus"
	calicov3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apiserver/pkg/endpoints/request"

	"github.com/projectcalico/calico/compliance/pkg/api"
	"github.com/projectcalico/calico/compliance/pkg/datastore"
	"github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/projectcalico/calico/lma/pkg/auth"
)

// New creates a new server.
func New(csFactory datastore.ClusterCtxK8sClientFactory, f api.StoreFactory,
	authenticator auth.JWTAuth, addr string, key string, cert string,
) ServerControl {
	s := &server{
		key:       key,
		cert:      cert,
		csFactory: csFactory,
		factory:   f,
	}

	// Create a new pattern matching MUX.
	mux := pat.New()
	mux.Get(UrlVersion, http.HandlerFunc(s.handleVersion))

	// We always authenticate in the local cluster (where server is running). This will add UserInfo to the context.
	// The the UserInfo will be used for authz in the target cluster (which could be a different cluster in a multi-
	// cluster setup.
	mux.Get(UrlList, authenticateRequest(authenticator, s.handleListReports))
	mux.Get(UrlDownload, authenticateRequest(authenticator, s.handleDownloadReports))

	tlsConfig, err := tls.NewTLSConfig()
	if err != nil {
		log.Fatal(err)
	}
	// Create a new server using the MUX.
	s.server = &http.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	return s
}

func authenticateRequest(auth auth.JWTAuth, handlerFunc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		usr, stat, err := auth.Authenticate(req)
		if err != nil {
			log.WithError(err).Debug("Kubernetes auth failure")
			http.Error(w, err.Error(), stat)
			return
		}
		req = req.WithContext(request.WithUser(req.Context(), usr))
		handlerFunc.ServeHTTP(w, req)
	}
}

// server implements the compliance server, and implements the ServerControl interface.
type server struct {
	running   bool
	server    *http.Server
	key       string
	cert      string
	wg        sync.WaitGroup
	factory   api.StoreFactory
	csFactory datastore.ClusterCtxK8sClientFactory

	// Track all of the reports and report types. We don't expect these to change too often, so we only need to
	// update the lists every so often. Access to this data should be through getReportTypes.
	reportLock  sync.RWMutex
	lastUpdate  time.Time
	reportTypes map[string]*calicov3.ReportTypeSpec
}

// Start will start the compliance api server and return. Call Wait() to block until server termination.
func (s *server) Start() {
	if s.key != "" && s.cert != "" {
		log.WithField("Addr", s.server.Addr).Info("Starting HTTPS server")
		s.wg.Go(func() {
			log.Warning(s.server.ListenAndServeTLS(s.cert, s.key))
		})
	} else {
		log.WithField("Addr", s.server.Addr).Info("Starting HTTP server")
		s.wg.Go(func() {
			log.Warning(s.server.ListenAndServe())
		})
	}
	s.running = true
}

// Wait for the compliance server to terminate.
func (s *server) Wait() {
	log.Info("Waiting")
	s.wg.Wait()
}

// Stop the compliance server.
func (s *server) Stop() {
	if s.running {
		log.WithField("Addr", s.server.Addr).Info("Stopping HTTPS server")
		e := s.server.Shutdown(context.Background())
		if e != nil {
			log.Fatal("ServerControl graceful shutdown fail")
			os.Exit(1)
		}
		s.wg.Wait()
		s.running = false
	}
}
