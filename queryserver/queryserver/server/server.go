// Copyright (c) 2018-2023 Tigera, Inc. All rights reserved.
package server

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"

	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/api"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/client"
	"github.com/projectcalico/calico/queryserver/queryserver/auth"
	"github.com/projectcalico/calico/queryserver/queryserver/config"
	"github.com/projectcalico/calico/queryserver/queryserver/handlers"
	authhandler "github.com/projectcalico/calico/queryserver/queryserver/handlers/auth"
	"github.com/projectcalico/calico/queryserver/queryserver/handlers/query"
)

type Server struct {
	authhandler authhandler.AuthHandler
	authorizer  auth.Authorizer
	cfg         *apiconfig.CalicoAPIConfig
	k8sClient   kubernetes.Interface
	servercfg   *config.Config

	server *http.Server
	wg     sync.WaitGroup

	stopCh chan struct{}
}

func NewServer(
	k8sClient kubernetes.Interface,
	cfg *apiconfig.CalicoAPIConfig,
	servercfg *config.Config,
	authenticator authhandler.AuthHandler,
	authorizer auth.Authorizer,
) *Server {
	return &Server{
		authhandler: authenticator,
		authorizer:  authorizer,
		cfg:         cfg,
		k8sClient:   k8sClient,
		servercfg:   servercfg,

		stopCh: make(chan struct{}),
	}
}

// Start the query server.
func (s *Server) Start() error {
	c, err := clientv3.New(*s.cfg)
	if err != nil {
		return err
	}

	sm := http.NewServeMux()
	qh := query.NewQuery(client.NewQueryInterface(s.k8sClient, c, s.stopCh), s.servercfg, s.authorizer)
	sm.HandleFunc("/endpoints", s.authhandler.AuthenticationHandler(qh.Endpoints, authhandler.MethodPOST))
	sm.HandleFunc("/endpoints/", s.authhandler.AuthenticationHandler(qh.Endpoint, authhandler.MethodGET))
	sm.HandleFunc("/nodes", s.authhandler.AuthenticationHandler(qh.Nodes, authhandler.MethodGET))
	sm.HandleFunc("/nodes/", s.authhandler.AuthenticationHandler(qh.Node, authhandler.MethodGET))
	sm.HandleFunc("/summary", s.authhandler.AuthenticationHandler(qh.Summary, authhandler.MethodGET))
	sm.HandleFunc("/metrics", s.authhandler.AuthenticationHandler(qh.Metrics, authhandler.MethodGET))

	// Handler for querying all policies.
	sm.HandleFunc("/policies", s.authhandler.AuthenticationHandler(qh.Policies, authhandler.MethodGET))

	// Legacy handler for querying a specific policy, kept for backward compatibility.
	sm.HandleFunc("/policies/", s.authhandler.AuthenticationHandler(qh.LegacyPolicy, authhandler.MethodGET))

	// Handlers for specific network policy kinds.
	kinds := []string{
		"networkpolicy",
		"stagednetworkpolicy",
		"globalnetworkpolicy",
		"stagedglobalnetworkpolicy",
		"kubernetesnetworkpolicy",
		"stagedkubernetesnetworkpolicy",
		"adminnetworkpolicy",
		"baselineadminnetworkpolicy",
	}
	for _, kind := range kinds {
		sm.HandleFunc(fmt.Sprintf("/%s/", kind), s.authhandler.AuthenticationHandler(qh.GetPolicy, authhandler.MethodGET))
	}

	sm.HandleFunc("/v1/pods/labels",
		s.authhandler.AuthenticationHandler(qh.Labels(api.LabelsResourceTypePods), authhandler.MethodGET))
	sm.HandleFunc("/v1/namespaces/labels",
		s.authhandler.AuthenticationHandler(qh.Labels(api.LabelsResourceTypeNamespaces), authhandler.MethodGET))
	sm.HandleFunc("/v1/serviceaccounts/labels",
		s.authhandler.AuthenticationHandler(qh.Labels(api.LabelsResourceTypeServiceAccounts), authhandler.MethodGET))
	sm.HandleFunc("/projectcalico.org/v3/globalthreatfeeds/labels",
		s.authhandler.AuthenticationHandler(qh.Labels(api.LabelsResourceTypeGlobalThreatFeeds), authhandler.MethodGET))
	sm.HandleFunc("/projectcalico.org/v3/managedclusters/labels",
		s.authhandler.AuthenticationHandler(qh.Labels(api.LabelsResourceTypeManagedClusters), authhandler.MethodGET))
	sm.HandleFunc("/allpolicies/labels",
		s.authhandler.AuthenticationHandler(qh.Labels(api.LabelsResourceTypeAllPolicies), authhandler.MethodGET))
	sm.HandleFunc("/allnetworksets/labels",
		s.authhandler.AuthenticationHandler(qh.Labels(api.LabelsResourceTypeAllNetworkSets), authhandler.MethodGET))

	sm.HandleFunc("/version", handlers.VersionHandler)

	lic := handlers.License{Client: c}
	sm.HandleFunc("/license", s.authhandler.AuthenticationHandler(lic.LicenseHandler, authhandler.MethodGET))
	tlsConfig, err := calicotls.NewTLSConfig()
	if err != nil {
		return err
	}
	s.server = &http.Server{
		Addr:      s.servercfg.ListenAddr,
		Handler:   sm,
		TLSConfig: tlsConfig,
	}
	if s.servercfg.TLSCert != "" && s.servercfg.TLSKey != "" {
		log.WithField("Addr", s.server.Addr).Info("Starting HTTPS server")
		s.wg.Add(1)
		go func() {
			log.Warningf("%v", s.server.ListenAndServeTLS(s.servercfg.TLSCert, s.servercfg.TLSKey))
			<-s.stopCh
			s.wg.Done()
		}()
	} else {
		log.WithField("Addr", s.server.Addr).Info("Starting HTTP server")
		s.wg.Add(1)
		go func() {
			log.Warning(s.server.ListenAndServe())
			<-s.stopCh
			s.wg.Done()
		}()
	}

	return nil
}

// Wait for the query server to terminate.
func (s *Server) Wait() {
	s.wg.Wait()
}

// Stop the query server.
func (s *Server) Stop() {
	if s.server != nil {
		log.WithField("Addr", s.server.Addr).Info("Stopping HTTPS server")
		_ = s.server.Shutdown(context.Background())
		s.server = nil
		close(s.stopCh)
		s.wg.Wait()
	}
}
