// Copyright (c) 2018-2026 Tigera, Inc. All rights reserved.
package main

import (
	"flag"
	"os"
	"time"

	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"
	"github.com/tigera/api/pkg/client/clientset_generated/clientset"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	lsrest "github.com/projectcalico/calico/linseed/pkg/client/rest"
	"github.com/projectcalico/calico/pkg/buildinfo"
	"github.com/projectcalico/calico/queryserver/pkg/clientmgr"
	authjwt "github.com/projectcalico/calico/queryserver/queryserver/auth"
	"github.com/projectcalico/calico/queryserver/queryserver/config"
	handler "github.com/projectcalico/calico/queryserver/queryserver/handlers/auth"
	"github.com/projectcalico/calico/queryserver/queryserver/server"
	"github.com/projectcalico/calico/ui-apis/pkg/authzreview"
)

// Client Config from environment option.
const cfFromEnv = ""

// These are filled out during the build process (using git describe output)
var version bool

func init() {
	// Add a flag to check the version.
	flag.BoolVar(&version, "version", false, "Display version")
}

func main() {
	flag.Parse()
	if version {
		buildinfo.PrintVersion()
		os.Exit(0)
	}

	// Set the logging level (default to warning).
	logLevel := log.WarnLevel
	logLevelStr := os.Getenv("LOGLEVEL")
	if logLevelStr != "" {
		logLevel = logutils.SafeParseLogLevel(logLevelStr)
	}
	log.SetLevel(logLevel)

	// Load the client config. Currently, we only support loading from environment.
	cfg, err := clientmgr.LoadClientConfig(cfFromEnv)
	if err != nil {
		log.Error("Error loading config")
	}
	log.Infof("Loaded client config: %#v", cfg.Spec)

	// Get server config from environments.
	serverCfg := &config.Config{}
	err = envconfig.Process("", serverCfg)
	if err != nil {
		log.WithError(err).Fatal("Error getting server config")
	}

	// Create a rest config from supplied kubeconfig.
	kubeconfig := os.Getenv("KUBECONFIG")
	restCfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		log.WithError(err).Fatal("Error processing kubeconfig file in environment variable KUBECONFIG")
	}
	restCfg.Timeout = 15 * time.Second
	restCfg.Burst = serverCfg.K8sClientBurst
	restCfg.QPS = serverCfg.K8sClientQPS

	// Create a k8s and calico v3 clientset, and associated informer factories.
	k8sClient, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		log.WithError(err).Fatal("Failed to load k8s client")
	}

	// Define a new authentication handler.
	authJWT, err := authjwt.GetJWTAuth(serverCfg, restCfg, k8sClient)
	if err != nil {
		log.WithError(err).Fatal("Failed to create authenticator")
	}
	authnHandler := handler.NewAuthHandler(authJWT)

	// Create a Calico clientset for the RBAC calculator.
	calicoClient, err := clientset.NewForConfig(restCfg)
	if err != nil {
		log.WithError(err).Fatal("Failed to create Calico clientset")
	}

	// Create an RBAC Reviewer that evaluates permissions directly, avoiding
	// the extra hop to ui-apis. No ClientSetFactory needed since queryserver
	// only reviews the local cluster.
	reviewer := authzreview.NewAuthzReviewer(authzreview.NewCalculator(k8sClient, calicoClient), nil)
	authzHandler := authjwt.NewAuthorizer(reviewer)

	// Create the linseed client for policy activity enrichment.
	if serverCfg.LinseedClientCert == "" || serverCfg.LinseedClientKey == "" {
		log.Fatal("Linseed client cert/key not configured; queryserver requires Linseed for policy activity enrichment")
	}
	linseedClient, err := lsclient.NewClient(
		serverCfg.TenantID,
		lsrest.Config{
			URL:            serverCfg.LinseedURL,
			CACertPath:     serverCfg.LinseedCA,
			ClientKeyPath:  serverCfg.LinseedClientKey,
			ClientCertPath: serverCfg.LinseedClientCert,
		},
		lsrest.WithTokenPath(serverCfg.LinseedToken),
	)
	if err != nil {
		log.WithError(err).Fatal("Failed to create linseed client")
	}
	serverCfg.LinseedPolicyActivity = linseedClient.PolicyActivity(serverCfg.ClusterID)

	// Start the server.
	srv := server.NewServer(k8sClient, cfg, serverCfg, authnHandler, authzHandler)
	if err := srv.Start(); err != nil {
		log.WithError(err).Fatal("Error starting queryserver")
	}

	// Wait while the server is running.
	srv.Wait()
}
