// Copyright (c) 2022-2025 Tigera Inc. All rights reserved.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	lincensing_client "github.com/projectcalico/calico/licensing/client"
	"github.com/projectcalico/calico/licensing/client/features"
	"github.com/projectcalico/calico/licensing/monitor"
	linseedclient "github.com/projectcalico/calico/linseed/pkg/client"
	linseedrest "github.com/projectcalico/calico/linseed/pkg/client/rest"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	"github.com/projectcalico/calico/policy-recommendation/pkg/config"
	"github.com/projectcalico/calico/policy-recommendation/pkg/controllers/controller"
	mscontroller "github.com/projectcalico/calico/policy-recommendation/pkg/controllers/managed_cluster"
	rscontroller "github.com/projectcalico/calico/policy-recommendation/pkg/controllers/recommendation_scope"
)

const (
	// minPollInterval duration. The lower bound is set to 30 seconds to avoid excessive polling.
	minPollInterval = 30 * time.Second
)

// backendClientAccessor is an interface to access the backend client from the bapi client.
type backendClientAccessor interface {
	Backend() bapi.Client
}

func main() {
	config, err := config.LoadConfig()
	if err != nil {
		log.WithError(err).Fatal("Failed to load Policy Recommendation config")
	}
	config.InitializeLogging()

	//	Initialize context.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize the client factory. If the tenant namespace is set, we need to impersonate the
	// service account in the tenant namespace.
	clientFactory := lmak8s.NewClientSetFactory(config.MultiClusterForwardingCA,
		config.MultiClusterForwardingEndpoint,
	)
	restConfig := clientFactory.NewRestConfigForApplication(lmak8s.DefaultCluster)
	scheme := runtime.NewScheme()
	if err = v3.AddToScheme(scheme); err != nil {
		log.WithError(err).Fatal("Failed to configure controller runtime client")
	}

	// client is used to get ManagedCluster resources in both single-tenant and multi-tenant modes.
	client, err := ctrlclient.NewWithWatch(restConfig, ctrlclient.Options{Scheme: scheme})
	if err != nil {
		log.WithError(err).Fatal("Failed to configure controller runtime client with watch")
	}

	// Create clientset for application for the standalone (or management) cluster.
	clientSet, err := clientFactory.NewClientSetForApplication(lmak8s.DefaultCluster)
	if err != nil {
		log.WithError(err).Fatal("Failed to create application client for the standalone or management cluster")
	}

	// Create linseed Client.
	linseedClient, err := linseedclient.NewClient(
		config.TenantID,
		linseedrest.Config{
			URL:            config.LinseedURL,
			CACertPath:     config.LinseedCA,
			ClientKeyPath:  config.LinseedClientKey,
			ClientCertPath: config.LinseedClientCert,
		},
		linseedrest.WithTokenPath(config.LinseedToken),
	)
	if err != nil {
		log.WithError(err).Fatal("Failed to create linseed client")
	}

	v3Client, err := clientv3.NewFromEnv()
	if err != nil {
		log.WithError(err).Fatal("Failed to build v3 Calico client")
	}

	// Define callbacks for the license monitor. Any changes send a signal back on the license changed
	// channel.
	licenseMonitor := monitor.New(v3Client.(backendClientAccessor).Backend())
	err = licenseMonitor.RefreshLicense(ctx)
	if err != nil {
		log.WithError(err).Error("failed to get license from datastore; continuing without a license")
	}
	licenseUpdateChan := make(chan struct{})
	licenseMonitor.SetFeaturesChangedCallback(func() {
		licenseUpdateChan <- struct{}{}
	})
	licenseMonitor.SetStatusChangedCallback(func(newLicenseStatus lincensing_client.LicenseStatus) {
		licenseUpdateChan <- struct{}{}
	})

	go func() {
		// Start the license monitor, which will trigger the callback above at start of day and then
		// whenever the license status changes.
		err := licenseMonitor.MonitorForever(context.Background())
		if err != nil {
			log.WithError(err).Warn("Failed to continuously monitoring the license")
		}
	}()

	// Create the standalone or management cluster PolicyRecommendationScope controller.
	rctrl, err := rscontroller.NewRecommendationScopeController(
		ctx,
		lmak8s.DefaultCluster,
		clientSet,
		linseedClient,
		metav1.Duration{Duration: minPollInterval},
		rscontroller.WatcherConfig{
			WatchScope: true,
		},
	)
	if err != nil {
		log.WithError(err).Fatal("Failed to create PolicyRecommendationScope controller")
	}

	var mctrl controller.Controller
	isManagementCluster := config.ClusterConnectionType == "management"
	if isManagementCluster {
		// Create the managed cluster controller. Each managed cluster will have its own
		// PolicyRecommendationScope and Recommendation controllers.
		if config.TenantNamespace != "" {
			// We need to set the impersonation before passing the clientFactory to the managed cluster
			// controller in order to make sure we use this service account when calling managed cluster
			// in a multi-tenant setup. Inside a multi-tenant management setup, we want to be able to use
			// the tenant's service account when querying the management cluster
			impersonationInfo := user.DefaultInfo{
				Name:   "system:serviceaccount:tigera-policy-recommendation:tigera-policy-recommendation",
				Groups: []string{},
			}
			clientFactory = clientFactory.Impersonate(&impersonationInfo)
		}

		managedClusterRecScopeWatcherCfg := rscontroller.WatcherConfig{}
		if config.ManagedClusterType == "calico" {
			managedClusterRecScopeWatcherCfg.WatchTier = true
		} else {
			managedClusterRecScopeWatcherCfg.WatchScope = true
		}
		mctrl, err = mscontroller.NewManagedClusterController(
			ctx,
			client,
			clientFactory,
			linseedClient,
			config.TenantNamespace,
			metav1.Duration{Duration: minPollInterval},
			managedClusterRecScopeWatcherCfg,
		)
		if err != nil {
			log.WithError(err).Fatal("Failed to create ManagedCluster controller")
		}
	}

	// Setup shutdown sigs
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	// Start the controllers if we have a valid license.
	hasLicense := licenseMonitor.GetFeatureStatus(features.PolicyRecommendation)
	stopChan := make(chan struct{})
	controllersRunning := false

	for {
		if hasLicense && !controllersRunning {
			// The controllers run until the stop signal is received.
			log.Info("License status is valid, starting controllers")

			// Start the PolicyRecommendationScope controller for the standalone or management cluster.
			go rctrl.Run(stopChan)

			if isManagementCluster && mctrl != nil {
				// Start the ManagedCluster controller for management clusters only.
				go mctrl.Run(stopChan)
			}

			controllersRunning = true
		} else if !hasLicense && controllersRunning {
			log.Warning("License has expired, stopping controllers")
			controllersRunning = false
			close(stopChan)
		}

		select {
		case <-licenseUpdateChan:
			hasLicense = licenseMonitor.GetFeatureStatus(features.PolicyRecommendation)
			continue
		case <-shutdown:
			log.Info("Exiting")
			return
		}
	}
}
