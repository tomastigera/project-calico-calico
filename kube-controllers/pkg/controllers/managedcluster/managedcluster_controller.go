// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.

package managedcluster

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	tigeraapi "github.com/tigera/api/pkg/client/clientset_generated/clientset"
	"k8s.io/client-go/kubernetes"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/kube-controllers/pkg/config"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/controller"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/worker"
	"github.com/projectcalico/calico/pkg/managedcluster"
)

// ControllerManager is an interface for managing controllers that run for managed clusters. This abstraction obscures
// the implementation details of the underlying controller so that the managedClusterController does nothing but
// watch for managed clusters and pass changes to the ControllerManagers configured. This interface allows for the
// following:
// - Running an initial startup function that runs once when the managedClusterController starts up (Initialize).
// - Creating a controller for a new managed cluster (CreateController).
// - Handle the removal of a managed cluster (HandleManagedClusterRemoved).
type ControllerManager interface {
	// Initialize is called once when the managedClusterController starts up, and is used for any work that the
	// underlying controller needs done before it's run for the managed cluster.
	Initialize(stop chan struct{}, clusters ...string)
	// CreateController creates the controller this manager wraps, passing in the managed cluster information.
	CreateController(clusterName, ownerReference string, managedK8sCLI,
		managementK8sCLI kubernetes.Interface,
		managedCalicoCLI, managementCalicoCLI tigeraapi.Interface,
		restartChan chan<- string) controller.Controller
	// HandleManagedClusterRemoved is called whenever a managed cluster is removed, and is used for any clean up work
	// the underlying controller needs to do when a managed cluster is removed.
	HandleManagedClusterRemoved(clusterName string)
}

// managedClusterController watches for the addition and removal of managed clusters (by watching the ManagedCluster
// resource) and notifies the given ControllerManagers with that information.
type managedClusterController struct {
	createManagedK8sCLI func(string) (kubernetes.Interface, *tigeraapi.Clientset, error)
	clientSetFactory    *tigeraapi.Clientset
	client              ctrlclient.WithWatch
	cfg                 config.ManagedClusterControllerConfig
	kubeClientSet       *kubernetes.Clientset
	restartChan         chan<- string
	controllers         []ControllerManager
}

func New(
	createManagedK8sCLI func(string) (kubernetes.Interface, *tigeraapi.Clientset, error),
	kubeClientSet *kubernetes.Clientset,
	clientSetFactory *tigeraapi.Clientset,
	client ctrlclient.WithWatch,
	cfg config.ManagedClusterControllerConfig,
	restartChan chan<- string,
	controllers []ControllerManager,
) controller.Controller {

	return &managedClusterController{
		createManagedK8sCLI: createManagedK8sCLI,
		clientSetFactory:    clientSetFactory,
		client:              client,
		cfg:                 cfg,
		kubeClientSet:       kubeClientSet,
		restartChan:         restartChan,
		controllers:         controllers,
	}
}

// fetchRegisteredManagedClustersNames returns the name for the managed cluster as set or an error
// if the requests to k8s API failed
func (c *managedClusterController) fetchRegisteredManagedClustersNames(stop chan struct{}) []string {
	success := false
	waitTime := 5 * time.Second

	var err error
	managedClusters := &v3.ManagedClusterList{}
	for !success {
		select {
		case <-stop:
			return nil
		default:
			if err = c.client.List(context.Background(), managedClusters, &ctrlclient.ListOptions{Namespace: c.cfg.TenantNamespace}); err != nil {
				log.WithError(err).Error("Failed to clean up Elasticsearch users")
				time.Sleep(waitTime)
				continue
			}
			success = true
		}
	}

	var registeredClusters []string
	for _, managedCluster := range managedClusters.Items {
		registeredClusters = append(registeredClusters, managedCluster.Name)
	}

	return registeredClusters
}

func (c *managedClusterController) Run(stop chan struct{}) {
	clusterNames := c.fetchRegisteredManagedClustersNames(stop)
	for _, controller := range c.controllers {
		controller.Initialize(stop, clusterNames...)
	}

	mcReconciler := &reconciler{
		createManagedK8sCLI:      c.createManagedK8sCLI,
		kubeClientSet:            c.kubeClientSet,
		client:                   c.client,
		managedClustersStopChans: make(map[string]chan struct{}),
		restartChan:              c.restartChan,
		clientSetFactory:         c.clientSetFactory,
		controllers:              c.controllers,
		TenantNamespace:          c.cfg.TenantNamespace,
	}

	listWatcher := managedcluster.NewManagedClusterListWatcher(context.Background(), c.client, c.cfg.TenantNamespace)

	// Watch the ManagedCluster resources for changes
	managedClusterWorker := worker.New(mcReconciler)
	managedClusterWorker.AddWatch(listWatcher, &v3.ManagedCluster{})
	go managedClusterWorker.Run(c.cfg.NumberOfWorkers, stop)

	<-stop
}
