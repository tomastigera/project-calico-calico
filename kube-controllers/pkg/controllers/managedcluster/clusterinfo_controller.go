// Copyright (c) 2025 Tigera, Inc. All rights reserved.
package managedcluster

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	tigeraapi "github.com/tigera/api/pkg/client/clientset_generated/clientset"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/kube-controllers/pkg/config"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/controller"
)

// ClusterInfoController watches ManagedCluster resources, retrieves cluster information
// from each respective managed cluster, and updates the version details in its corresponding
// ManagedCluster CR.
type ClusterInfoController struct {
	createManagedK8sCLI func(string) (kubernetes.Interface, tigeraapi.Interface, error)
	client              ctrlclient.WithWatch
	cfg                 config.ManagedClusterControllerConfig
}

type ControllerOption func(*ClusterInfoController) error

func WithCreateManagedK8sCLI(createManagedK8sCLI func(string) (kubernetes.Interface, tigeraapi.Interface, error)) ControllerOption {
	return func(c *ClusterInfoController) error {
		c.createManagedK8sCLI = createManagedK8sCLI
		return nil
	}
}

// WithControllerRuntimeClient configures the controller runtime client used to access managed cluster resources.
func WithControllerRuntimeClient(client ctrlclient.WithWatch) ControllerOption {
	return func(c *ClusterInfoController) error {
		c.client = client
		return nil
	}
}

func WithManagedClusterControllerConfig(cfg config.ManagedClusterControllerConfig) ControllerOption {
	return func(c *ClusterInfoController) error {
		c.cfg = cfg
		return nil
	}
}

func NewClusterInfoController(opts ...ControllerOption) (controller.Controller, error) {
	c := &ClusterInfoController{}
	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}
	if c.cfg.ReconcilerPeriod == 0 {
		c.cfg.ReconcilerPeriod = 60 * time.Minute
	}
	if c.createManagedK8sCLI == nil {
		return nil, fmt.Errorf("must provide a managed Kubernetes client")
	}

	if c.client == nil {
		return nil, fmt.Errorf("must provide a management cluster controller runtime client")
	}

	return c, nil
}

func (c *ClusterInfoController) Run(stopCh chan struct{}) {
	logrus.Info("Starting ClusterInfo Controller")

	// Channels for sending updates.
	mcChan := make(chan *v3.ManagedCluster, 2000)
	defer close(mcChan)

	// Set up event handlers for ManagedCluster resources.
	managedClusterHandler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if mc, ok := obj.(*v3.ManagedCluster); ok && isConnected(mc) {
				mcChan <- mc
			}
		},
		UpdateFunc: func(_, obj interface{}) {
			if mc, ok := obj.(*v3.ManagedCluster); ok && isConnected(mc) {
				mcChan <- mc
			}
		},
		DeleteFunc: func(obj interface{}) {
			// No action needed on delete for now.
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Inititalize informer for watching ManagedCluster resources.
	listWatcher := newManagedClusterListWatcher(ctx, c.client, c.cfg.TenantNamespace)
	mcInformer := cache.NewSharedIndexInformer(listWatcher, &v3.ManagedCluster{}, 0, cache.Indexers{})

	if _, err := mcInformer.AddEventHandler(managedClusterHandler); err != nil {
		logrus.WithError(err).Fatal("Failed to register event handler for ManagedClusters")
	}

	go mcInformer.Run(stopCh)

	c.ManageClusterInfo(
		stopCh,
		mcChan,
		mcInformer,
	)

	<-stopCh
	logrus.Info("Stopping ClusterInfo Controller")
}

func (c *ClusterInfoController) ManageClusterInfo(stop <-chan struct{}, mcChan chan *v3.ManagedCluster, mcInformer cache.SharedIndexInformer) {
	logrus.Info("Started ManageClusterInfo")
	defer logrus.Info("Shutting down ManageClusterInfo")

	ticker := time.After(c.cfg.ReconcilerPeriod)

	for {
		select {
		case <-stop:
			return
		case <-ticker:
			logrus.Debug("Reconciling managedcluster version information for all clusters")

			// Start a new ticker.
			ticker = time.After(c.cfg.ReconcilerPeriod)

			mcs := mcInformer.GetStore().List()
			for _, obj := range mcs {
				mc, ok := obj.(*v3.ManagedCluster)
				if !ok {
					logrus.Warnf("Received unexpected object type in informer store %T", obj)
					continue
				}

				if err := isValid(mc); err == nil && isConnected(mc) {
					mcChan <- mc
				}
			}

		case mc := <-mcChan:
			log := c.loggerForManagedCluster(mc)

			_, managedCalicoCLI, err := c.createManagedK8sCLI(mc.Name)
			if err != nil {
				log.WithError(err).Error("Failed to create calico client for managed cluster")
				// TODO Add retry logic here to requeue
				continue
			}

			if err = c.reconcileClusterInfo(mc, managedCalicoCLI); err != nil {
				log.WithError(err).Error("Failed to reconcile version information for managed cluster")
			}
		}
	}
}

func (c *ClusterInfoController) loggerForManagedCluster(mc *v3.ManagedCluster) *logrus.Entry {
	fields := logrus.Fields{
		"cluster": mc.Name,
	}

	if mc.Namespace != "" {
		fields["namespace"] = mc.Namespace
	}

	if c.cfg.TenantNamespace != "" {
		fields["tenant"] = c.cfg.TenantNamespace
	}

	return logrus.WithFields(fields)
}

func (c *ClusterInfoController) reconcileClusterInfo(mc *v3.ManagedCluster, managedClient tigeraapi.Interface) error {
	log := c.loggerForManagedCluster(mc)

	if err := isValid(mc); err != nil {
		return err
	}
	if !isConnected(mc) {
		log.Debug("ManagedCluster is not connected, skipping reconciliation")
		return nil
	}

	// Attempt to fetch ClusterInformation from the managed cluster.
	ci, err := managedClient.ProjectcalicoV3().ClusterInformations().Get(context.Background(), "default", metav1.GetOptions{})
	if err != nil {
		// Managed clusters older than v3.22 lack the necessary RBAC for the kube-controller to fetch ClusterInformation.
		// Leave the version information unset for now, it would be always be populated in future releases.
		if k8serrors.IsForbidden(err) {
			log.Debugf("Forbidden error while fetching ClusterInformation: %v", err)
			return nil
		}
		log.WithError(err).Error("Failed to get ClusterInformation")
		return err
	}

	// Update ManagedCluster CR with the CNX version, if available.
	if ci != nil && ci.Spec.CNXVersion != "" {
		err := c.updateManagedClusterVersion(mc, ci.Spec.CNXVersion)
		if err != nil {
			log.WithError(err).Error("Failed to update managed cluster CR with newer version")
			return err
		}
	}

	return nil
}

func (c *ClusterInfoController) updateManagedClusterVersion(mc *v3.ManagedCluster, version string) error {
	log := c.loggerForManagedCluster(mc)

	mcToUpdate := &v3.ManagedCluster{}
	// Client Get act as single tenant when the TenantNamespace is empty.
	err := c.client.Get(context.Background(), types.NamespacedName{Name: mc.Name, Namespace: c.cfg.TenantNamespace}, mcToUpdate)
	if err != nil {
		log.WithError(err).Error("Failed to fetch managed cluster resource")
		return err
	}

	// Update the cluster version in the status field.
	mcToUpdate.Status.Version = version

	err = c.client.Update(context.Background(), mcToUpdate)
	if err != nil {
		log.WithError(err).Error("Failed to update managed cluster CR with version information")
		return err
	}
	log.WithField("version", version).Debug("Successfully updated ManagedCluster version")

	return nil
}

func isValid(mc *v3.ManagedCluster) error {
	if mc.Name == "" {
		return fmt.Errorf("managed cluster name is empty")
	}
	return nil
}

func isConnected(mc *v3.ManagedCluster) bool {
	for _, s := range mc.Status.Conditions {
		if s.Type == v3.ManagedClusterStatusTypeConnected {
			return s.Status == v3.ManagedClusterStatusValueTrue
		}
	}
	logrus.WithField("cluster", mc.Name).Debug("ManagedCluster is not connected")
	return false
}
