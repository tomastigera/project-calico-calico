// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package managedcluster

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/client/clientset_generated/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
)

// CleanupController is responsible for clearing the installation manifest from ManagedCluster objects.
type CleanupController struct {
	calico clientset.Interface
}

// NewCleanupController returns a new instance of the CleanupController.
func NewCleanupController(calico clientset.Interface) *CleanupController {
	return &CleanupController{calico: calico}
}

// Run starts the cleanup controller.
func (c *CleanupController) Run(ctx context.Context) {
	logrus.Info("Starting ManagedCluster manifest cleanup controller")

	// Create an informer to watch ManagedCluster objects.
	informer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return c.calico.ProjectcalicoV3().ManagedClusters().List(ctx, options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return c.calico.ProjectcalicoV3().ManagedClusters().Watch(ctx, options)
			},
		},
		&v3.ManagedCluster{},
		0,
		cache.Indexers{},
	)

	// Register an event handler to clear the manifest on add.
	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			mc := obj.(*v3.ManagedCluster)
			if mc.Spec.InstallationManifest == "" {
				return
			}

			logrus.WithField("name", mc.Name).Debug("Clearing installation manifest from ManagedCluster")

			// Update the object to clear the manifest.
			updateCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			mcCopy := mc.DeepCopy()
			mcCopy.Spec.InstallationManifest = ""

			_, err := c.calico.ProjectcalicoV3().ManagedClusters().Update(updateCtx, mcCopy, metav1.UpdateOptions{})
			if err != nil {
				logrus.WithError(err).WithField("name", mc.Name).Error("Failed to clear installation manifest from ManagedCluster")
			}
		},
	}); err != nil {
		logrus.WithError(err).Fatal("Failed to register event handler for ManagedCluster cleanup")
	}

	// Start the informer.
	go informer.Run(ctx.Done())

	// Wait for the context to be cancelled.
	<-ctx.Done()
	logrus.Info("Stopping ManagedCluster manifest cleanup controller")
}
