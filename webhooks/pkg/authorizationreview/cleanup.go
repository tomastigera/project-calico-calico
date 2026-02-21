// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package authorizationreview

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

// CleanupController is responsible for deleting AuthorizationReview objects as soon as they are created.
type CleanupController struct {
	calico clientset.Interface
}

// NewCleanupController returns a new instance of the CleanupController.
func NewCleanupController(calico clientset.Interface) *CleanupController {
	return &CleanupController{calico: calico}
}

// Run starts the cleanup controller.
func (c *CleanupController) Run(ctx context.Context) {
	logrus.Info("Starting AuthorizationReview cleanup controller")

	// Create an informer to watch AuthorizationReview objects.
	informer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return c.calico.ProjectcalicoV3().AuthorizationReviews().List(ctx, options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return c.calico.ProjectcalicoV3().AuthorizationReviews().Watch(ctx, options)
			},
		},
		&v3.AuthorizationReview{},
		0,
		cache.Indexers{},
	)

	// Register an event handler to delete objects on add.
	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			ar := obj.(*v3.AuthorizationReview)
			logrus.WithField("name", ar.Name).Debug("Deleting ephemeral AuthorizationReview object")

			deleteCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			err := c.calico.ProjectcalicoV3().AuthorizationReviews().Delete(deleteCtx, ar.Name, metav1.DeleteOptions{})
			if err != nil {
				logrus.WithError(err).WithField("name", ar.Name).Error("Failed to delete AuthorizationReview object")
			}
		},
	}); err != nil {
		logrus.WithError(err).Fatal("Failed to register event handler for AuthorizationReview cleanup")
	}

	// Start the informer.
	go informer.Run(ctx.Done())

	// Wait for the context to be cancelled.
	<-ctx.Done()
	logrus.Info("Stopping AuthorizationReview cleanup controller")
}
