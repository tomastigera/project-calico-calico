// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package license

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/client/clientset_generated/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/apiserver/pkg/helpers"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/controller"
	licensing "github.com/projectcalico/calico/licensing/client"
)

// LicenseStatusController is responsible for watching LicenseKey objects and maintaining the status of the license.
// This controller is only used when running without an API server - when the Calico aggregation API server is in use,
// the API server is responsible for maintaining the status of the license key and this controller is not started.
type LicenseStatusController struct {
	ctx context.Context

	// For syncing node objects from the k8s API.
	informer cache.SharedIndexInformer

	cli clientset.Interface
}

func NewStatusController(
	ctx context.Context,
	cli clientset.Interface,
	informer cache.SharedIndexInformer,
) controller.Controller {
	c := &LicenseStatusController{
		ctx:      ctx,
		cli:      cli,
		informer: informer,
	}

	// Configure events for new IP pools.
	handlers := cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj any) {},
		AddFunc: func(obj any) {
			logrus.WithField("name", obj.(*v3.LicenseKey).Name).Info("Handling LicenseKey add")
			if err := c.Reconcile(obj.(*v3.LicenseKey)); err != nil {
				logrus.WithError(err).Error("Error handling LicenseKey add")
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			logrus.WithField("name", newObj.(*v3.LicenseKey).Name).Info("Handling LicenseKey update")
			if err := c.Reconcile(newObj.(*v3.LicenseKey)); err != nil {
				logrus.WithError(err).Error("Error handling LicenseKey update")
			}
		},
	}
	if _, err := informer.AddEventHandler(handlers); err != nil {
		logrus.WithError(err).Fatal("Failed to register event handler for LicenseStatus")
	}
	return c
}

func (c *LicenseStatusController) Run(stopCh chan struct{}) {
	defer uruntime.HandleCrash()

	logrus.Info("Starting LicenseStatus controller")

	// Wait till k8s cache is synced
	logrus.Debug("Waiting to sync with Kubernetes API")
	if !cache.WaitForNamedCacheSync("pools", stopCh, c.informer.HasSynced) {
		logrus.Info("Failed to sync resources, received signal for controller to shut down.")
		return
	}

	logrus.Debug("Finished syncing with Kubernetes API")

	<-stopCh
	logrus.Info("Stopping LicenseStatus controller")
}

func (c *LicenseStatusController) Reconcile(p *v3.LicenseKey) error {
	logCtx := logrus.WithFields(logrus.Fields{
		"name": p.Name,
	})
	logCtx.Debug("Reconciling LicenseKey Status")

	claims, err := licensing.Decode(*p)
	if err != nil {
		return fmt.Errorf("failed to decode license key: %w", err)
	}

	p.Status = v3.LicenseKeyStatus{
		Expiry:   metav1.Time{Time: claims.Expiry.Time()},
		MaxNodes: *claims.Nodes,
		Package:  helpers.ConvertToPackageType(claims.Features),
		Features: helpers.ExpandFeatureNames(claims.Features),
	}
	_, err = c.cli.ProjectcalicoV3().LicenseKeys().UpdateStatus(context.Background(), p, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update license key status: %w", err)
	}
	return nil
}
