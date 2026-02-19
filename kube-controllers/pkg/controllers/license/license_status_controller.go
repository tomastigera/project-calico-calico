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

	// First, update the status fields based on license claims.
	status := claims.Validate()
	switch status {
	case licensing.Valid, licensing.InGracePeriod, licensing.Expired:
		// To be extra permissive, we treat all of these cases as valid licenses so far as status fields are
		// concerned. We'll set a condition indicating the actual license status for visibility.
		p.Status = v3.LicenseKeyStatus{
			Expiry:      metav1.Time{Time: claims.Expiry.Time()},
			GracePeriod: fmt.Sprintf("%dd", claims.GracePeriod),
			MaxNodes:    *claims.Nodes,
			Package:     helpers.ConvertToPackageType(claims.Features),
			Features:    helpers.ExpandFeatureNames(claims.Features),
		}
	default:
		// For any other status, we treat the license as invalid and update the status conditions accordingly.
		setLicenseKeyCondition(p, metav1.Condition{
			Type:    v3.LicenseKeyConditionValid,
			Status:  metav1.ConditionFalse,
			Reason:  v3.LicenseKeyReasonInvalidLicense,
			Message: fmt.Sprintf("License key is %s", status.String()),
		})
	}

	// Now, update the conditions to indicate the specific license status (valid, in grace period, expired, etc.) for visibility.
	switch status {
	case licensing.Valid:
		setLicenseKeyCondition(p, metav1.Condition{
			Type:    v3.LicenseKeyConditionValid,
			Status:  metav1.ConditionTrue,
			Reason:  v3.LicenseKeyReasonValidLicense,
			Message: fmt.Sprintf("License key is valid and expires on %s", claims.Expiry.Time().String()),
		})
	case licensing.InGracePeriod:
		setLicenseKeyCondition(p, metav1.Condition{
			Type:    v3.LicenseKeyConditionValid,
			Status:  metav1.ConditionTrue,
			Reason:  v3.LicenseKeyReasonExpiredLicense,
			Message: "License key is in grace period",
		})
	case licensing.Expired:
		setLicenseKeyCondition(p, metav1.Condition{
			Type:    v3.LicenseKeyConditionValid,
			Status:  metav1.ConditionFalse,
			Reason:  v3.LicenseKeyReasonExpiredLicense,
			Message: fmt.Sprintf("License key is expired (expired on %s)", claims.Expiry.Time().String()),
		})
	default:
		setLicenseKeyCondition(p, metav1.Condition{
			Type:    v3.LicenseKeyConditionValid,
			Status:  metav1.ConditionFalse,
			Reason:  v3.LicenseKeyReasonInvalidLicense,
			Message: fmt.Sprintf("License key is expired (expired on %s)", claims.Expiry.Time().String()),
		})
	}

	_, err = c.cli.ProjectcalicoV3().LicenseKeys().UpdateStatus(context.Background(), p, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update license key status: %w", err)
	}
	return nil
}

// setLicenseKeyCondition sets the specified condition (settings the transition time to now if needed) and returns true
// if the condition was updated or added, and false if the condition was already set to the specified values.
func setLicenseKeyCondition(p *v3.LicenseKey, condition metav1.Condition) bool {
	for i, c := range p.Status.Conditions {
		if c.Type == condition.Type {
			// Condition already exists - check if it needs to be updated.
			if c.Status != condition.Status || c.Reason != condition.Reason || c.Message != condition.Message {
				// Update the existing condition.
				p.Status.Conditions[i].Status = condition.Status
				p.Status.Conditions[i].Reason = condition.Reason
				p.Status.Conditions[i].Message = condition.Message
				p.Status.Conditions[i].LastTransitionTime = metav1.Now()
				return true
			}
			// Condition is already set to the desired values - no update needed.
			return false
		}
	}
	// Condition does not exist - add it.
	condition.LastTransitionTime = metav1.Now()
	p.Status.Conditions = append(p.Status.Conditions, condition)
	return true
}
