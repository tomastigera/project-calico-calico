// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package managedcluster

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/client/clientset_generated/clientset"
	v1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/apiserver/pkg/helpers"
	"github.com/projectcalico/calico/webhooks/pkg/utils"
)

type ManagedClusterHook struct {
	k8sClient               kubernetes.Interface
	managementClusterAddr   string
	managementClusterCAType string
	tunnelSecretName        string
	multiTenant             bool
}

func RegisterHook(
	k8sClient kubernetes.Interface,
	managementClusterAddr string,
	managementClusterCAType string,
	tunnelSecretName string,
	multiTenant bool,
	handleFn utils.HandleFn,
) {
	logrus.WithFields(logrus.Fields{
		"path": "/managedcluster",
	}).Info("Registering ManagedCluster admission webhook")

	handler := &ManagedClusterHook{
		k8sClient:               k8sClient,
		managementClusterAddr:   managementClusterAddr,
		managementClusterCAType: managementClusterCAType,
		tunnelSecretName:        tunnelSecretName,
		multiTenant:             multiTenant,
	}

	http.HandleFunc("/managedcluster", handleFn(handler.Handler()))
}

// StartCleanupController starts the ManagedCluster manifest cleanup controller.
func StartCleanupController(ctx context.Context, calico clientset.Interface) {
	go NewCleanupController(calico).Run(ctx)
}

func (h *ManagedClusterHook) Handler() utils.AdmissionReviewHandler {
	return utils.NewDelegateToV1AdmitHandler(h.admit)
}

func (h *ManagedClusterHook) admit(ar v1.AdmissionReview) *v1.AdmissionResponse {
	if ar.Request.Kind.Kind != v3.KindManagedCluster {
		return &v1.AdmissionResponse{Allowed: true}
	}

	raw := ar.Request.Object.Raw
	mc := &v3.ManagedCluster{}
	deserializer := utils.Codecs.UniversalDeserializer()
	if _, _, err := deserializer.Decode(raw, nil, mc); err != nil {
		return &v1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Status:  metav1.StatusFailure,
				Message: fmt.Sprintf("Failed to decode ManagedCluster: %v", err),
				Reason:  metav1.StatusReasonBadRequest,
			},
		}
	}

	if ar.Request.Operation == v1.Create {
		if len(mc.Spec.Certificate) == 0 {
			namespace := "calico-system"
			if h.multiTenant {
				namespace = mc.Namespace
			}

			fingerprint, manifest, err := helpers.PrepareManagedCluster(
				context.Background(),
				h.k8sClient,
				mc,
				h.tunnelSecretName,
				namespace,
				h.managementClusterAddr,
				h.managementClusterCAType,
			)
			if err != nil {
				return &v1.AdmissionResponse{
					Allowed: false,
					Result: &metav1.Status{
						Status:  metav1.StatusFailure,
						Message: fmt.Sprintf("Failed to prepare managed cluster: %v", err),
						Reason:  metav1.StatusReasonInternalError,
					},
				}
			}

			// Mutate the object
			if mc.Annotations == nil {
				mc.Annotations = make(map[string]string)
			}
			mc.Annotations[helpers.AnnotationActiveCertificateFingerprint] = fingerprint
			mc.Spec.InstallationManifest = manifest

			patch := []map[string]any{
				{
					"op":    "replace",
					"path":  "/metadata/annotations",
					"value": mc.Annotations,
				},
				{
					"op":    "replace",
					"path":  "/spec/installationManifest",
					"value": mc.Spec.InstallationManifest,
				},
			}
			patchBytes, err := json.Marshal(patch)
			if err != nil {
				return &v1.AdmissionResponse{
					Allowed: false,
					Result: &metav1.Status{
						Status:  metav1.StatusFailure,
						Message: fmt.Sprintf("Failed to marshal patch: %v", err),
						Reason:  metav1.StatusReasonInternalError,
					},
				}
			}
			patchType := v1.PatchTypeJSONPatch
			return &v1.AdmissionResponse{
				Allowed:   true,
				Patch:     patchBytes,
				PatchType: &patchType,
			}
		}
	}

	return &v1.AdmissionResponse{Allowed: true}
}
