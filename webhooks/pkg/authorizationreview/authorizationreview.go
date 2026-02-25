// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package authorizationreview

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/client/clientset_generated/clientset"
	v1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/apiserver/pkg/rbac"
	"github.com/projectcalico/calico/webhooks/pkg/utils"
)

// RegisterHook creates a new AuthorizationReview admission webhook and registers the necessary HTTP handler.
func RegisterHook(k8s kubernetes.Interface, calico clientset.Interface, handleFn utils.HandleFn) {
	logrus.WithFields(logrus.Fields{
		"path": "/authorizationreview",
	}).Info("Registering AuthorizationReview admission webhook")

	handler := NewAuthorizationReviewHook(k8s, calico).Handler()

	// Register the webhook handlers.
	http.HandleFunc("/authorizationreview", handleFn(handler))
}

// StartCleanupController starts the AuthorizationReview cleanup controller.
func StartCleanupController(ctx context.Context, calico clientset.Interface) {
	go NewCleanupController(calico).Run(ctx)
}

// NewAuthorizationReviewHook returns a new instance of the AuthorizationReview admission webhook backend.
func NewAuthorizationReviewHook(k8s kubernetes.Interface, calico clientset.Interface) utils.HandlerProvider {
	calc := rbac.NewCalculator(
		k8s.Discovery(),
		&k8sClusterRoleGetter{k8s},
		&k8sClusterRoleBindingLister{k8s},
		&k8sRoleGetter{k8s},
		&k8sRoleBindingLister{k8s},
		&k8sNamespaceLister{k8s},
		&calicoResourceLister{calico},
		0,
	)
	return &authorizationReviewHook{calculator: calc}
}

// authorizationReviewHook is an admission webhook that implements the Calico v3.AuthorizationReview API.
type authorizationReviewHook struct {
	calculator rbac.Calculator
}

// Handler returns an AdmissionReviewHandler that processes authorization reviews.
func (h *authorizationReviewHook) Handler() utils.AdmissionReviewHandler {
	return utils.NewDelegateToV1AdmitHandler(h.admit)
}

func (h *authorizationReviewHook) admit(ar v1.AdmissionReview) *v1.AdmissionResponse {
	logCtx := logrus.WithFields(logrus.Fields{
		"uid": ar.Request.UID,
	})
	logCtx.Debug("Handling AuthorizationReview")

	if ar.Request.Kind.Kind != v3.KindAuthorizationReview {
		return &v1.AdmissionResponse{Allowed: true}
	}

	// Decode the AuthorizationReview object.
	raw := ar.Request.Object.Raw
	in := &v3.AuthorizationReview{}
	deserializer := utils.Codecs.UniversalDeserializer()
	if _, _, err := deserializer.Decode(raw, nil, in); err != nil {
		logCtx.WithError(err).Error("Failed to decode AuthorizationReview")
		return &v1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Status:  metav1.StatusFailure,
				Message: fmt.Sprintf("Failed to decode AuthorizationReview: %v", err),
				Reason:  metav1.StatusReasonBadRequest,
			},
		}
	}

	// Calculate the permissions.
	out, err := h.calculatePermissions(in, ar.Request)
	if err != nil {
		logCtx.WithError(err).Error("Failed to calculate permissions")
		return &v1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Status:  metav1.StatusFailure,
				Message: fmt.Sprintf("Failed to calculate permissions: %v", err),
				Reason:  metav1.StatusReasonInternalError,
			},
		}
	}

	// Create a patch to update the status.
	patch := []map[string]any{
		{
			"op":    "replace",
			"path":  "/status",
			"value": out.Status,
		},
	}
	patchBytes, err := json.Marshal(patch)
	if err != nil {
		logCtx.WithError(err).Error("Failed to marshal patch")
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

func (h *authorizationReviewHook) calculatePermissions(in *v3.AuthorizationReview, req *v1.AdmissionRequest) (*v3.AuthorizationReview, error) {
	out := &v3.AuthorizationReview{
		TypeMeta:   in.TypeMeta,
		ObjectMeta: in.ObjectMeta,
		Spec:       in.Spec,
	}

	var userInfo user.Info

	if in.Spec.User != "" {
		// Extract user from spec
		userInfo = &user.DefaultInfo{
			Name:   in.Spec.User,
			UID:    in.Spec.UID,
			Groups: in.Spec.Groups,
		}
	} else {
		// Extract user info from the request.
		extra := map[string][]string{}
		for k, v := range req.UserInfo.Extra {
			extra[k] = v
		}
		userInfo = &user.DefaultInfo{
			Name:   req.UserInfo.Username,
			UID:    req.UserInfo.UID,
			Groups: req.UserInfo.Groups,
			Extra:  extra,
		}
	}

	// Expand the request into a set of ResourceVerbs as input to the RBAC calculator.
	rvs := rbac.RequestToResourceVerbs(in.Spec.ResourceAttributes)

	// Calculate the set of permissions.
	results, err := h.calculator.CalculatePermissions(userInfo, rvs)
	if err != nil {
		return nil, err
	}

	// Transfer the results to the status.
	out.Status = rbac.PermissionsToStatus(results)

	return out, nil
}

// k8sRoleGetter implements the RoleGetter interface returning matching Role.
type k8sRoleGetter struct {
	cs kubernetes.Interface
}

func (r *k8sRoleGetter) GetRole(ctx context.Context, namespace, name string) (*rbacv1.Role, error) {
	return r.cs.RbacV1().Roles(namespace).Get(ctx, name, metav1.GetOptions{})
}

// k8sRoleBindingLister implements the RoleBindingLister interface returning RoleBindings.
type k8sRoleBindingLister struct {
	cs kubernetes.Interface
}

func (r *k8sRoleBindingLister) ListRoleBindings(ctx context.Context, namespace string) ([]*rbacv1.RoleBinding, error) {
	list, err := r.cs.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	res := make([]*rbacv1.RoleBinding, len(list.Items))
	for i := range list.Items {
		res[i] = &list.Items[i]
	}
	return res, nil
}

// k8sClusterRoleGetter implements the ClusterRoleGetter interface returning matching ClusterRole.
type k8sClusterRoleGetter struct {
	cs kubernetes.Interface
}

func (r *k8sClusterRoleGetter) GetClusterRole(ctx context.Context, name string) (*rbacv1.ClusterRole, error) {
	return r.cs.RbacV1().ClusterRoles().Get(ctx, name, metav1.GetOptions{})
}

// k8sClusterRoleBindingLister implements the ClusterRoleBindingLister interface.
type k8sClusterRoleBindingLister struct {
	cs kubernetes.Interface
}

func (r *k8sClusterRoleBindingLister) ListClusterRoleBindings(ctx context.Context) ([]*rbacv1.ClusterRoleBinding, error) {
	list, err := r.cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	res := make([]*rbacv1.ClusterRoleBinding, len(list.Items))
	for i := range list.Items {
		res[i] = &list.Items[i]
	}
	return res, nil
}

// k8sNamespaceLister implements the NamespaceLister interface returning Namespaces.
type k8sNamespaceLister struct {
	cs kubernetes.Interface
}

func (n *k8sNamespaceLister) ListNamespaces() ([]*corev1.Namespace, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	list, err := n.cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	res := make([]*corev1.Namespace, len(list.Items))
	for i := range list.Items {
		res[i] = &list.Items[i]
	}
	return res, nil
}

type calicoResourceLister struct {
	calico clientset.Interface
}

func (t *calicoResourceLister) ListTiers() ([]*v3.Tier, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	list, err := t.calico.ProjectcalicoV3().Tiers().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	res := make([]*v3.Tier, len(list.Items))
	for i := range list.Items {
		res[i] = &list.Items[i]
	}
	return res, nil
}

func (t *calicoResourceLister) ListUISettingsGroups() ([]*v3.UISettingsGroup, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	list, err := t.calico.ProjectcalicoV3().UISettingsGroups().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	res := make([]*v3.UISettingsGroup, len(list.Items))
	for i := range list.Items {
		res[i] = &list.Items[i]
	}
	return res, nil
}

func (t *calicoResourceLister) ListManagedClusters() ([]*v3.ManagedCluster, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	list, err := t.calico.ProjectcalicoV3().ManagedClusters().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	res := make([]*v3.ManagedCluster, len(list.Items))
	for i := range list.Items {
		res[i] = &list.Items[i]
	}
	return res, nil
}
