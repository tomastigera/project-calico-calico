// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package uisettings

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/client/clientset_generated/clientset"
	v1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/webhooks/pkg/utils"
)

// RegisterHook creates a new UISettings admission webhook and registers the HTTP handler at /uisettings.
func RegisterHook(cs kubernetes.Interface, calico clientset.Interface, handleFn utils.HandleFn) {
	logrus.WithFields(logrus.Fields{
		"path": "/uisettings",
	}).Info("Registering UISettings admission webhook")

	handler := &uiSettingsHook{
		k8sClient:    cs,
		calicoClient: calico,
	}
	http.HandleFunc("/uisettings", handleFn(handler.Handler()))
}

// uiSettingsHook handles admission requests for UISettings resources, performing authorization,
// mutation (on Create), and immutability validation (on Update).
type uiSettingsHook struct {
	k8sClient    kubernetes.Interface
	calicoClient clientset.Interface
}

// Handler returns the admission review handler for UISettings.
func (h *uiSettingsHook) Handler() utils.AdmissionReviewHandler {
	return utils.NewDelegateToV1AdmitHandler(h.admit)
}

func (h *uiSettingsHook) admit(ar v1.AdmissionReview) *v1.AdmissionResponse {
	if ar.Request.Kind.Kind != v3.KindUISettings {
		return &v1.AdmissionResponse{Allowed: true}
	}

	logCtx := logrus.WithFields(logrus.Fields{
		"uid":       ar.Request.UID,
		"operation": ar.Request.Operation,
		"name":      ar.Request.Name,
		"user":      ar.Request.UserInfo.Username,
	})
	logCtx.Debug("Handling UISettings admission review")

	switch ar.Request.Operation {
	case v1.Create:
		return h.handleCreate(logCtx, ar)
	case v1.Update:
		return h.handleUpdate(logCtx, ar)
	case v1.Delete:
		return h.handleDelete(logCtx, ar)
	default:
		return &v1.AdmissionResponse{Allowed: true}
	}
}

// handleCreate performs authorization, validates the UISettingsGroup exists, and returns a JSON patch
// that sets the ownerReference and (for User filter groups) the spec.user field.
func (h *uiSettingsHook) handleCreate(logCtx *logrus.Entry, ar v1.AdmissionReview) *v1.AdmissionResponse {
	uiSettings, resp := decodeUISettings(ar.Request.Object.Raw)
	if resp != nil {
		return resp
	}

	groupName := uiSettings.Spec.Group
	if groupName == "" {
		return denied(metav1.StatusReasonBadRequest, "spec.group is not specified")
	}

	// Authorize the operation against the UISettingsGroup.
	if resp := h.authorize(logCtx, ar, groupName); resp != nil {
		return resp
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Verify the UISettingsGroup exists and fetch it for the ownerReference.
	group, err := h.calicoClient.ProjectcalicoV3().UISettingsGroups().Get(ctx, groupName, metav1.GetOptions{})
	if err != nil {
		logCtx.WithError(err).Warn("Failed to get UISettingsGroup")
		return denied(metav1.StatusReasonBadRequest, fmt.Sprintf("failed to get UISettingsGroup %q: %v", groupName, err))
	}

	// Build the JSON patch to set the ownerReference.
	ownerRef := BuildGroupOwnerReference(group)
	patch := []jsonPatchOp{
		{Op: "add", Path: "/metadata/ownerReferences", Value: []metav1.OwnerReference{ownerRef}},
	}

	// If the group uses per-user filtering, inject the requesting user into spec.user.
	if ShouldInjectUser(group) {
		patch = append(patch, jsonPatchOp{
			Op:    "add",
			Path:  "/spec/user",
			Value: ar.Request.UserInfo.Username,
		})
	}

	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return denied(metav1.StatusReasonInternalError, fmt.Sprintf("failed to marshal patch: %v", err))
	}

	patchType := v1.PatchTypeJSONPatch
	logCtx.Debug("UISettings create authorized, returning patch")
	return &v1.AdmissionResponse{
		Allowed:   true,
		Patch:     patchBytes,
		PatchType: &patchType,
	}
}

// handleUpdate performs authorization and validates that immutable fields haven't changed.
func (h *uiSettingsHook) handleUpdate(logCtx *logrus.Entry, ar v1.AdmissionReview) *v1.AdmissionResponse {
	newSettings, resp := decodeUISettings(ar.Request.Object.Raw)
	if resp != nil {
		return resp
	}
	oldSettings, resp := decodeUISettings(ar.Request.OldObject.Raw)
	if resp != nil {
		return resp
	}

	groupName := oldSettings.Spec.Group
	if groupName == "" {
		return denied(metav1.StatusReasonBadRequest, "spec.group is not set on existing resource")
	}

	// Authorize the operation.
	if resp := h.authorize(logCtx, ar, groupName); resp != nil {
		return resp
	}

	// Validate immutable fields.
	if err := ValidateImmutableFields(oldSettings, newSettings); err != nil {
		return denied(metav1.StatusReasonForbidden, err.Error())
	}

	logCtx.Debug("UISettings update authorized")
	return &v1.AdmissionResponse{Allowed: true}
}

// handleDelete performs authorization only. On DELETE the object is in OldObject.
func (h *uiSettingsHook) handleDelete(logCtx *logrus.Entry, ar v1.AdmissionReview) *v1.AdmissionResponse {
	uiSettings, resp := decodeUISettings(ar.Request.OldObject.Raw)
	if resp != nil {
		return resp
	}

	groupName := uiSettings.Spec.Group
	if groupName == "" {
		return denied(metav1.StatusReasonBadRequest, "spec.group is not set on existing resource")
	}

	if resp := h.authorize(logCtx, ar, groupName); resp != nil {
		return resp
	}

	logCtx.Debug("UISettings delete authorized")
	return &v1.AdmissionResponse{Allowed: true}
}

// authorize performs the two SubjectAccessReview checks required for UISettings operations:
// 1. GET access on the UISettingsGroup resource
// 2. The request verb on the UISettingsGroup's /data subresource
// Returns nil if authorized, or an AdmissionResponse denying the request.
func (h *uiSettingsHook) authorize(logCtx *logrus.Entry, ar v1.AdmissionReview, groupName string) *v1.AdmissionResponse {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userInfo := ar.Request.UserInfo
	verb := strings.ToLower(string(ar.Request.Operation))

	var (
		wg             sync.WaitGroup
		getDecision    bool
		getErr         error
		subresDecision bool
		subresErr      error
	)

	wg.Add(2)

	// Check GET access to the UISettingsGroup.
	go func() {
		defer wg.Done()
		getDecision, getErr = h.checkAccess(ctx, userInfo, "get", "uisettingsgroups", "", groupName)
	}()

	// Check verb access to the UISettingsGroup /data subresource.
	go func() {
		defer wg.Done()
		subresDecision, subresErr = h.checkAccess(ctx, userInfo, verb, "uisettingsgroups", "data", groupName)
	}()

	wg.Wait()

	if getErr != nil {
		logCtx.WithError(getErr).Error("Failed to check UISettingsGroup GET access")
		return denied(metav1.StatusReasonInternalError, fmt.Sprintf("failed to check authorization: %v", getErr))
	}
	if subresErr != nil {
		logCtx.WithError(subresErr).Error("Failed to check UISettingsGroup data subresource access")
		return denied(metav1.StatusReasonInternalError, fmt.Sprintf("failed to check authorization: %v", subresErr))
	}

	if !getDecision || !subresDecision {
		msg := fmt.Sprintf(
			"user %q cannot %s uisettings in uisettingsgroup %q",
			userInfo.Username, verb, groupName,
		)
		if !getDecision {
			msg += " (user cannot get uisettingsgroup)"
		}
		logCtx.Warn(msg)
		return denied(metav1.StatusReasonForbidden, msg)
	}

	return nil
}

// checkAccess performs a SubjectAccessReview to check if the user has the given verb on the resource.
func (h *uiSettingsHook) checkAccess(
	ctx context.Context,
	userInfo authenticationv1.UserInfo,
	verb string,
	resource string,
	subresource string,
	name string,
) (bool, error) {
	// Convert authentication ExtraValue to authorization ExtraValue.
	extra := make(map[string]authorizationv1.ExtraValue)
	for k, v := range userInfo.Extra {
		extra[k] = authorizationv1.ExtraValue(v)
	}

	sar := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:   userInfo.Username,
			UID:    userInfo.UID,
			Groups: userInfo.Groups,
			Extra:  extra,
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Verb:        verb,
				Group:       "projectcalico.org",
				Version:     "v3",
				Resource:    resource,
				Subresource: subresource,
				Name:        name,
			},
		},
	}

	result, err := h.k8sClient.AuthorizationV1().SubjectAccessReviews().Create(ctx, sar, metav1.CreateOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to create SubjectAccessReview: %w", err)
	}
	return result.Status.Allowed, nil
}

// decodeUISettings decodes raw JSON into a UISettings object.
func decodeUISettings(raw []byte) (*v3.UISettings, *v1.AdmissionResponse) {
	if len(raw) == 0 {
		return nil, denied(metav1.StatusReasonBadRequest, "no object in admission request")
	}

	obj := &v3.UISettings{}
	deserializer := utils.Codecs.UniversalDeserializer()
	if _, _, err := deserializer.Decode(raw, nil, obj); err != nil {
		return nil, denied(metav1.StatusReasonBadRequest, fmt.Sprintf("failed to decode UISettings: %v", err))
	}
	return obj, nil
}

type jsonPatchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

func denied(reason metav1.StatusReason, message string) *v1.AdmissionResponse {
	return &v1.AdmissionResponse{
		Allowed: false,
		Result: &metav1.Status{
			Status:  metav1.StatusFailure,
			Message: message,
			Reason:  reason,
		},
	}
}
