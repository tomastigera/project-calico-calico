// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package uisettings

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	calicofake "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	v1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	_ "github.com/projectcalico/calico/webhooks/pkg/utils"
)

// allowAllSARReactor creates a reactor that approves all SubjectAccessReview requests.
func allowAllSARReactor(cs *k8sfake.Clientset) {
	cs.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		sar := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview)
		sar.Status.Allowed = true
		return true, sar, nil
	})
}

// denyAllSARReactor creates a reactor that denies all SubjectAccessReview requests.
func denyAllSARReactor(cs *k8sfake.Clientset) {
	cs.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		sar := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview)
		sar.Status.Allowed = false
		sar.Status.Reason = "denied by test"
		return true, sar, nil
	})
}

// denyGetSARReactor denies the GET check on the UISettingsGroup but allows the /data subresource check.
func denyGetSARReactor(cs *k8sfake.Clientset) {
	cs.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		sar := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview)
		if sar.Spec.ResourceAttributes != nil && sar.Spec.ResourceAttributes.Verb == "get" {
			sar.Status.Allowed = false
		} else {
			sar.Status.Allowed = true
		}
		return true, sar, nil
	})
}

func makeUISettings(name, group string) *v3.UISettings {
	return &v3.UISettings{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindUISettings,
			APIVersion: "projectcalico.org/v3",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v3.UISettingsSpec{
			Group:       group,
			Description: "test",
		},
	}
}

func makeAdmissionReview(op v1.Operation, obj, oldObj *v3.UISettings, name string) v1.AdmissionReview {
	ar := v1.AdmissionReview{
		Request: &v1.AdmissionRequest{
			UID:       "test-uid",
			Kind:      metav1.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: v3.KindUISettings},
			Operation: op,
			Name:      name,
			UserInfo: authenticationv1.UserInfo{
				Username: "test-user",
				Groups:   []string{"system:authenticated"},
			},
		},
	}
	if obj != nil {
		ar.Request.Object = runtime.RawExtension{Raw: mustMarshal(obj)}
	}
	if oldObj != nil {
		ar.Request.OldObject = runtime.RawExtension{Raw: mustMarshal(oldObj)}
	}
	return ar
}

func mustMarshal(obj any) []byte {
	raw, err := json.Marshal(obj)
	if err != nil {
		panic(err)
	}
	return raw
}

func TestAdmit_IgnoresNonUISettings(t *testing.T) {
	k8sClient := k8sfake.NewSimpleClientset()
	calicoClient := calicofake.NewSimpleClientset()

	h := &uiSettingsHook{k8sClient: k8sClient, calicoClient: calicoClient}

	ar := v1.AdmissionReview{
		Request: &v1.AdmissionRequest{
			UID:       "test-uid",
			Kind:      metav1.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: "SomethingElse"},
			Operation: v1.Create,
		},
	}

	resp := h.admit(ar)
	assert.True(t, resp.Allowed)
}

func TestHandleCreate_Success(t *testing.T) {
	group := &v3.UISettingsGroup{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindUISettingsGroup,
			APIVersion: "projectcalico.org/v3",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "mygroup",
			UID:  "group-uid-123",
		},
		Spec: v3.UISettingsGroupSpec{
			Description: "test group",
			FilterType:  v3.FilterTypeNone,
		},
	}

	k8sClient := k8sfake.NewSimpleClientset()
	allowAllSARReactor(k8sClient)
	calicoClient := calicofake.NewSimpleClientset(group)

	h := &uiSettingsHook{k8sClient: k8sClient, calicoClient: calicoClient}

	uiSettings := makeUISettings("mygroup.view1", "mygroup")
	ar := makeAdmissionReview(v1.Create, uiSettings, nil, "mygroup.view1")

	resp := h.admit(ar)
	assert.True(t, resp.Allowed, "expected allowed, got: %v", resp.Result)
	assert.NotNil(t, resp.Patch)
	assert.Equal(t, v1.PatchTypeJSONPatch, *resp.PatchType)

	// Verify the patch contains the ownerReference.
	var patch []map[string]any
	err := json.Unmarshal(resp.Patch, &patch)
	require.NoError(t, err)
	assert.Len(t, patch, 1, "expected 1 patch op for ownerReference only (non-user group)")
	assert.Equal(t, "add", patch[0]["op"])
	assert.Equal(t, "/metadata/ownerReferences", patch[0]["path"])
}

func TestHandleCreate_UserGroup(t *testing.T) {
	group := &v3.UISettingsGroup{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindUISettingsGroup,
			APIVersion: "projectcalico.org/v3",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "usergroup",
			UID:  "group-uid-456",
		},
		Spec: v3.UISettingsGroupSpec{
			Description: "user group",
			FilterType:  v3.FilterTypeUser,
		},
	}

	k8sClient := k8sfake.NewSimpleClientset()
	allowAllSARReactor(k8sClient)
	calicoClient := calicofake.NewSimpleClientset(group)

	h := &uiSettingsHook{k8sClient: k8sClient, calicoClient: calicoClient}

	uiSettings := makeUISettings("usergroup.prefs", "usergroup")
	ar := makeAdmissionReview(v1.Create, uiSettings, nil, "usergroup.prefs")

	resp := h.admit(ar)
	assert.True(t, resp.Allowed, "expected allowed, got: %v", resp.Result)
	require.NotNil(t, resp.Patch)

	// Should have 2 patch ops: ownerReference + spec.user.
	var patch []map[string]any
	err := json.Unmarshal(resp.Patch, &patch)
	require.NoError(t, err)
	assert.Len(t, patch, 2, "expected 2 patch ops (ownerReference + spec.user)")

	paths := []string{patch[0]["path"].(string), patch[1]["path"].(string)}
	assert.Contains(t, paths, "/metadata/ownerReferences")
	assert.Contains(t, paths, "/spec/user")

	// Verify spec.user is set to the requesting user.
	for _, p := range patch {
		if p["path"] == "/spec/user" {
			assert.Equal(t, "test-user", p["value"])
		}
	}
}

func TestHandleCreate_MissingGroup(t *testing.T) {
	k8sClient := k8sfake.NewSimpleClientset()
	allowAllSARReactor(k8sClient)

	// No UISettingsGroup exists.
	calicoClient := calicofake.NewSimpleClientset()

	h := &uiSettingsHook{k8sClient: k8sClient, calicoClient: calicoClient}

	uiSettings := makeUISettings("nogroup.view1", "nogroup")
	ar := makeAdmissionReview(v1.Create, uiSettings, nil, "nogroup.view1")

	resp := h.admit(ar)
	assert.False(t, resp.Allowed)
	assert.Contains(t, resp.Result.Message, "failed to get UISettingsGroup")
}

func TestHandleCreate_EmptyGroup(t *testing.T) {
	k8sClient := k8sfake.NewSimpleClientset()
	calicoClient := calicofake.NewSimpleClientset()

	h := &uiSettingsHook{k8sClient: k8sClient, calicoClient: calicoClient}

	uiSettings := makeUISettings("mygroup.view1", "")
	ar := makeAdmissionReview(v1.Create, uiSettings, nil, "mygroup.view1")

	resp := h.admit(ar)
	assert.False(t, resp.Allowed)
	assert.Contains(t, resp.Result.Message, "spec.group is not specified")
}

func TestHandleCreate_Unauthorized(t *testing.T) {
	group := &v3.UISettingsGroup{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindUISettingsGroup,
			APIVersion: "projectcalico.org/v3",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "mygroup",
			UID:  "group-uid",
		},
		Spec: v3.UISettingsGroupSpec{
			Description: "test group",
		},
	}

	k8sClient := k8sfake.NewSimpleClientset()
	denyAllSARReactor(k8sClient)
	calicoClient := calicofake.NewSimpleClientset(group)

	h := &uiSettingsHook{k8sClient: k8sClient, calicoClient: calicoClient}

	uiSettings := makeUISettings("mygroup.view1", "mygroup")
	ar := makeAdmissionReview(v1.Create, uiSettings, nil, "mygroup.view1")

	resp := h.admit(ar)
	assert.False(t, resp.Allowed)
	assert.Equal(t, metav1.StatusReasonForbidden, resp.Result.Reason)
	assert.Contains(t, resp.Result.Message, "cannot create uisettings")
}

func TestHandleCreate_UnauthorizedGetGroup(t *testing.T) {
	k8sClient := k8sfake.NewSimpleClientset()
	denyGetSARReactor(k8sClient)
	calicoClient := calicofake.NewSimpleClientset()

	h := &uiSettingsHook{k8sClient: k8sClient, calicoClient: calicoClient}

	uiSettings := makeUISettings("mygroup.view1", "mygroup")
	ar := makeAdmissionReview(v1.Create, uiSettings, nil, "mygroup.view1")

	resp := h.admit(ar)
	assert.False(t, resp.Allowed)
	assert.Equal(t, metav1.StatusReasonForbidden, resp.Result.Reason)
	assert.Contains(t, resp.Result.Message, "user cannot get uisettingsgroup")
}

func TestHandleUpdate_Success(t *testing.T) {
	k8sClient := k8sfake.NewSimpleClientset()
	allowAllSARReactor(k8sClient)
	calicoClient := calicofake.NewSimpleClientset()

	h := &uiSettingsHook{k8sClient: k8sClient, calicoClient: calicoClient}

	oldSettings := makeUISettings("mygroup.view1", "mygroup")
	oldSettings.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: v3.GroupVersionCurrent,
		Kind:       v3.KindUISettingsGroup,
		Name:       "mygroup",
		UID:        "group-uid",
	}}

	newSettings := oldSettings.DeepCopy()
	newSettings.Spec.Description = "updated description"

	ar := makeAdmissionReview(v1.Update, newSettings, oldSettings, "mygroup.view1")

	resp := h.admit(ar)
	assert.True(t, resp.Allowed, "expected allowed, got: %v", resp.Result)
}

func TestHandleUpdate_ImmutableGroup(t *testing.T) {
	k8sClient := k8sfake.NewSimpleClientset()
	allowAllSARReactor(k8sClient)
	calicoClient := calicofake.NewSimpleClientset()

	h := &uiSettingsHook{k8sClient: k8sClient, calicoClient: calicoClient}

	oldSettings := makeUISettings("mygroup.view1", "mygroup")
	newSettings := makeUISettings("mygroup.view1", "othergroup")

	ar := makeAdmissionReview(v1.Update, newSettings, oldSettings, "mygroup.view1")

	resp := h.admit(ar)
	assert.False(t, resp.Allowed)
	assert.Equal(t, metav1.StatusReasonForbidden, resp.Result.Reason)
	assert.Contains(t, resp.Result.Message, "not permitted to change spec.group")
}

func TestHandleUpdate_ImmutableUser(t *testing.T) {
	k8sClient := k8sfake.NewSimpleClientset()
	allowAllSARReactor(k8sClient)
	calicoClient := calicofake.NewSimpleClientset()

	h := &uiSettingsHook{k8sClient: k8sClient, calicoClient: calicoClient}

	oldSettings := makeUISettings("mygroup.view1", "mygroup")
	oldSettings.Spec.User = "original-user"

	newSettings := oldSettings.DeepCopy()
	newSettings.Spec.User = "different-user"

	ar := makeAdmissionReview(v1.Update, newSettings, oldSettings, "mygroup.view1")

	resp := h.admit(ar)
	assert.False(t, resp.Allowed)
	assert.Equal(t, metav1.StatusReasonForbidden, resp.Result.Reason)
	assert.Contains(t, resp.Result.Message, "not permitted to change spec.user")
}

func TestHandleUpdate_ImmutableOwnerReferences(t *testing.T) {
	k8sClient := k8sfake.NewSimpleClientset()
	allowAllSARReactor(k8sClient)
	calicoClient := calicofake.NewSimpleClientset()

	h := &uiSettingsHook{k8sClient: k8sClient, calicoClient: calicoClient}

	oldSettings := makeUISettings("mygroup.view1", "mygroup")
	oldSettings.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: v3.GroupVersionCurrent,
		Kind:       v3.KindUISettingsGroup,
		Name:       "mygroup",
		UID:        "group-uid",
	}}

	newSettings := oldSettings.DeepCopy()
	newSettings.OwnerReferences = nil

	ar := makeAdmissionReview(v1.Update, newSettings, oldSettings, "mygroup.view1")

	resp := h.admit(ar)
	assert.False(t, resp.Allowed)
	assert.Equal(t, metav1.StatusReasonForbidden, resp.Result.Reason)
	assert.Contains(t, resp.Result.Message, "not permitted to change UISettingsGroup owner reference")
}

func TestHandleUpdate_Unauthorized(t *testing.T) {
	k8sClient := k8sfake.NewSimpleClientset()
	denyAllSARReactor(k8sClient)
	calicoClient := calicofake.NewSimpleClientset()

	h := &uiSettingsHook{k8sClient: k8sClient, calicoClient: calicoClient}

	oldSettings := makeUISettings("mygroup.view1", "mygroup")
	newSettings := oldSettings.DeepCopy()

	ar := makeAdmissionReview(v1.Update, newSettings, oldSettings, "mygroup.view1")

	resp := h.admit(ar)
	assert.False(t, resp.Allowed)
	assert.Equal(t, metav1.StatusReasonForbidden, resp.Result.Reason)
}

func TestHandleDelete_Success(t *testing.T) {
	k8sClient := k8sfake.NewSimpleClientset()
	allowAllSARReactor(k8sClient)
	calicoClient := calicofake.NewSimpleClientset()

	h := &uiSettingsHook{k8sClient: k8sClient, calicoClient: calicoClient}

	oldSettings := makeUISettings("mygroup.view1", "mygroup")
	ar := makeAdmissionReview(v1.Delete, nil, oldSettings, "mygroup.view1")

	resp := h.admit(ar)
	assert.True(t, resp.Allowed)
}

func TestHandleDelete_Unauthorized(t *testing.T) {
	k8sClient := k8sfake.NewSimpleClientset()
	denyAllSARReactor(k8sClient)
	calicoClient := calicofake.NewSimpleClientset()

	h := &uiSettingsHook{k8sClient: k8sClient, calicoClient: calicoClient}

	oldSettings := makeUISettings("mygroup.view1", "mygroup")
	ar := makeAdmissionReview(v1.Delete, nil, oldSettings, "mygroup.view1")

	resp := h.admit(ar)
	assert.False(t, resp.Allowed)
	assert.Equal(t, metav1.StatusReasonForbidden, resp.Result.Reason)
}

func TestHandleDelete_NoObject(t *testing.T) {
	k8sClient := k8sfake.NewSimpleClientset()
	calicoClient := calicofake.NewSimpleClientset()

	h := &uiSettingsHook{k8sClient: k8sClient, calicoClient: calicoClient}

	// DELETE with no OldObject at all.
	ar := makeAdmissionReview(v1.Delete, nil, nil, "mygroup.view1")

	resp := h.admit(ar)
	assert.False(t, resp.Allowed)
	assert.Contains(t, resp.Result.Message, "no object in admission request")
}

func TestCheckAccess_VerifiesSARFields(t *testing.T) {
	k8sClient := k8sfake.NewSimpleClientset()

	// Capture the SAR to verify its fields.
	var capturedSAR *authorizationv1.SubjectAccessReview
	k8sClient.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		sar := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview)
		capturedSAR = sar.DeepCopy()
		sar.Status.Allowed = true
		return true, sar, nil
	})

	h := &uiSettingsHook{k8sClient: k8sClient}

	userInfo := authenticationv1.UserInfo{
		Username: "testuser",
		UID:      "uid-1",
		Groups:   []string{"group1"},
	}

	allowed, err := h.checkAccess(
		context.TODO(),
		userInfo,
		"get",
		"uisettingsgroups",
		"data",
		"mygroup",
	)
	require.NoError(t, err)
	assert.True(t, allowed)

	require.NotNil(t, capturedSAR)
	assert.Equal(t, "testuser", capturedSAR.Spec.User)
	assert.Equal(t, "uid-1", capturedSAR.Spec.UID)
	assert.Equal(t, []string{"group1"}, capturedSAR.Spec.Groups)
	assert.Equal(t, "get", capturedSAR.Spec.ResourceAttributes.Verb)
	assert.Equal(t, "projectcalico.org", capturedSAR.Spec.ResourceAttributes.Group)
	assert.Equal(t, "v3", capturedSAR.Spec.ResourceAttributes.Version)
	assert.Equal(t, "uisettingsgroups", capturedSAR.Spec.ResourceAttributes.Resource)
	assert.Equal(t, "data", capturedSAR.Spec.ResourceAttributes.Subresource)
	assert.Equal(t, "mygroup", capturedSAR.Spec.ResourceAttributes.Name)
}
