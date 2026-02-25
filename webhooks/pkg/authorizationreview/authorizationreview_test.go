// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package authorizationreview

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/admission/v1"
	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/projectcalico/calico/apiserver/pkg/rbac"
)

type MockCalculator struct {
	mock.Mock
}

func (m *MockCalculator) CalculatePermissions(user user.Info, rvs []rbac.ResourceVerbs) (rbac.Permissions, error) {
	args := m.Called(user, rvs)
	return args.Get(0).(rbac.Permissions), args.Error(1)
}

func TestAdmit(t *testing.T) {
	mockCalc := &MockCalculator{}
	h := &authorizationReviewHook{calculator: mockCalc}

	arObj := &v3.AuthorizationReview{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindAuthorizationReview,
			APIVersion: "projectcalico.org/v3",
		},
		Spec: v3.AuthorizationReviewSpec{
			ResourceAttributes: []v3.AuthorizationReviewResourceAttributes{
				{
					APIGroup:  "projectcalico.org",
					Resources: []string{"networkpolicies"},
					Verbs:     []string{"get"},
				},
			},
		},
	}
	raw, err := json.Marshal(arObj)
	assert.NoError(t, err)

	ar := v1.AdmissionReview{
		Request: &v1.AdmissionRequest{
			UID:  "test-uid",
			Kind: metav1.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: v3.KindAuthorizationReview},
			Object: runtime.RawExtension{
				Raw: raw,
			},
			UserInfo: authnv1.UserInfo{Username: "test-user"},
		},
	}

	expectedPermissions := rbac.Permissions{
		rbac.ResourceType{APIGroup: "projectcalico.org", Resource: "networkpolicies"}: {
			rbac.VerbGet: []rbac.Match{{Namespace: "default"}},
		},
	}

	mockCalc.On("CalculatePermissions", mock.Anything, mock.Anything).Return(expectedPermissions, nil)

	resp := h.admit(ar)

	assert.True(t, resp.Allowed)
	assert.NotNil(t, resp.Patch)
	assert.Equal(t, v1.PatchTypeJSONPatch, *resp.PatchType)

	var patch []map[string]any
	err = json.Unmarshal(resp.Patch, &patch)
	assert.NoError(t, err)
	assert.Len(t, patch, 1)
	assert.Equal(t, "replace", patch[0]["op"])
	assert.Equal(t, "/status", patch[0]["path"])

	// Verify status content
	statusVal := patch[0]["value"].(map[string]any)
	authVerbs := statusVal["authorizedResourceVerbs"].([]any)
	assert.Len(t, authVerbs, 1)

	mockCalc.AssertExpectations(t)
}
