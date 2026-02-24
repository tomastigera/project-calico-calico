// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package auditlogs

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/admission/v1"
	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
)

func TestConvertRequestToEvent(t *testing.T) {
	h := &auditLogHook{}
	req := &v1.AdmissionRequest{
		UID:       "test-uid",
		Kind:      metav1.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: "NetworkPolicy"},
		Resource:  metav1.GroupVersionResource{Group: "projectcalico.org", Version: "v3", Resource: "networkpolicies"},
		Name:      "test-policy",
		Namespace: "test-ns",
		Operation: v1.Create,
		UserInfo: authnv1.UserInfo{
			Username: "test-user",
			UID:      "user-123",
			Groups:   []string{"group1"},
		},
		Object: runtime.RawExtension{
			Raw: []byte(`{"metadata":{"name":"test-policy"}}`),
		},
	}

	event := h.convertRequestToEvent(req)

	assert.Equal(t, auditv1.LevelRequestResponse, event.Level)
	assert.Equal(t, req.UID, event.AuditID)
	assert.Equal(t, "test-user", event.User.Username)
	assert.Equal(t, "CREATE", event.Verb)
	assert.Contains(t, event.RequestURI, "networkpolicies")
	assert.NotNil(t, event.RequestObject)
}

func TestWriteEventToFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "audit-log-test")
	assert.NoError(t, err)
	defer func() {
		if err := os.Remove(tmpFile.Name()); err != nil {
			t.Logf("Failed to remove temp file: %v", err)
		}
	}()

	h := &auditLogHook{logPath: tmpFile.Name()}
	event := &auditv1.Event{
		AuditID: "test-uid",
	}

	err = h.writeEventToFile(event)
	assert.NoError(t, err)

	content, err := os.ReadFile(tmpFile.Name())
	assert.NoError(t, err)

	var readEvent auditv1.Event
	err = json.Unmarshal(content, &readEvent)
	assert.NoError(t, err)
	assert.Equal(t, event.AuditID, readEvent.AuditID)
}

func TestAdmit(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "audit-log-admit-test")
	assert.NoError(t, err)
	defer func() {
		if err := os.Remove(tmpFile.Name()); err != nil {
			t.Logf("Failed to remove temp file: %v", err)
		}
	}()

	h := &auditLogHook{logPath: tmpFile.Name()}
	ar := v1.AdmissionReview{
		Request: &v1.AdmissionRequest{
			UID:       "test-uid-admit",
			Operation: v1.Create,
			UserInfo:  authnv1.UserInfo{Username: "test-user"},
		},
	}

	resp := h.admit(ar)
	assert.True(t, resp.Allowed)

	content, err := os.ReadFile(tmpFile.Name())
	assert.NoError(t, err)
	assert.NotEmpty(t, content)
}
