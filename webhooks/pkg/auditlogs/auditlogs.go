// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package auditlogs

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/admission/v1"
	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"

	"github.com/projectcalico/calico/webhooks/pkg/utils"
)

// RegisterHook creates a new audit log admission webhook and registers the necessary HTTP handler.
func RegisterHook(logPath string, handleFn utils.HandleFn) {
	logrus.WithFields(logrus.Fields{
		"path":    "/audit",
		"logPath": logPath,
	}).Info("Registering audit log admission webhook")

	handler := NewAuditLogHook(logPath).Handler()

	// Register the webhook handlers.
	http.HandleFunc("/audit", handleFn(handler))
}

// NewAuditLogHook returns a new instance of the audit log admission webhook backend.
func NewAuditLogHook(logPath string) utils.HandlerProvider {
	return &auditLogHook{logPath: logPath}
}

// auditLogHook is an admission webhook that writes audit logs to a file.
type auditLogHook struct {
	logPath string
}

// Handler returns an AdmissionReviewHandler that processes admission reviews and writes audit logs.
func (h *auditLogHook) Handler() utils.AdmissionReviewHandler {
	return utils.NewDelegateToV1AdmitHandler(h.admit)
}

func (h *auditLogHook) admit(ar v1.AdmissionReview) *v1.AdmissionResponse {
	if ar.Request == nil {
		return &v1.AdmissionResponse{Allowed: true}
	}

	event := h.convertRequestToEvent(ar.Request)
	if err := h.writeEventToFile(event); err != nil {
		logrus.WithError(err).Error("Failed to write audit log event")
	}

	return &v1.AdmissionResponse{Allowed: true}
}

func (h *auditLogHook) convertRequestToEvent(req *v1.AdmissionRequest) *auditv1.Event {
	requestURL := fmt.Sprintf("/apis/%s/%s/namespaces/%s/%s/%s", req.Resource.Group, req.Resource.Version, req.Namespace, req.Resource.Resource, req.Name)
	if req.Namespace == "" {
		requestURL = fmt.Sprintf("/apis/%s/%s/%s/%s", req.Resource.Group, req.Resource.Version, req.Resource.Resource, req.Name)
	}

	now := metav1.MicroTime{Time: time.Now()}
	event := &auditv1.Event{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "audit.k8s.io/v1",
			Kind:       "Event",
		},
		Level:      auditv1.LevelRequestResponse,
		AuditID:    req.UID,
		Stage:      auditv1.StageResponseComplete,
		RequestURI: requestURL,
		Verb:       string(req.Operation),
		User: authnv1.UserInfo{
			Username: req.UserInfo.Username,
			UID:      req.UserInfo.UID,
			Groups:   req.UserInfo.Groups,
		},
		ObjectRef: &auditv1.ObjectReference{
			Resource:   req.Resource.Resource,
			Namespace:  req.Namespace,
			Name:       req.Name,
			APIGroup:   req.Resource.Group,
			APIVersion: req.Resource.Version,
		},
		RequestReceivedTimestamp: now,
		StageTimestamp:           now,
	}

	if len(req.Object.Raw) > 0 {
		event.RequestObject = &runtime.Unknown{
			Raw: req.Object.Raw,
		}
	}

	return event
}

func (h *auditLogHook) writeEventToFile(event *auditv1.Event) error {
	if h.logPath == "" {
		return nil
	}

	f, err := os.OpenFile(h.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		if err := f.Close(); err != nil {
			logrus.WithError(err).Error("Failed to close audit log file")
		}
	}()

	b, err := json.Marshal(event)
	if err != nil {
		return err
	}

	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}

	return nil
}
