// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package v1

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	authnv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/apis/audit"

	"github.com/projectcalico/calico/linseed/pkg/testutils"
)

var (
	emptyK8sEvent = `
{
  "level": "",
  "auditID": "",
  "stage": "",
  "requestURI": "",
  "verb": "",
  "user": {},
  "sourceIPs": null,
  "userAgent": "",
  "requestReceivedTimestamp": null,
  "stageTimestamp": null,
  "annotations": null
}
`
	auditLog = `
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "",
  "auditID": "some-uuid-most-likely",
  "stage": "RequestReceived",
  "requestURI": "/apis/v1/namespaces",
  "verb": "GET",
  "user": {
    "username": "user",
    "uid": "uid",
    "extra": {
      "extra": [
        "value"
      ]
    }
  },
  "impersonatedUser": {
    "username": "impuser",
    "uid": "impuid",
    "groups": [
      "g1"
    ]
  },
  "sourceIPs": [
    "1.2.3.4"
  ],
  "userAgent": "user-agent",
  "objectRef": {
    "resource": "any",
    "namespace": "namespace",
    "name": "any",
    "apiVersion": "v1",
    "resourceVersion": "123"
  },
  "responseStatus": {
    "metadata": {}
  },
  "requestObject": {
    "kind": "Namespace",
    "apiVersion": "v1",
    "metadata": {
      "name": "some-name",
      "uid": "some-uid",
      "resourceVersion": "any"
    },
    "spec": {},
    "status": {}
  },
  "responseObject": {
    "kind": "Namespace",
    "apiVersion": "v1",
    "metadata": {
      "name": "some-name",
      "uid": "some-uid",
      "resourceVersion": "any"
    },
    "spec": {},
    "status": {}
  },
  "requestReceivedTimestamp": "1970-01-01T00:00:00.000000Z",
  "stageTimestamp": "1970-01-01T00:00:00.000000Z",
  "annotations": {
    "brick": "red"
  },
  "name": "any-name",
  "cluster": "cluster-one"
}
`
	impersonateUser = &authnv1.UserInfo{
		Username: "impuser",
		UID:      "impuid",
		Groups:   []string{"g1"},
	}

	namespacedObject = v1.Namespace{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Namespace",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            "some-name",
			UID:             "some-uid",
			ResourceVersion: "any",
		},
	}
	status          = &metav1.Status{}
	objectReference = &audit.ObjectReference{
		ResourceVersion: "123",
		Resource:        "any",
		Namespace:       "namespace",
		Name:            "any",
		APIVersion:      "v1",
	}
	k8sEvent = audit.Event{
		TypeMeta:   metav1.TypeMeta{Kind: "Event", APIVersion: "audit.k8s.io/v1"},
		Level:      "",
		AuditID:    types.UID("some-uuid-most-likely"),
		Stage:      audit.StageRequestReceived,
		RequestURI: "/apis/v1/namespaces",
		Verb:       "GET",
		User: authnv1.UserInfo{
			Username: "user",
			UID:      "uid",
			Extra:    map[string]authnv1.ExtraValue{"extra": authnv1.ExtraValue([]string{"value"})},
		},
		ImpersonatedUser: impersonateUser,
		SourceIPs:        []string{"1.2.3.4"},
		UserAgent:        "user-agent",
		ObjectRef:        objectReference,
		ResponseStatus:   status,
		RequestObject: &runtime.Unknown{
			Raw:         compact(marshal(namespacedObject)),
			ContentType: runtime.ContentTypeJSON,
		},
		ResponseObject: &runtime.Unknown{
			Raw:         compact(marshal(namespacedObject)),
			ContentType: runtime.ContentTypeJSON,
		},
		RequestReceivedTimestamp: metav1.NewMicroTime(time.Unix(0, 0)),
		StageTimestamp:           metav1.NewMicroTime(time.Unix(0, 0)),
		Annotations:              map[string]string{"brick": "red"},
	}
)

func TestAuditLog_MarshalJSON(t *testing.T) {
	type fields struct {
		Event   audit.Event
		Name    *string
		Cluster string
	}
	tests := []struct {
		name    string
		fields  fields
		want    []byte
		wantErr bool
	}{
		{"empty", fields{audit.Event{}, nil, ""}, []byte(emptyK8sEvent), false},
		{"valid audit log", fields{k8sEvent, testutils.StringPtr("any-name"), "cluster-one"}, []byte(auditLog), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auditLog := &AuditLog{
				Event:   tt.fields.Event,
				Name:    tt.fields.Name,
				Cluster: tt.fields.Cluster,
			}
			got, err := auditLog.MarshalJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			want := compact(tt.want)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("MarshalJSON() got = %v, want %v", string(got), string(want))
			}
		})
	}
}

func TestAuditLog_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    AuditLog
		wantErr bool
	}{
		{
			"empty", []byte(`{}`), AuditLog{}, false,
		},
		{
			name: "valid audit", data: compact([]byte(auditLog)), want: AuditLog{
				Event: k8sEvent, Name: testutils.StringPtr("any-name"), Cluster: "cluster-one",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auditLog := AuditLog{}
			err := auditLog.UnmarshalJSON(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Errorf("UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else {
				require.NoError(t, err)
				if !reflect.DeepEqual(auditLog, tt.want) {
					t.Errorf("UnmarshalJSON() got = %+v,\n want %+v", auditLog, tt.want)
				}
			}
		})
	}
}

func TestAuditLog_NilPointerReceiver(t *testing.T) {
	t.Run("Nil Pointer Receiver - MarshalJSON", func(t *testing.T) {
		var c *AuditLog
		data, err := c.MarshalJSON()
		require.Error(t, err)
		require.Empty(t, data)
	})

	t.Run("Nil Pointer Receiver - UnmarshalJSON", func(t *testing.T) {
		var c *AuditLog
		err := c.UnmarshalJSON([]byte{})
		require.Error(t, err)
	})
}

func marshal(source any) []byte {
	val, _ := json.Marshal(source)
	return val
}

func compact(source []byte) []byte {
	destination := &bytes.Buffer{}
	_ = json.Compact(destination, source)
	return destination.Bytes()
}
