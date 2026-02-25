// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package audit

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	authnv1 "k8s.io/api/authentication/v1"
	knet "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kaudit "k8s.io/apiserver/pkg/apis/audit"

	"github.com/projectcalico/calico/libcalico-go/lib/json"
	lapi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
)

var auditRequest = `
{
  "page": 0,
  "max_page_size": 1000,
  "type": "ee",
  "kinds": ["networkpolicies", "globalnetworkpolicies"],
  "object_refs": [{
        "name": "calico-system.es-kube-controller-access",
        "namespace": "calico-system"
  }],
  "verbs": ["create", "delete", "patch", "update"],
  "response_codes": [200, 201]
}
`

var negativePagetRequest = `
{
  "page": -1,
  "max_page_size": 1000,
  "type": "ee",
  "kinds": ["networkpolicies", "globalnetworkpolicies"],
  "object_refs": [{
        "name": "calico-system.es-kube-controller-access",
        "namespace": "calico-system"
  }],
  "verbs": ["create", "delete", "patch", "update"],
  "response_codes": [200, 201]
}
`

var paginatedAuditRequest = `
{
  "page": 1,
  "max_page_size": 1000,
  "type": "ee",
  "kinds": ["networkpolicies", "globalnetworkpolicies"],
  "object_refs": [{
        "name": "calico-system.es-kube-controller-access",
        "namespace": "calico-system"
  }],
  "verbs": ["create", "delete", "patch", "update"],
  "response_codes": [200, 201]
}
`

var missingLogType = `
{
  "page": 0,
  "max_page_size": 1000,
  "kinds": ["networkpolicies", "globalnetworkpolicies"],
  "object_refs": [{
        "name": "calico-system.es-kube-controller-access",
        "namespace": "calico-system"
  }],
  "verbs": ["create", "delete", "patch", "update"],
  "response_codes": [200, 201]
}`

func TestNewHandler(t *testing.T) {
	tests := []struct {
		name                string
		method              string
		input               string
		mockResults         []rest.MockResult
		backendRequests     []*lapi.AuditLogParams
		expectedStatus      int
		expectedBody        string
		expectedContentType string
	}{
		{
			name:                "other methods",
			method:              "PUT",
			input:               auditRequest,
			expectedStatus:      http.StatusMethodNotAllowed,
			expectedBody:        "invalid http method",
			expectedContentType: "text/plain; charset=utf-8",
		},
		{
			name:                "invalid json",
			method:              "POST",
			input:               `{$@351}`,
			expectedStatus:      http.StatusBadRequest,
			expectedBody:        "Request body contains badly-formed JSON (at position 2)",
			expectedContentType: "text/plain; charset=utf-8",
		},
		{
			name:                "missing logs type",
			method:              "POST",
			input:               missingLogType,
			expectedStatus:      http.StatusBadRequest,
			expectedBody:        "Missing log type parameter",
			expectedContentType: "text/plain; charset=utf-8",
		},
		{
			name:                "backend returns an error",
			method:              "POST",
			input:               auditRequest,
			mockResults:         []rest.MockResult{{Err: fmt.Errorf("mock error")}},
			expectedStatus:      http.StatusInternalServerError,
			expectedBody:        "mock error",
			expectedContentType: "text/plain; charset=utf-8",
		},
		{
			name:   "negative page requested",
			method: "POST",
			input:  negativePagetRequest,
			mockResults: []rest.MockResult{
				{
					Body: lapi.List[lapi.AuditLog]{
						Items: []lapi.AuditLog{{Event: buildEvent(t)}},
					},
				},
			},
			backendRequests: []*lapi.AuditLogParams{
				{
					QueryParams: lapi.QueryParams{
						MaxPageSize: 1000,
					},
					Type: lapi.AuditLogTypeEE,
					Sort: []lapi.SearchRequestSortBy{
						{
							Field:      "stageTimestamp",
							Descending: true,
						},
					},
					Kinds: []lapi.Kind{
						lapi.KindNetworkPolicy,
						lapi.KindGlobalNetworkPolicy,
					},
					ObjectRefs: []lapi.ObjectReference{
						{
							Name:      "calico-system.es-kube-controller-access",
							Namespace: "calico-system",
						},
					},
					Verbs:          []lapi.Verb{"create", "delete", "patch", "update"},
					Stages:         []kaudit.Stage{kaudit.StageResponseComplete},
					Levels:         []kaudit.Level{kaudit.LevelRequestResponse},
					ResponseCodes:  []int32{200, 201},
					ExcludeDryRuns: true,
				},
			},
			expectedStatus: http.StatusOK,
			expectedBody: string(marshal(t,
				lapi.List[lapi.AuditLog]{
					Items: []lapi.AuditLog{
						{Event: buildEvent(t)},
					},
				})),
			expectedContentType: "application/json",
		},
		{
			name:   "valid request",
			method: "POST",
			mockResults: []rest.MockResult{
				{
					Body: lapi.List[lapi.AuditLog]{
						Items: []lapi.AuditLog{{Event: buildEvent(t)}},
					},
				},
			},
			backendRequests: []*lapi.AuditLogParams{
				{
					QueryParams: lapi.QueryParams{
						MaxPageSize: 1000,
					},
					Type: lapi.AuditLogTypeEE,
					Sort: []lapi.SearchRequestSortBy{
						{
							Field:      "stageTimestamp",
							Descending: true,
						},
					},
					Kinds: []lapi.Kind{
						lapi.KindNetworkPolicy,
						lapi.KindGlobalNetworkPolicy,
					},
					ObjectRefs: []lapi.ObjectReference{
						{
							Name:      "calico-system.es-kube-controller-access",
							Namespace: "calico-system",
						},
					},
					Verbs:          []lapi.Verb{"create", "delete", "patch", "update"},
					Stages:         []kaudit.Stage{kaudit.StageResponseComplete},
					Levels:         []kaudit.Level{kaudit.LevelRequestResponse},
					ResponseCodes:  []int32{200, 201},
					ExcludeDryRuns: true,
				},
			},
			input:          auditRequest,
			expectedStatus: http.StatusOK,
			expectedBody: string(marshal(t,
				lapi.List[lapi.AuditLog]{
					Items: []lapi.AuditLog{
						{Event: buildEvent(t)},
					},
				})),
			expectedContentType: "application/json",
		},
		{
			name:   "paginated requests",
			method: "POST",
			mockResults: []rest.MockResult{
				{
					Body: lapi.List[lapi.AuditLog]{
						Items: []lapi.AuditLog{{Event: buildEvent(t)}},
					},
				},
			},
			backendRequests: []*lapi.AuditLogParams{
				{
					QueryParams: lapi.QueryParams{
						MaxPageSize: 1000,
						// Expect AfterKey to be set for a paginated request
						AfterKey: map[string]any{
							"startFrom": 1000,
						},
					},
					Type: lapi.AuditLogTypeEE,
					Sort: []lapi.SearchRequestSortBy{
						{
							Field:      "stageTimestamp",
							Descending: true,
						},
					},
					Kinds: []lapi.Kind{
						lapi.KindNetworkPolicy,
						lapi.KindGlobalNetworkPolicy,
					},
					ObjectRefs: []lapi.ObjectReference{
						{
							Name:      "calico-system.es-kube-controller-access",
							Namespace: "calico-system",
						},
					},
					Verbs:          []lapi.Verb{"create", "delete", "patch", "update"},
					Stages:         []kaudit.Stage{kaudit.StageResponseComplete},
					Levels:         []kaudit.Level{kaudit.LevelRequestResponse},
					ResponseCodes:  []int32{200, 201},
					ExcludeDryRuns: true,
				},
			},
			input:          paginatedAuditRequest,
			expectedStatus: http.StatusOK,
			expectedBody: string(marshal(t,
				lapi.List[lapi.AuditLog]{
					Items: []lapi.AuditLog{
						{Event: buildEvent(t)},
					},
				})),
			expectedContentType: "application/json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// mock linseed client
			lsc := client.NewMockClient("", tt.mockResults...)

			// validate responses
			req, err := http.NewRequest(tt.method, "", bytes.NewReader([]byte(tt.input)))
			require.NoError(t, err)

			rr := httptest.NewRecorder()
			handler := NewHandler(lsc, true)
			handler.ServeHTTP(rr, req)

			require.Equal(t, rr.Code, tt.expectedStatus)
			body := strings.Trim(rr.Body.String(), "\n")
			require.Equal(t, tt.expectedBody, body)
			require.Equal(t, rr.Header().Get("Content-Type"), tt.expectedContentType)

			if tt.backendRequests != nil {
				var auditLogParams []*lapi.AuditLogParams
				for _, req := range lsc.Requests() {
					auditLogParams = append(auditLogParams, req.GetParams().(*lapi.AuditLogParams))
				}
				require.EqualValues(t, tt.backendRequests, auditLogParams)
			}
		})
	}
}

func marshal(t *testing.T, input any) []byte {
	newData, err := json.Marshal(input)
	require.NoError(t, err)
	return newData
}

func buildEvent(t *testing.T) kaudit.Event {
	obj := knet.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "Networkpolicy", APIVersion: "networking.k8s.io/v1"},
	}

	return kaudit.Event{
		TypeMeta:   metav1.TypeMeta{Kind: "Event", APIVersion: "audit.k8s.io/v1"},
		AuditID:    "some-uuid-most-likely",
		Stage:      kaudit.StageRequestReceived,
		RequestURI: "/apis/v3/projectcalico.org",
		Verb:       "PUT",
		User: authnv1.UserInfo{
			Username: "user",
			UID:      "uid",
			Extra:    map[string]authnv1.ExtraValue{"extra": authnv1.ExtraValue([]string{"value"})},
		},
		ImpersonatedUser: &authnv1.UserInfo{
			Username: "impuser",
			UID:      "impuid",
			Groups:   []string{"g1"},
		},
		SourceIPs:      []string{"1.2.3.4"},
		UserAgent:      "user-agent",
		ObjectRef:      &kaudit.ObjectReference{},
		ResponseStatus: &metav1.Status{},
		RequestObject: &runtime.Unknown{
			Raw:         marshal(t, obj),
			ContentType: runtime.ContentTypeJSON,
		},
		ResponseObject: &runtime.Unknown{
			Raw:         marshal(t, obj),
			ContentType: runtime.ContentTypeJSON,
		},
		RequestReceivedTimestamp: metav1.NewMicroTime(time.Unix(1, 0).UTC().Add(-5 * time.Second)),
		StageTimestamp:           metav1.NewMicroTime(time.Unix(1, 0).UTC()),
		Annotations:              map[string]string{"brick": "red"},
	}
}
