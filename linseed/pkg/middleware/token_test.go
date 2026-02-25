// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package middleware_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/projectcalico/calico/linseed/pkg/middleware"
	"github.com/projectcalico/calico/linseed/pkg/testutils"
	"github.com/projectcalico/calico/lma/pkg/auth"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
)

func TestTokenMiddleware(t *testing.T) {
	type testAttributes struct {
		URL     string
		Verb    string
		Attrs   *authzv1.ResourceAttributes
		Disable bool
	}
	type testcase struct {
		// Name of the test.
		Name string

		// Expected body returned from the handler.
		Resp   string
		Status int

		// Headers to set on the request passed to the handler.
		Headers map[string]string

		// Return values for calls to Authenticate made by the handler.
		AuthnMocks []any

		// Return values for calls to Authorize made by the handler.
		AuthzMocks []any

		// Attributes are attributes to use for RBAC.
		Attributes []testAttributes

		// Configure cluster and tenant IDs to be used in headers.
		ClusterHeader        string
		TenantHeader         string
		ExpectedTenantHeader string
	}

	userInfo := user.DefaultInfo{Name: "Horseshoe Crab", UID: "055/261"}

	okResp := "Test OK"

	testcases := []testcase{
		{
			Name:          "No Authorization header",
			Resp:          `{"Status":401,"Msg":"No Authorization header provided"}`,
			Status:        401,
			ClusterHeader: "cluster-id",
			TenantHeader:  "tenant-id",
		},
		{
			Name:          "Unrecognized Authorization type",
			Resp:          `{"Status":401,"Msg":"Authorization is not Bearer"}`,
			Status:        401,
			Headers:       map[string]string{"Authorization": "Basic"},
			ClusterHeader: "cluster-id",
			TenantHeader:  "tenant-id",
		},
		{
			Name:          "Missing a token",
			Resp:          `{"Status":401,"Msg":"No token found in request"}`,
			Status:        401,
			Headers:       map[string]string{"Authorization": "Bearer "},
			ClusterHeader: "cluster-id",
			TenantHeader:  "tenant-id",
		},
		{
			Name:          "No space after 'Bearer'",
			Resp:          `{"Status":401,"Msg":"Authorization is not Bearer"}`,
			Status:        401,
			Headers:       map[string]string{"Authorization": "Bearer"},
			ClusterHeader: "cluster-id",
			TenantHeader:  "tenant-id",
		},
		{
			Name:          "Valid bearer token, but no matching authz configuration",
			Resp:          `{"Status":404,"Msg":"no matching authz options for POST /api/v1/flows"}`,
			Status:        404,
			Headers:       map[string]string{"Authorization": fmt.Sprintf("Bearer %s", K8SToken(t))},
			AuthnMocks:    []any{&userInfo, 200, nil},
			ClusterHeader: "cluster-id",
			TenantHeader:  "tenant-id",
		},
		{
			Name:          "Token is not authentic",
			Resp:          `{"Status":500,"Msg":"Token is not authentic"}`,
			Status:        500,
			Headers:       map[string]string{"Authorization": "Bearer foobar"},
			AuthnMocks:    []any{nil, 500, fmt.Errorf("Token is not authentic")},
			ClusterHeader: "cluster-id",
			TenantHeader:  "tenant-id",
		},
		{
			Name:                 "Missing tenant header for MT",
			Resp:                 `{"Status":401,"Msg":"Bad tenant identifier"}`,
			Status:               401,
			Headers:              map[string]string{"Authorization": "Bearer foobar"},
			AuthnMocks:           []any{nil, 401, fmt.Errorf("Bad tenant identifier")},
			ClusterHeader:        "cluster-id",
			TenantHeader:         "",
			ExpectedTenantHeader: "tenant-id",
		},
		{
			Name:                 "Mismatch tenant header for MT",
			Resp:                 `{"Status":401,"Msg":"Bad tenant identifier"}`,
			Status:               401,
			Headers:              map[string]string{"Authorization": "Bearer foobar"},
			AuthnMocks:           []any{nil, 401, fmt.Errorf("Bad tenant identifier")},
			ClusterHeader:        "cluster-id",
			TenantHeader:         "another-tenant-id",
			ExpectedTenantHeader: "tenant-id",
		},
		{
			Name:                 "Missing tenant header for ST",
			Resp:                 okResp,
			Headers:              map[string]string{"Authorization": fmt.Sprintf("Bearer %s", K8SToken(t))},
			ClusterHeader:        "cluster-id",
			TenantHeader:         "",
			ExpectedTenantHeader: "",
			AuthnMocks:           []any{&userInfo, 200, nil},
			AuthzMocks:           []any{true, nil},
			Attributes: []testAttributes{
				{
					Verb:  "POST",
					URL:   "/flows",
					Attrs: &authzv1.ResourceAttributes{},
				},
			},
		},

		{
			Name:                 "Valid bearer token, authorized",
			Resp:                 okResp,
			Headers:              map[string]string{"Authorization": fmt.Sprintf("Bearer %s", K8SToken(t))},
			ClusterHeader:        "cluster-id",
			TenantHeader:         "tenant-id",
			ExpectedTenantHeader: "tenant-id",
			AuthnMocks:           []any{&userInfo, 200, nil},
			AuthzMocks:           []any{true, nil},
			Attributes: []testAttributes{
				{
					Verb:  "POST",
					URL:   "/flows",
					Attrs: &authzv1.ResourceAttributes{},
				},
			},
		},
		{
			Name:                 "Valid bearer token, not authorized",
			Resp:                 `{"Status":401,"Msg":"Unauthorized"}`,
			Status:               401,
			Headers:              map[string]string{"Authorization": fmt.Sprintf("Bearer %s", K8SToken(t))},
			ClusterHeader:        "cluster-id",
			TenantHeader:         "tenant-id",
			ExpectedTenantHeader: "tenant-id",
			AuthnMocks:           []any{&userInfo, 200, nil},
			AuthzMocks:           []any{false, nil},
			Attributes: []testAttributes{
				{
					Verb:  "POST",
					URL:   "/flows",
					Attrs: &authzv1.ResourceAttributes{},
				},
			},
		},
		{
			Name:                 "Valid bearer token, error performing authorization",
			Resp:                 `{"Status":401,"Msg":"Error performing authz"}`,
			Status:               401,
			Headers:              map[string]string{"Authorization": fmt.Sprintf("Bearer %s", K8SToken(t))},
			ClusterHeader:        "cluster-id",
			TenantHeader:         "tenant-id",
			ExpectedTenantHeader: "tenant-id",
			AuthnMocks:           []any{&userInfo, 200, nil},
			AuthzMocks:           []any{false, fmt.Errorf("Error performing authz")},
			Attributes: []testAttributes{
				{
					Verb:  "POST",
					URL:   "/flows",
					Attrs: &authzv1.ResourceAttributes{},
				},
			},
		},
		{
			Name:                 "Skip authorization for APIs that have it disabled",
			Resp:                 okResp,
			Headers:              map[string]string{"Authorization": fmt.Sprintf("Bearer %s", K8SToken(t))},
			ClusterHeader:        "cluster-id",
			TenantHeader:         "tenant-id",
			ExpectedTenantHeader: "tenant-id",
			AuthnMocks:           []any{&userInfo, 200, nil},
			Attributes: []testAttributes{
				{
					Verb:    "POST",
					URL:     "/flows",
					Disable: true,
				},
			},
		},
		{
			Name:                 "Linseed service account bearer tokens - authorization successful",
			Resp:                 okResp,
			Headers:              map[string]string{"Authorization": fmt.Sprintf("Bearer %s", LinseedToken(t, "tenant-id", "cluster-id"))},
			ClusterHeader:        "cluster-id",
			TenantHeader:         "tenant-id",
			ExpectedTenantHeader: "tenant-id",
			AuthnMocks:           []any{&userInfo, 200, nil},
			Attributes: []testAttributes{
				{
					Verb: "POST",
					URL:  "/flows",
				},
			},
		},
		{
			Name:                 "Linseed service account bearer tokens - different tenant",
			Status:               401,
			Resp:                 `{"Status":401,"Msg":"tenant id or cluster id do not match token"}`,
			Headers:              map[string]string{"Authorization": fmt.Sprintf("Bearer %s", LinseedToken(t, "tenant-id", "cluster-id"))},
			ClusterHeader:        "cluster-id",
			TenantHeader:         "SpongeBob",
			ExpectedTenantHeader: "SpongeBob",
			AuthnMocks:           []any{&userInfo, 200, nil},
			Attributes: []testAttributes{
				{
					Verb: "POST",
					URL:  "/flows",
				},
			},
		},
		{
			Name:                 "Linseed service account bearer tokens - different cluster",
			Status:               401,
			Resp:                 `{"Status":401,"Msg":"tenant id or cluster id do not match token"}`,
			Headers:              map[string]string{"Authorization": fmt.Sprintf("Bearer %s", LinseedToken(t, "tenant-id", "cluster-id"))},
			ClusterHeader:        "SquarePants",
			TenantHeader:         "tenant-id",
			ExpectedTenantHeader: "tenant-id",
			AuthnMocks:           []any{&userInfo, 200, nil},
			Attributes: []testAttributes{
				{
					Verb: "POST",
					URL:  "/flows",
				},
			},
		},
	}

	for _, tt := range testcases {
		t.Run(tt.Name, func(t *testing.T) {
			// Set up expected values. The token handler expects cluster and tenant
			// information to be specified in the context.
			req, err := http.NewRequest("POST", "/api/v1/flows", nil)

			req.Header.Set(lmak8s.XClusterIDHeader, tt.ClusterHeader)
			assert.NoError(t, err)
			req = req.WithContext(middleware.WithClusterID(req.Context(), tt.ClusterHeader))
			req.Header.Set(lmak8s.XTenantIDHeader, tt.TenantHeader)
			assert.NoError(t, err)
			req = req.WithContext(middleware.WithTenantID(req.Context(), tt.TenantHeader))

			for k, v := range tt.Headers {
				req.Header.Set(k, v)
			}

			// Create mocked out authn/authz and the authz handler.
			an := auth.NewMockJWTAuth(t)
			az := auth.NewMockRBACAuthorizer(t)

			if tt.AuthnMocks != nil {
				an.On("Authenticate", mock.Anything).Return(tt.AuthnMocks...)
			}
			if tt.AuthzMocks != nil {
				az.On("Authorize", &userInfo, mock.Anything, mock.Anything).Return(tt.AuthzMocks...)
			}

			authTracker := middleware.NewKubernetesAuthzTracker(az)
			for _, a := range tt.Attributes {
				if a.Disable {
					authTracker.Disable(a.Verb, a.URL)
				} else {
					authTracker.Register(a.Verb, a.URL, a.Attrs)
				}
			}
			tokenHandler := middleware.NewTokenAuth(an, authTracker, tt.ExpectedTenantHeader).Do()

			// Call the token handler.
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// The test handler simply returns an OK body. This is used by the
				// tests to prove that the token middleware passed the request on
				// to the next handler.
				_, err := w.Write([]byte(okResp))
				require.NoError(t, err)
				w.WriteHeader(http.StatusOK)
			})
			rec := httptest.NewRecorder()
			tokenHandler(testHandler).ServeHTTP(rec, req)

			// Assert on status code. Assume an OK response unless the test
			// says otherwise.
			if tt.Status == 0 {
				tt.Status = http.StatusOK
			}
			require.Equal(t, tt.Status, rec.Result().StatusCode)

			// Assert on body.
			raw, err := io.ReadAll(rec.Body)
			resp := strings.Trim(string(raw), " \n")
			require.NoError(t, err)
			require.Equal(t, tt.Resp, resp)
		})
	}
}

func K8SToken(t *testing.T) string {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	token, err := testutils.K8sToken("any-namspace", "any-service-account", 24*time.Hour, privateKey)
	require.NoError(t, err)

	return string(token)
}

func LinseedToken(t *testing.T, tenant, cluster string) string {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	token, err := testutils.LinseedToken(tenant, cluster, "any-namspace", "any-service-account", 24*time.Hour, privateKey)
	require.NoError(t, err)

	return string(token)
}
