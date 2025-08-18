// Copyright (c) 2023 Tigera, Inc. All rights reserved.
//

package middleware_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/projectcalico/calico/linseed/pkg/middleware"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
)

func TestClusterInfo(t *testing.T) {
	tests := []struct {
		name       string
		xClusterID string
		xTenantID  string
		clusterID  string
		tenantID   string
	}{
		{"missing tenant id - multi tenant", "any", "", "any", ""},
		{"missing cluster id ", "", "any", lmak8s.DefaultCluster, "any"},
		{"extract cluster id and tenant id", "any-cluster", "any-tenant", "any-cluster", "any-tenant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Expect cluster ID and tenant ID to be set on the context
				assert.Equal(t, middleware.ClusterIDFromContext(r.Context()), tt.clusterID)
				assert.Equal(t, middleware.TenantIDFromContext(r.Context()), tt.tenantID)
			})

			clusterInfo := middleware.ClusterInfo{}.Extract()
			req, err := http.NewRequest("POST", "/flows", nil)

			// Set cluster and tenant ID header
			req.Header.Set(lmak8s.XClusterIDHeader, tt.xClusterID)
			assert.NoError(t, err)
			req.Header.Set(lmak8s.XTenantIDHeader, tt.xTenantID)
			assert.NoError(t, err)

			rec := httptest.NewRecorder()
			clusterInfo(testHandler).ServeHTTP(rec, req)

			_, err = io.ReadAll(rec.Body)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, rec.Result().StatusCode)
		})
	}
}
