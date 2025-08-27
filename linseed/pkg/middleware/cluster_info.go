// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package middleware

import (
	"net/http"

	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
)

// ClusterInfo is a middleware that extracts cluster information.
// A cluster ID is identified by x-cluster-id header
// A tenant ID is identified by x-tenant-id header
type ClusterInfo struct{}

// Extract identifies cluster information from the received request
// A cluster ID is identified by x-cluster-id header. If not present it will default to "default"
// A tenant ID is identified by x-tenant-id header. For multi-tenant mode, it will return a 401 http
// status code. For a single tenant mode it is not required.
func (m ClusterInfo) Extract() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// extract cluster id
			clusterID := req.Header.Get(lmak8s.XClusterIDHeader)
			if clusterID == "" {
				clusterID = lmak8s.DefaultCluster
			}

			// extract tenant id
			tenant := req.Header.Get(lmak8s.XTenantIDHeader)

			req = req.WithContext(WithClusterID(req.Context(), clusterID))
			req = req.WithContext(WithTenantID(req.Context(), tenant))

			next.ServeHTTP(w, req)
		})
	}
}
