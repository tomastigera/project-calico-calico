// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package middleware

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/projectcalico/calico/linseed/pkg/metrics"
)

type Metrics struct{}

func (m Metrics) Track() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			start := time.Now().UTC()
			wrap := responseInterceptor{ResponseWriter: w}
			next.ServeHTTP(&wrap, req)

			if req.URL.Path != "/version" {
				cluster := ClusterIDFromContext(req.Context())
				tenant := TenantIDFromContext(req.Context())

				contentLength := float64(req.ContentLength)
				if contentLength > 0 {
					if strings.HasSuffix(req.URL.Path, "bulk") {
						// Increment how many bytes are written via Linseed per cluster ID
						metrics.BytesWrittenPerClusterIDAndTenantID.
							With(m.clusterAndTenantLabels(cluster, tenant)).Add(contentLength)
					} else {
						// Increment how many bytes are read via Linseed per cluster ID
						metrics.BytesReadPerClusterIDAndTenantID.
							With(m.clusterAndTenantLabels(cluster, tenant)).Add(contentLength)
					}
				}

				// Increment the number of total http request
				metrics.HTTPTotalRequests.With(m.allLabels(req, wrap, cluster, tenant)).Inc()

				// Observe the response duration
				metrics.HTTPResponseDuration.With(m.methodAndPathLabels(req)).Observe(time.Since(start).Seconds())

				// Observe the request input size
				metrics.HTTPRequestSize.With(m.methodAndPathLabels(req)).Observe(float64(req.ContentLength))

				// Observe the response size
				metrics.HTTPResponseSize.With(m.methodAndPathLabels(req)).Observe(float64(wrap.bytesWritten))
			}
		})
	}
}

func (m Metrics) TrackInflightRequest() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			metrics.HTTPInflightRequests.With(m.methodAndPathLabels(req)).Add(float64(1))
			defer metrics.HTTPInflightRequests.With(m.methodAndPathLabels(req)).Add(float64(-1))
			next.ServeHTTP(w, req)
		})
	}
}

func (m Metrics) clusterAndTenantLabels(cluster string, tenant string) prometheus.Labels {
	return prometheus.Labels{
		metrics.LabelClusterID: cluster,
		metrics.LabelTenantID:  tenant,
	}
}

func (m Metrics) allLabels(req *http.Request, wrap responseInterceptor, cluster, tenant string) prometheus.Labels {
	return prometheus.Labels{
		metrics.LabelMethod:    req.Method,
		metrics.LabelCode:      wrap.StatusCode(),
		metrics.LabelPath:      req.URL.Path,
		metrics.LabelTenantID:  tenant,
		metrics.LabelClusterID: cluster,
	}
}

func (m Metrics) methodAndPathLabels(req *http.Request) prometheus.Labels {
	return prometheus.Labels{
		metrics.LabelMethod: req.Method,
		metrics.LabelPath:   req.URL.Path,
	}
}

type responseInterceptor struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

func (r *responseInterceptor) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *responseInterceptor) Write(p []byte) (int, error) {
	r.bytesWritten += int64(len(p))
	return r.ResponseWriter.Write(p)
}

func (r *responseInterceptor) StatusCode() string {
	if r.statusCode == 0 {
		return "200"
	}

	return strconv.Itoa(r.statusCode)
}
