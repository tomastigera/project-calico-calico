package server

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/felixge/httpsnoop"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	jclust "github.com/projectcalico/calico/voltron/internal/pkg/clusters"
	"github.com/projectcalico/calico/voltron/internal/pkg/server/metrics"
	"github.com/projectcalico/calico/voltron/internal/pkg/utils"
)

type InnerHandler interface {
	Handler() http.Handler
}

// tokenPath is the path to the serviceaccount token provided to Voltron.
const voltronToken = "/var/run/secrets/kubernetes.io/serviceaccount/token"

type InnerHandlerOption func(*handlerHelper)

func WithTokenPath(tokenPath string) InnerHandlerOption {
	return func(h *handlerHelper) {
		log.WithField("tokenPath", tokenPath).Debug("Using token path for inner handler")
		h.tokenPath = tokenPath
	}
}

func WithRateLimiter(rl *rate.Limiter) InnerHandlerOption {
	return func(h *handlerHelper) {
		log.Debug("Using rate limiter for inner handler")
		h.rl = rl
	}
}

func NewInnerHandler(t string, c *jclust.ManagedCluster, proxy http.Handler, opts ...InnerHandlerOption) InnerHandler {
	h := &handlerHelper{
		ManagedCluster: c,
		proxy:          proxy,
		tenantID:       t,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

type handlerHelper struct {
	ManagedCluster *jclust.ManagedCluster
	proxy          http.Handler
	tenantID       string

	// If specified, this tokenPath will be inserted for use when forwarding requests to Linseed.
	// This is used for OSS clusters that don't have their own tokenPath.
	tokenPath string

	// If specified, use this rate limited to limit the number of requests to Linseed.
	rl *rate.Limiter
}

func (h *handlerHelper) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set the cluster and tenant ID headers here. If they are already set,
		// but don't match the expected value for this cluster, return an error.
		clusterID := r.Header.Get(utils.ClusterHeaderField)
		tenantID := r.Header.Get(utils.TenantHeaderField)
		fields := log.Fields{
			"url":                    r.URL,
			utils.ClusterHeaderField: clusterID,
			utils.TenantHeaderField:  tenantID,
		}
		logCtx := log.WithFields(fields)
		start := time.Now()

		promLabels := []string{h.ManagedCluster.ID, tenantID, r.URL.String()}

		httpStatus := http.StatusOK
		w = httpsnoop.Wrap(w, httpsnoop.Hooks{
			WriteHeader: func(headerFunc httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
				return func(code int) {
					httpStatus = code
					headerFunc(code)
				}
			},
		})

		defer func() {
			// Update metrics tracking request duration.
			if requestTimeMetric, err := metrics.InnerRequestTimeSecondsTotal.GetMetricWithLabelValues(promLabels...); err != nil {
				logCtx.WithError(err).Warn("Failed to get request time metric")
			} else {
				requestTimeMetric.Add(time.Since(start).Seconds())
			}
			if requestDurationMetrics, err := metrics.InnerRequestTimeSeconds.GetMetricWithLabelValues(promLabels...); err != nil {
				logCtx.WithError(err).Warn("Failed to get request duration metric")
			} else {
				requestDurationMetrics.Observe(time.Since(start).Seconds())
			}

			// Update metrics tracking request status.
			totalRequestsLabels := promLabels
			totalRequestsLabels = append(totalRequestsLabels, metrics.HttpStatusCategory(httpStatus), metrics.HttpStatusCode(httpStatus))
			if totalRequestsMetrics, err := metrics.InnerRequestsTotal.GetMetricWithLabelValues(totalRequestsLabels...); err != nil {
				logCtx.WithError(err).Warn("Failed to get total requests metric")
			} else {
				totalRequestsMetrics.Inc()
			}
		}()

		// Increment the number of requests in flight
		if inflightMetric, err := metrics.InnerRequestsInflight.GetMetricWithLabelValues(promLabels...); err != nil {
			logCtx.WithError(err).Warn("Failed to get inflight metric")
		} else {
			inflightMetric.Inc()
			defer inflightMetric.Dec()
		}

		// Enforce rate limiting if configured to do so.
		if h.rl != nil && !h.rl.Allow() {
			logCtx.Warn("Rate limit exceeded")
			writeHTTPError(w, rateLimitExceededError())
			return
		}

		if clusterID != "" {
			if clusterID != h.ManagedCluster.ID {
				// Cluster ID is set, and it doesn't match what we expect.
				logCtx.Warn("Unexpected cluster ID")
				if metric, err := metrics.InnerRequestBadClusterIDErrors.GetMetricWithLabelValues(promLabels...); err != nil {
					logCtx.WithError(err).Warn("Failed to get bad cluster ID metric")
				} else {
					metric.Inc()
				}
				writeHTTPError(w, unexpectedClusterIDError(clusterID))
				return
			}
		}

		// Set the cluster ID header before forwarding to indicate the originating cluster.
		r.Header.Set(utils.ClusterHeaderField, h.ManagedCluster.ID)

		if h.tenantID != "" {
			// Running in multi-tenant mode. We need to set the tenant ID on
			// any requests received over the tunnel.
			if tenantID != "" && tenantID != h.tenantID {
				// Tenant ID is set, and it doesn't match what we expect.
				logCtx.Warn("Unexpected tenant ID")
				if metric, err := metrics.InnerRequestBadTenantIDErrors.GetMetricWithLabelValues(promLabels...); err != nil {
					logCtx.WithError(err).Warn("Failed to get bad tenant ID metric")
				} else {
					metric.Inc()
				}
				writeHTTPError(w, unexpectedTenantIDError(tenantID))
				return
			}

			// Set the tenant ID before forwarding to indicate the originating tenant.
			r.Header.Set(utils.TenantHeaderField, h.tenantID)
		}

		if h.tokenPath != "" {
			// Get token from the path on disk.  We load this each time as the token may change.
			token, err := os.ReadFile(h.tokenPath)
			if err != nil {
				logCtx.WithError(err).Warn("Failed to read token file")
				writeHTTPError(w, serverError("Failed to read token file"))
				return
			}

			// If a token is specified, set it in the requests authorization header.
			logCtx.Info("Inserting Linseed authorization token into request")
			r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", string(token)))
		}

		// Headers have been set properly. Now, proxy the connection
		// using Voltron's own key / cert for mTLS with Linseed.
		logCtx.Debug("Handling connection received over the tunnel")
		h.proxy.ServeHTTP(w, r)
	})
}
