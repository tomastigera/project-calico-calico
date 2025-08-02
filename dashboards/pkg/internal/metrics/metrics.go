package metrics

import (
	"context"
	"net/http"
	"strconv"

	"github.com/felixge/httpsnoop"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tigera/tds-apiserver/lib/logging"

	lsmetrics "github.com/projectcalico/calico/linseed/pkg/metrics"
)

func init() {
	prometheus.MustRegister(HTTPTotalRequests)
	prometheus.MustRegister(HTTPRequestDuration)
	prometheus.MustRegister(HTTPResponseSize)
}

const (
	subsystem = "cc_dashboard_query_api"
)

var (
	histogramBuckets = []float64{.1, .25, .5, 1, 5, 10}
	sizeBuckets      = prometheus.ExponentialBuckets(1000, 10, 4)

	// HTTPTotalRequests will track the number of HTTP requests
	// across all APIs broken down by code, method and path
	HTTPTotalRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "tigera",
			Subsystem: subsystem,
			Name:      "http_requests_total",
			Help:      "Number of total requests.",
		},
		[]string{lsmetrics.LabelPath, lsmetrics.LabelMethod, lsmetrics.LabelTenantID})

	// HTTPRequestDuration will track the duration of HTTP requests
	// across all APIs broken down by path and method
	HTTPRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "tigera",
		Subsystem: subsystem,
		Name:      "http_request_duration_seconds",
		Help:      "Duration of HTTP requests by method and path.",
		Buckets:   histogramBuckets,
	},
		[]string{lsmetrics.LabelPath, lsmetrics.LabelMethod, lsmetrics.LabelTenantID})

	// HTTPResponseSize will track the size of HTTP responses
	// across all APIs broken down by path and method
	HTTPResponseSize = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "tigera",
		Subsystem: subsystem,
		Name:      "http_response_size_bytes",
		Help:      "Size of HTTP response.",
		Buckets:   sizeBuckets,
	},
		[]string{lsmetrics.LabelPath, lsmetrics.LabelCode, lsmetrics.LabelMethod, lsmetrics.LabelTenantID})
)

func Wrap(ctx context.Context, logger logging.Logger, next http.Handler, tenantID string) http.Handler {
	logger = logger.WithName("metrics")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		labels := prometheus.Labels{
			lsmetrics.LabelMethod:   r.Method,
			lsmetrics.LabelPath:     r.URL.Path,
			lsmetrics.LabelTenantID: tenantID,
		}

		HTTPTotalRequests.With(labels).Inc()

		m := httpsnoop.CaptureMetrics(next, w, r)

		HTTPRequestDuration.With(labels).Observe(m.Duration.Seconds())

		statusCode := "200"
		if m.Code != 0 {
			statusCode = strconv.Itoa(m.Code)
		}

		labels[lsmetrics.LabelCode] = statusCode
		HTTPResponseSize.With(labels).Observe(float64(m.Written))

		logger.DebugC(ctx, "HTTP Request",
			logging.String("method", r.Method),
			logging.String("path", r.URL.Path),
			logging.String("statusCode", statusCode),
			logging.Duration("duration", m.Duration),
			logging.Int64("written", m.Written),
		)
	})
}
