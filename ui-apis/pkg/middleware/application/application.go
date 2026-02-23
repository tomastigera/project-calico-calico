// Copyright (c) 2022 Tigera, Inc. All rights reserved.
package application

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	lapi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/lma/pkg/api"
	"github.com/projectcalico/calico/lma/pkg/httputils"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
	"github.com/projectcalico/calico/ui-apis/pkg/middleware"
)

type ApplicationType int

const (
	ApplicationTypeService = iota
	ApplicationTypeURL

	httpStatusServerErrorUpperBound = 599
)

// ApplicationHandler handles application layer (l7) log requests from manager dashboard.
func ApplicationHandler(
	authReview middleware.AuthorizationReview,
	lsclient client.Client,
	applicationType ApplicationType,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		params, err := parseApplicationRequest(w, r)
		if err != nil {
			httputils.EncodeError(w, err)
			return
		}

		var resp any
		switch applicationType {
		case ApplicationTypeService:
			resp, err = processServiceRequest(params, authReview, lsclient, r)
		case ApplicationTypeURL:
			resp, err = processURLRequest(params, authReview, lsclient, r)
		default:
			log.Errorf("Invalid application type %v.", applicationType)

			err = &httputils.HttpStatusError{
				Status: http.StatusInternalServerError,
				Msg:    http.StatusText(http.StatusInternalServerError),
				Err:    errors.New("invalid application handler type"),
			}
		}

		if err != nil {
			httputils.EncodeError(w, err)
			return
		}
		httputils.Encode(w, resp)
	})
}

// parseApplicationRequest extracts parameters from the request body and validates them.
func parseApplicationRequest(w http.ResponseWriter, r *http.Request) (*v1.ApplicationRequest, error) {
	// Validate http method.
	if r.Method != http.MethodPost {
		log.WithError(middleware.ErrInvalidMethod).Info("Invalid http method.")

		return nil, &httputils.HttpStatusError{
			Status: http.StatusMethodNotAllowed,
			Msg:    middleware.ErrInvalidMethod.Error(),
			Err:    middleware.ErrInvalidMethod,
		}
	}

	// Decode the http request body into the struct.
	var params v1.ApplicationRequest

	if err := httputils.Decode(w, r, &params); err != nil {
		var mr *httputils.HttpStatusError
		if errors.As(err, &mr) {
			log.WithError(mr.Err).Info(mr.Msg)
			return nil, mr
		} else {
			log.WithError(mr.Err).Info("Error validating service requests.")
			return nil, &httputils.HttpStatusError{
				Status: http.StatusBadRequest,
				Msg:    http.StatusText(http.StatusBadRequest),
				Err:    err,
			}
		}
	}

	if params.TimeRange == nil {
		err := errors.New("missing time range")
		log.WithError(err).Info("Error validating service requests.")
		return nil, &httputils.HttpStatusError{
			Status: http.StatusBadRequest,
			Msg:    http.StatusText(http.StatusBadRequest),
			Err:    err,
		}
	}

	// Set cluster name to default: "cluster", if empty.
	if params.ClusterName == "" {
		params.ClusterName = middleware.MaybeParseClusterNameFromRequest(r)
	}

	return &params, nil
}

type service struct {
	Count            int
	SourceNameAggr   string
	TotalBytesIn     int           // sum(bytes_in)
	TotalBytesOut    int           // sum(bytes_out)
	TotalDuration    time.Duration // sum(duration_mean * count) in milliseconds
	TotalLatency     time.Duration // sum(latency) in milliseconds
	TotalErrorCount  int           // count(http response_code 400-599)
	TotalLogDuration int64         // sum(end_time - start_time) in seconds
}

// processServiceRequest translates service request parameters to Elastic queries and returns responses.
func processServiceRequest(
	reqParams *v1.ApplicationRequest,
	authReview middleware.AuthorizationReview,
	lsclient client.Client,
	r *http.Request,
) (*v1.ServiceResponse, error) {
	// create a context with timeout to ensure we don't block for too long.
	ctx, cancelWithTimeout := context.WithTimeout(r.Context(), middleware.DefaultRequestTimeout)
	defer cancelWithTimeout()

	// Build list params.
	params := lapi.L7LogParams{}
	params.TimeRange = reqParams.TimeRange
	params.Selector = reqParams.Selector

	if authReview != nil {
		verbs, err := authReview.PerformReview(ctx, reqParams.ClusterName)
		if err != nil {
			return nil, err
		}
		params.Permissions = verbs
	}
	params.MaxPageSize = middleware.MaxResultsPerPage
	params.Timeout = &metav1.Duration{Duration: middleware.DefaultRequestTimeout}

	// Perform paginated list.
	pager := client.NewListPager(&params, client.WithMaxResults[lapi.L7Log](middleware.MaxNumResults))
	pages, errors := pager.Stream(ctx, lsclient.L7Logs(reqParams.ClusterName).List)

	serviceMap := make(map[string]*service)
	for page := range pages {
		for _, l7Log := range page.Items {
			// ignore l7 log entries when source is empty.
			sourceNameAggr := l7Log.SourceNameAggr
			// filter out zero-duration l7 log entries.
			// l7-log-collector sometimes reports zero duration_mean log entries. this will cause invalid
			// rate calculation below and internal server error when marshaling json response.
			durationMean := l7Log.DurationMean
			if sourceNameAggr != "" &&
				sourceNameAggr != api.FlowLogNetworkPrivate && sourceNameAggr != api.FlowLogNetworkPublic &&
				durationMean > 0 {
				errCount := 0
				if responseCode, err := strconv.Atoi(l7Log.ResponseCode); err == nil {
					// Count HTTP error responses from 400 - 499 (client error) + 500 - 599 (server error)
					if responseCode >= http.StatusBadRequest && responseCode <= httpStatusServerErrorUpperBound {
						errCount = int(l7Log.Count)
					}
				}

				if s, found := serviceMap[sourceNameAggr]; found {
					s.Count += int(l7Log.Count)
					s.TotalBytesIn += int(l7Log.BytesIn)
					s.TotalBytesOut += int(l7Log.BytesOut)
					s.TotalDuration += time.Duration(int(l7Log.Count * l7Log.DurationMean))
					s.TotalLatency += time.Duration(l7Log.Latency)
					s.TotalErrorCount += errCount
					s.TotalLogDuration += l7Log.EndTime - l7Log.StartTime
				} else {
					serviceMap[sourceNameAggr] = &service{
						Count:            int(l7Log.Count),
						SourceNameAggr:   sourceNameAggr,
						TotalBytesIn:     int(l7Log.BytesIn),
						TotalBytesOut:    int(l7Log.BytesOut),
						TotalDuration:    time.Duration(l7Log.Count * l7Log.DurationMean),
						TotalLatency:     time.Duration(l7Log.Latency),
						TotalErrorCount:  errCount,
						TotalLogDuration: l7Log.EndTime - l7Log.StartTime,
					}
				}
			}

		}
	}

	if err, ok := <-errors; ok {
		return nil, err
	}

	services := make([]v1.Service, 0)
	for k, v := range serviceMap {
		service := v1.Service{
			Name:               k,
			ErrorRate:          float64(v.TotalErrorCount) / float64(v.Count) * 100,        // %
			Latency:            float64(v.TotalDuration.Microseconds()) / float64(v.Count), // microseconds
			InboundThroughput:  float64(v.TotalBytesIn) / v.TotalDuration.Seconds(),        // bytes/second
			OutboundThroughput: float64(v.TotalBytesOut) / v.TotalDuration.Seconds(),       // bytes/second
			RequestThroughput:  float64(v.Count) / float64(v.TotalLogDuration),             // /second
		}
		services = append(services, service)
	}

	return &v1.ServiceResponse{
		Services: services,
	}, nil
}

type url struct {
	RequestCount int
}

type urlMapKey struct {
	URL            string
	SourceNameAggr string
}

// processURLRequest translates url request parameters to Elastic queries and returns responses.
func processURLRequest(
	reqParams *v1.ApplicationRequest,
	authReview middleware.AuthorizationReview,
	lsclient client.Client,
	r *http.Request,
) (*v1.URLResponse, error) {
	// create a context with timeout to ensure we don't block for too long.
	ctx, cancelWithTimeout := context.WithTimeout(r.Context(), middleware.DefaultRequestTimeout)
	defer cancelWithTimeout()

	// Build list params.
	params := lapi.L7LogParams{}
	params.TimeRange = reqParams.TimeRange
	params.Selector = reqParams.Selector

	if authReview != nil {
		verbs, err := authReview.PerformReview(ctx, reqParams.ClusterName)
		if err != nil {
			return nil, err
		}
		params.Permissions = verbs
	}
	params.MaxPageSize = middleware.MaxResultsPerPage
	params.Timeout = &metav1.Duration{Duration: middleware.DefaultRequestTimeout}

	// Perform paginated list.
	pager := client.NewListPager(&params, client.WithMaxResults[lapi.L7Log](middleware.MaxNumResults))
	pages, errors := pager.Stream(ctx, lsclient.L7Logs(reqParams.ClusterName).List)

	urlMap := make(map[urlMapKey]*url)
	for page := range pages {
		for _, l7Log := range page.Items {
			key := urlMapKey{
				URL:            l7Log.URL,
				SourceNameAggr: l7Log.SourceNameAggr,
			}
			if key.URL != "" && key.SourceNameAggr != "" &&
				key.SourceNameAggr != api.FlowLogNetworkPrivate && key.SourceNameAggr != api.FlowLogNetworkPublic {
				if s, found := urlMap[key]; found {
					s.RequestCount += int(l7Log.Count)
				} else {
					urlMap[key] = &url{
						RequestCount: int(l7Log.Count),
					}
				}
			}
		}
	}

	if err, ok := <-errors; ok {
		return nil, err
	}

	urls := make([]v1.URL, 0)
	for k, v := range urlMap {
		url := v1.URL{
			URL:          k.URL,
			Service:      k.SourceNameAggr,
			RequestCount: v.RequestCount,
		}
		urls = append(urls, url)
	}

	return &v1.URLResponse{
		URLs: urls,
	}, nil
}
