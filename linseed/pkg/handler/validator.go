// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package handler

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/goldmane/proto"
	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/lma/pkg/httputils"
)

// maxBulkBytes represents the maximum bytes an HTTP request body on a bulk request can have.
// We cap this out at 100MB - the default value set by Elastic for an HTTP request.
const maxBulkBytes = 100 * 1000000

// newlineJsonContent is the supported content type
// for bulk APIs
const newlineJsonContent = "application/x-ndjson"

// jsonContent is the supported content type
// for bulk APIs
const jsonContent = "application/json"

// contentType is the content type header
const contentType = "Content-Type"

// RequestParams is the collection of request parameters types
// that will be decoded and validated from an HTTP request
type RequestParams interface {
	v1.L3FlowParams | v1.L3FlowCountParams |
		v1.FlowLogParams | v1.FlowLogCountParams | v1.FlowLogAggregationParams |
		v1.L7FlowParams | v1.L7LogParams | v1.L7AggregationParams |
		v1.DNSFlowParams | v1.DNSLogParams | v1.DNSAggregationParams |
		v1.EventParams | v1.AuditLogParams | v1.AuditLogAggregationParams |
		v1.BGPLogParams | v1.ProcessParams |
		v1.WAFLogParams | v1.WAFLogAggregationParams |
		v1.ReportDataParams | v1.SnapshotParams | v1.BenchmarksParams |
		v1.RuntimeReportParams | v1.IPSetThreatFeedParams |
		v1.DomainNameSetThreatFeedParams | v1.EventStatisticsParams |
		v1.PolicyActivityParams
}

// BulkRequestParams is the collection of request parameters types
// for bulk requests that will be decoded and validated from an HTTP request
type BulkRequestParams interface {
	v1.FlowLog | v1.Event | *proto.Flow |
		v1.L7Log | v1.DNSLog |
		v1.AuditLog | v1.BGPLog |
		v1.WAFLog | v1.ReportData |
		v1.Snapshot | v1.Benchmarks |
		v1.Report | v1.IPSetThreatFeed |
		v1.DomainNameSetThreatFeed |
		v1.PolicyActivity
}

// BulkDecodeResult holds the result of decoding a bulk NDJSON request body.
type BulkDecodeResult[T BulkRequestParams] struct {
	Items       []T
	FailedCount int
}

// DecodeAndValidateBulkParams will decode and validate input parameters
// passed on the HTTP body of a bulk request. Malformed JSON lines are
// skipped and counted as failures. If no valid items can be decoded,
// an HTTPStatusError will be returned.
func DecodeAndValidateBulkParams[T BulkRequestParams](w http.ResponseWriter, req *http.Request) (BulkDecodeResult[T], *v1.HTTPError) {
	var result BulkDecodeResult[T]

	// Check content-type
	content := strings.ToLower(strings.TrimSpace(req.Header.Get(contentType)))
	if content != newlineJsonContent {
		return result, &v1.HTTPError{
			Status: http.StatusUnsupportedMediaType,
			Msg:    fmt.Sprintf("Received a request with content-type (%s) that is not supported", content),
		}
	}

	// Check body
	if req.Body == nil {
		return result, &v1.HTTPError{
			Status: http.StatusBadRequest,
			Msg:    "Received a request with an empty body",
		}
	}

	// Read only max bytes
	req.Body = http.MaxBytesReader(w, req.Body, maxBulkBytes)
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return result, &v1.HTTPError{
			Status: http.StatusBadRequest,
			Msg:    err.Error(),
		}
	}
	req.Body = io.NopCloser(bytes.NewBuffer(body))

	trimBody := bytes.Trim(body, "\r\n")
	scanner := bufio.NewScanner(bytes.NewReader(trimBody))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var input T
		d := json.NewDecoder(bytes.NewReader(line))
		d.DisallowUnknownFields()
		if err := d.Decode(&input); err != nil {
			logrus.WithError(err).Warnf("Failed to decode message on line %d, skipping", lineNum)
			result.FailedCount++
			continue
		}
		result.Items = append(result.Items, input)
	}

	if len(result.Items) == 0 {
		return result, &v1.HTTPError{
			Status: http.StatusBadRequest,
			Msg:    "Request body contains badly-formed JSON",
		}
	}

	return result, nil
}

// Timeout gets the user-provided timeout from the request, or default timeout
// if none was provided.
func Timeout(w http.ResponseWriter, req *http.Request) (metav1.Duration, error) {
	p := v1.QueryParams{}
	if err := httputils.DecodeIgnoreUnknownFields(w, req, &p); err != nil {
		return metav1.Duration{}, err
	}
	if p.Timeout == nil {
		return metav1.Duration{Duration: v1.DefaultTimeOut}, nil
	}
	return *p.Timeout, nil
}

// DecodeAndValidateReqParams will decode and validate input parameters
// passed on the HTTP body of a request. In case the input parameters
// are invalid or cannot be decoded, an HTTPStatusError will be returned
func DecodeAndValidateReqParams[T RequestParams](w http.ResponseWriter, req *http.Request) (*T, *v1.HTTPError) {
	reqParams := new(T)

	content := strings.ToLower(strings.TrimSpace(req.Header.Get(contentType)))
	if content != jsonContent {
		return reqParams, &v1.HTTPError{
			Status: http.StatusUnsupportedMediaType,
			Msg:    fmt.Sprintf("Received a request with content-type (%s) that is not supported", content),
		}
	}

	// Decode the http request body into the struct.
	if err := httputils.Decode(w, req, &reqParams); err != nil {
		return reqParams, &v1.HTTPError{
			Msg:    err.Error(),
			Status: http.StatusBadRequest,
		}
	}

	// Validate parameters.
	if err := validator.Validate(reqParams); err != nil {
		return reqParams, &v1.HTTPError{
			Status: http.StatusBadRequest,
			Msg:    err.Error(),
		}
	}

	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		// If debug logging is enabled, print out pretty params.
		paramsStr := spew.Sdump(reqParams)
		logrus.Debugf("Decoded %T: %s", reqParams, paramsStr)
	}

	return reqParams, nil
}
