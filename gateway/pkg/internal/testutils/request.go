// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package testutils

import (
	"maps"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
)

type ProcessingRequestBuilder struct {
	requestId                            string
	srcHost, dstHost                     string
	srcPort, dstPort                     uint32
	protocol, method, scheme, host, path string
	headers                              map[string]string
	body, responseBody                   []byte
	responseHeaders                      map[string]string
}

type ProcessingRequestBuilderOption func(*ProcessingRequestBuilder)

func NewProcessingRequestBuilder(opts ...ProcessingRequestBuilderOption) *ProcessingRequestBuilder {
	res := &ProcessingRequestBuilder{
		requestId:    "test-request-id",
		srcHost:      "0.0.0.0",
		srcPort:      0,
		dstHost:      "127.0.0.1",
		dstPort:      80,
		protocol:     "HTTP/1.1",
		method:       "GET",
		scheme:       "http",
		host:         "www.example.com",
		path:         "/",
		headers:      map[string]string{},
		body:         []byte{},
		responseBody: []byte{},
		responseHeaders: map[string]string{
			"Content-Type":                  "text/plain",
			"Server":                        "Dikastes",
			"X-Envoy-Upstream-Service-Time": "0",
		},
	}

	for _, opt := range opts {
		opt(res)
	}
	return res
}

func WithSourceHostPort(srcHost string, srcPort uint32) ProcessingRequestBuilderOption {
	return func(b *ProcessingRequestBuilder) {
		b.srcHost = srcHost
		b.srcPort = srcPort
	}
}

func WithDestinationHostPort(dstHost string, dstPort uint32) ProcessingRequestBuilderOption {
	return func(b *ProcessingRequestBuilder) {
		b.dstHost = dstHost
		b.dstPort = dstPort
	}
}

func WithMethod(method string) ProcessingRequestBuilderOption {
	return func(b *ProcessingRequestBuilder) {
		b.method = method
	}
}

func WithHost(host string) ProcessingRequestBuilderOption {
	return func(b *ProcessingRequestBuilder) {
		b.host = host
	}
}

func WithPath(path string) ProcessingRequestBuilderOption {
	return func(b *ProcessingRequestBuilder) {
		b.path = path
	}
}

func WithScheme(scheme string) ProcessingRequestBuilderOption {
	return func(b *ProcessingRequestBuilder) {
		b.scheme = scheme
	}
}

func WithRequestHeaders(headers map[string]string) ProcessingRequestBuilderOption {
	return func(b *ProcessingRequestBuilder) {
		maps.Copy(b.headers, headers)
	}
}

func WithRequestBody(body []byte) ProcessingRequestBuilderOption {
	return func(b *ProcessingRequestBuilder) {
		b.body = body
	}
}

func WithResponseHeaders(headers map[string]string) ProcessingRequestBuilderOption {
	return func(b *ProcessingRequestBuilder) {
		maps.Copy(b.responseHeaders, headers)
	}
}

func WithResponseBody(body []byte) ProcessingRequestBuilderOption {
	return func(b *ProcessingRequestBuilder) {
		b.responseBody = body
	}
}

func (b *ProcessingRequestBuilder) Values() []*envoy_service_proc_v3.ProcessingRequest {
	return b.toProcessingRequest()
}

func (b *ProcessingRequestBuilder) toProcessingRequest() []*envoy_service_proc_v3.ProcessingRequest {
	headers := make([]*corev3.HeaderValue, 0, len(b.headers))
	for k, v := range b.headers {
		headers = append(headers, &corev3.HeaderValue{
			Key:      k,
			Value:    v,
			RawValue: []byte(v),
		})
	}

	// add special headers e.g. ":scheme", ":authority", ":path", ":method", ":protocol"
	headers = append(headers,
		// request id
		&corev3.HeaderValue{
			Key:      "x-request-id",
			Value:    b.requestId,
			RawValue: []byte(b.requestId),
		},
		// not really important, but good to have
		&corev3.HeaderValue{
			Key:      ":scheme",
			Value:    b.scheme,
			RawValue: []byte(b.scheme),
		},
		// important for SetServerName and AddRequestHeader "Host" in coraza
		&corev3.HeaderValue{
			Key:      ":authority",
			Value:    b.host,
			RawValue: []byte(b.host),
		},
		// important for ProcessURI in coraza
		&corev3.HeaderValue{
			Key:      ":path",
			Value:    b.path,
			RawValue: []byte(b.path),
		},
		&corev3.HeaderValue{
			Key:      ":method",
			Value:    b.method,
			RawValue: []byte(b.method),
		},
		&corev3.HeaderValue{
			Key:      ":protocol",
			Value:    b.protocol,
			RawValue: []byte(b.protocol),
		},
	)

	responseHeaders := make([]*corev3.HeaderValue, 0, len(b.responseHeaders))
	for k, v := range b.responseHeaders {
		responseHeaders = append(responseHeaders, &corev3.HeaderValue{
			Key:      k,
			Value:    v,
			RawValue: []byte(v),
		})
	}

	return []*envoy_service_proc_v3.ProcessingRequest{
		0: { // phase 1, REQ headers
			Request: &envoy_service_proc_v3.ProcessingRequest_RequestHeaders{
				RequestHeaders: &envoy_service_proc_v3.HttpHeaders{
					Headers: &corev3.HeaderMap{
						Headers: headers,
					},
				},
			},
		},
		1: { // phase 2, REQ body
			Request: &envoy_service_proc_v3.ProcessingRequest_RequestBody{
				RequestBody: &envoy_service_proc_v3.HttpBody{
					Body: b.body,
				},
			},
		},
		2: { // phase 2, REQ body - end of stream
			Request: &envoy_service_proc_v3.ProcessingRequest_RequestBody{
				RequestBody: &envoy_service_proc_v3.HttpBody{
					Body:        []byte{},
					EndOfStream: true,
				},
			},
		},

		3: { // phase 3, RES headers
			Request: &envoy_service_proc_v3.ProcessingRequest_ResponseHeaders{
				ResponseHeaders: &envoy_service_proc_v3.HttpHeaders{
					Headers: &corev3.HeaderMap{
						Headers: responseHeaders,
					},
				},
			},
		},
		4: { // phase 4, RES body
			Request: &envoy_service_proc_v3.ProcessingRequest_ResponseBody{
				ResponseBody: &envoy_service_proc_v3.HttpBody{
					Body: b.responseBody,
				},
			},
		},
		5: { // phase 4, RES body - end of stream
			Request: &envoy_service_proc_v3.ProcessingRequest_ResponseBody{
				ResponseBody: &envoy_service_proc_v3.HttpBody{
					Body:        []byte{},
					EndOfStream: true,
				},
			},
		},
	}
}
