// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package utils

import (
	envoy_service_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
)

type Phase int8

const (
	PHASE_REQUEST_HEADERS Phase = iota
	PHASE_REQUEST_BODY
	PHASE_RESPONSE_HEADERS
	PHASE_RESPONSE_BODY
)

func NewPhaseContinueResponse(phase Phase) *envoy_service_proc_v3.ProcessingResponse {
	switch phase {
	case PHASE_REQUEST_HEADERS:
		return &envoy_service_proc_v3.ProcessingResponse{
			Response: &envoy_service_proc_v3.ProcessingResponse_RequestHeaders{
				RequestHeaders: &envoy_service_proc_v3.HeadersResponse{
					Response: &envoy_service_proc_v3.CommonResponse{
						Status: envoy_service_proc_v3.CommonResponse_CONTINUE,
					},
				},
			},
		}
	case PHASE_REQUEST_BODY:
		return &envoy_service_proc_v3.ProcessingResponse{
			Response: &envoy_service_proc_v3.ProcessingResponse_RequestBody{
				RequestBody: &envoy_service_proc_v3.BodyResponse{
					Response: &envoy_service_proc_v3.CommonResponse{
						Status: envoy_service_proc_v3.CommonResponse_CONTINUE,
					},
				},
			},
		}
	case PHASE_RESPONSE_HEADERS:
		return &envoy_service_proc_v3.ProcessingResponse{
			Response: &envoy_service_proc_v3.ProcessingResponse_ResponseHeaders{
				ResponseHeaders: &envoy_service_proc_v3.HeadersResponse{
					Response: &envoy_service_proc_v3.CommonResponse{
						Status: envoy_service_proc_v3.CommonResponse_CONTINUE,
					},
				},
			},
		}
	case PHASE_RESPONSE_BODY:
		return &envoy_service_proc_v3.ProcessingResponse{
			Response: &envoy_service_proc_v3.ProcessingResponse_ResponseBody{
				ResponseBody: &envoy_service_proc_v3.BodyResponse{
					Response: &envoy_service_proc_v3.CommonResponse{
						Status: envoy_service_proc_v3.CommonResponse_CONTINUE,
					},
				},
			},
		}
	}
	return &envoy_service_proc_v3.ProcessingResponse{}
}

func NewForbiddenResponse(body []byte) *envoy_service_proc_v3.ProcessingResponse_ImmediateResponse {
	return NewImmediateResponse(envoy_type_v3.StatusCode_Forbidden, body)
}

func NewImmediateResponse(code envoy_type_v3.StatusCode, body []byte) *envoy_service_proc_v3.ProcessingResponse_ImmediateResponse {
	return &envoy_service_proc_v3.ProcessingResponse_ImmediateResponse{
		ImmediateResponse: &envoy_service_proc_v3.ImmediateResponse{
			Status: &envoy_type_v3.HttpStatus{
				Code: code,
			},
			Body: body,
		},
	}
}

func IsContinueResponse(resp *envoy_service_proc_v3.ProcessingResponse) bool {
	if resp == nil {
		return false
	}
	switch r := resp.Response.(type) {
	case *envoy_service_proc_v3.ProcessingResponse_RequestHeaders:
		return r.RequestHeaders.Response.Status == envoy_service_proc_v3.CommonResponse_CONTINUE
	case *envoy_service_proc_v3.ProcessingResponse_RequestBody:
		return r.RequestBody.Response.Status == envoy_service_proc_v3.CommonResponse_CONTINUE
	case *envoy_service_proc_v3.ProcessingResponse_ResponseHeaders:
		return r.ResponseHeaders.Response.Status == envoy_service_proc_v3.CommonResponse_CONTINUE
	case *envoy_service_proc_v3.ProcessingResponse_ResponseBody:
		return r.ResponseBody.Response.Status == envoy_service_proc_v3.CommonResponse_CONTINUE
	default:
		return false
	}
}
