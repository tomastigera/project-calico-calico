// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package collector

import (
	"reflect"
	"testing"
)

func TestParseEnvoyRouteName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected *RouteReference
	}{
		{
			name:  "valid httproute with match",
			input: "httproute/default/ns1-2-echo/rule/1/match/0/*",
			expected: &RouteReference{
				RouteType: "http",
				Namespace: "default",
				Name:      "ns1-2-echo",
				Rule:      1,
				Match:     0,
			},
		},
		{
			name:  "valid grpcroute with match",
			input: "grpcroute/kube-system/grpc-route/rule/2/match/1/*",
			expected: &RouteReference{
				RouteType: "grpc",
				Namespace: "kube-system",
				Name:      "grpc-route",
				Rule:      2,
				Match:     1,
			},
		},
		{
			name:  "valid httproute without match",
			input: "httproute/default/test-route/rule/0",
			expected: &RouteReference{
				RouteType: "http",
				Namespace: "default",
				Name:      "test-route",
				Rule:      0,
				Match:     -1,
			},
		},
		{
			name:  "valid httproute minimal format",
			input: "httproute/default/test-route",
			expected: &RouteReference{
				RouteType: "http",
				Namespace: "default",
				Name:      "test-route",
				Rule:      -1,
				Match:     -1,
			},
		},
		{
			name:     "dash value",
			input:    "-",
			expected: nil,
		},
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "invalid format - too few parts",
			input:    "invalid/format",
			expected: nil,
		},
		{
			name:     "invalid route type",
			input:    "tcproute/default/test",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseEnvoyRouteName(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ParseEnvoyRouteName(%q) = %+v, want %+v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParseGatewayName(t *testing.T) {
	tests := []struct {
		name              string
		input             string
		expectedNamespace string
		expectedName      string
	}{
		{
			name:              "valid namespaced gateway",
			input:             "default/eg",
			expectedNamespace: "default",
			expectedName:      "eg",
		},
		{
			name:              "gateway without namespace",
			input:             "my-gateway",
			expectedNamespace: "default",
			expectedName:      "my-gateway",
		},
		{
			name:              "dash value",
			input:             "-",
			expectedNamespace: "",
			expectedName:      "",
		},
		{
			name:              "empty string",
			input:             "",
			expectedNamespace: "",
			expectedName:      "",
		},
		{
			name:              "multi-part namespace",
			input:             "kube-system/istio-gateway",
			expectedNamespace: "kube-system",
			expectedName:      "istio-gateway",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			namespace, name := ParseGatewayName(tt.input)
			if namespace != tt.expectedNamespace || name != tt.expectedName {
				t.Errorf("ParseGatewayName(%q) = (%q, %q), want (%q, %q)",
					tt.input, namespace, name, tt.expectedNamespace, tt.expectedName)
			}
		})
	}
}
