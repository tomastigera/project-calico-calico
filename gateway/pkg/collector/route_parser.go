// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package collector

import (
	"strconv"
	"strings"
)

// RouteReference contains parsed information from Envoy's route_name attribute
type RouteReference struct {
	RouteType string // "http" or "grpc"
	Namespace string
	Name      string
	Rule      int
	Match     int
}

// ParseEnvoyRouteName parses Envoy's route_name attribute to extract route details.
//
// Expected format: "httproute/<namespace>/<name>/rule/<rule-idx>/match/<match-idx>/*"
// Example: "httproute/default/ns1-2-echo/rule/1/match/0/*"
//
// Returns nil if the route name doesn't match the expected format.
func ParseEnvoyRouteName(routeName string) *RouteReference {
	if routeName == "" || routeName == "-" {
		return nil
	}

	// Split by '/'
	parts := strings.Split(routeName, "/")
	if len(parts) < 3 {
		return nil
	}

	// First part is the route type (httproute or grpcroute)
	routeType := parts[0]
	if routeType != "httproute" && routeType != "grpcroute" {
		return nil
	}

	ref := &RouteReference{
		Namespace: parts[1],
		Name:      parts[2],
		Rule:      -1,
		Match:     -1,
	}

	// Convert route type to our format
	switch routeType {
	case "httproute":
		ref.RouteType = "http"
	case "grpcroute":
		ref.RouteType = "grpc"
	}

	// Parse rule index if present
	if len(parts) >= 5 && parts[3] == "rule" {
		if ruleIdx, err := strconv.Atoi(parts[4]); err == nil {
			ref.Rule = ruleIdx
		}
	}

	// Parse match index if present
	if len(parts) >= 7 && parts[5] == "match" {
		if matchIdx, err := strconv.Atoi(parts[6]); err == nil {
			ref.Match = matchIdx
		}
	}

	return ref
}

// ParseGatewayName parses a gateway identifier in the format "namespace/name"
// and returns the namespace and name components.
func ParseGatewayName(gatewayID string) (namespace, name string) {
	if gatewayID == "" || gatewayID == "-" {
		return "", ""
	}

	parts := strings.Split(gatewayID, "/")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}

	// If no namespace separator, assume default namespace
	return "default", gatewayID
}
