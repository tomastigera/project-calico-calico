// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package collector

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/gateway/pkg/indexer"
	l7collector "github.com/projectcalico/calico/l7-collector/pkg/collector"
)

// Enricher enriches EnvoyLog entries with Gateway API resource status information
type Enricher struct {
	statusIndexer *indexer.StatusIndexer
	logger        *log.Entry

	// Default gateway info from environment variables (set by operator via downward API)
	// These are used when the log entry doesn't have gateway info from Envoy
	defaultGatewayName      string
	defaultGatewayNamespace string
}

// EnricherOption is a functional option for configuring the Enricher
type EnricherOption func(*Enricher)

// WithDefaultGateway sets the default gateway name and namespace to use
// when the log entry doesn't contain gateway information from Envoy.
// These values typically come from OWNING_GATEWAY_NAME and OWNING_GATEWAY_NAMESPACE
// environment variables set via Kubernetes downward API from pod labels.
func WithDefaultGateway(namespace, name string) EnricherOption {
	return func(e *Enricher) {
		e.defaultGatewayNamespace = namespace
		e.defaultGatewayName = name
	}
}

// NewEnricher creates a new Enricher instance
func NewEnricher(statusIndexer *indexer.StatusIndexer, opts ...EnricherOption) *Enricher {
	e := &Enricher{
		statusIndexer: statusIndexer,
		logger:        log.WithField("component", "enricher"),
	}

	for _, opt := range opts {
		opt(e)
	}

	if e.defaultGatewayName != "" && e.defaultGatewayNamespace != "" {
		e.logger.WithFields(log.Fields{
			"defaultGatewayName":      e.defaultGatewayName,
			"defaultGatewayNamespace": e.defaultGatewayNamespace,
		}).Info("Enricher configured with default gateway from environment")
	}

	return e
}

// EnrichLog adds Gateway API resource context to the log entry.
// This includes:
// - Parsing the Envoy route_name to extract HTTPRoute/GRPCRoute details
// - Adding Gateway status information (class, status, conditions)
// - Adding Route status information (accepted, resolved refs, conditions)
func (e *Enricher) EnrichLog(envoyLog *l7collector.EnvoyLog) {
	// Parse route reference from Envoy route_name
	var routeNamespace, routeResourceName, routeType string
	if envoyLog.RouteName != "" {
		routeRef := ParseEnvoyRouteName(envoyLog.RouteName)
		if routeRef != nil {
			routeNamespace = routeRef.Namespace
			routeResourceName = routeRef.Name
			routeType = routeRef.RouteType
		}
	}

	// Parse Gateway name to extract namespace (only if not already set)
	if envoyLog.GatewayName != "" && envoyLog.GatewayNamespace == "" {
		gwNamespace, gwName := ParseGatewayName(envoyLog.GatewayName)
		envoyLog.GatewayNamespace = gwNamespace
		envoyLog.GatewayName = gwName
	}

	// Apply default gateway info from environment if not set from Envoy log.
	// This is the typical case since Envoy logs don't include gateway name.
	// The defaults come from OWNING_GATEWAY_NAME and OWNING_GATEWAY_NAMESPACE
	// environment variables set via Kubernetes downward API from pod labels.
	if envoyLog.GatewayName == "" && e.defaultGatewayName != "" {
		envoyLog.GatewayName = e.defaultGatewayName
	}
	if envoyLog.GatewayNamespace == "" && e.defaultGatewayNamespace != "" {
		envoyLog.GatewayNamespace = e.defaultGatewayNamespace
	}

	// Enrich Route status based on type.
	// This must happen BEFORE gateway enrichment because route enrichment
	// can populate GatewayName/GatewayNamespace from the route's parent refs
	// when they weren't set from environment variables.
	switch routeType {
	case "http":
		e.enrichHTTPRouteStatus(envoyLog, routeNamespace, routeResourceName)
	case "grpc":
		e.enrichGRPCRouteStatus(envoyLog, routeNamespace, routeResourceName)
	}

	// Enrich Gateway status (must happen after route enrichment which may populate gateway info)
	e.enrichGatewayStatus(envoyLog)
}

// enrichGatewayStatus adds Gateway status information to the log entry
func (e *Enricher) enrichGatewayStatus(envoyLog *l7collector.EnvoyLog) {
	if envoyLog.GatewayNamespace == "" || envoyLog.GatewayName == "" {
		return
	}

	gwStatus, ok := e.statusIndexer.GetGatewayStatus(
		envoyLog.GatewayNamespace,
		envoyLog.GatewayName,
	)
	if !ok {
		envoyLog.GatewayStatus = "unknown"
		envoyLog.GatewayStatusMessage = "Gateway not found in indexer"
		return
	}

	envoyLog.GatewayClass = gwStatus.GatewayClass

	// Derive Gateway status from conditions
	if gwStatus.Programmed && gwStatus.Accepted {
		envoyLog.GatewayStatus = "active"
		envoyLog.GatewayStatusMessage = "The gateway is operating normally."
	} else if gwStatus.Accepted {
		envoyLog.GatewayStatus = "accepted"
		envoyLog.GatewayStatusMessage = gwStatus.ProgrammedMessage
	} else {
		envoyLog.GatewayStatus = "not-accepted"
		envoyLog.GatewayStatusMessage = gwStatus.AcceptedMessage
	}

	// Store listener details (use first listener for now)
	// TODO: In the future, match listener based on port or other criteria from the access log
	if len(gwStatus.Listeners) > 0 {
		for _, listener := range gwStatus.Listeners {
			envoyLog.GatewayListenerName = listener.Name
			envoyLog.GatewayListenerPort = listener.Port
			envoyLog.GatewayListenerProtocol = listener.Protocol
			envoyLog.GatewayListenerHostname = listener.Hostname
			// Compute full listener name: <gateway-name>-<listener-name>-<listener-port>
			envoyLog.GatewayListenerFullName = fmt.Sprintf("%s-%s-%d",
				envoyLog.GatewayName, listener.Name, listener.Port)
			break // Use first listener
		}
	}
}

// enrichHTTPRouteStatus adds HTTPRoute status information to the log entry
func (e *Enricher) enrichHTTPRouteStatus(envoyLog *l7collector.EnvoyLog, routeNamespace, routeResourceName string) {
	if routeNamespace == "" || routeResourceName == "" {
		return
	}

	routeStatus, ok := e.statusIndexer.GetHTTPRouteStatus(
		routeNamespace,
		routeResourceName,
	)
	if !ok {
		envoyLog.GatewayRouteType = "http"
		envoyLog.GatewayRouteName = routeResourceName
		envoyLog.GatewayRouteNamespace = routeNamespace
		envoyLog.GatewayRouteStatus = "unknown"
		envoyLog.GatewayRouteStatusMessage = "HTTPRoute not found in indexer"
		return
	}

	// Set unified route fields
	envoyLog.GatewayRouteType = "http"
	envoyLog.GatewayRouteName = routeResourceName
	envoyLog.GatewayRouteNamespace = routeNamespace

	// Use first hostname from route spec if available
	if len(routeStatus.Hostnames) > 0 {
		envoyLog.GatewayRouteHostname = routeStatus.Hostnames[0]
	}

	// If gateway info is available, find matching parent ref
	// Otherwise, use the first parent ref (or first accepted one)
	var matchingParentRef *indexer.ParentRefStatus
	for i := range routeStatus.ParentRefs {
		parentRef := &routeStatus.ParentRefs[i]

		// If we have gateway info, look for an exact match
		if envoyLog.GatewayNamespace != "" && envoyLog.GatewayName != "" {
			if parentRef.ParentNamespace == envoyLog.GatewayNamespace &&
				parentRef.ParentName == envoyLog.GatewayName {
				matchingParentRef = parentRef
				break
			}
		} else {
			// No gateway info available - prefer first accepted parent ref
			if matchingParentRef == nil || (parentRef.Accepted && !matchingParentRef.Accepted) {
				matchingParentRef = parentRef
			}
		}
	}

	if matchingParentRef != nil {
		// Populate gateway info from the parent ref if not already set
		if envoyLog.GatewayNamespace == "" {
			envoyLog.GatewayNamespace = matchingParentRef.ParentNamespace
		}
		if envoyLog.GatewayName == "" {
			envoyLog.GatewayName = matchingParentRef.ParentName
		}

		if matchingParentRef.Accepted && matchingParentRef.ResolvedRefs {
			envoyLog.GatewayRouteStatus = "active"
			envoyLog.GatewayRouteStatusMessage = "The http route is operating normally"
		} else if matchingParentRef.Accepted {
			envoyLog.GatewayRouteStatus = "accepted"
			envoyLog.GatewayRouteStatusMessage = matchingParentRef.ResolvedMessage
		} else {
			envoyLog.GatewayRouteStatus = "not-accepted"
			envoyLog.GatewayRouteStatusMessage = matchingParentRef.AcceptedMessage
		}
		return
	}

	// No parent refs found at all
	envoyLog.GatewayRouteStatus = "not-attached"
	envoyLog.GatewayRouteStatusMessage = "Route has no parent gateway references"
}

// enrichGRPCRouteStatus adds GRPCRoute status information to the log entry
func (e *Enricher) enrichGRPCRouteStatus(envoyLog *l7collector.EnvoyLog, routeNamespace, routeResourceName string) {
	if routeNamespace == "" || routeResourceName == "" {
		return
	}

	routeStatus, ok := e.statusIndexer.GetGRPCRouteStatus(
		routeNamespace,
		routeResourceName,
	)
	if !ok {
		envoyLog.GatewayRouteType = "grpc"
		envoyLog.GatewayRouteName = routeResourceName
		envoyLog.GatewayRouteNamespace = routeNamespace
		envoyLog.GatewayRouteStatus = "unknown"
		envoyLog.GatewayRouteStatusMessage = "GRPCRoute not found in indexer"
		return
	}

	// Set unified route fields
	envoyLog.GatewayRouteType = "grpc"
	envoyLog.GatewayRouteName = routeResourceName
	envoyLog.GatewayRouteNamespace = routeNamespace

	// Use first hostname from route spec if available
	if len(routeStatus.Hostnames) > 0 {
		envoyLog.GatewayRouteHostname = routeStatus.Hostnames[0]
	}

	// If gateway info is available, find matching parent ref
	// Otherwise, use the first parent ref (or first accepted one)
	var matchingParentRef *indexer.ParentRefStatus
	for i := range routeStatus.ParentRefs {
		parentRef := &routeStatus.ParentRefs[i]

		// If we have gateway info, look for an exact match
		if envoyLog.GatewayNamespace != "" && envoyLog.GatewayName != "" {
			if parentRef.ParentNamespace == envoyLog.GatewayNamespace &&
				parentRef.ParentName == envoyLog.GatewayName {
				matchingParentRef = parentRef
				break
			}
		} else {
			// No gateway info available - prefer first accepted parent ref
			if matchingParentRef == nil || (parentRef.Accepted && !matchingParentRef.Accepted) {
				matchingParentRef = parentRef
			}
		}
	}

	if matchingParentRef != nil {
		// Populate gateway info from the parent ref if not already set
		if envoyLog.GatewayNamespace == "" {
			envoyLog.GatewayNamespace = matchingParentRef.ParentNamespace
		}
		if envoyLog.GatewayName == "" {
			envoyLog.GatewayName = matchingParentRef.ParentName
		}

		if matchingParentRef.Accepted && matchingParentRef.ResolvedRefs {
			envoyLog.GatewayRouteStatus = "active"
			envoyLog.GatewayRouteStatusMessage = "The grpc route is operating normally"
		} else if matchingParentRef.Accepted {
			envoyLog.GatewayRouteStatus = "accepted"
			envoyLog.GatewayRouteStatusMessage = matchingParentRef.ResolvedMessage
		} else {
			envoyLog.GatewayRouteStatus = "not-accepted"
			envoyLog.GatewayRouteStatusMessage = matchingParentRef.AcceptedMessage
		}
		return
	}

	// No parent refs found at all
	envoyLog.GatewayRouteStatus = "not-attached"
	envoyLog.GatewayRouteStatusMessage = "Route has no parent gateway references"
}
