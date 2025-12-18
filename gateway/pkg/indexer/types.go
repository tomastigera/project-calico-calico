package indexer

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// GatewayStatus contains indexed status information for a Gateway resource
type GatewayStatus struct {
	Namespace         string
	Name              string
	GatewayClass      string
	Accepted          bool
	AcceptedReason    string
	AcceptedMessage   string
	Programmed        bool
	ProgrammedReason  string
	ProgrammedMessage string
	Addresses         []gwv1.GatewayStatusAddress
	Listeners         map[string]*ListenerStatus
	LastUpdated       time.Time
}

// ListenerStatus contains indexed status for a Gateway listener
type ListenerStatus struct {
	Name           string
	Port           int
	Protocol       string
	Hostname       string
	AttachedRoutes int32
	Programmed     bool
	Accepted       bool
	ResolvedRefs   bool
	Conditions     []metav1.Condition
}

// HTTPRouteStatus contains indexed status for an HTTPRoute resource
type HTTPRouteStatus struct {
	Namespace   string
	Name        string
	Hostnames   []string // spec.hostnames for matching
	ParentRefs  []ParentRefStatus
	LastUpdated time.Time
}

// GRPCRouteStatus contains indexed status for a GRPCRoute resource
type GRPCRouteStatus struct {
	Namespace   string
	Name        string
	Hostnames   []string // spec.hostnames for matching
	ParentRefs  []ParentRefStatus
	LastUpdated time.Time
}

// ParentRefStatus contains status for a specific parent Gateway reference
type ParentRefStatus struct {
	ParentNamespace string
	ParentName      string
	ControllerName  string
	Accepted        bool
	AcceptedReason  string
	AcceptedMessage string
	ResolvedRefs    bool
	ResolvedReason  string
	ResolvedMessage string
	Conditions      []metav1.Condition
}

// extractGatewayStatus extracts status information from a Gateway resource
func extractGatewayStatus(gateway *gwv1.Gateway) *GatewayStatus {
	status := &GatewayStatus{
		Namespace:    gateway.Namespace,
		Name:         gateway.Name,
		GatewayClass: string(gateway.Spec.GatewayClassName),
		Addresses:    gateway.Status.Addresses,
		Listeners:    make(map[string]*ListenerStatus),
		LastUpdated:  time.Now(),
	}

	// Extract Gateway-level conditions
	for _, cond := range gateway.Status.Conditions {
		switch cond.Type {
		case string(gwv1.GatewayConditionAccepted):
			status.Accepted = cond.Status == metav1.ConditionTrue
			status.AcceptedReason = string(cond.Reason)
			status.AcceptedMessage = cond.Message
		case string(gwv1.GatewayConditionProgrammed):
			status.Programmed = cond.Status == metav1.ConditionTrue
			status.ProgrammedReason = string(cond.Reason)
			status.ProgrammedMessage = cond.Message
		}
	}

	// Extract listener status - merge spec and status information
	for _, listener := range gateway.Status.Listeners {
		listenerStatus := &ListenerStatus{
			Name:           string(listener.Name),
			AttachedRoutes: listener.AttachedRoutes,
			Conditions:     listener.Conditions,
		}

		// Extract port, protocol, and hostname from spec
		for _, specListener := range gateway.Spec.Listeners {
			if string(specListener.Name) == listenerStatus.Name {
				listenerStatus.Port = int(specListener.Port)
				listenerStatus.Protocol = string(specListener.Protocol)
				if specListener.Hostname != nil {
					listenerStatus.Hostname = string(*specListener.Hostname)
				} else {
					listenerStatus.Hostname = "*"
				}
				break
			}
		}

		for _, cond := range listener.Conditions {
			switch cond.Type {
			case string(gwv1.ListenerConditionProgrammed):
				listenerStatus.Programmed = cond.Status == metav1.ConditionTrue
			case string(gwv1.ListenerConditionAccepted):
				listenerStatus.Accepted = cond.Status == metav1.ConditionTrue
			case string(gwv1.ListenerConditionResolvedRefs):
				listenerStatus.ResolvedRefs = cond.Status == metav1.ConditionTrue
			}
		}

		status.Listeners[listenerStatus.Name] = listenerStatus
	}

	return status
}

// extractHTTPRouteStatus extracts status information from an HTTPRoute resource
func extractHTTPRouteStatus(route *gwv1.HTTPRoute) *HTTPRouteStatus {
	// Extract hostnames from spec
	hostnames := make([]string, 0, len(route.Spec.Hostnames))
	for _, hostname := range route.Spec.Hostnames {
		hostnames = append(hostnames, string(hostname))
	}

	status := &HTTPRouteStatus{
		Namespace:   route.Namespace,
		Name:        route.Name,
		Hostnames:   hostnames,
		ParentRefs:  make([]ParentRefStatus, 0, len(route.Status.Parents)),
		LastUpdated: time.Now(),
	}

	// Extract status for each parent Gateway
	for _, parent := range route.Status.Parents {
		parentStatus := ParentRefStatus{
			ControllerName: string(parent.ControllerName),
			Conditions:     parent.Conditions,
		}

		// Extract parent reference details
		if parent.ParentRef.Namespace != nil {
			parentStatus.ParentNamespace = string(*parent.ParentRef.Namespace)
		} else {
			// Default to route's namespace if not specified
			parentStatus.ParentNamespace = route.Namespace
		}
		parentStatus.ParentName = string(parent.ParentRef.Name)

		// Extract conditions
		for _, cond := range parent.Conditions {
			switch cond.Type {
			case string(gwv1.RouteConditionAccepted):
				parentStatus.Accepted = cond.Status == metav1.ConditionTrue
				parentStatus.AcceptedReason = string(cond.Reason)
				parentStatus.AcceptedMessage = cond.Message
			case string(gwv1.RouteConditionResolvedRefs):
				parentStatus.ResolvedRefs = cond.Status == metav1.ConditionTrue
				parentStatus.ResolvedReason = string(cond.Reason)
				parentStatus.ResolvedMessage = cond.Message
			}
		}

		status.ParentRefs = append(status.ParentRefs, parentStatus)
	}

	return status
}

// extractGRPCRouteStatus extracts status information from a GRPCRoute resource
func extractGRPCRouteStatus(route *gwv1.GRPCRoute) *GRPCRouteStatus {
	// Extract hostnames from spec
	hostnames := make([]string, 0, len(route.Spec.Hostnames))
	for _, hostname := range route.Spec.Hostnames {
		hostnames = append(hostnames, string(hostname))
	}

	status := &GRPCRouteStatus{
		Namespace:   route.Namespace,
		Name:        route.Name,
		Hostnames:   hostnames,
		ParentRefs:  make([]ParentRefStatus, 0, len(route.Status.Parents)),
		LastUpdated: time.Now(),
	}

	// Extract status for each parent Gateway (same logic as HTTPRoute)
	for _, parent := range route.Status.Parents {
		parentStatus := ParentRefStatus{
			ControllerName: string(parent.ControllerName),
			Conditions:     parent.Conditions,
		}

		if parent.ParentRef.Namespace != nil {
			parentStatus.ParentNamespace = string(*parent.ParentRef.Namespace)
		} else {
			parentStatus.ParentNamespace = route.Namespace
		}
		parentStatus.ParentName = string(parent.ParentRef.Name)

		for _, cond := range parent.Conditions {
			switch cond.Type {
			case string(gwv1.RouteConditionAccepted):
				parentStatus.Accepted = cond.Status == metav1.ConditionTrue
				parentStatus.AcceptedReason = string(cond.Reason)
				parentStatus.AcceptedMessage = cond.Message
			case string(gwv1.RouteConditionResolvedRefs):
				parentStatus.ResolvedRefs = cond.Status == metav1.ConditionTrue
				parentStatus.ResolvedReason = string(cond.Reason)
				parentStatus.ResolvedMessage = cond.Message
			}
		}

		status.ParentRefs = append(status.ParentRefs, parentStatus)
	}

	return status
}
