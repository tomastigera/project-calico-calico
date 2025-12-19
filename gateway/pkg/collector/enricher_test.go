// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package collector

import (
	"testing"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayfake "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/fake"

	"github.com/projectcalico/calico/gateway/pkg/indexer"
	l7collector "github.com/projectcalico/calico/l7-collector/pkg/collector"
)

func TestEnricherEnrichLog(t *testing.T) {
	// Create test Gateway and Route resources
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "test-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
		Status: gatewayv1.GatewayStatus{
			Conditions: []metav1.Condition{
				{
					Type:   "Accepted",
					Status: metav1.ConditionTrue,
				},
				{
					Type:   "Programmed",
					Status: metav1.ConditionTrue,
				},
			},
			Listeners: []gatewayv1.ListenerStatus{
				{
					Name: "http",
					Conditions: []metav1.Condition{
						{
							Type:   "Accepted",
							Status: metav1.ConditionTrue,
						},
						{
							Type:   "Programmed",
							Status: metav1.ConditionTrue,
						},
					},
				},
			},
		},
	}

	httpRoute := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name:      "test-gateway",
						Namespace: ptrTo(gatewayv1.Namespace("default")),
					},
				},
			},
		},
		Status: gatewayv1.HTTPRouteStatus{
			RouteStatus: gatewayv1.RouteStatus{
				Parents: []gatewayv1.RouteParentStatus{
					{
						ParentRef: gatewayv1.ParentReference{
							Name:      "test-gateway",
							Namespace: ptrTo(gatewayv1.Namespace("default")),
						},
						ControllerName: "test-controller",
						Conditions: []metav1.Condition{
							{
								Type:   "Accepted",
								Status: metav1.ConditionTrue,
							},
							{
								Type:   "ResolvedRefs",
								Status: metav1.ConditionTrue,
							},
						},
					},
				},
			},
		},
	}

	// Create fake clients
	k8sClient := fake.NewSimpleClientset()
	gatewayClient := gatewayfake.NewSimpleClientset(gateway, httpRoute)

	// Create status indexer
	logger := zap.NewNop()
	statusIndexer, err := indexer.NewStatusIndexer(logger, k8sClient, gatewayClient)
	if err != nil {
		t.Fatalf("Failed to create status indexer: %v", err)
	}

	// Manually index the test resources since we're not starting the informers
	statusIndexer.AddGatewayForTesting(gateway)
	statusIndexer.AddHTTPRouteForTesting(httpRoute)

	// Create enricher
	enricher := NewEnricher(statusIndexer)

	tests := []struct {
		name     string
		log      *l7collector.EnvoyLog
		validate func(*testing.T, *l7collector.EnvoyLog)
	}{
		{
			name: "enrich with parsed route name",
			log: &l7collector.EnvoyLog{
				RouteName:   "httproute/default/test-route/rule/0/match/0/*",
				GatewayName: "test-gateway",
			},
			validate: func(t *testing.T, log *l7collector.EnvoyLog) {
				// Route info is now in GatewayRoute* fields
				if log.GatewayRouteNamespace != "default" {
					t.Errorf("GatewayRouteNamespace = %q, want %q", log.GatewayRouteNamespace, "default")
				}
				if log.GatewayRouteName != "test-route" {
					t.Errorf("GatewayRouteName = %q, want %q", log.GatewayRouteName, "test-route")
				}
				if log.GatewayRouteType != "http" {
					t.Errorf("GatewayRouteType = %q, want %q", log.GatewayRouteType, "http")
				}
				if log.GatewayNamespace != "default" {
					t.Errorf("GatewayNamespace = %q, want %q", log.GatewayNamespace, "default")
				}
			},
		},
		{
			name: "enrich with gateway context",
			log: &l7collector.EnvoyLog{
				RouteName:        "httproute/default/test-route/rule/0/match/0/*",
				GatewayName:      "test-gateway",
				GatewayNamespace: "default",
			},
			validate: func(t *testing.T, log *l7collector.EnvoyLog) {
				if log.GatewayClass != "test-class" {
					t.Errorf("GatewayClass = %q, want %q", log.GatewayClass, "test-class")
				}
				if log.GatewayStatus != "active" {
					t.Errorf("GatewayStatus = %q, want %q", log.GatewayStatus, "active")
				}
				if log.GatewayListenerName != "http" {
					t.Errorf("GatewayListenerName = %q, want %q", log.GatewayListenerName, "http")
				}
			},
		},
		{
			name: "enrich HTTPRoute status",
			log: &l7collector.EnvoyLog{
				RouteName:        "httproute/default/test-route/rule/0/match/0/*",
				GatewayName:      "test-gateway",
				GatewayNamespace: "default",
			},
			validate: func(t *testing.T, log *l7collector.EnvoyLog) {
				if log.GatewayRouteType != "http" {
					t.Errorf("GatewayRouteType = %q, want %q", log.GatewayRouteType, "http")
				}
				if log.GatewayRouteName != "test-route" {
					t.Errorf("GatewayRouteName = %q, want %q", log.GatewayRouteName, "test-route")
				}
				if log.GatewayRouteNamespace != "default" {
					t.Errorf("GatewayRouteNamespace = %q, want %q", log.GatewayRouteNamespace, "default")
				}
				if log.GatewayRouteStatus != "active" {
					t.Errorf("GatewayRouteStatus = %q, want %q", log.GatewayRouteStatus, "active")
				}
			},
		},
		{
			name: "no enrichment for missing gateway",
			log: &l7collector.EnvoyLog{
				RouteName:        "httproute/default/test-route/rule/0/match/0/*",
				GatewayName:      "nonexistent-gateway",
				GatewayNamespace: "default",
			},
			validate: func(t *testing.T, log *l7collector.EnvoyLog) {
				if log.GatewayStatus != "unknown" {
					t.Errorf("GatewayStatus = %q, want %q", log.GatewayStatus, "unknown")
				}
			},
		},
		{
			name: "empty route name",
			log: &l7collector.EnvoyLog{
				RouteName: "",
			},
			validate: func(t *testing.T, log *l7collector.EnvoyLog) {
				// Should not crash, just skip enrichment
				if log.GatewayRouteNamespace != "" {
					t.Errorf("Expected no enrichment for empty route name")
				}
			},
		},
		{
			name: "GRPCRoute type",
			log: &l7collector.EnvoyLog{
				RouteName:   "grpcroute/default/grpc-route/rule/0/match/0/*",
				GatewayName: "test-gateway",
			},
			validate: func(t *testing.T, log *l7collector.EnvoyLog) {
				if log.GatewayRouteType != "grpc" {
					t.Errorf("GatewayRouteType = %q, want %q", log.GatewayRouteType, "grpc")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enricher.EnrichLog(tt.log)
			tt.validate(t, tt.log)
		})
	}
}

func TestEnricherGatewayInference(t *testing.T) {
	// Create test Gateway
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "inferred-gateway",
			Namespace: "test-ns",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "inferred-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
		Status: gatewayv1.GatewayStatus{
			Conditions: []metav1.Condition{
				{
					Type:   "Accepted",
					Status: metav1.ConditionTrue,
				},
				{
					Type:    "Programmed",
					Status:  metav1.ConditionFalse,
					Message: "Not yet programmed",
				},
			},
			Listeners: []gatewayv1.ListenerStatus{
				{
					Name: "http",
					Conditions: []metav1.Condition{
						{
							Type:   "Accepted",
							Status: metav1.ConditionTrue,
						},
					},
				},
			},
		},
	}

	k8sClient := fake.NewSimpleClientset()
	gatewayClient := gatewayfake.NewSimpleClientset(gateway)

	logger := zap.NewNop()
	statusIndexer, err := indexer.NewStatusIndexer(logger, k8sClient, gatewayClient)
	if err != nil {
		t.Fatalf("Failed to create status indexer: %v", err)
	}

	// Manually index the test resources since we're not starting the informers
	statusIndexer.AddGatewayForTesting(gateway)

	enricher := NewEnricher(statusIndexer)

	log := &l7collector.EnvoyLog{
		RouteName:        "httproute/test-ns/my-route/rule/0/match/0/*",
		GatewayName:      "inferred-gateway",
		GatewayNamespace: "test-ns",
	}

	enricher.EnrichLog(log)

	// Verify Gateway namespace was correctly set
	if log.GatewayNamespace != "test-ns" {
		t.Errorf("GatewayNamespace = %q, want %q", log.GatewayNamespace, "test-ns")
	}

	// Verify Gateway name was correctly parsed from inferred-gateway
	if log.GatewayName != "inferred-gateway" {
		t.Errorf("GatewayName = %q, want %q", log.GatewayName, "inferred-gateway")
	}

	// Verify Gateway status reflects accepted but not programmed
	if log.GatewayStatus != "accepted" {
		t.Errorf("GatewayStatus = %q, want %q (should be accepted but not programmed)", log.GatewayStatus, "accepted")
	}
}

func TestEnricherWithDefaultGateway(t *testing.T) {
	// Create test Gateway
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "env-gateway",
			Namespace: "env-namespace",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "env-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
		Status: gatewayv1.GatewayStatus{
			Conditions: []metav1.Condition{
				{
					Type:   "Accepted",
					Status: metav1.ConditionTrue,
				},
				{
					Type:   "Programmed",
					Status: metav1.ConditionTrue,
				},
			},
			Listeners: []gatewayv1.ListenerStatus{
				{
					Name: "http",
					Conditions: []metav1.Condition{
						{
							Type:   "Accepted",
							Status: metav1.ConditionTrue,
						},
						{
							Type:   "Programmed",
							Status: metav1.ConditionTrue,
						},
					},
				},
			},
		},
	}

	k8sClient := fake.NewSimpleClientset()
	gatewayClient := gatewayfake.NewSimpleClientset(gateway)

	logger := zap.NewNop()
	statusIndexer, err := indexer.NewStatusIndexer(logger, k8sClient, gatewayClient)
	if err != nil {
		t.Fatalf("Failed to create status indexer: %v", err)
	}

	statusIndexer.AddGatewayForTesting(gateway)

	// Create enricher with default gateway from environment
	enricher := NewEnricher(statusIndexer, WithDefaultGateway("env-namespace", "env-gateway"))

	tests := []struct {
		name     string
		log      *l7collector.EnvoyLog
		validate func(*testing.T, *l7collector.EnvoyLog)
	}{
		{
			name: "uses default gateway when log has no gateway info",
			log: &l7collector.EnvoyLog{
				RouteName: "httproute/env-namespace/some-route/rule/0/match/0/*",
				// No GatewayName set
				// No GatewayNamespace set
			},
			validate: func(t *testing.T, log *l7collector.EnvoyLog) {
				if log.GatewayName != "env-gateway" {
					t.Errorf("GatewayName = %q, want %q", log.GatewayName, "env-gateway")
				}
				if log.GatewayNamespace != "env-namespace" {
					t.Errorf("GatewayNamespace = %q, want %q", log.GatewayNamespace, "env-namespace")
				}
				if log.GatewayClass != "env-class" {
					t.Errorf("GatewayClass = %q, want %q", log.GatewayClass, "env-class")
				}
				if log.GatewayStatus != "active" {
					t.Errorf("GatewayStatus = %q, want %q", log.GatewayStatus, "active")
				}
			},
		},
		{
			name: "log gateway info takes precedence over default",
			log: &l7collector.EnvoyLog{
				RouteName:        "httproute/other-ns/some-route/rule/0/match/0/*",
				GatewayName:      "other-gateway",
				GatewayNamespace: "other-ns",
			},
			validate: func(t *testing.T, log *l7collector.EnvoyLog) {
				// Should keep the original values from the log, not use defaults
				if log.GatewayName != "other-gateway" {
					t.Errorf("GatewayName = %q, want %q", log.GatewayName, "other-gateway")
				}
				if log.GatewayNamespace != "other-ns" {
					t.Errorf("GatewayNamespace = %q, want %q", log.GatewayNamespace, "other-ns")
				}
			},
		},
		{
			name: "fills in only missing gateway name when namespace is set",
			log: &l7collector.EnvoyLog{
				RouteName: "httproute/env-namespace/some-route/rule/0/match/0/*",
				// GatewayName not set - should be filled from default
				GatewayNamespace: "env-namespace",
			},
			validate: func(t *testing.T, log *l7collector.EnvoyLog) {
				if log.GatewayName != "env-gateway" {
					t.Errorf("GatewayName = %q, want %q", log.GatewayName, "env-gateway")
				}
				if log.GatewayNamespace != "env-namespace" {
					t.Errorf("GatewayNamespace = %q, want %q", log.GatewayNamespace, "env-namespace")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enricher.EnrichLog(tt.log)
			tt.validate(t, tt.log)
		})
	}
}

// ptrTo is a helper function to get pointer to a value
func ptrTo[T any](v T) *T {
	return &v
}
