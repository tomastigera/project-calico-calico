package indexer

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestExtractGatewayStatus(t *testing.T) {
	tests := []struct {
		name     string
		gateway  *gwv1.Gateway
		validate func(t *testing.T, status *GatewayStatus)
	}{
		{
			name: "basic gateway with accepted and programmed conditions",
			gateway: &gwv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
					Name:      "test-gateway",
				},
				Spec: gwv1.GatewaySpec{
					GatewayClassName: "test-class",
				},
				Status: gwv1.GatewayStatus{
					Conditions: []metav1.Condition{
						{
							Type:    string(gwv1.GatewayConditionAccepted),
							Status:  metav1.ConditionTrue,
							Reason:  "Accepted",
							Message: "Gateway is accepted",
						},
						{
							Type:    string(gwv1.GatewayConditionProgrammed),
							Status:  metav1.ConditionTrue,
							Reason:  "Programmed",
							Message: "Gateway is programmed",
						},
					},
					Addresses: []gwv1.GatewayStatusAddress{
						{
							Value: "10.0.0.1",
							Type:  ptrTo(gwv1.IPAddressType),
						},
					},
				},
			},
			validate: func(t *testing.T, status *GatewayStatus) {
				if status.Namespace != "test-ns" {
					t.Errorf("expected namespace test-ns, got %s", status.Namespace)
				}
				if status.Name != "test-gateway" {
					t.Errorf("expected name test-gateway, got %s", status.Name)
				}
				if status.GatewayClass != "test-class" {
					t.Errorf("expected gateway class test-class, got %s", status.GatewayClass)
				}
				if !status.Accepted {
					t.Error("expected Accepted to be true")
				}
				if status.AcceptedReason != "Accepted" {
					t.Errorf("expected AcceptedReason 'Accepted', got %s", status.AcceptedReason)
				}
				if !status.Programmed {
					t.Error("expected Programmed to be true")
				}
				if len(status.Addresses) != 1 {
					t.Errorf("expected 1 address, got %d", len(status.Addresses))
				}
			},
		},
		{
			name: "gateway with false conditions",
			gateway: &gwv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
					Name:      "test-gateway",
				},
				Spec: gwv1.GatewaySpec{
					GatewayClassName: "test-class",
				},
				Status: gwv1.GatewayStatus{
					Conditions: []metav1.Condition{
						{
							Type:    string(gwv1.GatewayConditionAccepted),
							Status:  metav1.ConditionFalse,
							Reason:  "Invalid",
							Message: "Gateway is invalid",
						},
						{
							Type:    string(gwv1.GatewayConditionProgrammed),
							Status:  metav1.ConditionFalse,
							Reason:  "NotReady",
							Message: "Gateway is not ready",
						},
					},
				},
			},
			validate: func(t *testing.T, status *GatewayStatus) {
				if status.Accepted {
					t.Error("expected Accepted to be false")
				}
				if status.AcceptedReason != "Invalid" {
					t.Errorf("expected AcceptedReason 'Invalid', got %s", status.AcceptedReason)
				}
				if status.Programmed {
					t.Error("expected Programmed to be false")
				}
				if status.ProgrammedReason != "NotReady" {
					t.Errorf("expected ProgrammedReason 'NotReady', got %s", status.ProgrammedReason)
				}
			},
		},
		{
			name: "gateway with listeners",
			gateway: &gwv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
					Name:      "test-gateway",
				},
				Spec: gwv1.GatewaySpec{
					GatewayClassName: "test-class",
					Listeners: []gwv1.Listener{
						{
							Name:     "http",
							Port:     8080,
							Protocol: gwv1.HTTPProtocolType,
							Hostname: ptrTo(gwv1.Hostname("example.com")),
						},
					},
				},
				Status: gwv1.GatewayStatus{
					Conditions: []metav1.Condition{},
					Listeners: []gwv1.ListenerStatus{
						{
							Name:           "http",
							AttachedRoutes: 5,
							Conditions: []metav1.Condition{
								{
									Type:   string(gwv1.ListenerConditionProgrammed),
									Status: metav1.ConditionTrue,
								},
								{
									Type:   string(gwv1.ListenerConditionAccepted),
									Status: metav1.ConditionTrue,
								},
								{
									Type:   string(gwv1.ListenerConditionResolvedRefs),
									Status: metav1.ConditionTrue,
								},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, status *GatewayStatus) {
				if len(status.Listeners) != 1 {
					t.Errorf("expected 1 listener, got %d", len(status.Listeners))
					return
				}
				listener := status.Listeners["http"]
				if listener == nil {
					t.Fatal("expected listener 'http' to exist")
				}
				if listener.AttachedRoutes != 5 {
					t.Errorf("expected 5 attached routes, got %d", listener.AttachedRoutes)
				}
				if listener.Port != 8080 {
					t.Errorf("expected port 8080, got %d", listener.Port)
				}
				if listener.Protocol != string(gwv1.HTTPProtocolType) {
					t.Errorf("expected protocol %s, got %s", gwv1.HTTPProtocolType, listener.Protocol)
				}
				if listener.Hostname != "example.com" {
					t.Errorf("expected hostname example.com, got %s", listener.Hostname)
				}
				if !listener.Programmed {
					t.Error("expected listener Programmed to be true")
				}
				if !listener.Accepted {
					t.Error("expected listener Accepted to be true")
				}
				if !listener.ResolvedRefs {
					t.Error("expected listener ResolvedRefs to be true")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := extractGatewayStatus(tt.gateway)
			tt.validate(t, status)
		})
	}
}

func TestExtractHTTPRouteStatus(t *testing.T) {
	tests := []struct {
		name     string
		route    *gwv1.HTTPRoute
		validate func(t *testing.T, status *HTTPRouteStatus)
	}{
		{
			name: "basic httproute with accepted parent",
			route: &gwv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
					Name:      "test-route",
				},
				Status: gwv1.HTTPRouteStatus{
					RouteStatus: gwv1.RouteStatus{
						Parents: []gwv1.RouteParentStatus{
							{
								ParentRef: gwv1.ParentReference{
									Name:      "test-gateway",
									Namespace: ptrTo(gwv1.Namespace("test-ns")),
								},
								ControllerName: "example.com/controller",
								Conditions: []metav1.Condition{
									{
										Type:    string(gwv1.RouteConditionAccepted),
										Status:  metav1.ConditionTrue,
										Reason:  "Accepted",
										Message: "Route accepted",
									},
									{
										Type:    string(gwv1.RouteConditionResolvedRefs),
										Status:  metav1.ConditionTrue,
										Reason:  "ResolvedRefs",
										Message: "All refs resolved",
									},
								},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, status *HTTPRouteStatus) {
				if status.Namespace != "test-ns" {
					t.Errorf("expected namespace test-ns, got %s", status.Namespace)
				}
				if status.Name != "test-route" {
					t.Errorf("expected name test-route, got %s", status.Name)
				}
				if len(status.ParentRefs) != 1 {
					t.Errorf("expected 1 parent ref, got %d", len(status.ParentRefs))
					return
				}
				parent := status.ParentRefs[0]
				if parent.ParentNamespace != "test-ns" {
					t.Errorf("expected parent namespace test-ns, got %s", parent.ParentNamespace)
				}
				if parent.ParentName != "test-gateway" {
					t.Errorf("expected parent name test-gateway, got %s", parent.ParentName)
				}
				if !parent.Accepted {
					t.Error("expected parent Accepted to be true")
				}
				if !parent.ResolvedRefs {
					t.Error("expected parent ResolvedRefs to be true")
				}
			},
		},
		{
			name: "httproute with default namespace",
			route: &gwv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default-ns",
					Name:      "test-route",
				},
				Status: gwv1.HTTPRouteStatus{
					RouteStatus: gwv1.RouteStatus{
						Parents: []gwv1.RouteParentStatus{
							{
								ParentRef: gwv1.ParentReference{
									Name: "test-gateway",
									// Namespace not specified - should default to route's namespace
								},
								ControllerName: "example.com/controller",
								Conditions:     []metav1.Condition{},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, status *HTTPRouteStatus) {
				if len(status.ParentRefs) != 1 {
					t.Errorf("expected 1 parent ref, got %d", len(status.ParentRefs))
					return
				}
				parent := status.ParentRefs[0]
				if parent.ParentNamespace != "default-ns" {
					t.Errorf("expected parent namespace to default to default-ns, got %s", parent.ParentNamespace)
				}
			},
		},
		{
			name: "httproute with multiple parents",
			route: &gwv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
					Name:      "test-route",
				},
				Status: gwv1.HTTPRouteStatus{
					RouteStatus: gwv1.RouteStatus{
						Parents: []gwv1.RouteParentStatus{
							{
								ParentRef: gwv1.ParentReference{
									Name:      "gateway-1",
									Namespace: ptrTo(gwv1.Namespace("test-ns")),
								},
								ControllerName: "example.com/controller",
								Conditions: []metav1.Condition{
									{
										Type:   string(gwv1.RouteConditionAccepted),
										Status: metav1.ConditionTrue,
									},
								},
							},
							{
								ParentRef: gwv1.ParentReference{
									Name:      "gateway-2",
									Namespace: ptrTo(gwv1.Namespace("test-ns")),
								},
								ControllerName: "example.com/controller",
								Conditions: []metav1.Condition{
									{
										Type:   string(gwv1.RouteConditionAccepted),
										Status: metav1.ConditionFalse,
									},
								},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, status *HTTPRouteStatus) {
				if len(status.ParentRefs) != 2 {
					t.Errorf("expected 2 parent refs, got %d", len(status.ParentRefs))
					return
				}
				if !status.ParentRefs[0].Accepted {
					t.Error("expected first parent to be accepted")
				}
				if status.ParentRefs[1].Accepted {
					t.Error("expected second parent to not be accepted")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := extractHTTPRouteStatus(tt.route)
			tt.validate(t, status)
		})
	}
}

func TestExtractGRPCRouteStatus(t *testing.T) {
	tests := []struct {
		name     string
		route    *gwv1.GRPCRoute
		validate func(t *testing.T, status *GRPCRouteStatus)
	}{
		{
			name: "basic grpcroute with accepted parent",
			route: &gwv1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
					Name:      "test-grpc-route",
				},
				Status: gwv1.GRPCRouteStatus{
					RouteStatus: gwv1.RouteStatus{
						Parents: []gwv1.RouteParentStatus{
							{
								ParentRef: gwv1.ParentReference{
									Name:      "test-gateway",
									Namespace: ptrTo(gwv1.Namespace("test-ns")),
								},
								ControllerName: "example.com/controller",
								Conditions: []metav1.Condition{
									{
										Type:    string(gwv1.RouteConditionAccepted),
										Status:  metav1.ConditionTrue,
										Reason:  "Accepted",
										Message: "Route accepted",
									},
								},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, status *GRPCRouteStatus) {
				if status.Namespace != "test-ns" {
					t.Errorf("expected namespace test-ns, got %s", status.Namespace)
				}
				if status.Name != "test-grpc-route" {
					t.Errorf("expected name test-grpc-route, got %s", status.Name)
				}
				if len(status.ParentRefs) != 1 {
					t.Errorf("expected 1 parent ref, got %d", len(status.ParentRefs))
					return
				}
				parent := status.ParentRefs[0]
				if !parent.Accepted {
					t.Error("expected parent Accepted to be true")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := extractGRPCRouteStatus(tt.route)
			tt.validate(t, status)
		})
	}
}

// Helper function to create pointer to value
func ptrTo[T any](v T) *T {
	return &v
}
