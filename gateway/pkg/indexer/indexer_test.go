package indexer

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayfake "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/fake"
)

func TestStatusIndexer_NewStatusIndexer(t *testing.T) {
	logger := zap.NewNop()
	k8sClient := fake.NewSimpleClientset()
	gatewayClient := gatewayfake.NewSimpleClientset()

	indexer, err := NewStatusIndexer(logger, k8sClient, gatewayClient)
	if err != nil {
		t.Fatalf("failed to create indexer: %v", err)
	}

	if indexer == nil {
		t.Fatal("expected indexer to be non-nil")
	}

	if indexer.logger == nil {
		t.Error("expected logger to be set")
	}

	if indexer.gateways == nil {
		t.Error("expected gateways map to be initialized")
	}

	if indexer.httpRoutes == nil {
		t.Error("expected httpRoutes map to be initialized")
	}

	if indexer.grpcRoutes == nil {
		t.Error("expected grpcRoutes map to be initialized")
	}

	if indexer.gatewayToRoutes == nil {
		t.Error("expected gatewayToRoutes map to be initialized")
	}
}

func TestStatusIndexer_GatewayOperations(t *testing.T) {
	logger := zap.NewNop()
	k8sClient := fake.NewSimpleClientset()
	gatewayClient := gatewayfake.NewSimpleClientset()

	indexer, err := NewStatusIndexer(logger, k8sClient, gatewayClient)
	if err != nil {
		t.Fatalf("failed to create indexer: %v", err)
	}

	// Create gateway
	gateway := &gwv1.Gateway{
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
					Type:   string(gwv1.GatewayConditionAccepted),
					Status: metav1.ConditionTrue,
				},
				{
					Type:   string(gwv1.GatewayConditionProgrammed),
					Status: metav1.ConditionTrue,
				},
			},
		},
	}

	// Directly call event handler to test indexing logic
	indexer.handleGatewayAdd(gateway)

	// Test GetGatewayStatus
	status, ok := indexer.GetGatewayStatus("test-ns", "test-gateway")
	if !ok {
		t.Fatal("expected to find gateway in index")
	}

	if status.Name != "test-gateway" {
		t.Errorf("expected gateway name test-gateway, got %s", status.Name)
	}

	if status.Namespace != "test-ns" {
		t.Errorf("expected gateway namespace test-ns, got %s", status.Namespace)
	}

	if !status.Accepted {
		t.Error("expected gateway to be accepted")
	}

	if !status.Programmed {
		t.Error("expected gateway to be programmed")
	}

	// Test update
	gateway.Status.Conditions[1].Status = metav1.ConditionFalse
	indexer.handleGatewayUpdate(nil, gateway)

	status, ok = indexer.GetGatewayStatus("test-ns", "test-gateway")
	if !ok {
		t.Fatal("expected to find gateway after update")
	}

	if status.Programmed {
		t.Error("expected gateway to not be programmed after update")
	}

	// Test delete
	indexer.handleGatewayDelete(gateway)

	_, ok = indexer.GetGatewayStatus("test-ns", "test-gateway")
	if ok {
		t.Error("expected gateway to be deleted from index")
	}

	// Test GetGatewayStatus for non-existent gateway
	_, ok = indexer.GetGatewayStatus("test-ns", "non-existent")
	if ok {
		t.Error("expected to not find non-existent gateway")
	}

	// Test GetStats
	stats := indexer.GetStats()
	if stats["gateways"] != 0 {
		t.Errorf("expected 0 gateways in stats after delete, got %d", stats["gateways"])
	}
	if stats["httpRoutes"] != 0 {
		t.Errorf("expected 0 httpRoutes in stats, got %d", stats["httpRoutes"])
	}
	if stats["grpcRoutes"] != 0 {
		t.Errorf("expected 0 grpcRoutes in stats, got %d", stats["grpcRoutes"])
	}
}

func TestStatusIndexer_HTTPRouteOperations(t *testing.T) {
	logger := zap.NewNop()
	k8sClient := fake.NewSimpleClientset()

	httpRoute := &gwv1.HTTPRoute{
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
						ControllerName: "test-controller",
						Conditions: []metav1.Condition{
							{
								Type:   string(gwv1.RouteConditionAccepted),
								Status: metav1.ConditionTrue,
							},
						},
					},
				},
			},
		},
	}

	gatewayClient := gatewayfake.NewSimpleClientset(httpRoute)

	indexer, err := NewStatusIndexer(logger, k8sClient, gatewayClient)
	if err != nil {
		t.Fatalf("failed to create indexer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		if err := indexer.Start(ctx); err != nil {
			t.Logf("indexer start error: %v", err)
		}
	}()

	// Wait for cache sync
	time.Sleep(100 * time.Millisecond)

	// Test GetHTTPRouteStatus
	status, ok := indexer.GetHTTPRouteStatus("test-ns", "test-route")
	if !ok {
		t.Fatal("expected to find httproute in index")
	}

	if status.Name != "test-route" {
		t.Errorf("expected route name test-route, got %s", status.Name)
	}

	if len(status.ParentRefs) != 1 {
		t.Errorf("expected 1 parent ref, got %d", len(status.ParentRefs))
	}

	// Test GetRoutesForGateway
	routes := indexer.GetRoutesForGateway("test-ns", "test-gateway")
	if len(routes) != 1 {
		t.Errorf("expected 1 route for gateway, got %d", len(routes))
	}

	if routes[0] != "test-ns/test-route" {
		t.Errorf("expected route test-ns/test-route, got %s", routes[0])
	}

	// Test GetStats
	stats := indexer.GetStats()
	if stats["httpRoutes"] != 1 {
		t.Errorf("expected 1 httpRoute in stats, got %d", stats["httpRoutes"])
	}

	indexer.Stop()
}

func TestStatusIndexer_GRPCRouteOperations(t *testing.T) {
	logger := zap.NewNop()
	k8sClient := fake.NewSimpleClientset()

	grpcRoute := &gwv1.GRPCRoute{
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
						ControllerName: "test-controller",
						Conditions: []metav1.Condition{
							{
								Type:   string(gwv1.RouteConditionAccepted),
								Status: metav1.ConditionTrue,
							},
						},
					},
				},
			},
		},
	}

	gatewayClient := gatewayfake.NewSimpleClientset(grpcRoute)

	indexer, err := NewStatusIndexer(logger, k8sClient, gatewayClient)
	if err != nil {
		t.Fatalf("failed to create indexer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		if err := indexer.Start(ctx); err != nil {
			t.Logf("indexer start error: %v", err)
		}
	}()

	// Wait for cache sync
	time.Sleep(100 * time.Millisecond)

	// Test GetGRPCRouteStatus
	status, ok := indexer.GetGRPCRouteStatus("test-ns", "test-grpc-route")
	if !ok {
		t.Fatal("expected to find grpcroute in index")
	}

	if status.Name != "test-grpc-route" {
		t.Errorf("expected route name test-grpc-route, got %s", status.Name)
	}

	if len(status.ParentRefs) != 1 {
		t.Errorf("expected 1 parent ref, got %d", len(status.ParentRefs))
	}

	// Test GetRoutesForGateway
	routes := indexer.GetRoutesForGateway("test-ns", "test-gateway")
	if len(routes) != 1 {
		t.Errorf("expected 1 route for gateway, got %d", len(routes))
	}

	// Test GetStats
	stats := indexer.GetStats()
	if stats["grpcRoutes"] != 1 {
		t.Errorf("expected 1 grpcRoute in stats, got %d", stats["grpcRoutes"])
	}

	indexer.Stop()
}

func TestStatusIndexer_ReverseIndex(t *testing.T) {
	logger := zap.NewNop()
	k8sClient := fake.NewSimpleClientset()

	// Create multiple routes pointing to the same gateway
	httpRoute1 := &gwv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-ns",
			Name:      "route-1",
		},
		Status: gwv1.HTTPRouteStatus{
			RouteStatus: gwv1.RouteStatus{
				Parents: []gwv1.RouteParentStatus{
					{
						ParentRef: gwv1.ParentReference{
							Name:      "test-gateway",
							Namespace: ptrTo(gwv1.Namespace("test-ns")),
						},
						ControllerName: "test-controller",
					},
				},
			},
		},
	}

	httpRoute2 := &gwv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-ns",
			Name:      "route-2",
		},
		Status: gwv1.HTTPRouteStatus{
			RouteStatus: gwv1.RouteStatus{
				Parents: []gwv1.RouteParentStatus{
					{
						ParentRef: gwv1.ParentReference{
							Name:      "test-gateway",
							Namespace: ptrTo(gwv1.Namespace("test-ns")),
						},
						ControllerName: "test-controller",
					},
				},
			},
		},
	}

	grpcRoute := &gwv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-ns",
			Name:      "grpc-route-1",
		},
		Status: gwv1.GRPCRouteStatus{
			RouteStatus: gwv1.RouteStatus{
				Parents: []gwv1.RouteParentStatus{
					{
						ParentRef: gwv1.ParentReference{
							Name:      "test-gateway",
							Namespace: ptrTo(gwv1.Namespace("test-ns")),
						},
						ControllerName: "test-controller",
					},
				},
			},
		},
	}

	gatewayClient := gatewayfake.NewSimpleClientset(httpRoute1, httpRoute2, grpcRoute)

	indexer, err := NewStatusIndexer(logger, k8sClient, gatewayClient)
	if err != nil {
		t.Fatalf("failed to create indexer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		if err := indexer.Start(ctx); err != nil {
			t.Logf("indexer start error: %v", err)
		}
	}()

	// Wait for cache sync
	time.Sleep(100 * time.Millisecond)

	// Test GetRoutesForGateway - should return all routes
	routes := indexer.GetRoutesForGateway("test-ns", "test-gateway")
	if len(routes) != 3 {
		t.Errorf("expected 3 routes for gateway, got %d", len(routes))
	}

	// Verify all expected routes are present
	routeMap := make(map[string]bool)
	for _, route := range routes {
		routeMap[route] = true
	}

	expectedRoutes := []string{
		"test-ns/route-1",
		"test-ns/route-2",
		"test-ns/grpc-route-1",
	}

	for _, expected := range expectedRoutes {
		if !routeMap[expected] {
			t.Errorf("expected to find route %s in gateway routes", expected)
		}
	}

	indexer.Stop()
}

func TestStatusIndexer_ConcurrentAccess(t *testing.T) {
	logger := zap.NewNop()
	k8sClient := fake.NewSimpleClientset()

	gateway := &gwv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-ns",
			Name:      "test-gateway",
		},
		Spec: gwv1.GatewaySpec{
			GatewayClassName: "test-class",
		},
	}

	gatewayClient := gatewayfake.NewSimpleClientset(gateway)

	indexer, err := NewStatusIndexer(logger, k8sClient, gatewayClient)
	if err != nil {
		t.Fatalf("failed to create indexer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		if err := indexer.Start(ctx); err != nil {
			t.Logf("indexer start error: %v", err)
		}
	}()

	// Wait for cache sync
	time.Sleep(100 * time.Millisecond)

	// Test concurrent reads
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				indexer.GetGatewayStatus("test-ns", "test-gateway")
				indexer.GetStats()
				indexer.GetRoutesForGateway("test-ns", "test-gateway")
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	indexer.Stop()
}

func TestStatusIndexer_MultipleStarts(t *testing.T) {
	logger := zap.NewNop()
	k8sClient := fake.NewSimpleClientset()
	gatewayClient := gatewayfake.NewSimpleClientset()

	indexer, err := NewStatusIndexer(logger, k8sClient, gatewayClient)
	if err != nil {
		t.Fatalf("failed to create indexer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// First start
	go func() {
		if err := indexer.Start(ctx); err != nil {
			t.Logf("indexer start error: %v", err)
		}
	}()

	time.Sleep(200 * time.Millisecond)

	// Verify indexer is started
	if !indexer.started {
		t.Error("expected indexer to be started")
	}

	// Second start should return error
	err = indexer.Start(ctx)
	if err == nil {
		t.Error("expected error when starting indexer twice")
	}

	if err.Error() != "indexer already started" {
		t.Errorf("expected 'indexer already started' error, got: %v", err)
	}

	indexer.Stop()

	// Verify indexer is stopped
	if indexer.started {
		t.Error("expected indexer to be stopped")
	}
}
