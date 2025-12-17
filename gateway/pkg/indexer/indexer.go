package indexer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayclientset "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
)

// StatusIndexer maintains an in-memory index of Gateway API resource status
type StatusIndexer struct {
	mu     sync.RWMutex
	logger *zap.Logger

	// Indexed resources
	gateways   map[string]*GatewayStatus   // Key: "namespace/name"
	httpRoutes map[string]*HTTPRouteStatus // Key: "namespace/name"
	grpcRoutes map[string]*GRPCRouteStatus // Key: "namespace/name"

	// Reverse index: Gateway -> Routes
	gatewayToRoutes map[string][]string // Key: "gateway-ns/gateway-name", Value: ["route-ns/route-name", ...]

	// Kubernetes clients
	k8sClient     kubernetes.Interface
	gatewayClient gatewayclientset.Interface

	// Informers
	gatewayInformer   cache.SharedIndexInformer
	httpRouteInformer cache.SharedIndexInformer
	grpcRouteInformer cache.SharedIndexInformer

	// Lifecycle
	stopCh  chan struct{}
	started bool
}

// NewStatusIndexer creates a new Gateway API status indexer
func NewStatusIndexer(logger *zap.Logger, k8sClient kubernetes.Interface, gatewayClient gatewayclientset.Interface) (*StatusIndexer, error) {
	indexer := &StatusIndexer{
		logger:          logger,
		k8sClient:       k8sClient,
		gatewayClient:   gatewayClient,
		gateways:        make(map[string]*GatewayStatus),
		httpRoutes:      make(map[string]*HTTPRouteStatus),
		grpcRoutes:      make(map[string]*GRPCRouteStatus),
		gatewayToRoutes: make(map[string][]string),
		stopCh:          make(chan struct{}),
	}

	// Create informers with resync period
	resyncPeriod := 5 * time.Minute

	// Gateway informer
	indexer.gatewayInformer = cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return gatewayClient.GatewayV1().Gateways("").List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return gatewayClient.GatewayV1().Gateways("").Watch(context.TODO(), options)
			},
		},
		&gwv1.Gateway{},
		resyncPeriod,
		cache.Indexers{},
	)

	_, err := indexer.gatewayInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    indexer.handleGatewayAdd,
		UpdateFunc: indexer.handleGatewayUpdate,
		DeleteFunc: indexer.handleGatewayDelete,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add gateway event handler: %w", err)
	}

	// HTTPRoute informer
	indexer.httpRouteInformer = cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return gatewayClient.GatewayV1().HTTPRoutes("").List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return gatewayClient.GatewayV1().HTTPRoutes("").Watch(context.TODO(), options)
			},
		},
		&gwv1.HTTPRoute{},
		resyncPeriod,
		cache.Indexers{},
	)

	_, err = indexer.httpRouteInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    indexer.handleHTTPRouteAdd,
		UpdateFunc: indexer.handleHTTPRouteUpdate,
		DeleteFunc: indexer.handleHTTPRouteDelete,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add httproute event handler: %w", err)
	}

	// GRPCRoute informer
	indexer.grpcRouteInformer = cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return gatewayClient.GatewayV1().GRPCRoutes("").List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return gatewayClient.GatewayV1().GRPCRoutes("").Watch(context.TODO(), options)
			},
		},
		&gwv1.GRPCRoute{},
		resyncPeriod,
		cache.Indexers{},
	)

	_, err = indexer.grpcRouteInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    indexer.handleGRPCRouteAdd,
		UpdateFunc: indexer.handleGRPCRouteUpdate,
		DeleteFunc: indexer.handleGRPCRouteDelete,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add grpcroute event handler: %w", err)
	}

	return indexer, nil
}

// Start begins watching Kubernetes resources and building the index
func (idx *StatusIndexer) Start(ctx context.Context) error {
	if idx.started {
		return fmt.Errorf("indexer already started")
	}

	idx.logger.Info("Starting Gateway API status indexer")

	// Start informers
	go idx.gatewayInformer.Run(idx.stopCh)
	go idx.httpRouteInformer.Run(idx.stopCh)
	go idx.grpcRouteInformer.Run(idx.stopCh)

	// Wait for caches to sync
	idx.logger.Info("Waiting for informer caches to sync")
	if !cache.WaitForCacheSync(idx.stopCh,
		idx.gatewayInformer.HasSynced,
		idx.httpRouteInformer.HasSynced,
		idx.grpcRouteInformer.HasSynced) {
		return fmt.Errorf("timed out waiting for caches to sync")
	}

	idx.started = true
	idx.logger.Info("Gateway API status indexer started and synced",
		zap.Int("gateways", len(idx.gateways)),
		zap.Int("httpRoutes", len(idx.httpRoutes)),
		zap.Int("grpcRoutes", len(idx.grpcRoutes)))

	return nil
}

// Stop gracefully stops the indexer
func (idx *StatusIndexer) Stop() {
	if !idx.started {
		return
	}

	idx.logger.Info("Stopping Gateway API status indexer")
	close(idx.stopCh)
	idx.started = false
}

// GetGatewayStatus retrieves Gateway status from the index
func (idx *StatusIndexer) GetGatewayStatus(namespace, name string) (*GatewayStatus, bool) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	key := fmt.Sprintf("%s/%s", namespace, name)
	status, ok := idx.gateways[key]
	return status, ok
}

// GetHTTPRouteStatus retrieves HTTPRoute status from the index
func (idx *StatusIndexer) GetHTTPRouteStatus(namespace, name string) (*HTTPRouteStatus, bool) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	key := fmt.Sprintf("%s/%s", namespace, name)
	status, ok := idx.httpRoutes[key]
	return status, ok
}

// GetGRPCRouteStatus retrieves GRPCRoute status from the index
func (idx *StatusIndexer) GetGRPCRouteStatus(namespace, name string) (*GRPCRouteStatus, bool) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	key := fmt.Sprintf("%s/%s", namespace, name)
	status, ok := idx.grpcRoutes[key]
	return status, ok
}

// GetRoutesForGateway returns all routes attached to a specific Gateway
func (idx *StatusIndexer) GetRoutesForGateway(namespace, name string) []string {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	key := fmt.Sprintf("%s/%s", namespace, name)
	routes, ok := idx.gatewayToRoutes[key]
	if !ok {
		return nil
	}

	// Return copy to avoid race conditions
	result := make([]string, len(routes))
	copy(result, routes)
	return result
}

// ListHTTPRoutesForGateway returns all HTTPRoutes attached to a specific Gateway
func (idx *StatusIndexer) ListHTTPRoutesForGateway(gwNamespace, gwName string) []*HTTPRouteStatus {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	result := make([]*HTTPRouteStatus, 0)

	// Iterate through all HTTP routes and check if they're attached to this gateway
	for _, route := range idx.httpRoutes {
		for _, parentRef := range route.ParentRefs {
			if parentRef.ParentNamespace == gwNamespace && parentRef.ParentName == gwName {
				result = append(result, route)
				break
			}
		}
	}

	return result
}

// ListGRPCRoutesForGateway returns all GRPCRoutes attached to a specific Gateway
func (idx *StatusIndexer) ListGRPCRoutesForGateway(gwNamespace, gwName string) []*GRPCRouteStatus {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	result := make([]*GRPCRouteStatus, 0)

	// Iterate through all GRPC routes and check if they're attached to this gateway
	for _, route := range idx.grpcRoutes {
		for _, parentRef := range route.ParentRefs {
			if parentRef.ParentNamespace == gwNamespace && parentRef.ParentName == gwName {
				result = append(result, route)
				break
			}
		}
	}

	return result
}

// GetStats returns current indexer statistics
func (idx *StatusIndexer) GetStats() map[string]int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	return map[string]int{
		"gateways":   len(idx.gateways),
		"httpRoutes": len(idx.httpRoutes),
		"grpcRoutes": len(idx.grpcRoutes),
	}
}

// Gateway event handlers

func (idx *StatusIndexer) handleGatewayAdd(obj interface{}) {
	gateway := obj.(*gwv1.Gateway)
	status := extractGatewayStatus(gateway)

	idx.mu.Lock()
	defer idx.mu.Unlock()

	key := fmt.Sprintf("%s/%s", gateway.Namespace, gateway.Name)
	idx.gateways[key] = status

	idx.logger.Debug("Indexed Gateway",
		zap.String("key", key),
		zap.String("class", status.GatewayClass),
		zap.Bool("programmed", status.Programmed))
}

func (idx *StatusIndexer) handleGatewayUpdate(oldObj, newObj interface{}) {
	gateway := newObj.(*gwv1.Gateway)
	status := extractGatewayStatus(gateway)

	idx.mu.Lock()
	defer idx.mu.Unlock()

	key := fmt.Sprintf("%s/%s", gateway.Namespace, gateway.Name)
	idx.gateways[key] = status

	idx.logger.Debug("Updated Gateway index",
		zap.String("key", key),
		zap.Bool("programmed", status.Programmed))
}

func (idx *StatusIndexer) handleGatewayDelete(obj interface{}) {
	gateway := obj.(*gwv1.Gateway)

	idx.mu.Lock()
	defer idx.mu.Unlock()

	key := fmt.Sprintf("%s/%s", gateway.Namespace, gateway.Name)
	delete(idx.gateways, key)
	delete(idx.gatewayToRoutes, key)

	idx.logger.Debug("Removed Gateway from index", zap.String("key", key))
}

// HTTPRoute event handlers

func (idx *StatusIndexer) handleHTTPRouteAdd(obj interface{}) {
	route := obj.(*gwv1.HTTPRoute)
	status := extractHTTPRouteStatus(route)

	idx.mu.Lock()
	defer idx.mu.Unlock()

	key := fmt.Sprintf("%s/%s", route.Namespace, route.Name)
	idx.httpRoutes[key] = status

	// Update reverse index (gateway -> routes)
	idx.updateGatewayRouteIndex(route.Namespace, route.Name, status.ParentRefs)

	idx.logger.Debug("Indexed HTTPRoute",
		zap.String("key", key),
		zap.Int("parents", len(status.ParentRefs)))
}

func (idx *StatusIndexer) handleHTTPRouteUpdate(oldObj, newObj interface{}) {
	route := newObj.(*gwv1.HTTPRoute)
	status := extractHTTPRouteStatus(route)

	idx.mu.Lock()
	defer idx.mu.Unlock()

	key := fmt.Sprintf("%s/%s", route.Namespace, route.Name)
	idx.httpRoutes[key] = status

	// Update reverse index
	idx.updateGatewayRouteIndex(route.Namespace, route.Name, status.ParentRefs)

	idx.logger.Debug("Updated HTTPRoute index", zap.String("key", key))
}

func (idx *StatusIndexer) handleHTTPRouteDelete(obj interface{}) {
	route := obj.(*gwv1.HTTPRoute)

	idx.mu.Lock()
	defer idx.mu.Unlock()

	key := fmt.Sprintf("%s/%s", route.Namespace, route.Name)
	delete(idx.httpRoutes, key)

	// Remove from reverse index
	idx.removeFromGatewayRouteIndex(key)

	idx.logger.Debug("Removed HTTPRoute from index", zap.String("key", key))
}

// GRPCRoute event handlers

func (idx *StatusIndexer) handleGRPCRouteAdd(obj interface{}) {
	route := obj.(*gwv1.GRPCRoute)
	status := extractGRPCRouteStatus(route)

	idx.mu.Lock()
	defer idx.mu.Unlock()

	key := fmt.Sprintf("%s/%s", route.Namespace, route.Name)
	idx.grpcRoutes[key] = status

	// Update reverse index
	idx.updateGatewayRouteIndex(route.Namespace, route.Name, status.ParentRefs)

	idx.logger.Debug("Indexed GRPCRoute",
		zap.String("key", key),
		zap.Int("parents", len(status.ParentRefs)))
}

func (idx *StatusIndexer) handleGRPCRouteUpdate(oldObj, newObj interface{}) {
	route := newObj.(*gwv1.GRPCRoute)
	status := extractGRPCRouteStatus(route)

	idx.mu.Lock()
	defer idx.mu.Unlock()

	key := fmt.Sprintf("%s/%s", route.Namespace, route.Name)
	idx.grpcRoutes[key] = status

	// Update reverse index
	idx.updateGatewayRouteIndex(route.Namespace, route.Name, status.ParentRefs)

	idx.logger.Debug("Updated GRPCRoute index", zap.String("key", key))
}

func (idx *StatusIndexer) handleGRPCRouteDelete(obj interface{}) {
	route := obj.(*gwv1.GRPCRoute)

	idx.mu.Lock()
	defer idx.mu.Unlock()

	key := fmt.Sprintf("%s/%s", route.Namespace, route.Name)
	delete(idx.grpcRoutes, key)

	// Remove from reverse index
	idx.removeFromGatewayRouteIndex(key)

	idx.logger.Debug("Removed GRPCRoute from index", zap.String("key", key))
}

// AddGatewayForTesting manually adds a Gateway to the index for testing purposes
func (idx *StatusIndexer) AddGatewayForTesting(gateway *gwv1.Gateway) {
	idx.handleGatewayAdd(gateway)
}

// AddHTTPRouteForTesting manually adds an HTTPRoute to the index for testing purposes
func (idx *StatusIndexer) AddHTTPRouteForTesting(route *gwv1.HTTPRoute) {
	idx.handleHTTPRouteAdd(route)
}

// AddGRPCRouteForTesting manually adds a GRPCRoute to the index for testing purposes
func (idx *StatusIndexer) AddGRPCRouteForTesting(route *gwv1.GRPCRoute) {
	idx.handleGRPCRouteAdd(route)
}

// Helper methods for reverse index management

func (idx *StatusIndexer) updateGatewayRouteIndex(routeNamespace, routeName string, parentRefs []ParentRefStatus) {
	routeKey := fmt.Sprintf("%s/%s", routeNamespace, routeName)

	// First, remove this route from all gateway indices
	idx.removeFromGatewayRouteIndex(routeKey)

	// Then add to new parent gateways
	for _, parentRef := range parentRefs {
		gatewayKey := fmt.Sprintf("%s/%s", parentRef.ParentNamespace, parentRef.ParentName)

		routes, ok := idx.gatewayToRoutes[gatewayKey]
		if !ok {
			routes = []string{}
		}

		// Add route if not already present
		found := false
		for _, r := range routes {
			if r == routeKey {
				found = true
				break
			}
		}
		if !found {
			routes = append(routes, routeKey)
			idx.gatewayToRoutes[gatewayKey] = routes
		}
	}
}

func (idx *StatusIndexer) removeFromGatewayRouteIndex(routeKey string) {
	// Remove this route from all gateway indices
	for gatewayKey, routes := range idx.gatewayToRoutes {
		newRoutes := []string{}
		for _, r := range routes {
			if r != routeKey {
				newRoutes = append(newRoutes, r)
			}
		}
		if len(newRoutes) > 0 {
			idx.gatewayToRoutes[gatewayKey] = newRoutes
		} else {
			delete(idx.gatewayToRoutes, gatewayKey)
		}
	}
}
