// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package proxy

import (
	"fmt"
	"iter"
	"net/netip"
	"sync"

	log "github.com/sirupsen/logrus"
	discovery "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/types"
	k8sp "k8s.io/kubernetes/pkg/proxy"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// EndpointSliceKey is an identifier for an endpoint slice.
type EndpointSliceKey struct {
	ServiceName       types.NamespacedName
	EndpointSliceName types.NamespacedName
}

// EndpointTracker is a locked map, updated by informer threads,
// and read by KP syncer threads.
type EndpointTracker struct {
	sync.Mutex
	// m keys endpoint slices by service-namespace, service-name, endpoint-slice-name.
	// The value is an endpoint-slice.
	m map[EndpointSliceKey]*discovery.EndpointSlice
}

// NewEndpointTracker returns an initialized EndpointTracker.
func NewEndpointTracker() *EndpointTracker {
	m := new(EndpointTracker)
	m.m = make(map[EndpointSliceKey]*discovery.EndpointSlice)
	return m
}

// All returns an iterator which locks the tracker and iterates over all KVs.
func (m *EndpointTracker) All() iter.Seq2[EndpointSliceKey, discovery.Endpoint] {
	return func(yield func(k EndpointSliceKey, s discovery.Endpoint) bool) {
		m.Lock()
		defer m.Unlock()
		for k, epSlice := range m.m {
			for _, ep := range epSlice.Endpoints {
				if !yield(k, ep) {
					return
				}
			}
		}
	}
}

// EndpointSliceUpdate mimics the signature of the k8s change trackers.
// It unpacks the slice into constituent endpoint addresses and either stores or removes them from the internal map.
func (m *EndpointTracker) EndpointSliceUpdate(eps *discovery.EndpointSlice, remove bool) {
	if eps == nil {
		return
	}

	switch eps.AddressType {
	case discovery.AddressTypeIPv4:
	case discovery.AddressTypeIPv6:
	default:
		log.WithFields(log.Fields{"endpointSlice": eps.Name, "addressType": eps.AddressType}).Debug("Won't process endpoint slice update for unsupported addresses.")
		return
	}

	// Generate keys similarly to k8sp pkg.
	// Bail out altogether if they can't be generated.
	serviceKey, sliceKey, err := endpointSliceCacheKeys(eps)
	if err != nil {
		log.WithField("endpointSlice", eps.Name).Warn("Couldn't generate cache keys for endpoint slice")
		return
	}
	key := EndpointSliceKey{ServiceName: serviceKey, EndpointSliceName: sliceKey}

	m.Lock()
	defer m.Unlock()

	if remove {
		delete(m.m, key)
	} else {
		m.m[key] = eps
	}
}

// MaintenanceEndpoints is a cache of service endpoints which are likely
// to be on nodes marked for maintenance.
// "Likely" is used here, as the cache does not discern between endpoints which:
// - Share an address, and,
// - Both back the same service.
// This is due to syncer not being able to provide sufficient endpoint information
// to filter by endpoint ID.
type MaintenanceEndpoints struct {
	set.Set[MaintenanceEndpointKey]
}

type MaintenanceEndpointKey struct {
	ServiceName  types.NamespacedName
	EndpointAddr netip.Addr
}

func NewMaintenanceEndpointKey(svcName types.NamespacedName, epIP string) (MaintenanceEndpointKey, error) {
	epAddr, err := netip.ParseAddr(epIP)
	if err != nil {
		return MaintenanceEndpointKey{}, fmt.Errorf("couldn't parse endpoint address as an IP: %w", err)
	}
	return MaintenanceEndpointKey{
		ServiceName:  svcName,
		EndpointAddr: epAddr,
	}, nil
}

func NewMaintenanceEndpoints() *MaintenanceEndpoints {
	return &MaintenanceEndpoints{set.New[MaintenanceEndpointKey]()}
}

// Update updates MaintenanceEndpoints with the latest endpoints living on hosts under maintenance.
func (t *MaintenanceEndpoints) Update(hostMetadataByHostname map[string]*proto.HostMetadataV4V6Update, epSliceTracker *EndpointTracker) {
	t.Clear()

	maintenanceNodes := set.NewAdaptive[string]()
	// First check if there are any maintenance nodes, and short-circuit the endpoints iteration if not.
	// This will be much cheaper for the normal path where no nodes are under maintenance.
	for _, hm := range hostMetadataByHostname {
		if hm.LoadbalancerMaintenance == proto.LoadbalancerMaintenance_LB_MAINT_EXCLUDE_LOCAL_BACKENDS {
			maintenanceNodes.Add(hm.Hostname)
		}
	}
	if maintenanceNodes.Len() == 0 {
		log.Debug("Won't calculate endpoints on maintenance nodes, as no marked nodes were found")
		return
	}

	log.Debug("Updating set of endpoints on nodes marked for maintenance")
	for key, ep := range epSliceTracker.All() {
		if ep.NodeName == nil {
			log.WithField("slice", key).Debug("Skipping maintenance check for endpoint with no node name")
			continue
		}
		if !maintenanceNodes.Contains(*ep.NodeName) {
			continue
		}

		if len(ep.Addresses) == 0 {
			log.WithField("slice", key).Debug("Skipping maintenance checks for endpoint with no address")
			continue
		}

		maintenanceKey, err := NewMaintenanceEndpointKey(key.ServiceName, ep.Addresses[0])
		if err != nil {
			log.WithField("endpoint", key).WithError(err).Error("Couldn't key endpoint for node-maintenance checks")
		}
		t.Add(maintenanceKey)
	}

}

// FilterEpsByNodeMaintenance removes endpoint items from the provided slice if they
// are matched to a node which is marked with a maintenance annotation.
// This is similar to how endpoints are filtered for topology-awareness.
func FilterEpsByNodeMaintenance(serviceName k8sp.ServicePortName, endpoints []k8sp.Endpoint, epsUnderMaintenance *MaintenanceEndpoints) []k8sp.Endpoint {
	if epsUnderMaintenance == nil || epsUnderMaintenance.Len() == 0 || serviceName.Name == "" {
		return endpoints
	}

	filtered := make([]k8sp.Endpoint, 0, len(endpoints))
	for _, ep := range endpoints {
		key, err := NewMaintenanceEndpointKey(serviceName.NamespacedName, ep.IP())
		if err != nil {
			log.WithField("endpoint", ep.String()).Warn("Couldn't generate key for endpoint. Won't attempt to filter by node maintenance")
			// Should not happen — k8s only stores valid IPs. Keep the endpoint.
			filtered = append(filtered, ep)
			continue
		}
		if epsUnderMaintenance.Contains(key) {
			log.WithField("ep", ep.IP()).Debug("Node maintenance: filtered out ep")
			continue
		}
		filtered = append(filtered, ep)
	}

	if len(filtered) == 0 {
		log.WithField("service", serviceName.NamespacedName).Warn("Node maintenance: Refusing to filter endpoints based on node-maintenance annotation, because it would result in no available endpoints")
		return endpoints
	}

	return filtered
}

// endpointSliceCacheKeys mostly copies k8s's pkg/proxy `endpointSliceCacheKeys` func.
func endpointSliceCacheKeys(endpointSlice *discovery.EndpointSlice) (svcName types.NamespacedName, sliceName types.NamespacedName, err error) {
	serviceName, ok := endpointSlice.Labels[discovery.LabelServiceName]
	if !ok || serviceName == "" {
		return svcName, sliceName, fmt.Errorf("no %s label set on endpoint slice: %s", discovery.LabelServiceName, endpointSlice.Name)
	} else if endpointSlice.Namespace == "" || endpointSlice.Name == "" {
		return svcName, sliceName, fmt.Errorf("expected EndpointSlice name and namespace to be set: %v", endpointSlice)
	}

	svcKey := types.NamespacedName{Namespace: endpointSlice.Namespace, Name: serviceName}
	sliceKey := types.NamespacedName{Namespace: endpointSlice.Namespace, Name: endpointSlice.Name}
	return svcKey, sliceKey, err
}
