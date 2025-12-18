// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package calc

import (
	"net"

	log "github.com/sirupsen/logrus"
	discovery "k8s.io/api/discovery/v1"

	"github.com/projectcalico/calico/felix/k8sutils"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// EndpointSliceAddrIndexer indexes the endpoint slices of a subset of services,
// making it easy to extract all the active (IP, port, protocol) of the
// matching EndpointSlices.
//
// This component should included in other components which can register
// themselves with update dispatcher. Ex L7ServiceIPSetsCalculator
//
// It processes the updates passed to it and creates maps for index searchable
// data on memmory.
type EndpointSliceAddrIndexer struct {
	// EndpointSlice relationships and cached resource info.
	ipPortProtoSetByService map[model.ResourceKey]set.Set[ipPortProtoKey]
	endpointSlicesByService map[model.ResourceKey]set.Set[model.ResourceKey]
	endpointSlices          map[model.ResourceKey]*discovery.EndpointSlice
	ignoredWorkloads        map[model.WorkloadEndpointKey]*model.WorkloadEndpoint
}

func NewEndpointSliceAddrIndexer() *EndpointSliceAddrIndexer {
	e := &EndpointSliceAddrIndexer{
		ipPortProtoSetByService: map[model.ResourceKey]set.Set[ipPortProtoKey]{},
		endpointSlicesByService: map[model.ResourceKey]set.Set[model.ResourceKey]{},
		endpointSlices:          map[model.ResourceKey]*discovery.EndpointSlice{},
		ignoredWorkloads:        map[model.WorkloadEndpointKey]*model.WorkloadEndpoint{},
	}
	return e
}

func extractIPPortProto(endpointSlice *discovery.EndpointSlice) (
	ipPortProtos []ipPortProtoKey,
) {
	// Construct a full set of ipPortProto for the endpointSlice.
	ipPortProtos = []ipPortProtoKey{}
	for _, edp := range endpointSlice.Endpoints {
		for _, address := range edp.Addresses {
			ip := net.ParseIP(address)
			if ip == nil {
				// address can be a FQDN, what we skip
				log.Debugf("Failed to parse endpoint slice address (%v), skipping", ip)
				continue
			}

			for _, port := range endpointSlice.Ports {
				ipPortProto := ipPortProtoKey{
					port:  int(*port.Port),
					proto: k8sutils.GetProtocolAsInt(*port.Protocol),
				}
				copy(ipPortProto.ip[:], ip.To16())
				ipPortProtos = append(ipPortProtos, ipPortProto)
			}
		}
	}
	return
}

func (e *EndpointSliceAddrIndexer) flush(
	svcsToUpdate []*model.ResourceKey,
) {
	processedSvcs := set.New[model.ResourceKey]()
	// Recreates ipPortProto by service
	for _, svc := range svcsToUpdate {
		if svc == nil || processedSvcs.Contains(*svc) {
			continue
		}
		processedSvcs.Add(*svc)

		delete(e.ipPortProtoSetByService, *svc)

		endpointSlices, ok := e.endpointSlicesByService[*svc]
		if !ok {
			continue
		}
		ipPortProtoSet := set.New[ipPortProtoKey]()
		for endpointSliceKey := range endpointSlices.All() {
			ipPortProtoSet.AddAll(extractIPPortProto(e.endpointSlices[endpointSliceKey]))
		}
		e.ipPortProtoSetByService[*svc] = ipPortProtoSet
	}
}

// handleEndpointSlice updates all indexes of the update handler based on the
// new key value info, to keep a simple logic we always delete the old data then
// add the new one befor flushing. Passing nil to endpointSlice argument is for
// just removal.
func (e *EndpointSliceAddrIndexer) handleEndpointSlice(
	key model.ResourceKey, endpointSlice *discovery.EndpointSlice,
) {
	var serviceKey, oldServiceKey *model.ResourceKey
	needFlush := false
	log.WithFields(log.Fields{"key": key}).Debugf("Handle endpointSlice")

	// deleting
	oldEndpointSlice, ok := e.endpointSlices[key]
	if ok {
		needFlush = true
		delete(e.endpointSlices, key)

		oldServiceKey = &model.ResourceKey{
			Namespace: key.Namespace,
			Name:      oldEndpointSlice.Labels["kubernetes.io/service-name"],
			Kind:      model.KindKubernetesService,
		}
		endpointsSet, ok := e.endpointSlicesByService[*oldServiceKey]
		if ok {
			endpointsSet.Discard(key)
			if endpointsSet.Len() == 0 {
				delete(e.endpointSlicesByService, *oldServiceKey)
			}
		}
	}

	// inserting
	if endpointSlice != nil {
		needFlush = true
		e.endpointSlices[key] = endpointSlice

		serviceKey = &model.ResourceKey{
			Namespace: key.Namespace,
			Name:      endpointSlice.Labels["kubernetes.io/service-name"],
			Kind:      model.KindKubernetesService,
		}
		endpointsSet, ok := e.endpointSlicesByService[*serviceKey]
		if !ok {
			endpointsSet = set.New[model.ResourceKey]()
			e.endpointSlicesByService[*serviceKey] = endpointsSet
		}
		endpointsSet.Add(key)
	}

	if needFlush {
		e.flush([]*model.ResourceKey{serviceKey, oldServiceKey})
	}
}

// Add ignored WorkloadEndpoint appends to the ignore list endpoints won't be
// diverted by TPROXY
func (e *EndpointSliceAddrIndexer) AddIgnoredWorkloadEndpoint(k model.WorkloadEndpointKey, v *model.WorkloadEndpoint) {
	e.ignoredWorkloads[k] = v
}

func (e *EndpointSliceAddrIndexer) RemoveIgnoredWorkloadEndpoint(k model.WorkloadEndpointKey) bool {
	if _, ok := e.ignoredWorkloads[k]; ok {
		delete(e.ignoredWorkloads, k)
		return true
	}
	return false
}

// AddOrUpdateEndpointSlice tracks endpointSlice IP to EndpointSlice mappings.
func (e *EndpointSliceAddrIndexer) AddOrUpdateEndpointSlice(key model.ResourceKey, endpointSlice *discovery.EndpointSlice) {

	e.handleEndpointSlice(key, endpointSlice)
}

func (e *EndpointSliceAddrIndexer) RemoveEndpointSlice(key model.ResourceKey) {

	e.handleEndpointSlice(key, nil)
}

// IPPortProtosByService returns a set with all ipPortProtoKeys by services
func (e *EndpointSliceAddrIndexer) IPPortProtosByService(
	svcs ...model.ResourceKey,
) set.Set[ipPortProtoKey] {

	result := set.New[ipPortProtoKey]()
	for _, svc := range svcs {
		set, ok := e.ipPortProtoSetByService[svc]
		if ok {
			result.AddSet(set)
		}
	}

	return result
}
