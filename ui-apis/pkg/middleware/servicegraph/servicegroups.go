// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package servicegraph

import (
	"fmt"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
)

// This file implements a service group organizer per-request cache. It effectively defines the concept of a service
// group which is a group of services that are related by a common set of endpoints. It is careful with HostEndpoints,
// NetworkSets, GlobalNetworkSets and networks - ensuring that when included in a service, they are unrelated to the
// same endpoint not in a service (i.e. A "pub" Network in service X will be a separate graph node from a "pub"
// Network in service Y, both will be a separate graph node from a "pub" Network not in a service).
//
// The service group mappings are calculated on a per-request basis to avoid overly bloating the service group
// relationships - if we held a persistent cache of service group info then we'd need to age out expired endpoints.

// GetServiceGroupFlowEndpointKey returns an aggregated FlowEndpoint associated with the endpoint, protocol and port.
// This is the natural grouping of the endpoint for service groups (i.e. endpoints falling within the same
// aggregation level defined here will be part of the same service group).
func GetServiceGroupFlowEndpointKey(ep FlowEndpoint) *FlowEndpoint {
	switch ep.Type {
	case v1.GraphNodeTypeWorkload, v1.GraphNodeTypeReplicaSet:
		// All pods within a replica set are part of the same service group, so just use name_aggr for the key and
		// exclude the port.
		return &FlowEndpoint{
			Type:      v1.GraphNodeTypeReplicaSet,
			Namespace: ep.Namespace,
			NameAggr:  ep.NameAggr,
		}
	case v1.GraphNodeTypeClusterNode, v1.GraphNodeTypeHost,
		v1.GraphNodeTypeNetworkSet, v1.GraphNodeTypeNetwork:
		// Match on port and proto for these endpoint types since they do not truly represent a single microservice
		// endpoint.  Also use the full name since the aggregated set does not represent a sensible grouping for
		// services.
		return &FlowEndpoint{
			Type:      ep.Type,
			Namespace: ep.Namespace,
			Name:      ep.Name,
			NameAggr:  ep.NameAggr,
			PortNum:   ep.PortNum,
			Protocol:  ep.Protocol,
		}
	}
	return nil
}

// ServiceGroups interface is used to populate and query the service group relationship cache.
type ServiceGroups interface {
	// Methods used to populate the service groups
	AddMapping(svc v1.ServicePort, ep FlowEndpoint)
	FinishMappings()

	// Accessor methods used to lookup service groups.
	Iter(cb func(*ServiceGroup) error) error
	GetByService(svc v1.NamespacedName) *ServiceGroup
	GetByEndpoint(ep FlowEndpoint) *ServiceGroup
}

// ServiceGroup contains the endpoint and service information for a single service group.
type ServiceGroup struct {
	// The ID for this service group.
	ID v1.GraphNodeID

	// The set of services in this group.
	Services []v1.NamespacedName

	// The NameAggr and Namespace for this service group, and the set of underlying services. The name and/or namespace may
	// be set to "*" to indicate it has been aggregated from the set of underlying services.
	Namespace    string
	Name         string
	ServicePorts map[v1.ServicePort]map[FlowEndpoint]struct{}
}

func (s ServiceGroup) String() string {
	return fmt.Sprintf("ServiceGroup(%s/%s)", s.Namespace, s.Name)
}

type serviceGroups struct {
	serviceGroups              set.Set[*ServiceGroup]
	serviceGroupsByServiceName map[v1.NamespacedName]*ServiceGroup
	serviceGroupsByEndpointKey map[FlowEndpoint]*ServiceGroup
	finished                   bool
}

func (sgs *serviceGroups) String() string {
	var lines []string
	lines = append(lines, "==== Services ====")
	for sn := range sgs.serviceGroupsByServiceName {
		lines = append(lines, sn.String())
	}
	lines = append(lines, "==== Endpoints ====")
	for ek := range sgs.serviceGroupsByEndpointKey {
		lines = append(lines, ek.String())
	}
	return strings.Join(lines, "\n")
}

func (sgs *serviceGroups) Iter(cb func(*ServiceGroup) error) error {
	for item := range sgs.serviceGroups.All() {
		if err := cb(item); err != nil {
			return err
		}
	}
	return nil
}

func (sgs *serviceGroups) GetByService(svc v1.NamespacedName) *ServiceGroup {
	return sgs.serviceGroupsByServiceName[svc]
}

func (sgs *serviceGroups) GetByEndpoint(ep FlowEndpoint) *ServiceGroup {
	if key := GetServiceGroupFlowEndpointKey(ep); key != nil {
		return sgs.serviceGroupsByEndpointKey[*key]
	}
	return nil
}

func NewServiceGroups() ServiceGroups {
	// Create a ServiceGroups helper.
	sd := &serviceGroups{
		serviceGroups:              set.New[*ServiceGroup](),
		serviceGroupsByServiceName: make(map[v1.NamespacedName]*ServiceGroup),
		serviceGroupsByEndpointKey: make(map[FlowEndpoint]*ServiceGroup),
	}

	return sd
}

// FinishMappings is called when all of the service<->endpoint mappings have been added to this cache. This method
// calculates the service groupings by collecting services with common sets of endpoints. It should be called once
// only.
func (sd *serviceGroups) FinishMappings() {
	// Check we haven't finished the mappings already.
	if sd.finished {
		log.Panic("FinishMappings called more than once")
	}
	sd.finished = true

	// Calculate the service groups name and namespace.
	for sg := range sd.serviceGroups.All() {
		names := &nameCalculator{names: make(map[string]bool)}
		namespaces := &nameCalculator{names: make(map[string]bool)}
		for svcKey := range sg.ServicePorts {
			names.add(svcKey.Name)
			namespaces.add(svcKey.Namespace)
		}
		sg.Name = names.combined()
		sg.Namespace = namespaces.uniq()
	}

	// Trace out the service groups if the log level is debug.
	if log.IsLevelEnabled(log.DebugLevel) {
		log.Debug("=== Service groups ===")
		for sg := range sd.serviceGroups.All() {
			log.Debugf("%s ->", sg)
			for sk, svc := range sg.ServicePorts {
				log.Debugf("  %s ->", sk)
				for ep := range svc {
					log.Debugf("    o %s", ep)
				}
			}
		}
		log.Debug("=== Endpoint key to service group ===")
		for ep, sg := range sd.serviceGroupsByEndpointKey {
			log.Debugf("%s -> %s", ep, sg)
		}
		log.Debug("=== Service name to service group ===")
		for svc, sg := range sd.serviceGroupsByServiceName {
			log.Debugf("%s -> %s", svc, sg)
		}
	}

	// Update the set of services in each service group. It is easiest to do this at the end when each service has
	// the correct service group assigned to it.
	for sn, sg := range sd.serviceGroupsByServiceName {
		sg.Services = append(sg.Services, sn)
	}

	// Update the ID for each group, and simplify the groups to use the aggregated name instead of the full name if the
	// port is common across replicas.
	for sg := range sd.serviceGroups.All() {
		// Sort the services for easier testing.
		sort.Sort(v1.SortableNamespacedNames(sg.Services))

		// Construct the id using the IDInfo.
		sg.ID = GetServiceGroupID(sg.Services)

		// Update the service group to not include the full name if the port/proto is fixed across all endpoints in the
		// replica set for a given service port (and there is more than one endpoint)
		aggrs := make(map[FlowEndpoint]map[v1.ServicePort][]FlowEndpoint)
		for sp, eps := range sg.ServicePorts {
			for ep := range eps {
				ae := FlowEndpoint{
					Type:      ConvertEndpointTypeToAggrEndpointType(ep.Type),
					Namespace: ep.Namespace,
					NameAggr:  ep.NameAggr,
					Protocol:  ep.Protocol,
					PortNum:   ep.PortNum,
				}
				m := aggrs[ae]
				if m == nil {
					m = make(map[v1.ServicePort][]FlowEndpoint)
					aggrs[ae] = m
				}
				m[sp] = append(m[sp], ep)
			}
		}
		for aep, sps := range aggrs {
			if len(sps) > 1 {
				// There are multiple service ports associated with this aggregated endpoint port, so do not aggregate
				// the data in the service group.
				continue
			}
			// There is only one entry, but only way to get it is to iterate.
			for sp, eps := range sps {
				for _, ep := range eps {
					delete(sg.ServicePorts[sp], ep)
				}

				// Replace with a single aggregated-endpoint-name/port/proto. Use the aggregated form of the type
				// when storing in the service group.
				sg.ServicePorts[sp][aep] = struct{}{}
			}
		}
	}
}

// AddMapping adds a service port <-> endpoint mapping to the cache.  When all mappings have been added, the caller
// should call FinishMappings.
func (s *serviceGroups) AddMapping(svc v1.ServicePort, ep FlowEndpoint) {
	// If there is an existing service group either by service or endpoint then apply updates to that service
	// group, otherwise create a new service group.
	var sg, sge *ServiceGroup

	// Get the existing service groups associated with the endpoint and the service.
	epKey := GetServiceGroupFlowEndpointKey(ep)
	if epKey != nil {
		sge = s.serviceGroupsByEndpointKey[*epKey]
	}
	sgs := s.serviceGroupsByServiceName[svc.NamespacedName]

	if sge != nil && sgs != nil {
		// There is an entry by service and endpoint. If they are the same ServiceGroup then nothing to do, if they are
		// different then combine the two ServiceGroups.
		if sge != sgs {
			// The ServiceGroup referenced by service is different to the one referenced by the endpoint. Migrate the
			// references from the service SG to the endpoint SG. Copy across the data - since the endpoint SG will not
			// already have the service, it's possible to copy across the endpoint map in full.
			log.Debugf("Merging ServiceGroup for %s into ServiceGroup for %s", ep, svc)
			s.migrateReferences(sgs, sge)
		}
		sg = sge
	} else if sge != nil {
		// No entry by service, but there is by endpoint - use that.
		log.Debugf("Including %s into ServiceGroup for %s", svc, ep)
		sg = sge
	} else if sgs != nil {
		// No entry by endpoint, but there is by service - use that.
		log.Debugf("Including %s into ServiceGroup for %s", ep, svc)
		sg = sgs
	} else {
		// No existing entry by endpoint or service, so create a new service group.
		log.Debugf("Creating new ServiceGroup containing %s and %s", svc, ep)
		sg = &ServiceGroup{
			ServicePorts: make(map[v1.ServicePort]map[FlowEndpoint]struct{}),
		}
		s.serviceGroups.Add(sg)
	}

	// Set references.
	s.serviceGroupsByServiceName[svc.NamespacedName] = sg
	if epKey != nil {
		s.serviceGroupsByEndpointKey[*epKey] = sg
	}

	// Update service group data to include the endpoint.
	if sg.ServicePorts[svc] == nil {
		sg.ServicePorts[svc] = map[FlowEndpoint]struct{}{
			ep: {},
		}
	} else {
		sg.ServicePorts[svc][ep] = struct{}{}
	}
}

// migrateReferences is invoked when a service->endoint mapping is added that links two service groups together. In this
// case the service groups are combined into a single group by migrating the endpoint data from one service group into
// the other.
func (s *serviceGroups) migrateReferences(from, to *ServiceGroup) {
	// Update the mappings.
	for svc, eps := range from.ServicePorts {
		s.serviceGroupsByServiceName[svc.NamespacedName] = to

		for ep := range eps {
			if epKey := GetServiceGroupFlowEndpointKey(ep); epKey != nil {
				s.serviceGroupsByEndpointKey[*epKey] = to
			}
		}

		// Copy across the service ports.
		to.ServicePorts[svc] = eps
	}

	// Remove the old group.
	s.serviceGroups.Discard(from)
}

// nameCalculator is used to track names underpinning a group of resources, and to create an aggregated name from the
// set of names.
type nameCalculator struct {
	names map[string]bool
}

// Add a name to the calculator.
func (nc *nameCalculator) add(name string) {
	nc.names[name] = true
}

// Return a name constructed from a  unique combination of the names.
func (nc *nameCalculator) combined() string {
	names := make([]string, 0, len(nc.names))
	for name := range nc.names {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, "/")
}

// Return the unique name. If there are multiple different names then return a "*".
func (nc *nameCalculator) uniq() string {
	if len(nc.names) > 1 {
		return "*"
	}
	for name := range nc.names {
		return name
	}
	return ""
}
