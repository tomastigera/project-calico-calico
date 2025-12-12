// Copyright (c) 2016-2021 Tigera, Inc. All rights reserved.

package calc

import (
	"net"
	"reflect"

	log "github.com/sirupsen/logrus"
	kapiv1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/labelindex/ipsetmember"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/tproxydefs"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const (
	l7LoggingAnnotation = "projectcalico.org/l7-logging"
)

// L7ServiceIPSetsCalculator maintains IP sets for the service-related IPs that should be sent to
// Envoy for "L7" treatment (either ALP, L7 logging, or WAF).
//
// This includes:
//   - The Service ClusterIPs and NodePorts of services with the l7LoggingAnnotation.
//   - The backing pod IPs of the same (across the whole cluster).  This is calculated
//     from the EndpointSlices of the above services.
type L7ServiceIPSetsCalculator struct {
	createdIpSet bool
	conf         *config.Config
	sai          *ServiceAddrIndexer
	esai         *EndpointSliceAddrIndexer

	activeWorkloadIPSetMembers map[ipsetmember.IPSetMember]struct{}
	activeEndpoints            set.Set[ipPortProtoKey]
	activeNodePorts            set.Set[portProtoKey]

	callbacks ipSetUpdateCallbacks
}

func NewL7ServiceIPSetsCalculator(callbacks ipSetUpdateCallbacks, conf *config.Config) *L7ServiceIPSetsCalculator {
	tpr := &L7ServiceIPSetsCalculator{
		conf:         conf,
		createdIpSet: false,
		callbacks:    callbacks,
		sai:          NewServiceAddrIndexer(),

		activeWorkloadIPSetMembers: make(map[ipsetmember.IPSetMember]struct{}),
		esai:                       NewEndpointSliceAddrIndexer(),
		activeEndpoints:            set.New[ipPortProtoKey](),
		activeNodePorts:            set.New[portProtoKey](),
	}

	tpr.callbacks.OnIPSetAdded(tproxydefs.ServiceIPsIPSet, proto.IPSetUpdate_IP_AND_PORT)
	tpr.callbacks.OnIPSetAdded(tproxydefs.NodePortsIPSet, proto.IPSetUpdate_PORTS)
	return tpr
}

func (c *L7ServiceIPSetsCalculator) RegisterWithAllUpdates(allUpdateDisp, localUpdDisp *dispatcher.Dispatcher) {
	log.Debugf("registering with all update dispatcher for tproxy service updates")
	allUpdateDisp.Register(model.ResourceKey{}, c.OnResourceUpdate)
	localUpdDisp.Register(model.WorkloadEndpointKey{}, c.OnResourceUpdate)
}

func (c *L7ServiceIPSetsCalculator) isEndpointSliceFromAnnotatedService(
	k model.ResourceKey, v *discovery.EndpointSlice,
) bool {
	serviceKey := model.ResourceKey{
		Namespace: k.Namespace,
		Kind:      model.KindKubernetesService,
	}
	if v == nil {
		edp, ok := c.esai.endpointSlices[k]
		if !ok {
			return false
		}
		v = edp
	}
	serviceKey.Name = v.Labels["kubernetes.io/service-name"]
	_, ok := c.sai.services[serviceKey]
	return ok
}

// OnResourceUpdate is the callback method registered with the allUpdates dispatcher. We filter out everything except
// kubernetes services updates (for now). We can add other resources to L7 in future here.
func (c *L7ServiceIPSetsCalculator) OnResourceUpdate(update api.Update) (_ bool) {
	switch k := update.Key.(type) {
	case model.ResourceKey:
		switch k.Kind {
		case model.KindKubernetesService:
			log.Debugf("processing update for service %s", k)
			if update.Value == nil {
				if _, ok := c.sai.services[k]; ok {
					c.sai.RemoveService(k)
					c.flush()
				}
			} else {
				service := update.Value.(*kapiv1.Service)
				annotations := service.Annotations
				// process services annotated with l7 or all service when in EnabledAllServices mode
				if hasAnnotation(annotations, l7LoggingAnnotation) || c.conf.TPROXYModeEnabledAllServices() {
					log.Debugf("processing update for tproxy annotated service %s", k)
					c.sai.AddOrUpdateService(k, service)
					c.flush()
				} else {
					// case when service is present in services and no longer has annotation
					if _, ok := c.sai.services[k]; ok {
						log.Debugf("removing unannotated service from ipset %s", k)
						c.sai.RemoveService(k)
						c.flush()
					}
				}
			}
		case model.KindKubernetesEndpointSlice:
			log.Debugf("processing update for endpointslice %s", k)
			needFlush := false
			if update.Value == nil {
				if c.isEndpointSliceFromAnnotatedService(k, nil) {
					needFlush = true
				}
				c.esai.RemoveEndpointSlice(k)
			} else {
				endpointSlice := update.Value.(*discovery.EndpointSlice)
				c.esai.AddOrUpdateEndpointSlice(k, endpointSlice)
				if c.isEndpointSliceFromAnnotatedService(k, endpointSlice) {
					needFlush = true
				}
			}

			if needFlush {
				c.flush()
			}
		default:
			log.Debugf("Ignoring update for resource: %s", k)
		}
	case model.WorkloadEndpointKey:
		// skip this workload because it is set to be using sidecars
		if update.Value == nil {
			if c.esai.RemoveIgnoredWorkloadEndpoint(update.Key.(model.WorkloadEndpointKey)) {
				c.flush()
			}
			return
		}
		if v, ok := update.Value.(*model.WorkloadEndpoint); ok && v.ApplicationLayer != nil {
			c.esai.AddIgnoredWorkloadEndpoint(update.Key.(model.WorkloadEndpointKey), v)
			c.flush()
		}
	default:
		log.Errorf("Ignoring unexpected update: %v %#v",
			reflect.TypeOf(update.Key), update)
	}
	return
}

// flush emits ipSetUpdateCallbacks (OnIPSetAdded, OnIPSetMemberAdded, OnIPSetMemberRemoved) when endpoints
// for tproxy traffic selection changes. It detects the change in state by comparing most up to date
// members list maintained by UpdateHandlers to the list maintained by
// L7ServiceIPSetsCalculator.
func (c *L7ServiceIPSetsCalculator) flush() {
	addedSvs, removedSvs := c.resolveRegularEndpoints()

	if len(addedSvs) > 0 || len(removedSvs) > 0 {
		c.flushRegularEndpoints(addedSvs, removedSvs)
	}

	addedNPs, removedNPs := c.resolveNodePorts()

	if len(addedNPs) > 0 || len(removedNPs) > 0 {
		c.flushNodePorts(addedNPs, removedNPs)
	}
}

func isTCP(ipPortProto ipPortProtoKey) bool {
	protocol := ipsetmember.Protocol(ipPortProto.proto)
	if protocol != ipsetmember.ProtocolTCP {
		log.Warningf("IP/Port/Protocol (%v/%d/%d) Protocol not valid for l7 logging",
			ipPortProto.ip, protocol, ipPortProto.port)
		return false
	}

	return true
}

func (c *L7ServiceIPSetsCalculator) resolveRegularEndpoints() (added []ipPortProtoKey, removed []ipPortProtoKey) {
	// todo: felix maintains a diff of changes. We should use that instead if iterating over entire map
	log.Infof("flush regular services for tproxy")

	// Get all ipPortProtos from endpointSlice update handler
	allSvcKeys := make([]model.ResourceKey, len(c.sai.services))
	for k := range c.sai.services {
		allSvcKeys = append(allSvcKeys, k)
	}
	esaiIPPortProtos := c.esai.IPPortProtosByService(allSvcKeys...)

	for ipPortProto := range c.activeEndpoints.All() {
		// if member key exists in up-to-date list, else add to removed
		_, ok := c.sai.ipPortProtoToServices[ipPortProto]
		if ok {
			continue
		}

		if esaiIPPortProtos.Contains(ipPortProto) {
			continue
		}
		removed = append(removed, ipPortProto)
	}

	// add new items to tproxy from updated list of annotated endpoints
	for ipPortProto := range c.sai.ipPortProtoToServices {
		// if it already exists in active endpoints skip it
		if c.activeEndpoints.Contains(ipPortProto) {
			continue
		}
		// if protocol is not TCP skip it for now
		if !isTCP(ipPortProto) {
			continue
		}
		added = append(added, ipPortProto)
	}

	for ipPortProto := range esaiIPPortProtos.All() {
		// if it already exists in active endpoints skip it
		if c.activeEndpoints.Contains(ipPortProto) {
			continue
		}
		// if protocol is not TCP skip it for now
		if !isTCP(ipPortProto) {
			continue
		}
		added = append(added, ipPortProto)
	}

	return added, removed
}

func (c *L7ServiceIPSetsCalculator) flushRegularEndpoints(added []ipPortProtoKey,
	removed []ipPortProtoKey) {

	ignored := map[[16]byte]struct{}{}
	for _, wledp := range c.esai.ignoredWorkloads {
		for _, ipnet := range wledp.IPv4Nets {
			var ip [16]byte
			copy(ip[:], ipnet.IP.To16())
			ignored[ip] = struct{}{}
		}
	}

	for _, ipPortProto := range removed {
		member := getIpSetMemberFromIpPortProto(ipPortProto)
		c.callbacks.OnIPSetMemberRemoved(tproxydefs.ServiceIPsIPSet, member)
		c.activeEndpoints.Discard(ipPortProto)
	}

	for _, ipPortProto := range added {
		// skip to add ignored
		if _, ok := ignored[ipPortProto.ip]; ok {
			continue
		}
		member := getIpSetMemberFromIpPortProto(ipPortProto)
		c.callbacks.OnIPSetMemberAdded(tproxydefs.ServiceIPsIPSet, member)
		c.activeEndpoints.Add(ipPortProto)
	}

}

func (c *L7ServiceIPSetsCalculator) resolveNodePorts() ([]portProtoKey, []portProtoKey) {
	// todo: felix maintains a diff of changes. We should use that instead if iterating over entire map
	log.Infof("flush node ports for tproxy")

	var added, removed []portProtoKey

	for portProto := range c.activeNodePorts.All() {
		// if member key exists in up-to-date list, update the value to latest in active node ports and continue to next
		if _, ok := c.sai.nodePortServices[portProto]; ok {
			continue
		}
		removed = append(removed, portProto)
	}

	for portProto := range c.sai.nodePortServices {
		// if it already exists in active node ports skip it
		if c.activeNodePorts.Contains(portProto) {
			continue
		}
		protocol := ipsetmember.Protocol(portProto.proto)
		// skip non tcp for now
		if protocol != ipsetmember.ProtocolTCP {
			log.Warningf("Port/Protocol (%d/%d) Protocol not valid for tproxy", portProto.port, protocol)
			continue
		}
		// if node port is zero skip callbacks
		if portProto.port == 0 {
			continue
		}
		added = append(added, portProto)
		log.Debugf("Added Port/Protocol (%d/%d).", portProto.port, protocol)
	}
	return added, removed
}

func (c *L7ServiceIPSetsCalculator) flushNodePorts(added []portProtoKey,
	removed []portProtoKey) {

	for _, portProto := range removed {
		if ipsetmember.Protocol(portProto.proto) == ipsetmember.ProtocolTCP {
			member := getIpSetPortMemberFromPortProto(portProto, 4)
			c.callbacks.OnIPSetMemberRemoved(tproxydefs.NodePortsIPSet, member)
			member = getIpSetPortMemberFromPortProto(portProto, 6)
			c.callbacks.OnIPSetMemberRemoved(tproxydefs.NodePortsIPSet, member)
			c.activeNodePorts.Discard(portProto)
		}
	}

	for _, portProto := range added {
		if ipsetmember.Protocol(portProto.proto) == ipsetmember.ProtocolTCP {
			member := getIpSetPortMemberFromPortProto(portProto, 4)
			c.callbacks.OnIPSetMemberAdded(tproxydefs.NodePortsIPSet, member)
			member = getIpSetPortMemberFromPortProto(portProto, 6)
			c.callbacks.OnIPSetMemberAdded(tproxydefs.NodePortsIPSet, member)
			c.activeNodePorts.Add(portProto)
		}
	}

}

func getIpSetMemberFromIpPortProto(ipPortProto ipPortProtoKey) ipsetmember.IPSetMember {
	netIP := net.IP(ipPortProto.ip[:])
	member := ipsetmember.MakeIPPortProto(
		ip.FromNetIP(netIP),
		uint16(ipPortProto.port),
		ipsetmember.Protocol(ipPortProto.proto),
	)
	return member
}

func getIpSetPortMemberFromPortProto(portProto portProtoKey, family int) ipsetmember.IPSetMember {
	return ipsetmember.MakePortOnly(uint16(portProto.port), family)
}

func hasAnnotation(annotations map[string]string, annotation string) bool {
	if annotations != nil {
		if value, ok := annotations[annotation]; ok {
			return value == "true"
		}
	}

	return false
}
