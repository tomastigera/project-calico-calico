// Copyright (c) 2016-2017,2020-2021 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package calc

import (
	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	kapiv1 "k8s.io/api/core/v1"

	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	cresources "github.com/projectcalico/calico/libcalico-go/lib/resources"
)

// DataplanePassthru passes through some datamodel updates to the dataplane layer, removing some
// duplicates along the way.  It maps OnUpdate() calls to dedicated method calls for consistency
// with the rest of the dataplane API.
type DataplanePassthru struct {
	ipv6Support bool
	callbacks   passthruCallbacks

	hostIPs   map[string]*net.IP
	hostIPv6s map[string]*net.IP

	remoteIPPools map[string]*model.KVPair
}

func NewDataplanePassthru(callbacks passthruCallbacks, ipv6Support bool) *DataplanePassthru {
	return &DataplanePassthru{
		ipv6Support:   ipv6Support,
		callbacks:     callbacks,
		hostIPs:       map[string]*net.IP{},
		hostIPv6s:     map[string]*net.IP{},
		remoteIPPools: map[string]*model.KVPair{},
	}
}

func (h *DataplanePassthru) RegisterWith(dispatcher *dispatcher.Dispatcher) {
	dispatcher.Register(model.HostIPKey{}, h.OnUpdate)
	dispatcher.Register(model.IPPoolKey{}, h.OnUpdate)
	dispatcher.Register(model.WireguardKey{}, h.OnUpdate)
	dispatcher.Register(model.ResourceKey{}, h.OnUpdate)
	dispatcher.Register(model.RemoteClusterResourceKey{}, h.OnUpdate)
}

func (h *DataplanePassthru) OnUpdate(update api.Update) (filterOut bool) {
	switch key := update.Key.(type) {
	case model.HostIPKey:
		hostname := key.Hostname
		if update.Value == nil {
			log.WithField("update", update).Debug("Passing-through HostIP deletion")
			delete(h.hostIPs, hostname)
			h.callbacks.OnHostIPRemove(hostname)
		} else {
			ip := update.Value.(*net.IP)
			oldIP := h.hostIPs[hostname]
			// libcalico-go's IP struct wraps a standard library IP struct.  To
			// compare two IPs, we need to unwrap them and use Equal() since standard
			// library IPs have multiple, equivalent, representations.
			if oldIP != nil && ip.Equal(oldIP.IP) {
				log.WithField("update", update).Debug("Ignoring duplicate HostIP update")
				return
			}
			log.WithField("update", update).Debug("Passing-through HostIP update")
			h.hostIPs[hostname] = ip
			h.callbacks.OnHostIPUpdate(hostname, ip)
		}
	case model.IPPoolKey:
		if update.Value == nil {
			log.WithField("update", update).Debug("Passing-through IPPool deletion")
			h.callbacks.OnIPPoolRemove(key)
		} else {
			log.WithField("update", update).Debug("Passing-through IPPool update")
			pool := update.Value.(*model.IPPool)
			h.callbacks.OnIPPoolUpdate(key, pool)
		}
	case model.WireguardKey:
		if update.Value == nil {
			log.WithField("update", update).Debug("Passing-through Wireguard deletion")
			h.callbacks.OnWireguardRemove(key.NodeName)
		} else {
			log.WithField("update", update).Debug("Passing-through Wireguard update")
			wg := update.Value.(*model.Wireguard)
			h.callbacks.OnWireguardUpdate(key.NodeName, wg)
		}
	case model.ResourceKey:
		if key.Kind == v3.KindBGPConfiguration && key.Name == "default" {
			log.WithField("update", update).Debug("Passing through global BGPConfiguration")
			bgpConfig, _ := update.Value.(*v3.BGPConfiguration)
			h.callbacks.OnGlobalBGPConfigUpdate(bgpConfig)
		} else if key.Kind == v3.KindExternalNetwork {
			log.WithField("update", update).Debug("Passing through external network")
			id := proto.ExternalNetworkID{Name: key.Name}
			if update.Value == nil {
				h.callbacks.OnExternalNetworkRemove(&proto.ExternalNetworkRemove{Id: &id})
			} else {
				var routeTableIndex uint32
				externalNetwork, _ := update.Value.(*v3.ExternalNetwork)
				if externalNetwork.Spec.RouteTableIndex != nil {
					routeTableIndex = *externalNetwork.Spec.RouteTableIndex
				}
				network := proto.ExternalNetwork{
					Name:            key.Name,
					RouteTableIndex: routeTableIndex,
				}
				h.callbacks.OnExternalNetworkUpdate(&proto.ExternalNetworkUpdate{Id: &id, Network: &network})
			}
		} else if key.Kind == model.KindKubernetesService {
			log.WithField("update", update).Debug("Passing through a Service")
			if update.Value == nil {
				h.callbacks.OnServiceRemove(&proto.ServiceRemove{Name: key.Name, Namespace: key.Namespace})
			} else {
				h.callbacks.OnServiceUpdate(kubernetesServiceToProto(update.Value.(*kapiv1.Service)))
			}
		} else if key.Kind == internalapi.KindNode {
			// Handle node resource to pass-through HostMetadataV6Update/HostMetadataV6Remove messages
			// with IPv6 node address updates. IPv4 updates are handled above my model.HostIPKey updates.
			log.WithField("update", update).Debug("Passing-through a Node IPv6 address update")
			log.WithField("update", update).Debug("Passing-through a Node update")
			hostname := key.Name
			if update.Value == nil {
				log.WithField("update", update).Debug("Passing-through Node IPv6 address remove")
				delete(h.hostIPv6s, hostname)
				h.callbacks.OnHostIPv6Remove(hostname)
				log.WithField("update", update).Debug("Passing-through Node remove")
				h.callbacks.OnHostMetadataRemove(hostname)
			} else {
				node, _ := update.Value.(*internalapi.Node)
				log.WithField("update", update).Debug("Passing-through Node update")
				bgpIp4net := &net.IPNet{} // required for print in event sequencer
				bgpIp6net := &net.IPNet{} // required for print in event sequencer
				asnumber := ""

				lbMaintenance := proto.LoadbalancerMaintenance_LB_MAINT_NONE
				if node.Spec.LoadBalancer != nil && node.Spec.LoadBalancer.Maintenance == internalapi.NodeLBMaintenanceExcludeLocalBackends {
					lbMaintenance = proto.LoadbalancerMaintenance_LB_MAINT_EXCLUDE_LOCAL_BACKENDS
				}

				if node.Spec.BGP != nil {
					ip4, ip4net, _ := net.ParseCIDR(node.Spec.BGP.IPv4Address)
					ip6, ip6net, _ := net.ParseCIDR(node.Spec.BGP.IPv6Address)
					if ip4net != nil {
						ip4net.IP = ip4.IP
						bgpIp4net = ip4net
					}
					if ip6net != nil {
						ip6net.IP = ip6.IP
						bgpIp6net = ip6net
					}
					if node.Spec.BGP.ASNumber != nil {
						asnumber = node.Spec.BGP.ASNumber.String()
					}
				}
				h.callbacks.OnHostMetadataUpdate(hostname, bgpIp4net, bgpIp6net, asnumber, lbMaintenance, node.Labels)
				if node.Spec.BGP != nil {
					if node.Spec.BGP.IPv6Address != "" {
						ip, _, _ := net.ParseCIDR(node.Spec.BGP.IPv6Address)
						oldIP := h.hostIPv6s[hostname]
						if oldIP != nil && ip.Equal(oldIP.IP) {
							log.WithField("update", update).Debug("Ignoring duplicate Node IPv6 address update")
							return
						}
						log.WithField("update", update).Debug("Passing-through Node IPv6 address update")
						h.hostIPv6s[hostname] = ip
						h.callbacks.OnHostIPv6Update(hostname, ip)
					} else if h.hostIPv6s[hostname] != nil {
						log.WithField("update", update).Debug("Passing-through Node IPv6 address remove")
						delete(h.hostIPv6s, hostname)
						h.callbacks.OnHostIPv6Remove(hostname)
					}
				}

				if h.ipv6Support && node.Spec.BGP == nil {
					// BGP is turned off, try to get one from the node resource. This is a
					// similar fallback as for IPv4, see how HostIPKey is generated in
					// libcalico-go/lib/backend/syncersv1/updateprocessors/felixnodeprocessor.go
					var ip *net.IP
					ip, _ = cresources.FindNodeAddress(node, internalapi.InternalIP, 6)
					if ip == nil {
						ip, _ = cresources.FindNodeAddress(node, internalapi.ExternalIP, 6)
					}
					if ip != nil {
						oldIP := h.hostIPv6s[hostname]
						if oldIP != nil && ip.Equal(oldIP.IP) {
							log.WithField("update", update).Debug("Ignoring duplicate Node IPv6 address update")
							return
						}
						log.WithField("update", update).Debug("Passing-through Node IPv6 address update")
						h.hostIPv6s[hostname] = ip
						h.callbacks.OnHostIPv6Update(hostname, ip)
					} else if h.hostIPv6s[hostname] != nil {
						log.WithField("update", update).Debug("Passing-through Node IPv6 address remove")
						delete(h.hostIPv6s, hostname)
						h.callbacks.OnHostIPv6Remove(hostname)
					}
				}
			}
		} else {
			log.WithField("key", key).Debugf("Ignoring v3 resource of kind %s", key.Kind)
		}
	case model.RemoteClusterResourceKey:
		if key.Kind == v3.KindIPPool {
			cluster := key.Cluster
			cacheKey := getRemoteClusterAwareKeyString(update)
			oldV1KVP := h.remoteIPPools[cacheKey]
			if update.Value == nil {
				log.WithField("update", update).Debug("Passing-through remote IPPool deletion")
				if oldV1KVP != nil {
					h.callbacks.OnRemoteIPPoolRemove(cluster, oldV1KVP.Key.(model.IPPoolKey))
					delete(h.remoteIPPools, cacheKey)
				}
			} else {
				log.WithField("update", update).Debug("Passing-through remote IPPool update")
				newV1KVP, err := resources.IPPoolV3ToV1(&update.KVPair)
				if err != nil {
					log.WithError(err).Panic("Failed to convert v3 IPPool to v1")
				}

				// If the v1 key differs, we must issue a delete.
				// This can happen when the CIDR changes: the v3 key stays the same, but the v1 key changes.
				if oldV1KVP != nil && oldV1KVP.Key.String() != newV1KVP.Key.String() {
					log.WithField("update", update).Debug("Issuing remote IPPool delete due to v1 key change")
					h.callbacks.OnRemoteIPPoolRemove(cluster, oldV1KVP.Key.(model.IPPoolKey))
				}

				h.remoteIPPools[cacheKey] = newV1KVP
				h.callbacks.OnRemoteIPPoolUpdate(cluster, newV1KVP.Key.(model.IPPoolKey), newV1KVP.Value.(*model.IPPool))
			}
		} else {
			log.WithField("key", key).Debugf("Ignoring remote v3 resource of kind %s", key.Kind)
		}
	}
	return
}

func kubernetesServiceToProto(s *kapiv1.Service) *proto.ServiceUpdate {
	up := &proto.ServiceUpdate{
		Name:           s.Name,
		Namespace:      s.Namespace,
		Type:           string(s.Spec.Type),
		ClusterIps:     s.Spec.ClusterIPs,
		LoadbalancerIp: s.Spec.LoadBalancerIP,
		ExternalIps:    s.Spec.ExternalIPs,
	}

	ports := make([]*proto.ServicePort, 0, len(s.Spec.Ports))

	protoGet := func(kp kapiv1.Protocol) string {
		switch kp {
		case kapiv1.ProtocolUDP:
			return "UDP"
		case kapiv1.ProtocolSCTP:
			return "SCTP"
		}

		return "TCP"
	}

	for _, p := range s.Spec.Ports {
		ports = append(ports, &proto.ServicePort{
			Protocol: protoGet(p.Protocol),
			Port:     p.Port,
			NodePort: p.NodePort,
		})
	}

	up.Ports = ports

	return up
}
