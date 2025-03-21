// Copyright (c) 2016-2024 Tigera, Inc. All rights reserved.
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
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/labelindex"
	"github.com/projectcalico/calico/felix/multidict"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type EventHandler func(message interface{})

type configInterface interface {
	UpdateFrom(map[string]string, config.Source) (changed bool, err error)
	RawValues() map[string]string
	ToConfigUpdate() *proto.ConfigUpdate
}

// Struct for additional data that feeds into proto.WorkloadEndpoint but is computed rather than
// taken directly from model.WorkloadEndpoint.  Currently this is all related to egress IP function.
// (It could be generalised in future, and so perhaps renamed EndpointComputedData.)
type EndpointEgressData struct {
	// The egress IP set for this endpoint. This is non-empty when an active local endpoint is
	// configured to use egress gateways.
	EgressGatewayRules []EpEgressData

	// Whether this endpoint _is_ an egress gateway.
	IsEgressGateway bool

	// Health port of the EGW or 0 if EGW has none.
	HealthPort uint16
}

func (e EndpointEgressData) IsEmpty() bool {
	if e.IsEgressGateway || e.HealthPort != 0 {
		return false
	}
	if len(e.EgressGatewayRules) != 0 {
		return false
	}
	return true
}

// EndpointUpdate contains information about updates applied to the endpoint.
type endpointUpdate struct {
	endpoint   interface{}
	peerData   *EndpointBGPPeer
	egressData EndpointEgressData
	tierInfo   []TierInfo
}

// EventSequencer buffers and coalesces updates from the calculation graph then flushes them
// when Flush() is called.  It flushed updates in a dependency-safe order.
type EventSequencer struct {
	config configInterface

	// Buffers used to hold data that we haven't flushed yet so we can coalesce multiple
	// updates and generate updates in dependency order.
	pendingAddedIPSets            map[string]proto.IPSetUpdate_IPSetType
	pendingRemovedIPSets          set.Set[string]
	pendingAddedIPSetMembers      multidict.Multidict[string, labelindex.IPSetMember]
	pendingRemovedIPSetMembers    multidict.Multidict[string, labelindex.IPSetMember]
	pendingPolicyUpdates          map[model.PolicyKey]*ParsedRules
	pendingPolicyDeletes          set.Set[model.PolicyKey]
	pendingProfileUpdates         map[model.ProfileRulesKey]*ParsedRules
	pendingProfileDeletes         set.Set[model.ProfileRulesKey]
	pendingEncapUpdate            *config.Encapsulation
	pendingEndpointUpdates        map[model.Key]endpointUpdate
	pendingEndpointDeletes        set.Set[model.Key]
	pendingHostIPUpdates          map[string]*net.IP
	pendingHostIPDeletes          set.Set[string]
	pendingHostIPv6Updates        map[string]*net.IP
	pendingHostIPv6Deletes        set.Set[string]
	pendingHostMetadataUpdates    map[string]*hostInfo
	pendingHostMetadataDeletes    set.Set[string]
	pendingIPPoolUpdates          map[ip.CIDR]*model.IPPool
	pendingIPPoolDeletes          set.Set[ip.CIDR]
	pendingNotReady               bool
	pendingGlobalConfig           map[string]string
	pendingHostConfig             map[string]string
	pendingServiceAccountUpdates  map[types.ServiceAccountID]*proto.ServiceAccountUpdate
	pendingServiceAccountDeletes  set.Set[types.ServiceAccountID]
	pendingNamespaceUpdates       map[types.NamespaceID]*proto.NamespaceUpdate
	pendingNamespaceDeletes       set.Set[types.NamespaceID]
	pendingRouteUpdates           map[routeID]*proto.RouteUpdate
	pendingRouteDeletes           set.Set[routeID]
	pendingVTEPUpdates            map[string]*proto.VXLANTunnelEndpointUpdate
	pendingVTEPDeletes            set.Set[string]
	pendingIPSecTunnelAdds        set.Set[ip.Addr]
	pendingIPSecTunnelRemoves     set.Set[ip.Addr]
	pendingIPSecBindingAdds       set.Set[IPSecBinding]
	pendingIPSecBindingRemoves    set.Set[IPSecBinding]
	pendingIPSecBlacklistAdds     set.Set[ip.Addr]
	pendingIPSecBlacklistRemoves  set.Set[ip.Addr]
	pendingWireguardUpdates       map[string]*model.Wireguard
	pendingWireguardDeletes       set.Set[string]
	pendingGlobalBGPConfig        *proto.GlobalBGPConfigUpdate
	pendingExternalNetworkUpdates map[types.ExternalNetworkID]*proto.ExternalNetworkUpdate
	pendingExternalNetworkDeletes set.Set[types.ExternalNetworkID]
	pendingPacketCaptureUpdates   map[string]*proto.PacketCaptureUpdate
	pendingPacketCaptureRemovals  map[string]*proto.PacketCaptureRemove
	pendingServiceUpdates         map[serviceID]*proto.ServiceUpdate
	pendingServiceDeletes         set.Set[serviceID]
	pendingRemoteIPPools          map[remotePoolID]*proto.RemoteIPAMPoolUpdate
	pendingRemoteIPPoolRemovals   set.Set[remotePoolID]

	// Sets to record what we've sent downstream. Updated whenever we flush.
	sentIPSets           set.Set[string]
	sentPolicies         set.Set[model.PolicyKey]
	sentProfiles         set.Set[model.ProfileRulesKey]
	sentEndpoints        set.Set[model.Key]
	sentHostIPs          set.Set[string]
	sentHostIPv6s        set.Set[string]
	sentHosts            set.Set[string]
	sentIPPools          set.Set[ip.CIDR]
	sentServiceAccounts  set.Set[types.ServiceAccountID]
	sentNamespaces       set.Set[types.NamespaceID]
	sentRoutes           set.Set[routeID]
	sentVTEPs            set.Set[string]
	sentWireguard        set.Set[string]
	sentWireguardV6      set.Set[string]
	sentServices         set.Set[serviceID]
	sentExternalNetworks set.Set[types.ExternalNetworkID]
	sentRemoteIPPools    set.Set[remotePoolID]

	// Enterprise-only fields.
	sentPacketCapture set.Set[string]

	Callback EventHandler
}

type hostInfo struct {
	ip4Addr  *net.IPNet
	ip6Addr  *net.IPNet
	labels   map[string]string
	asnumber string
}

type serviceID struct {
	Name      string
	Namespace string
}

type remotePoolID struct {
	cluster string
	cidr    ip.CIDR
}

// func (buf *EventSequencer) HasPendingUpdates() {
//	return buf.pendingAddedIPSets.Len() > 0 ||
//		buf.pendingRemovedIPSets.Len() > 0 ||
//		buf.pendingAddedIPSetMembers.Len() > 0 ||
//		buf.pendingRemovedIPSetMembers.Len() > 0 ||
//		len(buf.pendingPolicyUpdates) > 0 ||
//		buf.pendingPolicyDeletes.Len() > 0 ||
//
// }

func NewEventSequencer(conf configInterface) *EventSequencer {
	buf := &EventSequencer{
		config:                     conf,
		pendingAddedIPSets:         map[string]proto.IPSetUpdate_IPSetType{},
		pendingRemovedIPSets:       set.New[string](),
		pendingAddedIPSetMembers:   multidict.New[string, labelindex.IPSetMember](),
		pendingRemovedIPSetMembers: multidict.New[string, labelindex.IPSetMember](),

		pendingPolicyUpdates:          map[model.PolicyKey]*ParsedRules{},
		pendingPolicyDeletes:          set.New[model.PolicyKey](),
		pendingProfileUpdates:         map[model.ProfileRulesKey]*ParsedRules{},
		pendingProfileDeletes:         set.New[model.ProfileRulesKey](),
		pendingEndpointUpdates:        map[model.Key]endpointUpdate{},
		pendingEndpointDeletes:        set.New[model.Key](),
		pendingHostIPUpdates:          map[string]*net.IP{},
		pendingHostIPDeletes:          set.New[string](),
		pendingHostIPv6Updates:        map[string]*net.IP{},
		pendingHostIPv6Deletes:        set.New[string](),
		pendingHostMetadataUpdates:    map[string]*hostInfo{},
		pendingHostMetadataDeletes:    set.New[string](),
		pendingIPPoolUpdates:          map[ip.CIDR]*model.IPPool{},
		pendingIPPoolDeletes:          set.New[ip.CIDR](),
		pendingServiceAccountUpdates:  map[types.ServiceAccountID]*proto.ServiceAccountUpdate{},
		pendingServiceAccountDeletes:  set.New[types.ServiceAccountID](),
		pendingNamespaceUpdates:       map[types.NamespaceID]*proto.NamespaceUpdate{},
		pendingNamespaceDeletes:       set.New[types.NamespaceID](),
		pendingRouteUpdates:           map[routeID]*proto.RouteUpdate{},
		pendingRouteDeletes:           set.New[routeID](),
		pendingVTEPUpdates:            map[string]*proto.VXLANTunnelEndpointUpdate{},
		pendingVTEPDeletes:            set.New[string](),
		pendingIPSecTunnelAdds:        set.New[ip.Addr](),
		pendingIPSecTunnelRemoves:     set.New[ip.Addr](),
		pendingIPSecBindingAdds:       set.New[IPSecBinding](),
		pendingIPSecBindingRemoves:    set.New[IPSecBinding](),
		pendingIPSecBlacklistAdds:     set.New[ip.Addr](),
		pendingIPSecBlacklistRemoves:  set.New[ip.Addr](),
		pendingWireguardUpdates:       map[string]*model.Wireguard{},
		pendingWireguardDeletes:       set.New[string](),
		pendingPacketCaptureUpdates:   map[string]*proto.PacketCaptureUpdate{},
		pendingPacketCaptureRemovals:  map[string]*proto.PacketCaptureRemove{},
		pendingServiceUpdates:         map[serviceID]*proto.ServiceUpdate{},
		pendingServiceDeletes:         set.New[serviceID](),
		pendingExternalNetworkUpdates: map[types.ExternalNetworkID]*proto.ExternalNetworkUpdate{},
		pendingExternalNetworkDeletes: set.New[types.ExternalNetworkID](),
		pendingRemoteIPPools:          map[remotePoolID]*proto.RemoteIPAMPoolUpdate{},
		pendingRemoteIPPoolRemovals:   set.New[remotePoolID](),

		// Sets to record what we've sent downstream. Updated whenever we flush.
		sentIPSets:           set.New[string](),
		sentPolicies:         set.New[model.PolicyKey](),
		sentProfiles:         set.New[model.ProfileRulesKey](),
		sentEndpoints:        set.New[model.Key](),
		sentHostIPs:          set.New[string](),
		sentHostIPv6s:        set.New[string](),
		sentHosts:            set.New[string](),
		sentIPPools:          set.New[ip.CIDR](),
		sentServiceAccounts:  set.New[types.ServiceAccountID](),
		sentNamespaces:       set.New[types.NamespaceID](),
		sentRoutes:           set.New[routeID](),
		sentVTEPs:            set.New[string](),
		sentWireguard:        set.New[string](),
		sentWireguardV6:      set.New[string](),
		sentServices:         set.New[serviceID](),
		sentPacketCapture:    set.New[string](),
		sentExternalNetworks: set.New[types.ExternalNetworkID](),
		sentRemoteIPPools:    set.New[remotePoolID](),
	}
	return buf
}

type routeID struct {
	dst string
}

func (buf *EventSequencer) OnIPSetAdded(setID string, ipSetType proto.IPSetUpdate_IPSetType) {
	log.Debugf("IP set %v now active", setID)
	sent := buf.sentIPSets.Contains(setID)
	removePending := buf.pendingRemovedIPSets.Contains(setID)
	if sent && !removePending {
		log.Panic("OnIPSetAdded called for existing IP set")
	}
	buf.pendingAddedIPSets[setID] = ipSetType
	buf.pendingRemovedIPSets.Discard(setID)
	// An add implicitly means that the set is now empty.
	buf.pendingAddedIPSetMembers.DiscardKey(setID)
	buf.pendingRemovedIPSetMembers.DiscardKey(setID)
}

func (buf *EventSequencer) OnIPSetRemoved(setID string) {
	log.Debugf("IP set %v no longer active", setID)
	sent := buf.sentIPSets.Contains(setID)
	_, updatePending := buf.pendingAddedIPSets[setID]
	if !sent && !updatePending {
		log.WithField("setID", setID).Panic("IPSetRemoved called for unknown IP set")
	}
	if sent {
		buf.pendingRemovedIPSets.Add(setID)
	}
	delete(buf.pendingAddedIPSets, setID)
	buf.pendingAddedIPSetMembers.DiscardKey(setID)
	buf.pendingRemovedIPSetMembers.DiscardKey(setID)
}

func (buf *EventSequencer) OnIPSetMemberAdded(setID string, member labelindex.IPSetMember) {
	log.Debugf("IP set %v now contains %v", setID, member)
	sent := buf.sentIPSets.Contains(setID)
	_, updatePending := buf.pendingAddedIPSets[setID]
	if !sent && !updatePending {
		log.WithField("setID", setID).Panic("Member added to unknown IP set")
	}
	if buf.pendingRemovedIPSetMembers.Contains(setID, member) {
		buf.pendingRemovedIPSetMembers.Discard(setID, member)
	} else {
		buf.pendingAddedIPSetMembers.Put(setID, member)
	}
}

func (buf *EventSequencer) OnIPSetMemberRemoved(setID string, member labelindex.IPSetMember) {
	log.Debugf("IP set %v no longer contains %v", setID, member)
	sent := buf.sentIPSets.Contains(setID)
	_, updatePending := buf.pendingAddedIPSets[setID]
	if !sent && !updatePending {
		log.WithField("setID", setID).Panic("Member removed from unknown IP set")
	}
	if buf.pendingAddedIPSetMembers.Contains(setID, member) {
		buf.pendingAddedIPSetMembers.Discard(setID, member)
	} else {
		buf.pendingRemovedIPSetMembers.Put(setID, member)
	}
}

func (buf *EventSequencer) OnDatastoreNotReady() {
	buf.pendingNotReady = true
}

func (buf *EventSequencer) flushReadyFlag() {
	if !buf.pendingNotReady {
		return
	}
	buf.pendingNotReady = false
	buf.Callback(&DatastoreNotReady{})
}

type DatastoreNotReady struct{}

func (buf *EventSequencer) OnConfigUpdate(globalConfig, hostConfig map[string]string) {
	buf.pendingGlobalConfig = globalConfig
	buf.pendingHostConfig = hostConfig
}

func (buf *EventSequencer) flushConfigUpdate() {
	if buf.pendingGlobalConfig == nil {
		return
	}
	logCxt := log.WithFields(log.Fields{
		"global": buf.pendingGlobalConfig,
		"host":   buf.pendingHostConfig,
	})
	logCxt.Info("Possible config update.")
	globalChanged, err := buf.config.UpdateFrom(buf.pendingGlobalConfig, config.DatastoreGlobal)
	if err != nil {
		logCxt.WithError(err).Panic("Failed to parse config update")
	}
	hostChanged, err := buf.config.UpdateFrom(buf.pendingHostConfig, config.DatastorePerHost)
	if err != nil {
		logCxt.WithError(err).Panic("Failed to parse config update")
	}
	if globalChanged || hostChanged {
		rawConfig := buf.config.RawValues()
		log.WithField("merged", rawConfig).Info("Config changed. Sending ConfigUpdate message.")
		buf.Callback(buf.config.ToConfigUpdate())
	}
	buf.pendingGlobalConfig = nil
	buf.pendingHostConfig = nil
}

func (buf *EventSequencer) OnPolicyActive(key model.PolicyKey, rules *ParsedRules) {
	buf.pendingPolicyDeletes.Discard(key)
	buf.pendingPolicyUpdates[key] = rules
}

func (buf *EventSequencer) flushPolicyUpdates() {
	for key, rules := range buf.pendingPolicyUpdates {
		buf.Callback(ParsedRulesToActivePolicyUpdate(key, rules))
		buf.sentPolicies.Add(key)
		delete(buf.pendingPolicyUpdates, key)
	}
}

func ParsedRulesToActivePolicyUpdate(key model.PolicyKey, rules *ParsedRules) *proto.ActivePolicyUpdate {
	return &proto.ActivePolicyUpdate{
		Id: &proto.PolicyID{
			Tier: key.Tier,
			Name: key.Name,
		},
		Policy: &proto.Policy{
			Namespace: rules.Namespace,
			InboundRules: parsedRulesToProtoRules(
				rules.InboundRules,
				"pol-in-default/"+key.Name,
			),
			OutboundRules: parsedRulesToProtoRules(
				rules.OutboundRules,
				"pol-out-default/"+key.Name,
			),
			Untracked:        rules.Untracked,
			PreDnat:          rules.PreDNAT,
			OriginalSelector: rules.OriginalSelector,
		},
	}
}

func (buf *EventSequencer) OnPolicyInactive(key model.PolicyKey) {
	delete(buf.pendingPolicyUpdates, key)
	if buf.sentPolicies.Contains(key) {
		buf.pendingPolicyDeletes.Add(key)
	}
}

func (buf *EventSequencer) flushPolicyDeletes() {
	buf.pendingPolicyDeletes.Iter(func(item model.PolicyKey) error {
		buf.Callback(&proto.ActivePolicyRemove{
			Id: &proto.PolicyID{
				Tier: item.Tier,
				Name: item.Name,
			},
		})
		buf.sentPolicies.Discard(item)
		return set.RemoveItem
	})
}

func (buf *EventSequencer) OnProfileActive(key model.ProfileRulesKey, rules *ParsedRules) {
	buf.pendingProfileDeletes.Discard(key)
	buf.pendingProfileUpdates[key] = rules
}

func (buf *EventSequencer) flushProfileUpdates() {
	for key, rulesOrNil := range buf.pendingProfileUpdates {
		buf.Callback(&proto.ActiveProfileUpdate{
			Id: &proto.ProfileID{
				Name: key.Name,
			},
			Profile: &proto.Profile{
				InboundRules: parsedRulesToProtoRules(
					rulesOrNil.InboundRules,
					"prof-in-"+key.Name,
				),
				OutboundRules: parsedRulesToProtoRules(
					rulesOrNil.OutboundRules,
					"prof-out-"+key.Name,
				),
			},
		})
		buf.sentProfiles.Add(key)
		delete(buf.pendingProfileUpdates, key)
	}
}

func (buf *EventSequencer) OnProfileInactive(key model.ProfileRulesKey) {
	delete(buf.pendingProfileUpdates, key)
	if buf.sentProfiles.Contains(key) {
		buf.pendingProfileDeletes.Add(key)
	}
}

func (buf *EventSequencer) flushProfileDeletes() {
	buf.pendingProfileDeletes.Iter(func(item model.ProfileRulesKey) error {
		buf.Callback(&proto.ActiveProfileRemove{
			Id: &proto.ProfileID{
				Name: item.Name,
			},
		})
		buf.sentProfiles.Discard(item)
		return set.RemoveItem
	})
}

func ModelWorkloadEndpointToProto(ep *model.WorkloadEndpoint, egressData EndpointEgressData, peerData *EndpointBGPPeer, tiers []*proto.TierInfo) *proto.WorkloadEndpoint {
	mac := ""
	if ep.Mac != nil {
		mac = ep.Mac.String()
	}
	var qosControls *proto.QoSControls
	if ep.QoSControls != nil {
		qosControls = &proto.QoSControls{
			IngressBandwidth:      ep.QoSControls.IngressBandwidth,
			EgressBandwidth:       ep.QoSControls.EgressBandwidth,
			IngressBurst:          ep.QoSControls.IngressBurst,
			EgressBurst:           ep.QoSControls.EgressBurst,
			IngressPacketRate:     ep.QoSControls.IngressPacketRate,
			EgressPacketRate:      ep.QoSControls.EgressPacketRate,
			IngressMaxConnections: ep.QoSControls.IngressMaxConnections,
			EgressMaxConnections:  ep.QoSControls.EgressMaxConnections,
		}
	}

	var egressGatewayRules []*proto.EgressGatewayRule
	egressGatewayHealthPort := int32(egressData.HealthPort)
	isEgressGateway := egressData.IsEgressGateway
	// To break gatewaying loops, we do not allow a workload to route
	// via egress gateways if it is _itself_ an egress gateway.
	if !isEgressGateway {
		for _, r := range egressData.EgressGatewayRules {
			egressRule := proto.EgressGatewayRule{
				IpSetId:                  r.IpSetID,
				MaxNextHops:              int32(r.MaxNextHops),
				Destination:              r.CIDR,
				PreferLocalEgressGateway: r.PreferLocalGW,
			}
			egressGatewayRules = append(egressGatewayRules, &egressRule)
		}
	}

	var localBGPPeer *proto.LocalBGPPeer
	if peerData != nil {
		localBGPPeer = &proto.LocalBGPPeer{
			BgpPeerName: peerData.v3PeerName,
		}
	}

	return &proto.WorkloadEndpoint{
		State:                      ep.State,
		Name:                       ep.Name,
		Mac:                        mac,
		ProfileIds:                 ep.ProfileIDs,
		Ipv4Nets:                   netsToStrings(ep.IPv4Nets),
		Ipv6Nets:                   netsToStrings(ep.IPv6Nets),
		Tiers:                      tiers,
		Ipv4Nat:                    natsToProtoNatInfo(ep.IPv4NAT),
		Ipv6Nat:                    natsToProtoNatInfo(ep.IPv6NAT),
		AllowSpoofedSourcePrefixes: netsToStrings(ep.AllowSpoofedSourcePrefixes),
		Annotations:                ep.Annotations,
		AwsElasticIps:              ep.AWSElasticIPs,
		ExternalNetworkNames:       ep.ExternalNetworkNames,
		ApplicationLayer:           appLayerToProtoAppLayer(ep.ApplicationLayer),
		QosControls:                qosControls,
		LocalBgpPeer:               localBGPPeer,
		IsEgressGateway:            isEgressGateway,
		EgressGatewayHealthPort:    egressGatewayHealthPort,
		EgressGatewayRules:         egressGatewayRules,
	}
}

func ModelHostEndpointToProto(ep *model.HostEndpoint, tiers, untrackedTiers, preDNATTiers []*proto.TierInfo, forwardTiers []*proto.TierInfo) *proto.HostEndpoint {
	return &proto.HostEndpoint{
		Name:              ep.Name,
		ExpectedIpv4Addrs: ipsToStrings(ep.ExpectedIPv4Addrs),
		ExpectedIpv6Addrs: ipsToStrings(ep.ExpectedIPv6Addrs),
		ProfileIds:        ep.ProfileIDs,
		Tiers:             tiers,
		UntrackedTiers:    untrackedTiers,
		PreDnatTiers:      preDNATTiers,
		ForwardTiers:      forwardTiers,
	}
}

func (buf *EventSequencer) OnEndpointTierUpdate(
	endpointKey model.EndpointKey,
	endpoint model.Endpoint,
	egressData EndpointEgressData,
	peerData *EndpointBGPPeer,
	filteredTiers []TierInfo,
) {
	if endpoint == nil {
		// Deletion. Squash any queued updates.
		delete(buf.pendingEndpointUpdates, endpointKey)
		if buf.sentEndpoints.Contains(endpointKey) {
			// We'd previously sent an update, so we need to send a deletion.
			buf.pendingEndpointDeletes.Add(endpointKey)
		}
	} else {
		// Update.
		buf.pendingEndpointDeletes.Discard(endpointKey)
		buf.pendingEndpointUpdates[endpointKey] = endpointUpdate{
			endpoint:   endpoint,
			peerData:   peerData,
			egressData: egressData,
			tierInfo:   filteredTiers,
		}
	}
}

func (buf *EventSequencer) flushEndpointTierUpdates() {
	for key, endpointUpdate := range buf.pendingEndpointUpdates {
		endpoint := endpointUpdate.endpoint

		tiers, untrackedTiers, preDNATTiers, forwardTiers := tierInfoToProtoTierInfo(endpointUpdate.tierInfo)
		switch key := key.(type) {

		case model.WorkloadEndpointKey:
			wlep := endpoint.(*model.WorkloadEndpoint)

			protoEp := ModelWorkloadEndpointToProto(wlep, endpointUpdate.egressData, endpointUpdate.peerData, tiers)

			buf.Callback(&proto.WorkloadEndpointUpdate{
				Id: &proto.WorkloadEndpointID{
					OrchestratorId: key.OrchestratorID,
					WorkloadId:     key.WorkloadID,
					EndpointId:     key.EndpointID,
				},
				Endpoint: protoEp,
			})

		case model.HostEndpointKey:
			hep := endpoint.(*model.HostEndpoint)
			buf.Callback(&proto.HostEndpointUpdate{
				Id: &proto.HostEndpointID{
					EndpointId: key.EndpointID,
				},
				Endpoint: ModelHostEndpointToProto(hep, tiers, untrackedTiers, preDNATTiers, forwardTiers),
			})
		}
		// Record that we've sent this endpoint.
		buf.sentEndpoints.Add(key)
		// And clean up the pending buffer.
		delete(buf.pendingEndpointUpdates, key)
	}
}

func (buf *EventSequencer) flushEndpointTierDeletes() {
	buf.pendingEndpointDeletes.Iter(func(item model.Key) error {
		switch key := item.(type) {
		case model.WorkloadEndpointKey:
			buf.Callback(&proto.WorkloadEndpointRemove{
				Id: &proto.WorkloadEndpointID{
					OrchestratorId: key.OrchestratorID,
					WorkloadId:     key.WorkloadID,
					EndpointId:     key.EndpointID,
				},
			})
		case model.HostEndpointKey:
			buf.Callback(&proto.HostEndpointRemove{
				Id: &proto.HostEndpointID{
					EndpointId: key.EndpointID,
				},
			})
		}
		buf.sentEndpoints.Discard(item)
		return set.RemoveItem
	})
}

func (buf *EventSequencer) OnEncapUpdate(encap config.Encapsulation) {
	log.WithFields(log.Fields{
		"IPIPEnabled":    encap.IPIPEnabled,
		"VXLANEnabled":   encap.VXLANEnabled,
		"VXLANEnabledV6": encap.VXLANEnabledV6,
	}).Debug("Encapsulation update")
	buf.pendingEncapUpdate = &encap
}

func (buf *EventSequencer) flushEncapUpdate() {
	if buf.pendingEncapUpdate != nil {
		buf.Callback(&proto.Encapsulation{
			IpipEnabled:    buf.pendingEncapUpdate.IPIPEnabled,
			VxlanEnabled:   buf.pendingEncapUpdate.VXLANEnabled,
			VxlanEnabledV6: buf.pendingEncapUpdate.VXLANEnabledV6,
		})
		buf.pendingEncapUpdate = nil
	}
}

func (buf *EventSequencer) OnHostIPUpdate(hostname string, ip *net.IP) {
	log.WithFields(log.Fields{
		"hostname": hostname,
		"ip":       ip,
	}).Debug("HostIP update")
	buf.pendingHostIPDeletes.Discard(hostname)
	buf.pendingHostIPUpdates[hostname] = ip
}

func (buf *EventSequencer) flushHostIPUpdates() {
	for hostname, hostIP := range buf.pendingHostIPUpdates {
		hostAddr := ""
		if hostIP != nil {
			hostAddr = hostIP.IP.String()
		}
		buf.Callback(&proto.HostMetadataUpdate{
			Hostname: hostname,
			Ipv4Addr: hostAddr,
		})
		buf.sentHostIPs.Add(hostname)
		delete(buf.pendingHostIPUpdates, hostname)
	}
}

func (buf *EventSequencer) OnHostIPRemove(hostname string) {
	log.WithField("hostname", hostname).Debug("HostIP removed")
	delete(buf.pendingHostIPUpdates, hostname)
	if buf.sentHostIPs.Contains(hostname) {
		buf.pendingHostIPDeletes.Add(hostname)
	}
}

func (buf *EventSequencer) flushHostIPDeletes() {
	buf.pendingHostIPDeletes.Iter(func(item string) error {
		buf.Callback(&proto.HostMetadataRemove{
			Hostname: item,
		})
		buf.sentHostIPs.Discard(item)
		return set.RemoveItem
	})
}

func (buf *EventSequencer) OnHostIPv6Update(hostname string, ip *net.IP) {
	log.WithFields(log.Fields{
		"hostname": hostname,
		"ip":       ip,
	}).Debug("Host IPv6 update")
	buf.pendingHostIPv6Deletes.Discard(hostname)
	buf.pendingHostIPv6Updates[hostname] = ip
}

func (buf *EventSequencer) flushHostIPv6Updates() {
	for hostname, hostIP := range buf.pendingHostIPv6Updates {
		hostIPv6Addr := ""
		if hostIP != nil {
			hostIPv6Addr = hostIP.IP.String()
		}
		buf.Callback(&proto.HostMetadataV6Update{
			Hostname: hostname,
			Ipv6Addr: hostIPv6Addr,
		})
		buf.sentHostIPv6s.Add(hostname)
		delete(buf.pendingHostIPv6Updates, hostname)
	}
}

func (buf *EventSequencer) OnHostIPv6Remove(hostname string) {
	log.WithField("hostname", hostname).Debug("Host IPv6 removed")
	delete(buf.pendingHostIPv6Updates, hostname)
	if buf.sentHostIPv6s.Contains(hostname) {
		buf.pendingHostIPv6Deletes.Add(hostname)
	}
}

func (buf *EventSequencer) flushHostIPv6Deletes() {
	buf.pendingHostIPv6Deletes.Iter(func(item string) error {
		buf.Callback(&proto.HostMetadataV6Remove{
			Hostname: item,
		})
		buf.sentHostIPv6s.Discard(item)
		return set.RemoveItem
	})
}

func (buf *EventSequencer) OnHostMetadataUpdate(hostname string, ip4 *net.IPNet, ip6 *net.IPNet, asnumber string, labels map[string]string) {
	log.WithFields(log.Fields{
		"hostname": hostname,
		"ip4":      ip4,
		"ip6":      ip6,
		"labels":   labels,
		"asnumber": asnumber,
	}).Debug("Host update")
	buf.pendingHostMetadataDeletes.Discard(hostname)
	buf.pendingHostMetadataUpdates[hostname] = &hostInfo{ip4Addr: ip4, ip6Addr: ip6, labels: labels, asnumber: asnumber}
}

func (buf *EventSequencer) flushHostUpdates() {
	for hostname, hostInfo := range buf.pendingHostMetadataUpdates {
		var ip4str, ip6str string
		if hostInfo.ip4Addr.IP != nil {
			ip4str = hostInfo.ip4Addr.String()
		}
		if hostInfo.ip6Addr.IP != nil {
			ip6str = hostInfo.ip6Addr.String()
		}
		buf.Callback(&proto.HostMetadataV4V6Update{
			Hostname: hostname,
			Ipv4Addr: ip4str,
			Ipv6Addr: ip6str,
			Asnumber: hostInfo.asnumber,
			Labels:   hostInfo.labels,
		})
		buf.sentHosts.Add(hostname)
		delete(buf.pendingHostMetadataUpdates, hostname)
	}
}

func (buf *EventSequencer) OnHostMetadataRemove(hostname string) {
	log.WithField("hostname", hostname).Debug("Host removed")
	delete(buf.pendingHostMetadataUpdates, hostname)
	if buf.sentHosts.Contains(hostname) {
		buf.pendingHostMetadataDeletes.Add(hostname)
	}
}

func (buf *EventSequencer) flushHostDeletes() {
	buf.pendingHostMetadataDeletes.Iter(func(item string) error {
		buf.Callback(&proto.HostMetadataV4V6Remove{
			Hostname: item,
		})
		buf.sentHosts.Discard(item)
		return set.RemoveItem
	})
}

func (buf *EventSequencer) OnIPPoolUpdate(key model.IPPoolKey, pool *model.IPPool) {
	log.WithFields(log.Fields{
		"key":  key,
		"pool": pool,
	}).Debug("IPPool update")
	cidr := ip.CIDRFromCalicoNet(key.CIDR)
	buf.pendingIPPoolDeletes.Discard(cidr)
	buf.pendingIPPoolUpdates[cidr] = pool
}

func (buf *EventSequencer) flushIPPoolUpdates() {
	for key, pool := range buf.pendingIPPoolUpdates {
		buf.Callback(&proto.IPAMPoolUpdate{
			Id: cidrToIPPoolID(key),
			Pool: &proto.IPAMPool{
				Cidr:        pool.CIDR.String(),
				Masquerade:  pool.Masquerade,
				IpipMode:    string(pool.IPIPMode),
				VxlanMode:   string(pool.VXLANMode),
				AwsSubnetId: pool.AWSSubnetID,
			},
		})
		buf.sentIPPools.Add(key)
		delete(buf.pendingIPPoolUpdates, key)
	}
}

func (buf *EventSequencer) flushHostWireguardUpdates() {
	for nodename, wg := range buf.pendingWireguardUpdates {
		log.WithFields(log.Fields{"nodename": nodename, "wg": wg}).Debug("Processing pending wireguard update")

		var ipv4Str, ipv6Str string

		if wg.PublicKey != "" {
			if wg.InterfaceIPv4Addr != nil {
				ipv4Str = wg.InterfaceIPv4Addr.String()
			}
			log.WithField("ipv4Str", ipv4Str).Debug("Sending IPv4 wireguard endpoint update")
			buf.Callback(&proto.WireguardEndpointUpdate{
				Hostname:          nodename,
				PublicKey:         wg.PublicKey,
				InterfaceIpv4Addr: ipv4Str,
			})
			buf.sentWireguard.Add(nodename)
		} else if buf.sentWireguard.Contains(nodename) {
			log.Debug("Sending IPv4 wireguard endpoint remove")
			buf.Callback(&proto.WireguardEndpointRemove{
				Hostname: nodename,
			})
			buf.sentWireguard.Discard(nodename)
		}

		if wg.PublicKeyV6 != "" {
			if wg.InterfaceIPv6Addr != nil {
				ipv6Str = wg.InterfaceIPv6Addr.String()
			}
			log.WithField("ipv6Str", ipv6Str).Debug("Sending IPv6 wireguard endpoint update")
			buf.Callback(&proto.WireguardEndpointV6Update{
				Hostname:          nodename,
				PublicKeyV6:       wg.PublicKeyV6,
				InterfaceIpv6Addr: ipv6Str,
			})
			buf.sentWireguardV6.Add(nodename)
		} else if buf.sentWireguardV6.Contains(nodename) {
			log.Debug("Sending IPv6 wireguard endpoint remove")
			buf.Callback(&proto.WireguardEndpointV6Remove{
				Hostname: nodename,
			})
			buf.sentWireguardV6.Discard(nodename)
		}

		delete(buf.pendingWireguardUpdates, nodename)
	}
	log.Debug("Done flushing wireguard updates")
}

func (buf *EventSequencer) OnIPPoolRemove(key model.IPPoolKey) {
	log.WithField("key", key).Debug("IPPool removed")
	cidr := ip.CIDRFromCalicoNet(key.CIDR)
	delete(buf.pendingIPPoolUpdates, cidr)
	if buf.sentIPPools.Contains(cidr) {
		buf.pendingIPPoolDeletes.Add(cidr)
	}
}

func (buf *EventSequencer) flushIPPoolDeletes() {
	buf.pendingIPPoolDeletes.Iter(func(key ip.CIDR) error {
		buf.Callback(&proto.IPAMPoolRemove{
			Id: cidrToIPPoolID(key),
		})
		buf.sentIPPools.Discard(key)
		return set.RemoveItem
	})
}

func (buf *EventSequencer) flushHostWireguardDeletes() {
	buf.pendingWireguardDeletes.Iter(func(key string) error {
		log.WithField("nodename", key).Debug("Processing pending wireguard delete")
		if buf.sentWireguard.Contains(key) {
			log.Debug("Sending IPv4 wireguard endpoint remove")
			buf.Callback(&proto.WireguardEndpointRemove{
				Hostname: key,
			})
			buf.sentWireguard.Discard(key)
		}
		if buf.sentWireguardV6.Contains(key) {
			log.Debug("Sending IPv6 wireguard endpoint remove")
			buf.Callback(&proto.WireguardEndpointV6Remove{
				Hostname: key,
			})
			buf.sentWireguardV6.Discard(key)
		}
		return set.RemoveItem
	})
	log.Debug("Done flushing wireguard removes")
}

func (buf *EventSequencer) flushAddedIPSets() {
	for setID, setType := range buf.pendingAddedIPSets {
		log.WithField("setID", setID).Debug("Flushing added IP set")
		members := make([]string, 0)
		buf.pendingAddedIPSetMembers.Iter(setID, func(member labelindex.IPSetMember) {
			members = append(members, memberToProto(member))
		})
		buf.pendingAddedIPSetMembers.DiscardKey(setID)
		buf.Callback(&proto.IPSetUpdate{
			Id:      setID,
			Members: members,
			Type:    setType,
		})
		buf.sentIPSets.Add(setID)
		delete(buf.pendingAddedIPSets, setID)
	}
}

func memberToProto(member labelindex.IPSetMember) string {
	if member.IsEgressGateway {
		return EgressIPSetMemberToProto(member)
	}

	switch member.Protocol {
	case labelindex.ProtocolNone:
		if member.Domain != "" {
			return member.Domain
		}
		if member.CIDR == nil {
			return fmt.Sprintf("v%d,%d", member.Family, member.PortNumber)
		}
		return member.CIDR.String()
	case labelindex.ProtocolTCP:
		return fmt.Sprintf("%s,tcp:%d", member.CIDR.Addr(), member.PortNumber)
	case labelindex.ProtocolUDP:
		return fmt.Sprintf("%s,udp:%d", member.CIDR.Addr(), member.PortNumber)
	case labelindex.ProtocolSCTP:
		return fmt.Sprintf("%s,sctp:%d", member.CIDR.Addr(), member.PortNumber)
	}
	log.WithField("member", member).Panic("Unknown IP set member type")
	return ""
}

func EgressIPSetMemberToProto(member labelindex.IPSetMember) string {
	// The member strings for egress gateway need to contain the cidr, the maintenance started timestamp, and the
	// maintenance finished timestamps for each member, because the egress gateway manager needs to detect when
	// an egress gateway pod is terminating.
	maintenanceFinished := member.DeletionTimestamp
	maintenanceStarted := maintenanceFinished.Add(-time.Second * time.Duration(member.DeletionGracePeriodSeconds))

	startBytes, err := maintenanceStarted.MarshalText()
	if err != nil {
		log.WithField("member", member).Warnf("unable to marshal timestamp to text, defaulting to empty str: %s", maintenanceStarted)
		return fmt.Sprintf("%s,,", member.CIDR.String())
	}

	finishBytes, err := maintenanceFinished.MarshalText()
	if err != nil {
		log.WithField("member", member).Warnf("unable to marshal timestamp to text, defaulting to empty str: %s", maintenanceFinished)
		return fmt.Sprintf("%s,,", member.CIDR.String())
	}

	return fmt.Sprintf("%s,%s,%s,%d,%s",
		member.CIDR.String(),
		strings.ToLower(string(startBytes)),
		strings.ToLower(string(finishBytes)),
		member.PortNumber,
		member.Hostname,
	)
}

func (buf *EventSequencer) OnPacketCaptureActive(key model.ResourceKey, endpoint model.WorkloadEndpointKey, spec PacketCaptureSpecification) {
	id := buf.packetCaptureKey(key, endpoint)
	delete(buf.pendingPacketCaptureRemovals, id)
	buf.pendingPacketCaptureUpdates[id] = &proto.PacketCaptureUpdate{
		Id: &proto.PacketCaptureID{
			Name:      key.Name,
			Namespace: key.Namespace,
		}, Endpoint: &proto.WorkloadEndpointID{
			OrchestratorId: endpoint.OrchestratorID,
			WorkloadId:     endpoint.WorkloadID,
			EndpointId:     endpoint.EndpointID,
		},
		Specification: &proto.PacketCaptureSpecification{
			BpfFilter: spec.BPFFilter,
			StartTime: timestamppb.New(spec.StartTime),
			EndTime:   timestamppb.New(spec.EndTime),
		},
	}
}

// packetCaptureKey constructs the key to store pending PacketCaptureRemovals and PacketCaptureUpdates
// It is formed from the PacketCapture namespace, name and WorkloadEndpointID. This is required as
// PacketCapture is a namespaced resource
func (buf *EventSequencer) packetCaptureKey(key model.ResourceKey, endpoint model.WorkloadEndpointKey) string {
	return fmt.Sprintf("%s/%s-%s", key.Namespace, key.Name, endpoint.WorkloadID)
}

func (buf *EventSequencer) OnPacketCaptureInactive(key model.ResourceKey, endpoint model.WorkloadEndpointKey) {
	id := buf.packetCaptureKey(key, endpoint)
	delete(buf.pendingPacketCaptureUpdates, id)
	if buf.sentPacketCapture.Contains(id) {
		buf.pendingPacketCaptureRemovals[id] = &proto.PacketCaptureRemove{
			Id: &proto.PacketCaptureID{
				Name:      key.Name,
				Namespace: key.Namespace,
			}, Endpoint: &proto.WorkloadEndpointID{
				OrchestratorId: endpoint.OrchestratorID,
				WorkloadId:     endpoint.WorkloadID,
				EndpointId:     endpoint.EndpointID,
			},
		}
	}
}

func (buf *EventSequencer) OnRemoteIPPoolUpdate(cluster string, key model.IPPoolKey, pool *model.IPPool) {
	log.WithFields(log.Fields{
		"cluster": cluster,
		"key":     key,
		"pool":    pool,
	}).Debug("Remote IPPool update")
	cidr := ip.CIDRFromCalicoNet(key.CIDR)
	id := remotePoolID{
		cluster: cluster,
		cidr:    cidr,
	}
	buf.pendingRemoteIPPoolRemovals.Discard(id)
	buf.pendingRemoteIPPools[id] = &proto.RemoteIPAMPoolUpdate{
		Id:      cidrToIPPoolID(cidr),
		Cluster: cluster,
		Pool: &proto.IPAMPool{
			Cidr:        pool.CIDR.String(),
			Masquerade:  pool.Masquerade,
			IpipMode:    string(pool.IPIPMode),
			VxlanMode:   string(pool.VXLANMode),
			AwsSubnetId: pool.AWSSubnetID,
		},
	}
}

func (buf *EventSequencer) flushRemoteIPPoolUpdates() {
	for key, pool := range buf.pendingRemoteIPPools {
		buf.Callback(pool)
		buf.sentRemoteIPPools.Add(key)
		delete(buf.pendingRemoteIPPools, key)
	}
}

func (buf *EventSequencer) OnRemoteIPPoolRemove(cluster string, key model.IPPoolKey) {
	log.WithField("key", key).Debug("Remote IPPool removed")
	cidr := ip.CIDRFromCalicoNet(key.CIDR)
	id := remotePoolID{
		cluster: cluster,
		cidr:    cidr,
	}
	delete(buf.pendingRemoteIPPools, id)
	if buf.sentRemoteIPPools.Contains(id) {
		buf.pendingRemoteIPPoolRemovals.Add(id)
	}
}

func (buf *EventSequencer) flushRemoteIPPoolDeletes() {
	buf.pendingRemoteIPPoolRemovals.Iter(func(id remotePoolID) error {
		buf.Callback(&proto.RemoteIPAMPoolRemove{
			Id:      cidrToIPPoolID(id.cidr),
			Cluster: id.cluster,
		})
		buf.sentRemoteIPPools.Discard(id)
		return set.RemoveItem
	})
}

func (buf *EventSequencer) Flush() {
	// Flush (rare) config changes first, since they may trigger a restart of the process.
	buf.flushReadyFlag()
	buf.flushConfigUpdate()

	// Flush mainline additions/updates in dependency order (IP sets, policy, endpoints) so
	// that later updates always have their dependencies in place.
	buf.flushAddedIPSets()
	buf.flushIPSetDeltas()
	buf.flushPolicyUpdates()
	buf.flushProfileUpdates()
	buf.flushEndpointTierUpdates()

	// Then flush removals in reverse order.
	buf.flushEndpointTierDeletes()
	buf.flushProfileDeletes()
	buf.flushPolicyDeletes()
	buf.flushRemovedIPSets()

	// Flush ServiceAccount and Namespace updates. These have no particular ordering compared with other updates.
	buf.flushServiceAccounts()
	buf.flushNamespaces()

	// Flush VXLAN data. Order such that no routes are present in the data plane unless
	// they have a corresponding VTEP in the data plane as well. Do this by sending VTEP adds
	// before flushing route adds, and route removes before flushing VTEP removes. We also send
	// route removes before route adds in order to minimize maximum occupancy.
	buf.flushRouteRemoves()
	buf.flushVTEPRemoves()
	buf.flushVTEPAdds()
	buf.flushRouteAdds()

	// Flush IPSec bindings, these have no particular ordering with other updates.
	buf.flushIPSecBindings()

	// Flush PacketCaptures, these have no particular ordering with other updates.
	buf.flushPacketCaptureRemovals()
	buf.flushPacketCaptureUpdates()

	// Flush (rare) cluster-wide updates.  There's no particular ordering to these so we might
	// as well do deletions first to minimise occupancy.
	buf.flushHostWireguardDeletes()
	buf.flushHostWireguardUpdates()
	buf.flushHostIPDeletes()
	buf.flushHostIPUpdates()
	buf.flushHostIPv6Deletes()
	buf.flushHostIPv6Updates()
	buf.flushHostDeletes()
	buf.flushHostUpdates()
	buf.flushIPPoolDeletes()
	buf.flushIPPoolUpdates()
	buf.flushRemoteIPPoolDeletes()
	buf.flushRemoteIPPoolUpdates()
	buf.flushEncapUpdate()
	buf.flushExternalNetworkRemoves()
	buf.flushExternalNetworkUpdates()

	// Flush global BGPConfiguration updates.
	if buf.pendingGlobalBGPConfig != nil {
		buf.Callback(buf.pendingGlobalBGPConfig)
		buf.pendingGlobalBGPConfig = nil
	}

	buf.flushServices()
}

func (buf *EventSequencer) flushRemovedIPSets() {
	buf.pendingRemovedIPSets.Iter(func(setID string) (err error) {
		log.Debugf("Flushing IP set remove: %v", setID)
		buf.Callback(&proto.IPSetRemove{
			Id: setID,
		})
		buf.pendingRemovedIPSetMembers.DiscardKey(setID)
		buf.pendingAddedIPSetMembers.DiscardKey(setID)
		buf.pendingRemovedIPSets.Discard(setID)
		buf.sentIPSets.Discard(setID)
		return
	})
	log.Debugf("Done flushing IP set removes")
}

func (buf *EventSequencer) flushIPSetDeltas() {
	buf.pendingRemovedIPSetMembers.IterKeys(buf.flushAddsOrRemoves)
	buf.pendingAddedIPSetMembers.IterKeys(buf.flushAddsOrRemoves)
	log.Debugf("Done flushing IP address deltas")
}

func (buf *EventSequencer) flushAddsOrRemoves(setID string) {
	log.Debugf("Flushing IP set deltas: %v", setID)
	deltaUpdate := proto.IPSetDeltaUpdate{
		Id: setID,
	}
	buf.pendingAddedIPSetMembers.Iter(setID, func(member labelindex.IPSetMember) {
		deltaUpdate.AddedMembers = append(deltaUpdate.AddedMembers, memberToProto(member))
	})
	buf.pendingRemovedIPSetMembers.Iter(setID, func(member labelindex.IPSetMember) {
		deltaUpdate.RemovedMembers = append(deltaUpdate.RemovedMembers, memberToProto(member))
	})
	buf.pendingAddedIPSetMembers.DiscardKey(setID)
	buf.pendingRemovedIPSetMembers.DiscardKey(setID)
	buf.Callback(&deltaUpdate)
}

func (buf *EventSequencer) OnServiceAccountUpdate(update *proto.ServiceAccountUpdate) {
	// We trust the caller not to send us an update with nil ID, so safe to dereference.
	id := types.ProtoToServiceAccountID(update.Id)
	log.WithFields(log.Fields{
		"key":    id,
		"labels": update.GetLabels(),
	}).Debug("ServiceAccount update")
	buf.pendingServiceAccountDeletes.Discard(id)
	buf.pendingServiceAccountUpdates[id] = update
}

func (buf *EventSequencer) OnServiceAccountRemove(id types.ServiceAccountID) {
	log.WithFields(log.Fields{
		"key": id,
	}).Debug("ServiceAccount removed")
	delete(buf.pendingServiceAccountUpdates, id)
	if buf.sentServiceAccounts.Contains(id) {
		buf.pendingServiceAccountDeletes.Add(id)
	}
}

func (buf *EventSequencer) flushServiceAccounts() {
	// Order doesn't matter, but send removes first to reduce max occupancy
	buf.pendingServiceAccountDeletes.Iter(func(id types.ServiceAccountID) error {
		protoID := types.ServiceAccountIDToProto(id)
		msg := proto.ServiceAccountRemove{Id: protoID}
		buf.Callback(&msg)
		buf.sentServiceAccounts.Discard(id)
		return nil
	})
	buf.pendingServiceAccountDeletes.Clear()
	for _, msg := range buf.pendingServiceAccountUpdates {
		buf.Callback(msg)
		id := types.ProtoToServiceAccountID(msg.GetId())
		// We safely dereferenced the Id in OnServiceAccountUpdate before adding it to the pending updates map, so
		// it is safe to do so here.
		buf.sentServiceAccounts.Add(id)
	}
	buf.pendingServiceAccountUpdates = make(map[types.ServiceAccountID]*proto.ServiceAccountUpdate)
	log.Debug("Done flushing Service Accounts")
}

func (buf *EventSequencer) OnIPSecTunnelAdded(tunnelAddr ip.Addr) {
	if buf.pendingIPSecTunnelRemoves.Contains(tunnelAddr) {
		// We haven't sent this remove through to the dataplane yet so we can squash it here...
		buf.pendingIPSecTunnelRemoves.Discard(tunnelAddr)
	} else {
		buf.pendingIPSecTunnelAdds.Add(tunnelAddr)
	}
}

func (buf *EventSequencer) OnIPSecTunnelRemoved(tunnelAddr ip.Addr) {
	if buf.pendingIPSecTunnelAdds.Contains(tunnelAddr) {
		// We haven't sent this add through to the dataplane yet so we can squash it here...
		buf.pendingIPSecTunnelAdds.Discard(tunnelAddr)
	} else {
		buf.pendingIPSecTunnelRemoves.Add(tunnelAddr)
	}
}

func (buf *EventSequencer) OnIPSecBindingAdded(b IPSecBinding) {
	if buf.pendingIPSecBindingRemoves.Contains(b) {
		// We haven't sent this remove through to the dataplane yet so we can squash it here...
		buf.pendingIPSecBindingRemoves.Discard(b)
	} else {
		buf.pendingIPSecBindingAdds.Add(b)
	}
}

func (buf *EventSequencer) OnIPSecBindingRemoved(b IPSecBinding) {
	if buf.pendingIPSecBindingAdds.Contains(b) {
		// We haven't sent this add through to the dataplane yet so we can squash it here...
		buf.pendingIPSecBindingAdds.Discard(b)
	} else {
		buf.pendingIPSecBindingRemoves.Add(b)
	}
}

func (buf *EventSequencer) OnIPSecBlacklistAdded(b ip.Addr) {
	if buf.pendingIPSecBlacklistRemoves.Contains(b) {
		// We haven't sent this remove through to the dataplane yet so we can squash it here...
		buf.pendingIPSecBlacklistRemoves.Discard(b)
	} else {
		buf.pendingIPSecBlacklistAdds.Add(b)
	}
}

func (buf *EventSequencer) OnIPSecBlacklistRemoved(b ip.Addr) {
	if buf.pendingIPSecBlacklistAdds.Contains(b) {
		// We haven't sent this add through to the dataplane yet so we can squash it here...
		buf.pendingIPSecBlacklistAdds.Discard(b)
	} else {
		buf.pendingIPSecBlacklistRemoves.Add(b)
	}
}

func (buf *EventSequencer) flushIPSecBindings() {
	// Flush the blacklist removals first, otherwise, the presence of a blacklist entry prevents
	// the dataplane from adding a proper binding.
	if buf.pendingIPSecBlacklistRemoves.Len() > 0 {
		var addrs []string
		buf.pendingIPSecBlacklistRemoves.Iter(func(addr ip.Addr) error {
			addrs = append(addrs, addr.String())
			return set.RemoveItem
		})
		upd := &proto.IPSecBlacklistRemove{
			RemovedAddrs: addrs,
		}
		buf.Callback(upd)
	}

	// Then, flush the bindings removes and adds.
	updatesByTunnel := map[ip.Addr]*proto.IPSecBindingUpdate{}

	getOrCreateUpd := func(tunnelAddr ip.Addr) *proto.IPSecBindingUpdate {
		upd := updatesByTunnel[tunnelAddr]
		if upd == nil {
			upd = &proto.IPSecBindingUpdate{}
			updatesByTunnel[tunnelAddr] = upd
			upd.TunnelAddr = tunnelAddr.String()
		}
		return upd
	}

	// Send the removes first in a separate sequence of updates.  If we allow removes to be re-ordered with adds
	// then we can change "add, remove, add" into "add, update, remove" and accidentally remove the updated policy.
	// This is because the dataplane indexes policies on the policy selector (i.e. the match criteria for the
	// rule) rather than the whole rule, in order to match the kernel behaviour.
	buf.pendingIPSecBindingRemoves.Iter(func(b IPSecBinding) error {
		upd := getOrCreateUpd(b.TunnelAddr)
		upd.RemovedAddrs = append(upd.RemovedAddrs, b.WorkloadAddr.String())
		return set.RemoveItem
	})
	for k, upd := range updatesByTunnel {
		buf.Callback(upd)
		delete(updatesByTunnel, k)
	}

	// Now we've removed all the individual bindings, clean up any tunnels that are no longer present.
	buf.pendingIPSecTunnelRemoves.Iter(func(addr ip.Addr) error {
		buf.Callback(&proto.IPSecTunnelRemove{
			TunnelAddr: addr.String(),
		})
		return set.RemoveItem
	})

	// Then create any new tunnels.
	buf.pendingIPSecTunnelAdds.Iter(func(addr ip.Addr) error {
		buf.Callback(&proto.IPSecTunnelAdd{
			TunnelAddr: addr.String(),
		})
		return set.RemoveItem
	})

	// Now send the adds.
	buf.pendingIPSecBindingAdds.Iter(func(b IPSecBinding) error {
		upd := getOrCreateUpd(b.TunnelAddr)
		upd.AddedAddrs = append(upd.AddedAddrs, b.WorkloadAddr.String())
		return set.RemoveItem
	})

	for _, upd := range updatesByTunnel {
		buf.Callback(upd)
	}

	// Finally Add blacklist entries.  We do this after we remove the real entries to avoid clashes
	// in the dataplane.
	if buf.pendingIPSecBlacklistAdds.Len() > 0 {
		var addrs []string
		buf.pendingIPSecBlacklistAdds.Iter(func(addr ip.Addr) error {
			addrs = append(addrs, addr.String())
			return set.RemoveItem
		})
		upd := &proto.IPSecBlacklistAdd{
			AddedAddrs: addrs,
		}
		buf.Callback(upd)
	}
}

func (buf *EventSequencer) OnNamespaceUpdate(update *proto.NamespaceUpdate) {
	// We trust the caller not to send us an update with nil ID, so safe to dereference.
	id := types.ProtoToNamespaceID(update.GetId())
	log.WithFields(log.Fields{
		"key":    id,
		"labels": update.GetLabels(),
	}).Debug("Namespace update")
	buf.pendingNamespaceDeletes.Discard(id)
	buf.pendingNamespaceUpdates[id] = update
}

func (buf *EventSequencer) OnNamespaceRemove(id types.NamespaceID) {
	log.WithFields(log.Fields{
		"key": id,
	}).Debug("Namespace removed")
	delete(buf.pendingNamespaceUpdates, id)
	if buf.sentNamespaces.Contains(id) {
		buf.pendingNamespaceDeletes.Add(id)
	}
}

func (buf *EventSequencer) OnWireguardUpdate(nodename string, wg *model.Wireguard) {
	log.WithFields(log.Fields{
		"nodename": nodename,
	}).Debug("Wireguard updated")
	buf.pendingWireguardDeletes.Discard(nodename)
	buf.pendingWireguardUpdates[nodename] = wg
}

func (buf *EventSequencer) OnWireguardRemove(nodename string) {
	log.WithFields(log.Fields{
		"nodename": nodename,
	}).Debug("Wireguard removed")
	delete(buf.pendingWireguardUpdates, nodename)
	buf.pendingWireguardDeletes.Add(nodename)
}

func (buf *EventSequencer) OnGlobalBGPConfigUpdate(cfg *v3.BGPConfiguration) {
	log.WithField("cfg", cfg).Debug("Global BGPConfiguration updated")
	buf.pendingGlobalBGPConfig = &proto.GlobalBGPConfigUpdate{}
	if cfg != nil {
		for _, block := range cfg.Spec.ServiceClusterIPs {
			if block.CIDR == "" {
				// When we defined the CRD we allowed this field to be optional
				// for extensibility, ignore empty CIDRs.
				continue
			}
			buf.pendingGlobalBGPConfig.ServiceClusterCidrs = append(buf.pendingGlobalBGPConfig.ServiceClusterCidrs, block.CIDR)
		}
		for _, block := range cfg.Spec.ServiceExternalIPs {
			if block.CIDR == "" {
				// When we defined the CRD we allowed this field to be optional
				// for extensibility, ignore empty CIDRs.
				continue
			}
			buf.pendingGlobalBGPConfig.ServiceExternalCidrs = append(buf.pendingGlobalBGPConfig.ServiceExternalCidrs, block.CIDR)
		}
		for _, block := range cfg.Spec.ServiceLoadBalancerIPs {
			if block.CIDR == "" {
				// When we defined the CRD we allowed this field to be optional
				// for extensibility, ignore empty CIDRs.
				continue
			}
			buf.pendingGlobalBGPConfig.ServiceLoadbalancerCidrs = append(buf.pendingGlobalBGPConfig.ServiceLoadbalancerCidrs, block.CIDR)
		}
		buf.pendingGlobalBGPConfig.LocalWorkloadPeeringIpV4 = cfg.Spec.LocalWorkloadPeeringIPV4
		buf.pendingGlobalBGPConfig.LocalWorkloadPeeringIpV6 = cfg.Spec.LocalWorkloadPeeringIPV6
	}
}

func (buf *EventSequencer) flushNamespaces() {
	// Order doesn't matter, but send removes first to reduce max occupancy
	buf.pendingNamespaceDeletes.Iter(func(id types.NamespaceID) error {
		protoID := types.NamespaceIDToProto(id)
		msg := proto.NamespaceRemove{Id: protoID}
		buf.Callback(&msg)
		buf.sentNamespaces.Discard(id)
		return nil
	})
	buf.pendingNamespaceDeletes.Clear()
	for _, msg := range buf.pendingNamespaceUpdates {
		buf.Callback(msg)
		id := types.ProtoToNamespaceID(msg.GetId())
		// We safely dereferenced the Id in OnNamespaceUpdate before adding it to the pending updates map, so
		// it is safe to do so here.
		buf.sentNamespaces.Add(id)
	}
	buf.pendingNamespaceUpdates = make(map[types.NamespaceID]*proto.NamespaceUpdate)
	log.Debug("Done flushing Namespaces")
}

func (buf *EventSequencer) OnVTEPUpdate(update *proto.VXLANTunnelEndpointUpdate) {
	node := update.Node
	log.WithFields(log.Fields{"id": node}).Debug("VTEP update")
	buf.pendingVTEPDeletes.Discard(node)
	buf.pendingVTEPUpdates[node] = update
}

func (buf *EventSequencer) OnVTEPRemove(dst string) {
	log.WithFields(log.Fields{"dst": dst}).Debug("VTEP removed")
	delete(buf.pendingVTEPUpdates, dst)
	if buf.sentVTEPs.Contains(dst) {
		buf.pendingVTEPDeletes.Add(dst)
	}
}

func (buf *EventSequencer) flushVTEPRemoves() {
	buf.pendingVTEPDeletes.Iter(func(node string) error {
		msg := proto.VXLANTunnelEndpointRemove{Node: node}
		buf.Callback(&msg)
		buf.sentVTEPs.Discard(node)
		return nil
	})
	buf.pendingVTEPDeletes.Clear()
	log.Debug("Done flushing VTEP removes")
}

func (buf *EventSequencer) flushVTEPAdds() {
	for _, msg := range buf.pendingVTEPUpdates {
		buf.Callback(msg)
		buf.sentVTEPs.Add(msg.Node)
	}
	buf.pendingVTEPUpdates = make(map[string]*proto.VXLANTunnelEndpointUpdate)
	log.Debug("Done flushing VTEP adds")
}

func (buf *EventSequencer) OnRouteUpdate(update *proto.RouteUpdate) {
	routeID := routeID{
		dst: update.Dst,
	}
	log.WithFields(log.Fields{"id": routeID}).Debug("Route update")
	buf.pendingRouteDeletes.Discard(routeID)
	buf.pendingRouteUpdates[routeID] = update
}

func (buf *EventSequencer) OnRouteRemove(dst string) {
	routeID := routeID{
		dst: dst,
	}
	log.WithFields(log.Fields{"id": routeID}).Debug("Route update")
	delete(buf.pendingRouteUpdates, routeID)
	if buf.sentRoutes.Contains(routeID) {
		buf.pendingRouteDeletes.Add(routeID)
	}
}

func (buf *EventSequencer) flushRouteAdds() {
	for id, msg := range buf.pendingRouteUpdates {
		buf.Callback(msg)
		buf.sentRoutes.Add(id)
	}
	buf.pendingRouteUpdates = make(map[routeID]*proto.RouteUpdate)
	log.Debug("Done flushing route adds")
}

func (buf *EventSequencer) flushRouteRemoves() {
	buf.pendingRouteDeletes.Iter(func(id routeID) error {
		msg := proto.RouteRemove{Dst: id.dst}
		buf.Callback(&msg)
		buf.sentRoutes.Discard(id)
		return nil
	})
	buf.pendingRouteDeletes.Clear()
	log.Debug("Done flushing route deletes")
}

func (buf *EventSequencer) flushPacketCaptureUpdates() {
	for key, value := range buf.pendingPacketCaptureUpdates {
		buf.Callback(value)
		buf.sentPacketCapture.Add(key)
		delete(buf.pendingPacketCaptureUpdates, key)
	}
}

func (buf *EventSequencer) flushPacketCaptureRemovals() {
	for key, value := range buf.pendingPacketCaptureRemovals {
		buf.Callback(value)
		buf.sentPacketCapture.Discard(key)
		delete(buf.pendingPacketCaptureRemovals, key)
	}
}

func (buf *EventSequencer) OnExternalNetworkUpdate(update *proto.ExternalNetworkUpdate) {
	log.WithFields(log.Fields{
		"name":            update.Id.Name,
		"routeTableIndex": update.Network.RouteTableIndex,
	}).Debug("External network update")
	id := types.ProtoToExternalNetworkID(update.GetId())
	buf.pendingExternalNetworkDeletes.Discard(id)
	buf.pendingExternalNetworkUpdates[id] = update
}

func (buf *EventSequencer) OnExternalNetworkRemove(update *proto.ExternalNetworkRemove) {
	log.WithFields(log.Fields{
		"name": update.Id.Name,
	}).Debug("External network update")
	id := types.ProtoToExternalNetworkID(update.GetId())
	delete(buf.pendingExternalNetworkUpdates, id)
	if buf.sentExternalNetworks.Contains(id) {
		buf.pendingExternalNetworkDeletes.Add(id)
	}
}

func (buf *EventSequencer) flushExternalNetworkUpdates() {
	for id, msg := range buf.pendingExternalNetworkUpdates {
		buf.Callback(msg)
		buf.sentExternalNetworks.Add(id)
	}
	buf.pendingExternalNetworkUpdates = make(map[types.ExternalNetworkID]*proto.ExternalNetworkUpdate)
	log.Debug("Done flushing external network updates")
}

func (buf *EventSequencer) flushExternalNetworkRemoves() {
	buf.pendingExternalNetworkDeletes.Iter(func(id types.ExternalNetworkID) error {
		protoID := types.ExternalNetworkIDToProto(id)
		msg := proto.ExternalNetworkRemove{Id: protoID}
		buf.Callback(&msg)
		buf.sentExternalNetworks.Discard(id)
		return nil
	})
	buf.pendingExternalNetworkDeletes.Clear()
	log.Debug("Done flushing external network deletes")
}

func (buf *EventSequencer) OnServiceUpdate(update *proto.ServiceUpdate) {
	log.WithFields(log.Fields{
		"name":      update.Name,
		"namespace": update.Namespace,
	}).Debug("Service update")
	id := serviceID{
		Name:      update.Name,
		Namespace: update.Namespace,
	}
	buf.pendingServiceDeletes.Discard(id)
	buf.pendingServiceUpdates[id] = update
}

func (buf *EventSequencer) OnServiceRemove(update *proto.ServiceRemove) {
	log.WithFields(log.Fields{
		"name":      update.Name,
		"namespace": update.Namespace,
	}).Debug("Service delete")
	id := serviceID{
		Name:      update.Name,
		Namespace: update.Namespace,
	}
	delete(buf.pendingServiceUpdates, id)
	if buf.sentServices.Contains(id) {
		buf.pendingServiceDeletes.Add(id)
	}
}

func (buf *EventSequencer) flushServices() {
	// Order doesn't matter, but send removes first to reduce max occupancy
	buf.pendingServiceDeletes.Iter(func(id serviceID) error {
		msg := &proto.ServiceRemove{
			Name:      id.Name,
			Namespace: id.Namespace,
		}
		buf.Callback(msg)
		buf.sentServices.Discard(id)
		return nil
	})
	buf.pendingServiceDeletes.Clear()
	for _, msg := range buf.pendingServiceUpdates {
		buf.Callback(msg)
		id := serviceID{
			Name:      msg.Name,
			Namespace: msg.Namespace,
		}
		// We safely dereferenced the Id in OnServiceUpdate before adding it to the pending updates map, so
		// it is safe to do so here.
		buf.sentServices.Add(id)
	}
	buf.pendingServiceUpdates = make(map[serviceID]*proto.ServiceUpdate)
	log.Debug("Done flushing Services")
}

func cidrToIPPoolID(cidr ip.CIDR) string {
	return strings.Replace(cidr.String(), "/", "-", 1)
}

func addPolicyToTierInfo(pol *PolKV, tierInfo *proto.TierInfo, egressAllowed bool) {
	if pol.GovernsIngress() {
		tierInfo.IngressPolicies = append(tierInfo.IngressPolicies, pol.Key.Name)
	}
	if egressAllowed && pol.GovernsEgress() {
		tierInfo.EgressPolicies = append(tierInfo.EgressPolicies, pol.Key.Name)
	}
}

func tierInfoToProtoTierInfo(filteredTiers []TierInfo) (normalTiers, untrackedTiers, preDNATTiers, forwardTiers []*proto.TierInfo) {
	if len(filteredTiers) > 0 {
		for _, ti := range filteredTiers {
			// For untracked and preDNAT tiers, DefautlAction must be Pass, to make sure policies in the normal tier
			// are also checked.
			untrackedTierInfo := &proto.TierInfo{Name: ti.Name, DefaultAction: string(v3.Pass)}
			preDNATTierInfo := &proto.TierInfo{Name: ti.Name, DefaultAction: string(v3.Pass)}
			forwardTierInfo := &proto.TierInfo{Name: ti.Name, DefaultAction: string(ti.DefaultAction)}
			normalTierInfo := &proto.TierInfo{Name: ti.Name, DefaultAction: string(ti.DefaultAction)}
			for _, pol := range ti.OrderedPolicies {
				if pol.Value.DoNotTrack() {
					addPolicyToTierInfo(&pol, untrackedTierInfo, true)
				} else if pol.Value.PreDNAT() {
					addPolicyToTierInfo(&pol, preDNATTierInfo, false)
				} else {
					if pol.Value.ApplyOnForward() {
						addPolicyToTierInfo(&pol, forwardTierInfo, true)
					}
					addPolicyToTierInfo(&pol, normalTierInfo, true)
				}
			}

			if len(untrackedTierInfo.IngressPolicies) > 0 || len(untrackedTierInfo.EgressPolicies) > 0 {
				untrackedTiers = append(untrackedTiers, untrackedTierInfo)
			}
			if len(preDNATTierInfo.IngressPolicies) > 0 || len(preDNATTierInfo.EgressPolicies) > 0 {
				preDNATTiers = append(preDNATTiers, preDNATTierInfo)
			}
			if len(forwardTierInfo.IngressPolicies) > 0 || len(forwardTierInfo.EgressPolicies) > 0 {
				forwardTiers = append(forwardTiers, forwardTierInfo)
			}
			if len(normalTierInfo.IngressPolicies) > 0 || len(normalTierInfo.EgressPolicies) > 0 {
				normalTiers = append(normalTiers, normalTierInfo)
			}
		}
	}
	return
}

func netsToStrings(nets []net.IPNet) []string {
	output := make([]string, len(nets))
	for ii, ipNet := range nets {
		output[ii] = ipNet.String()
	}
	return output
}

func ipsToStrings(ips []net.IP) []string {
	output := make([]string, len(ips))
	for ii, netIP := range ips {
		output[ii] = netIP.String()
	}
	return output
}

func natsToProtoNatInfo(nats []model.IPNAT) []*proto.NatInfo {
	protoNats := make([]*proto.NatInfo, len(nats))
	for ii, nat := range nats {
		protoNats[ii] = &proto.NatInfo{
			ExtIp: nat.ExtIP.String(),
			IntIp: nat.IntIP.String(),
		}
	}
	return protoNats
}

func appLayerToProtoAppLayer(al *model.ApplicationLayer) *proto.ApplicationLayer {
	if al == nil {
		return nil
	}

	return &proto.ApplicationLayer{
		Logging:      al.Logging,
		Policy:       al.Policy,
		Waf:          al.WAF,
		WafConfigMap: al.WAFConfigMap,
	}
}
