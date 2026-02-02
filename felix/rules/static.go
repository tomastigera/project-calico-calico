// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.
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

package rules

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf/bpfdefs"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/dataplane/linux/dataplanedefs"
	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/nftables"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/tproxydefs"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

func (r *DefaultRuleRenderer) StaticFilterTableChains(ipVersion uint8) (chains []*generictables.Chain) {
	chains = append(chains, r.StaticFilterForwardChains(ipVersion)...)
	chains = append(chains, r.StaticFilterInputChains(ipVersion)...)
	chains = append(chains, r.StaticFilterOutputChains(ipVersion)...)

	// Include the DNS log chain; depending on configuration it may not get
	// used but the iptables layer will filter it out if it's not needed.
	chains = append(chains, r.dnsLogChain())

	return
}

const (
	ProtoIPIP   = 4
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoESP    = 50
	ProtoICMPv6 = 58
	PortIKE     = 500
)

const (
	DNSActionPrefix = "DNS"
)

func (r *DefaultRuleRenderer) tproxyInputPolicyRules(ipVersion uint8) []generictables.Rule {
	rules := []generictables.Rule{}

	// N.B. we do not snoop on DNS in input towards proxy, we defer it to output from proxy

	// Jump to from-host-endpoint dispatch chains.
	rules = append(rules, r.filterFromHEP(ipVersion)...)

	// Jump to workload dispatch chains - from wl only as we we are in INPUT to proxy and
	// we do not know the output ifaces, thus the to-wl must be done after proxy.
	for _, prefix := range r.WorkloadIfacePrefixes {
		log.WithField("ifacePrefix", prefix).Debug("Adding workload match rules")
		ifaceMatch := prefix + r.wildcard
		rules = append(rules,
			generictables.Rule{
				Match:  r.NewMatch().InInterface(ifaceMatch),
				Action: r.Jump(ChainFromWorkloadDispatch),
			},
		)
	}

	// Accept packet if policies above set ACCEPT mark.
	rules = append(rules,
		generictables.Rule{
			Match:   r.NewMatch().MarkSingleBitSet(r.MarkAccept),
			Action:  r.filterAllowAction,
			Comment: []string{"Policy explicitly accepted packet."},
		},
	)

	return rules
}

func (r *DefaultRuleRenderer) tproxyOutputPolicyRules(ipVersion uint8) []generictables.Rule {
	rules := []generictables.Rule{}

	// Jump to workload dispatch chains.
	for _, prefix := range r.WorkloadIfacePrefixes {
		log.WithField("ifacePrefix", prefix).Debug("Adding workload match rules")
		ifaceMatch := prefix + r.wildcard
		rules = append(rules,
			generictables.Rule{
				Match:  r.NewMatch().OutInterface(ifaceMatch),
				Action: r.Jump(ChainToWorkloadDispatch),
			},
		)
	}

	return rules
}

func (r *DefaultRuleRenderer) StaticFilterInputChains(ipVersion uint8) []*generictables.Chain {
	result := []*generictables.Chain{}
	result = append(result,
		r.filterInputChain(ipVersion),
		r.filterWorkloadToHostChain(ipVersion),
		r.failsafeInChain("filter", ipVersion),
	)
	if r.KubeIPVSSupportEnabled {
		result = append(result, r.StaticFilterInputForwardCheckChain(ipVersion))
	}
	if r.TPROXYModeEnabled() && !r.BPFEnabled {
		result = append(result,
			&generictables.Chain{
				Name:  ChainFilterInputTProxy,
				Rules: r.tproxyInputPolicyRules(ipVersion),
			})
	}
	return result
}

func (r *DefaultRuleRenderer) acceptAlreadyAccepted() []generictables.Rule {
	return []generictables.Rule{
		{
			Match:  r.NewMatch().MarkSingleBitSet(r.MarkAccept),
			Action: r.filterAllowAction,
		},
	}
}

// Forward check chain is to check if a packet belongs to a forwarded traffic or not.
// With kube-proxy running in ipvs mode, both local or forwarded traffic goes through INPUT filter chain.
func (r *DefaultRuleRenderer) StaticFilterInputForwardCheckChain(ipVersion uint8) *generictables.Chain {
	var fwRules []generictables.Rule
	var portRanges []*proto.PortRange

	// Assembly port ranges for kubernetes node ports.
	for _, portRange := range r.KubeNodePortRanges {
		pr := &proto.PortRange{
			First: int32(portRange.MinPort),
			Last:  int32(portRange.MaxPort),
		}
		portRanges = append(portRanges, pr)
	}

	// Get ipsets name for local host ips.
	nameForIPSet := func(ipsetID string) string {
		if ipVersion == 4 {
			return r.IPSetConfigV4.NameForMainIPSet(ipsetID)
		} else {
			return r.IPSetConfigV6.NameForMainIPSet(ipsetID)
		}
	}
	hostIPSet := nameForIPSet(IPSetIDThisHostIPs)

	fwRules = append(fwRules,
		// If packet belongs to an existing conntrack connection, it does not belong to a forwarded traffic even destination ip is a
		// service ip. This could happen when pod send back response to a local host process accessing a service ip.
		generictables.Rule{
			Match:  r.NewMatch().ConntrackState("RELATED,ESTABLISHED"),
			Action: r.Return(),
		},
	)

	// If packet is accessing local host within kubernetes NodePort range, it belongs to a forwarded traffic.
	for _, portSplit := range SplitPortList(portRanges) {
		fwRules = append(fwRules,
			generictables.Rule{
				Match: r.NewMatch().Protocol("tcp").
					DestPortRanges(portSplit).
					DestIPSet(hostIPSet),
				Action:  r.GoTo(ChainDispatchSetEndPointMark),
				Comment: []string{"To kubernetes NodePort service"},
			},
			generictables.Rule{
				Match: r.NewMatch().Protocol("udp").
					DestPortRanges(portSplit).
					DestIPSet(hostIPSet),
				Action:  r.GoTo(ChainDispatchSetEndPointMark),
				Comment: []string{"To kubernetes NodePort service"},
			},
		)
	}

	fwRules = append(fwRules,
		// If packet is accessing non local host ip, it belongs to a forwarded traffic.
		generictables.Rule{
			Match:   r.NewMatch().NotDestIPSet(hostIPSet),
			Action:  r.Jump(ChainDispatchSetEndPointMark),
			Comment: []string{"To kubernetes service"},
		},
	)

	return &generictables.Chain{
		Name:  ChainForwardCheck,
		Rules: fwRules,
	}
}

// With kube-proxy running in ipvs mode, we categorise traffic going through OUTPUT chain into three classes.
// Class 1. forwarded packet originated from a calico workload or host endpoint --> INPUT filter --> OUTPUT filter
// Class 2. forwarded packet originated from a non calico endpoint              --> INPUT filter --> OUTPUT filter
// Class 3. local process originated packet --> OUTPUT filter
// This function handles traffic in Class 1 and Class 2.
func (r *DefaultRuleRenderer) StaticFilterOutputForwardEndpointMarkChain() *generictables.Chain {
	var fwRules []generictables.Rule

	fwRules = append(fwRules,
		// Only packets that we know are really being forwarded reach this chain. However, since
		// we're called from the OUTPUT chain, we're forbidden from using the input interface match.
		// Instead, we rely on the INPUT chain to mark the packet with a per-endpoint mark value
		// and do our dispatch on that mark value.  So that we don't touch "Class 2" packets, we
		// mark them with mark pattern MarkNonCaliEndpoint and exclude them here.  This
		// prevents the default drop at the end of the dispatch chain from dropping non-Calico
		// traffic.
		generictables.Rule{
			Match:  r.NewMatch().NotMarkMatchesWithMask(r.MarkNonCaliEndpoint, r.MarkEndpoint),
			Action: r.Jump(ChainDispatchFromEndPointMark),
		},
	)

	// The packet may be going to a workload interface.  Send any such packets to the normal,
	// interface-name-based dispatch chains.
	for _, prefix := range r.WorkloadIfacePrefixes {
		log.WithField("ifacePrefix", prefix).Debug("Adding workload match rules")
		ifaceMatch := prefix + r.wildcard
		fwRules = append(fwRules,
			generictables.Rule{
				Match:  r.NewMatch().OutInterface(ifaceMatch),
				Action: r.Jump(ChainToWorkloadDispatch),
			},
		)
	}

	fwRules = append(fwRules,
		// The packet may be going to a host endpoint, send it to the host endpoint
		// apply-on-forward dispatch chain. That chain returns any packets that are not going to a
		// known host endpoint for further processing.
		generictables.Rule{
			Action: r.Jump(ChainDispatchToHostEndpointForward),
		},

		// Before we ACCEPT the packet, clear the per-interface mark bit.  This is required because
		// the packet may get encapsulated and pass through iptables again.  Since the new encapped
		// packet would inherit the mark bits, it would be (incorrectly) treated as a forwarded
		// packet.
		generictables.Rule{
			Action: r.ClearMark(r.MarkEndpoint),
		},

		// If a packet reaches here, one of the following must be true:
		//
		// - it is going to a workload endpoint and it has passed that endpoint's policy
		// - it is going to a host interface with a Calico host endpoint and it has passed that
		//   endpoint's policy
		// - it is going to a host interface with no Calico host endpoint.
		//
		// In the first two cases, the policy will have set the accept bit in the mark and we "own"
		// the packet so it's right for us to ACCEPT it here (unless configured otherwise).  In
		// the other case, we don't own the packet so we always return it to the OUTPUT chain
		// for further processing.
		generictables.Rule{
			Match:   r.NewMatch().MarkSingleBitSet(r.MarkAccept),
			Action:  r.filterAllowAction,
			Comment: []string{"Policy explicitly accepted packet."},
		},
	)

	return &generictables.Chain{
		Name:  ChainForwardEndpointMark,
		Rules: fwRules,
	}
}

func (r *DefaultRuleRenderer) FilterInputChainAllowWG(ipVersion uint8, c Config, allowAction generictables.Action) []generictables.Rule {
	var inputRules []generictables.Rule

	if ipVersion == 4 && c.WireguardEnabled {
		// When Wireguard is enabled, auto-allow Wireguard traffic from other nodes.  Without this,
		// it's too easy to make a host policy that blocks Wireguard traffic, resulting in very confusing
		// connectivity problems.
		inputRules = append(inputRules,
			generictables.Rule{
				Match: r.NewMatch().ProtocolNum(ProtoUDP).
					DestPorts(uint16(c.WireguardListeningPort)).
					DestAddrType(generictables.AddrTypeLocal),
				Action:  allowAction,
				Comment: []string{"Allow incoming IPv4 Wireguard packets"},
			},
			// Note that we do not need a drop rule for Wireguard because it already has the peering and allowed IPs
			// baked into the crypto routing table.
		)
	}

	if ipVersion == 6 && c.WireguardEnabledV6 {
		// When Wireguard is enabled, auto-allow Wireguard traffic from other nodes.  Without this,
		// it's too easy to make a host policy that blocks Wireguard traffic, resulting in very confusing
		// connectivity problems.
		inputRules = append(inputRules,
			generictables.Rule{
				Match: r.NewMatch().ProtocolNum(ProtoUDP).
					DestPorts(uint16(c.WireguardListeningPortV6)).
					DestAddrType(generictables.AddrTypeLocal),
				Action:  allowAction,
				Comment: []string{"Allow incoming IPv6 Wireguard packets"},
			},
			// Note that we do not need a drop rule for Wireguard because it already has the peering and allowed IPs
			// baked into the crypto routing table.
		)
	}

	return inputRules
}

func (r *DefaultRuleRenderer) filterInputChain(ipVersion uint8) *generictables.Chain {
	var inputRules []generictables.Rule

	if r.TPROXYModeEnabled() {
		mark := r.MarkProxy
		inputRules = append(inputRules,
			generictables.Rule{
				Comment: []string{"Police packets towards proxy"},
				Match:   r.NewMatch().MarkMatchesWithMask(mark, mark),
				Action:  r.Jump(ChainFilterInputTProxy),
			},
		)
	}

	// Snoop DNS responses to a client directly on this host (e.g. bare metal, or a
	// host-networked workload).  Place this first as it only snoops and does not accept or
	// drop.  There are cases where we can snoop some DNS info and the packet is then dropped,
	// e.g. because of host endpoint ingress policy.  However we are still filtering on trusted
	// DNS servers, so the DNS info is trustworthy even if the packet gets dropped later by
	// policy.  Also, if we placed this after host endpoint policy processing, we might be too
	// late because of the packet already having been accepted.
	inputRules = append(inputRules, r.dnsResponseSnoopingRules("", ipVersion)...)

	// Similar rules to snoop DNS requests from a local Calico-networked client to a local
	// host-networked DNS server.
	for _, prefix := range r.WorkloadIfacePrefixes {
		log.WithField("ifacePrefix", prefix).Debug("Adding DNS request snooping rules")
		ifaceMatch := prefix + r.wildcard
		inputRules = append(inputRules, r.dnsRequestSnoopingRules(ifaceMatch, ipVersion)...)
	}

	if ipVersion == 4 && r.IPIPEnabled {
		// IPIP is enabled, filter incoming IPIP packets to ensure they come from a
		// recognised host and are going to a local address on the host.  We use the protocol
		// number rather than its name because the name is not guaranteed to be known by the kernel.
		inputRules = append(inputRules,
			generictables.Rule{
				Match: r.NewMatch().ProtocolNum(ProtoIPIP).
					SourceIPSet(r.IPSetConfigV4.NameForMainIPSet(IPSetIDAllHostNets)).
					DestAddrType(generictables.AddrTypeLocal),
				Action:  r.filterAllowAction,
				Comment: []string{"Allow IPIP packets from Calico hosts"},
			},
		)
		inputRules = append(inputRules,
			r.DropRules(r.NewMatch().ProtocolNum(ProtoIPIP), fmt.Sprintf("%s IPIP packets from non-Calico hosts", r.IptablesFilterDenyAction()))...,
		)
	}

	if ipVersion == 4 && r.IPSecEnabled {
		// IPsec is enabled, filter incoming IPSec IKE and ESP packets to ensure they come from a
		// recognised host and are going to a local address on the host.  We use the protocol
		// number for ESP packets rather than its name because the name is not guaranteed to be known by the kernel.
		// For IKE packets, only port 500 is used since there can be no NAT between the hosts.
		inputRules = append(inputRules,
			generictables.Rule{
				Match: r.NewMatch().ProtocolNum(ProtoESP).
					SourceIPSet(r.IPSetConfigV4.NameForMainIPSet(IPSetIDAllHostNets)).
					DestAddrType(generictables.AddrTypeLocal),
				Action:  r.filterAllowAction,
				Comment: []string{"Allow IPSec ESP packets from Calico hosts"},
			},
		)
		inputRules = append(inputRules,
			generictables.Rule{
				Match: r.NewMatch().ProtocolNum(ProtoUDP).
					DestPorts(PortIKE).
					SourceIPSet(r.IPSetConfigV4.NameForMainIPSet(IPSetIDAllHostNets)).
					DestAddrType(generictables.AddrTypeLocal),
				Action:  r.filterAllowAction,
				Comment: []string{"Allow IPSec IKEv2 packets from Calico hosts"},
			},
		)
		inputRules = append(inputRules,
			r.DropRules(r.NewMatch().ProtocolNum(ProtoESP), fmt.Sprintf("%s IPSec ESP packets from non-Calico hosts", r.IptablesFilterDenyAction()))...,
		)
		inputRules = append(inputRules,
			r.DropRules(r.NewMatch().ProtocolNum(ProtoUDP).DestPorts(PortIKE),
				fmt.Sprintf("%s IPSec IKE packets from non-Calico hosts", r.IptablesFilterDenyAction()))...,
		)
	}

	if ipVersion == 4 && r.VXLANEnabled {
		// IPv4 VXLAN is enabled, filter incoming VXLAN packets that match our VXLAN port to ensure they
		// come from a recognised host and are going to a local address on the host.
		inputRules = append(inputRules,
			generictables.Rule{
				Match: r.NewMatch().ProtocolNum(ProtoUDP).
					DestPorts(uint16(r.Config.VXLANPort)).
					SourceIPSet(r.IPSetConfigV4.NameForMainIPSet(IPSetIDAllVXLANSourceNets)).
					DestAddrType(generictables.AddrTypeLocal),
				Action:  r.filterAllowAction,
				Comment: []string{"Allow IPv4 VXLAN packets from allowed hosts"},
			},
			generictables.Rule{
				Match: r.NewMatch().ProtocolNum(ProtoUDP).
					DestPorts(uint16(r.Config.VXLANPort)).
					DestAddrType(generictables.AddrTypeLocal),
				Action:  r.Drop(),
				Comment: []string{"Drop IPv4 VXLAN packets from non-allowed hosts"},
			},
		)
	}

	if ipVersion == 6 && r.VXLANEnabledV6 {
		// IPv6 VXLAN is enabled, filter incoming VXLAN packets that match our VXLAN port to ensure they
		// come from a recognised host and are going to a local address on the host.
		inputRules = append(inputRules,
			generictables.Rule{
				Match: r.NewMatch().ProtocolNum(ProtoUDP).
					DestPorts(uint16(r.Config.VXLANPort)).
					SourceIPSet(r.IPSetConfigV6.NameForMainIPSet(IPSetIDAllVXLANSourceNets)).
					DestAddrType(generictables.AddrTypeLocal),
				Action:  r.filterAllowAction,
				Comment: []string{"Allow IPv6 VXLAN packets from allowed hosts"},
			},
			generictables.Rule{
				Match: r.NewMatch().ProtocolNum(ProtoUDP).
					DestPorts(uint16(r.Config.VXLANPort)).
					DestAddrType(generictables.AddrTypeLocal),
				Action:  r.IptablesFilterDenyAction(),
				Comment: []string{fmt.Sprintf("%s IPv6 VXLAN packets from non-allowed hosts", r.IptablesFilterDenyAction())},
			},
		)
	}

	inputRules = append(inputRules, r.FilterInputChainAllowWG(ipVersion, r.Config, r.filterAllowAction)...)

	if ipVersion == 4 && r.EgressIPEnabled && !r.BPFEnabled {
		// Auto-allow VXLAN traffic destined to egress.calico.
		// Such traffic has destination of the local host and expected udp port.
		// Therefore we need to explicitly accept it in INPUT chain.
		inputRules = append(inputRules,
			generictables.Rule{
				Match: r.NewMatch().ProtocolNum(ProtoUDP).
					DestPorts(uint16(r.Config.EgressIPVXLANPort)).
					DestAddrType(generictables.AddrTypeLocal),
				Action:  r.filterAllowAction,
				Comment: []string{"Allow VXLAN UDP traffic to egress clients"},
			},
		)
		// Auto-allow egress gateways health probes.
		inputRules = append(inputRules, generictables.Rule{
			Match: r.NewMatch().ProtocolNum(ProtoTCP).DestAddrType(generictables.AddrTypeLocal).SourceIPPortSet(
				r.IPSetConfigV4.NameForMainIPSet(IPSetIDAllEGWHealthPorts)),
			Action:  r.filterAllowAction,
			Comment: []string{"Accept egress gateway health port probe traffic"},
		})

	}

	if r.KubeIPVSSupportEnabled {
		// Check if packet belongs to forwarded traffic. (e.g. part of an ipvs connection).
		// If it is, set endpoint mark and skip "to local host" rules below.
		inputRules = append(inputRules,
			generictables.Rule{
				Action: r.ClearMark(r.MarkEndpoint),
			},
			generictables.Rule{
				Action: r.Jump(ChainForwardCheck),
			},
			generictables.Rule{
				Match:  r.NewMatch().MarkNotClear(r.MarkEndpoint),
				Action: r.Return(),
			},
		)
	}

	// Apply our policy to packets coming from workload endpoints.
	for _, prefix := range r.WorkloadIfacePrefixes {
		log.WithField("ifacePrefix", prefix).Debug("Adding workload match rules")
		ifaceMatch := prefix + r.wildcard
		inputRules = append(inputRules, generictables.Rule{
			Match:  r.NewMatch().InInterface(ifaceMatch),
			Action: r.GoTo(ChainWorkloadToHost),
		})
	}

	// Now we only have ingress host endpoint processing to do.  The ingress host endpoint may
	// have already accepted this packet in the raw or mangle table.  In that case, accept the
	// packet immediately here too.
	inputRules = append(inputRules, r.acceptAlreadyAccepted()...)

	// Apply host endpoint policy.
	inputRules = append(inputRules,
		generictables.Rule{
			Action: r.ClearMark(r.allCalicoMarkBits()),
		},
		generictables.Rule{
			Action: r.Jump(ChainDispatchFromHostEndpoint),
		},
		generictables.Rule{
			Match:   r.NewMatch().MarkSingleBitSet(r.MarkAccept),
			Action:  r.filterAllowAction,
			Comment: []string{"Host endpoint policy accepted packet."},
		},
	)

	return &generictables.Chain{
		Name:  ChainFilterInput,
		Rules: inputRules,
	}
}

func (r *DefaultRuleRenderer) ICMPv6Filter(action generictables.Action) []generictables.Rule {
	var rules []generictables.Rule

	// For IPv6, we need to allow certain ICMP traffic from workloads in order to act
	// as a router.  Note: we do this before the policy chains, so we're bypassing the egress
	// rules for this traffic.  While that might be unexpected, it makes sure that the user
	// doesn't cut off their own connectivity in subtle ways that they shouldn't have to worry
	// about.
	//
	// - 130: multicast listener query.
	// - 131: multicast listener report.
	// - 132: multicast listener done.
	// - 133: router solicitation, which an endpoint uses to request
	//        configuration information rather than waiting for an
	//        unsolicited router advertisement.
	// - 135: neighbor solicitation.
	// - 136: neighbor advertisement.
	for _, icmpType := range []uint8{130, 131, 132, 133, 135, 136} {
		rules = append(rules, generictables.Rule{
			Match: r.NewMatch().
				ProtocolNum(ProtoICMPv6).
				ICMPV6Type(icmpType),
			Action: action,
		})
	}

	return rules
}

func (r *DefaultRuleRenderer) filterWorkloadToHostChain(ipVersion uint8) *generictables.Chain {
	var rules []generictables.Rule

	if ipVersion == 6 {
		rules = r.ICMPv6Filter(r.filterAllowAction)
	}

	if r.OpenStackSpecialCasesEnabled {
		log.Info("Adding OpenStack special-case rules.")
		if ipVersion == 4 && r.OpenStackMetadataIP != nil {
			// For OpenStack compatibility, we support a special-case to allow incoming traffic
			// to the OpenStack metadata IP/port.
			// TODO(smc) Long-term, it'd be nice if the OpenStack plugin programmed a policy to
			// do this instead.
			log.WithField("ip", r.OpenStackMetadataIP).Info(
				"OpenStack metadata IP specified, installing special-case rule.")
			rules = append(rules, generictables.Rule{
				Match: r.NewMatch().
					Protocol("tcp").
					DestNet(r.OpenStackMetadataIP.String()).
					DestPorts(r.OpenStackMetadataPort),
				Action: r.filterAllowAction,
			})
		}

		// Again, for OpenStack compatibility, allow certain protocols.
		// TODO(smc) Long-term, it'd be nice if the OpenStack plugin programmed a policy to
		// do this instead.
		dhcpSrcPort := uint16(68)
		dhcpDestPort := uint16(67)
		if ipVersion == 6 {
			dhcpSrcPort = uint16(546)
			dhcpDestPort = uint16(547)
		}
		dnsDestPort := uint16(53)
		rules = append(rules,
			generictables.Rule{
				Match: r.NewMatch().
					Protocol("udp").
					SourcePorts(dhcpSrcPort).
					DestPorts(dhcpDestPort),
				Action: r.filterAllowAction,
			},
			generictables.Rule{
				Match: r.NewMatch().
					Protocol("udp").
					DestPorts(dnsDestPort),
				Action: r.filterAllowAction,
			},
		)
	}

	// Now send traffic to the policy chains to apply the egress policy.
	rules = append(rules, generictables.Rule{
		Action: r.Jump(ChainFromWorkloadDispatch),
	})

	// If the dispatch chain accepts the packet, it returns to us here.  Apply the configured
	// action.  Note: we may have done work above to allow the packet and then end up dropping
	// it here.  We can't optimize that away because there may be other rules (such as log
	// rules in the policy).
	for _, action := range r.inputAcceptActions {
		rules = append(rules, generictables.Rule{
			Action:  action,
			Comment: []string{"Configured DefaultEndpointToHostAction"},
		})
	}

	return &generictables.Chain{
		Name:  ChainWorkloadToHost,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) failsafeInChain(table string, ipVersion uint8) *generictables.Chain {
	rules := []generictables.Rule{}

	for _, protoPort := range r.FailsafeInboundHostPorts {
		rule := generictables.Rule{
			Match: r.NewMatch().
				Protocol(protoPort.Protocol).
				DestPorts(protoPort.Port),
			Action: r.Allow(),
		}

		if protoPort.Net != "" {
			ip, _, err := cnet.ParseCIDROrIP(protoPort.Net)
			if err != nil {
				log.WithError(err).Error("Failed to parse CIDR in inbound failsafe rule. Skipping failsafe rule")
				continue
			}
			if int(ipVersion) == ip.Version() {
				rule.Match = r.NewMatch().
					Protocol(protoPort.Protocol).
					DestPorts(protoPort.Port).
					SourceNet(protoPort.Net)
			} else {
				continue // don't add the rule
			}
		}
		rules = append(rules, rule)
	}

	if table == "raw" {
		// We're in the raw table, before conntrack, so we need to allow response traffic.
		// Otherwise, it could fall through to some doNotTrack policy and half of the connection
		// would get untracked.  If we ACCEPT here then the traffic falls through to the filter
		// table, where it'll only be accepted if there's a conntrack entry.
		for _, protoPort := range r.FailsafeOutboundHostPorts {
			rule := generictables.Rule{
				Match: r.NewMatch().
					Protocol(protoPort.Protocol).
					SourcePorts(protoPort.Port),
				Action: r.Allow(),
			}

			if protoPort.Net != "" {
				ip, _, err := cnet.ParseCIDROrIP(protoPort.Net)
				if err != nil {
					log.WithError(err).Error("Failed to parse CIDR in inbound failsafe rule. Skipping failsafe rule")
					continue
				}
				if int(ipVersion) == ip.Version() {
					rule.Match = r.NewMatch().
						Protocol(protoPort.Protocol).
						SourcePorts(protoPort.Port).
						SourceNet(protoPort.Net)
				} else {
					continue // don't add the rule
				}
			}
			rules = append(rules, rule)
		}
	}

	return &generictables.Chain{
		Name:  ChainFailsafeIn,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) failsafeOutChain(table string, ipVersion uint8) *generictables.Chain {
	rules := []generictables.Rule{}

	for _, protoPort := range r.FailsafeOutboundHostPorts {
		rule := generictables.Rule{
			Match: r.NewMatch().
				Protocol(protoPort.Protocol).
				DestPorts(protoPort.Port),
			Action: r.Allow(),
		}

		if protoPort.Net != "" {
			ip, _, err := cnet.ParseCIDROrIP(protoPort.Net)
			if err != nil {
				log.WithError(err).Error("Failed to parse CIDR in outbound failsafe rule. Skipping failsafe rule")
				continue
			}
			if int(ipVersion) == ip.Version() {
				rule.Match = r.NewMatch().
					Protocol(protoPort.Protocol).
					DestPorts(protoPort.Port).
					DestNet(protoPort.Net)
			} else {
				continue // don't add the rule
			}
		}
		rules = append(rules, rule)
	}

	if table == "raw" {
		// We're in the raw table, before conntrack, so we need to allow response traffic.
		// Otherwise, it could fall through to some doNotTrack policy and half of the connection
		// would get untracked.  If we ACCEPT here then the traffic falls through to the filter
		// table, where it'll only be accepted if there's a conntrack entry.
		for _, protoPort := range r.FailsafeInboundHostPorts {
			rule := generictables.Rule{
				Match: r.NewMatch().
					Protocol(protoPort.Protocol).
					SourcePorts(protoPort.Port),
				Action: r.Allow(),
			}

			if protoPort.Net != "" {
				ip, _, err := cnet.ParseCIDROrIP(protoPort.Net)
				if err != nil {
					log.WithError(err).Error("Failed to parse CIDR in outbound failsafe rule. Skipping failsafe rule")
					continue
				}
				if int(ipVersion) == ip.Version() {
					rule.Match = r.NewMatch().
						Protocol(protoPort.Protocol).
						SourcePorts(protoPort.Port).
						DestNet(protoPort.Net)
				} else {
					continue // don't add the rule
				}
			}
			rules = append(rules, rule)
		}
	}

	return &generictables.Chain{
		Name:  ChainFailsafeOut,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) filterFromHEP(ipVersion uint8) []generictables.Rule {
	return []generictables.Rule{
		{
			// we're clearing all our mark bits to minimise non-determinism caused by rules in other chains.
			// We exclude the accept bit because we use that to communicate from the raw/pre-dnat chains.
			// Similarly, the IPsec bit is used across multiple tables.
			Action: r.ClearMark(r.allCalicoMarkBits() &^ (r.MarkAccept | r.MarkIPsec)),
		},
		{
			// Apply forward policy for the incoming Host endpoint if accept bit is clear which means the packet
			// was not accepted in a previous raw or pre-DNAT chain.
			Match:  r.NewMatch().MarkClear(r.MarkAccept),
			Action: r.Jump(ChainDispatchFromHostEndPointForward),
		},
	}
}

func (r *DefaultRuleRenderer) StaticFilterForwardChains(ipVersion uint8) []*generictables.Chain {
	rules := []generictables.Rule{}

	// generictables.Rules for filter forward chains dispatches the packet to our dispatch chains if it is going
	// to/from an interface that we're responsible for.  Note: the dispatch chains represent "allow"
	// by returning to this chain for further processing; this is required to handle traffic that
	// is going between endpoints on the same host.  In that case we need to apply the egress policy
	// for one endpoint and the ingress policy for the other.
	//
	// Packets will be accepted if they passed through both workload and host endpoint policy
	// and were returned.

	// Snoop DNS messages to or from a local workload.  Place this first as it only snoops and
	// does not accept or drop.  There are cases where we can snoop some DNS info and the packet
	// is then dropped, e.g. because of host endpoint ingress policy.  However we are still
	// filtering on trusted DNS servers, so the DNS info is trustworthy even if the packet gets
	// dropped later by policy.  Also, if we placed this after host endpoint policy processing,
	// we might be too late because of the packet already having been accepted.
	for _, prefix := range r.WorkloadIfacePrefixes {
		log.WithField("ifacePrefix", prefix).Debug("Adding DNS snooping rules")
		ifaceMatch := prefix + r.wildcard
		rules = append(rules, r.dnsResponseSnoopingRules(ifaceMatch, ipVersion)...)
		rules = append(rules, r.dnsRequestSnoopingRules(ifaceMatch, ipVersion)...)
	}

	// Jump to from-host-endpoint dispatch chains.
	rules = append(rules,
		generictables.Rule{
			// we're clearing all our mark bits to minimise non-determinism caused by rules in other chains.
			// We exclude the accept bit because we use that to communicate from the raw/pre-dnat chains.
			Action: r.ClearMark(r.allCalicoMarkBits() &^ r.MarkAccept),
		},
		generictables.Rule{
			// Apply forward policy for the incoming Host endpoint if accept bit is clear which means the packet
			// was not accepted in a previous raw or pre-DNAT chain.
			Match:  r.NewMatch().MarkClear(r.MarkAccept),
			Action: r.Jump(ChainDispatchFromHostEndPointForward),
		},
	)

	// Jump to workload dispatch chains.
	for _, prefix := range r.WorkloadIfacePrefixes {
		log.WithField("ifacePrefix", prefix).Debug("Adding workload match rules")
		ifaceMatch := prefix + r.wildcard
		rules = append(rules,
			generictables.Rule{
				Match:  r.NewMatch().InInterface(ifaceMatch),
				Action: r.Jump(ChainFromWorkloadDispatch),
			},
			generictables.Rule{
				Match:  r.NewMatch().OutInterface(ifaceMatch),
				Action: r.Jump(ChainToWorkloadDispatch),
			},
		)
	}

	// Jump to to-host-endpoint dispatch chains.
	rules = append(rules,
		generictables.Rule{
			// Apply forward policy for the outgoing host endpoint.
			Action: r.Jump(ChainDispatchToHostEndpointForward),
		},
	)

	// Jump to chain for blocking service CIDR loops.
	rules = append(rules,
		generictables.Rule{
			Action: r.Jump(ChainCIDRBlock),
		},
	)

	return []*generictables.Chain{{
		Name:  ChainFilterForward,
		Rules: rules,
	}}
}

func (r *DefaultRuleRenderer) dnsResponseSnoopingRules(ifaceMatch string, ipVersion uint8) (rules []generictables.Rule) {
	for _, server := range r.DNSTrustedServers {
		if (ipVersion == 4) && strings.Contains(server.IP, ":") {
			continue
		}
		if (ipVersion == 6) && !strings.Contains(server.IP, ":") {
			continue
		}
		var baseMatch generictables.MatchCriteria
		if ifaceMatch != "" {
			// DNS response FORWARD/OUTPUT to Calico-networked client workload: match on workload prefix.
			baseMatch = r.NewMatch().OutInterface(ifaceMatch)
		} else {
			// DNS response INPUT to host-networked client workload, so there is no outgoing interface.
			baseMatch = r.NewMatch()
		}
		if r.IsDNSPolicyModeDelayDNSResponse(r.nft) && r.DNSPacketsNfqueueID != 0 {
			// We are delaying the DNS response by queueing the response packet.
			rules = append(rules,
				generictables.Rule{
					Match: baseMatch.Protocol("udp").
						ConntrackState("ESTABLISHED").
						ConntrackOrigDstPort(server.Port).
						ConntrackOrigDst(server.IP),
					Action: r.NfqueueWithBypass(r.DNSPacketsNfqueueID),
				},
			)
		} else if r.IsDNSPolicyModeInline(r.nft) {
			// We are parsing the DNS response inline by passing the response packet to a BPF Parser.
			// BPF parser, parses the DNS response and fills the BPF IPSets.
			// Add an NFLOG rule to snoop responses to felix.
			rules = append(rules,
				generictables.Rule{
					Match: baseMatch.Protocol("udp").
						ConntrackState("ESTABLISHED").
						ConntrackOrigDstPort(server.Port).
						ConntrackOrigDst(server.IP).BPFProgram(bpfdefs.IPTDNSParserProg(r.BPFLogLevel)),
					Action: r.Jump(
						ChainDNSLog,
					),
				},
			)
		} else {
			// We are not delaying the DNS response, so just add an NFLOG rule to snoop responses.
			rules = append(rules,
				generictables.Rule{
					Match: baseMatch.Protocol("udp").
						ConntrackState("ESTABLISHED").
						ConntrackOrigDstPort(server.Port).
						ConntrackOrigDst(server.IP),
					Action: r.Jump(
						ChainDNSLog,
					),
				},
			)
		}
	}
	return
}

// Similar rules for snooping DNS requests, which we do only so that we can access the timestamp on
// each request and hence calculate the latency of each DNS request/response pair.
func (r *DefaultRuleRenderer) dnsRequestSnoopingRules(ifaceMatch string, ipVersion uint8) (rules []generictables.Rule) {
	for _, server := range r.DNSTrustedServers {
		if (ipVersion == 4) && strings.Contains(server.IP, ":") {
			continue
		}
		if (ipVersion == 6) && !strings.Contains(server.IP, ":") {
			continue
		}
		var baseMatch generictables.MatchCriteria
		if ifaceMatch != "" {
			// DNS request FORWARD/INPUT from a Calico-networked client workload: match on workload prefix.
			baseMatch = r.NewMatch().InInterface(ifaceMatch)
		} else {
			// DNS request OUTPUT from a host-networked client workload, so there is no incoming interface.
			baseMatch = r.NewMatch()
		}
		rules = append(rules,
			generictables.Rule{
				Match: baseMatch.Protocol("udp").
					ConntrackState("NEW").
					ConntrackOrigDstPort(server.Port).
					ConntrackOrigDst(server.IP),
				Action: r.Jump(
					ChainDNSLog,
				),
			},
		)
	}
	return
}

// StaticFilterForwardAppendRules returns rules which should be statically appended to the end of the filter
// table's forward chain.
func (r *DefaultRuleRenderer) StaticFilterForwardAppendRules() []generictables.Rule {
	return []generictables.Rule{
		{
			Match:   r.NewMatch().MarkSingleBitSet(r.MarkAccept),
			Action:  r.filterAllowAction,
			Comment: []string{"Policy explicitly accepted packet."},
		},
		// Set MarkAccept bit here, to indicate to our mangle-POSTROUTING chain that this is
		// forwarded traffic and should not be subject to normal host endpoint policy.
		{
			Action: r.SetMark(r.MarkAccept),
		},
	}
}

func (r *DefaultRuleRenderer) StaticFilterOutputChains(ipVersion uint8) []*generictables.Chain {
	result := []*generictables.Chain{}
	result = append(result,
		r.filterOutputChain(ipVersion),
		r.failsafeOutChain("filter", ipVersion),
	)

	if r.KubeIPVSSupportEnabled {
		result = append(result, r.StaticFilterOutputForwardEndpointMarkChain())
	}

	if r.TPROXYModeEnabled() && !r.BPFEnabled {
		result = append(result,
			&generictables.Chain{
				Name:  ChainFilterOutputTProxy,
				Rules: r.tproxyOutputPolicyRules(ipVersion),
			})
	}

	return result
}

func (r *DefaultRuleRenderer) filterOutputChain(ipVersion uint8) *generictables.Chain {
	var rules []generictables.Rule

	if r.TPROXYModeEnabled() {
		rules = append(rules,
			generictables.Rule{
				Comment: []string{"Police packets from proxy"},
				// Atm any traffic from local host that does not have a local source.
				// XXX that would not work well for nodeports if we let proxy to use local
				// XXX source instead of passing it through MASQUERADE
				Match:  r.NewMatch().NotSrcAddrType(generictables.AddrTypeLocal, false),
				Action: r.Jump(ChainFilterOutputTProxy),
			},
		)
	}

	// Accept immediately if we've already accepted this packet in the raw or mangle table.
	rules = append(rules, r.acceptAlreadyAccepted()...)

	if r.KubeIPVSSupportEnabled {
		// Special case: packets that are forwarded through IPVS hit the INPUT and OUTPUT chains
		// instead of FORWARD.  In the INPUT chain, we mark such packets with a per-interface ID.
		// Divert those packets to a chain that handles them as we would if they had hit the FORWARD
		// chain.
		//
		// We use a goto so that a RETURN from that chain will skip the rest of this chain
		// and continue execution in the parent chain (OUTPUT).
		rules = append(rules,
			generictables.Rule{
				Match:  r.NewMatch().MarkNotClear(r.MarkEndpoint),
				Action: r.GoTo(ChainForwardEndpointMark),
			},
		)
	}

	// Add rules to snoop DNS requests from a host-networked client workload.
	rules = append(rules, r.dnsRequestSnoopingRules("", ipVersion)...)

	// We don't currently police host -> endpoint according to the endpoint's ingress policy.
	// That decision is based on pragmatism; it's generally very useful to be able to contact
	// any local workload from the host and policing the traffic doesn't really protect
	// against host compromise.  If a host is compromised, then the rules could be removed!
	// However, we do apply policy to workload ingress traffic if it belongs to an IPVS connection.
	for _, prefix := range r.WorkloadIfacePrefixes {
		// If the packet is going to a workload endpoint, apply workload ingress policy if traffic
		// belongs to an IPVS connection and return at the end.
		log.WithField("ifacePrefix", prefix).Debug("Adding workload match rules")
		ifaceMatch := prefix + r.wildcard
		rules = append(rules, r.dnsResponseSnoopingRules(ifaceMatch, ipVersion)...)
		rules = append(rules,
			generictables.Rule{
				// if packet goes to a workload endpoint. set return action properly.
				Match:  r.NewMatch().OutInterface(ifaceMatch),
				Action: r.Return(),
			},
		)
	}

	// If we reach here, the packet is not going to a workload so it must be going to a
	// host endpoint. It also has no endpoint mark so it must be going from a process.

	if ipVersion == 4 && r.IPIPEnabled {
		// When IPIP is enabled, auto-allow IPIP traffic to other Calico nodes.  Without this,
		// it's too easy to make a host policy that blocks IPIP traffic, resulting in very confusing
		// connectivity problems.
		rules = append(rules,
			generictables.Rule{
				Match: r.NewMatch().ProtocolNum(ProtoIPIP).
					DestIPSet(r.IPSetConfigV4.NameForMainIPSet(IPSetIDAllHostNets)).
					SrcAddrType(generictables.AddrTypeLocal, false),
				Action:  r.filterAllowAction,
				Comment: []string{"Allow IPIP packets to other Calico hosts"},
			},
		)
	}

	if ipVersion == 4 && r.VXLANEnabled {
		// When IPv4 VXLAN is enabled, auto-allow VXLAN traffic to other Calico nodes.  Without this,
		// it's too easy to make a host policy that blocks VXLAN traffic, resulting in very confusing
		// connectivity problems.
		rules = append(rules,
			generictables.Rule{
				Match: r.NewMatch().ProtocolNum(ProtoUDP).
					DestPorts(uint16(r.Config.VXLANPort)).
					SrcAddrType(generictables.AddrTypeLocal, false).
					DestIPSet(r.IPSetConfigV4.NameForMainIPSet(IPSetIDAllVXLANSourceNets)),
				Action:  r.filterAllowAction,
				Comment: []string{"Allow IPv4 VXLAN packets to other allowed hosts"},
			},
		)
	}

	if ipVersion == 4 && r.EgressIPEnabled && !r.BPFEnabled {
		// When Egress IP is enabled, auto-allow VXLAN traffic to egress gateways with source IP
		// as host IP.
		match := r.NewMatch().ProtocolNum(ProtoUDP)
		match = match.SrcAddrType(generictables.AddrTypeLocal, false)
		match = match.
			DestPorts(
				uint16(r.EgressIPVXLANPort), // egress.calico
			)
		rules = append(rules, generictables.Rule{
			Match:   match,
			Action:  r.filterAllowAction,
			Comment: []string{"Accept VXLAN UDP traffic from egress clients"},
		})

		// Auto-allow HTTP traffic to the egress gateways health ports.
		rules = append(rules, generictables.Rule{
			Match: r.NewMatch().ProtocolNum(ProtoTCP).SrcAddrType(generictables.AddrTypeLocal, false).DestIPPortSet(
				r.IPSetConfigV4.NameForMainIPSet(IPSetIDAllEGWHealthPorts)),
			Action:  r.filterAllowAction,
			Comment: []string{"Accept egress gateway health port probe traffic"},
		})
	}

	if ipVersion == 6 && r.VXLANEnabledV6 {
		// When IPv6 VXLAN is enabled, auto-allow VXLAN traffic to other Calico nodes.  Without this,
		// it's too easy to make a host policy that blocks VXLAN traffic, resulting in very confusing
		// connectivity problems.
		rules = append(rules,
			generictables.Rule{
				Match: r.NewMatch().ProtocolNum(ProtoUDP).
					DestPorts(uint16(r.Config.VXLANPort)).
					SrcAddrType(generictables.AddrTypeLocal, false).
					DestIPSet(r.IPSetConfigV6.NameForMainIPSet(IPSetIDAllVXLANSourceNets)),
				Action:  r.filterAllowAction,
				Comment: []string{"Allow IPv6 VXLAN packets to other allowed hosts"},
			},
		)
	}

	if ipVersion == 4 && r.IPSecEnabled {
		// When IPSec is enabled, auto-allow IPSec traffic to other Calico nodes.  Without this,
		// it's too easy to make a host policy that blocks IPSec traffic, resulting in very confusing
		// connectivity problems.
		rules = append(rules,
			generictables.Rule{
				Match: r.NewMatch().ProtocolNum(ProtoESP).
					DestIPSet(r.IPSetConfigV4.NameForMainIPSet(IPSetIDAllHostNets)).
					SrcAddrType(generictables.AddrTypeLocal, false),
				Action:  r.filterAllowAction,
				Comment: []string{"Allow IPSec ESP packets to other Calico hosts"},
			},
		)

		rules = append(rules,
			generictables.Rule{
				Match: r.NewMatch().ProtocolNum(ProtoUDP).
					DestPorts(PortIKE).
					DestIPSet(r.IPSetConfigV4.NameForMainIPSet(IPSetIDAllHostNets)).
					SrcAddrType(generictables.AddrTypeLocal, false),
				Action:  r.filterAllowAction,
				Comment: []string{"Allow IPSec IKE packets to other Calico hosts"},
			},
		)
	}

	if ipVersion == 4 && r.WireguardEnabled {
		// When Wireguard is enabled, auto-allow Wireguard traffic to other Calico nodes.  Without this,
		// it's too easy to make a host policy that blocks Wireguard traffic, resulting in very confusing
		// connectivity problems.
		rules = append(rules,
			generictables.Rule{
				Match: r.NewMatch().ProtocolNum(ProtoUDP).
					DestPorts(uint16(r.Config.WireguardListeningPort)).
					// Note that we do not need to limit the destination hosts to Calico nodes because allowed peers are
					// programmed separately
					SrcAddrType(generictables.AddrTypeLocal, false),
				Action:  r.filterAllowAction,
				Comment: []string{"Allow outgoing IPv4 Wireguard packets"},
			},
		)
	}

	if ipVersion == 6 && r.WireguardEnabledV6 {
		// When Wireguard is enabled, auto-allow Wireguard traffic to other Calico nodes.  Without this,
		// it's too easy to make a host policy that blocks Wireguard traffic, resulting in very confusing
		// connectivity problems.
		rules = append(rules,
			generictables.Rule{
				Match: r.NewMatch().ProtocolNum(ProtoUDP).
					DestPorts(uint16(r.Config.WireguardListeningPortV6)).
					// Note that we do not need to limit the destination hosts to Calico nodes because allowed peers are
					// programmed separately
					SrcAddrType(generictables.AddrTypeLocal, false),
				Action:  r.filterAllowAction,
				Comment: []string{"Allow outgoing IPv6 Wireguard packets"},
			},
		)
	}

	// Matching on conntrack status varies by table type.
	notDNATMatch := r.NewMatch()
	if m, ok := notDNATMatch.(nftables.NFTMatchCriteria); ok {
		notDNATMatch = m.NotConntrackStatus("DNAT")
	} else {
		notDNATMatch = notDNATMatch.NotConntrackState("DNAT")
	}

	// Apply host endpoint policy to traffic that has not been DNAT'd.  In the DNAT case we
	// can't correctly apply policy here because the packet's OIF is still the OIF from a
	// routing lookup based on the pre-DNAT destination IP; Linux will shortly update it based
	// on the new destination IP, but that hasn't happened yet.  Instead, in the DNAT case, we
	// apply host endpoint in the mangle POSTROUTING chain; see StaticManglePostroutingChain for
	// that.
	rules = append(rules,
		generictables.Rule{
			Action: r.ClearMark(r.allCalicoMarkBits()),
		},
		generictables.Rule{
			Match:  notDNATMatch,
			Action: r.Jump(ChainDispatchToHostEndpoint),
		},
		generictables.Rule{
			Match:   r.NewMatch().MarkSingleBitSet(r.MarkAccept),
			Action:  r.filterAllowAction,
			Comment: []string{"Host endpoint policy accepted packet."},
		},
	)

	return &generictables.Chain{
		Name:  ChainFilterOutput,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) StaticNATTableChains(ipVersion uint8) (chains []*generictables.Chain) {
	chains = append(chains, r.StaticNATPreroutingChains(ipVersion)...)
	chains = append(chains, r.StaticNATPostroutingChains(ipVersion)...)
	chains = append(chains, r.StaticNATOutputChains(ipVersion)...)
	return
}

func (r *DefaultRuleRenderer) StaticNATPreroutingChains(ipVersion uint8) []*generictables.Chain {
	rules := []generictables.Rule{
		{
			Action: r.Jump(ChainFIPDnat),
		},
	}

	if ipVersion == 4 && r.OpenStackSpecialCasesEnabled && r.OpenStackMetadataIP != nil {
		rules = append(rules, generictables.Rule{
			Match: r.NewMatch().
				Protocol("tcp").
				DestPorts(80).
				DestNet("169.254.169.254/32"),
			Action: r.DNAT(
				r.OpenStackMetadataIP.String(),
				r.OpenStackMetadataPort,
			),
		})
	}

	chains := []*generictables.Chain{{
		Name:  ChainNATPrerouting,
		Rules: rules,
	}}

	if ipVersion == 4 && r.EgressIPEnabled {
		var egressRules []generictables.Rule

		// Set mark on first packet from a pod to destinations other than pod or host.
		egressRules = append(egressRules,
			generictables.Rule{
				Match: r.NewMatch().
					SourceIPSet(r.IPSetConfigV4.NameForMainIPSet(IPSetIDAllPools)).
					NotDestIPSet(r.IPSetConfigV4.NameForMainIPSet(IPSetIDAllPools)).
					NotDestIPSet(r.IPSetConfigV4.NameForMainIPSet(IPSetIDAllHostNets)),
				Action:  r.SetMaskedMark(r.MarkEgress, r.MarkEgress),
				Comment: []string{"Set mark for egress packet"},
			},
		)

		// Save mark to connmark which is used to be restored for subsequent packets in the same connection.
		egressRules = append(egressRules,
			generictables.Rule{
				Match:   r.NewMatch().MarkSingleBitSet(r.MarkEgress),
				Action:  r.SaveConnMark(r.MarkEgress),
				Comment: []string{"Save mark for egress connection"},
			},
		)

		chains = append(chains, &generictables.Chain{Name: ChainNATPreroutingEgress, Rules: egressRules})
	}

	return chains
}

func (r *DefaultRuleRenderer) StaticNATPostroutingChains(ipVersion uint8) []*generictables.Chain {
	rules := []generictables.Rule{
		{
			Action: r.Jump(ChainFIPSnat),
		},
		{
			Action: r.Jump(ChainNATOutgoing),
		},
	}

	if r.BPFEnabled {
		// Prepend a BPF SNAT rule.
		rules = append([]generictables.Rule{
			{
				Comment: []string{"BPF loopback SNAT"},
				Match:   r.NewMatch().MarkMatchesWithMask(tcdefs.MarkSeenMASQ, tcdefs.MarkSeenMASQMask),
				Action:  r.Masq(""),
			},
		}, rules...)
	}

	var tunnelIfaces []string

	if ipVersion == 4 && r.IPIPEnabled && len(r.IPIPTunnelAddress) > 0 {
		tunnelIfaces = append(tunnelIfaces, dataplanedefs.IPIPIfaceName)
	}
	if ipVersion == 4 && r.VXLANEnabled && len(r.VXLANTunnelAddress) > 0 {
		tunnelIfaces = append(tunnelIfaces, dataplanedefs.VXLANIfaceNameV4)
	}
	if ipVersion == 6 && r.VXLANEnabledV6 && len(r.VXLANTunnelAddressV6) > 0 {
		tunnelIfaces = append(tunnelIfaces, dataplanedefs.VXLANIfaceNameV6)
	}
	if ipVersion == 4 && r.WireguardEnabled && len(r.WireguardInterfaceName) > 0 {
		// Wireguard is assigned an IP dynamically and without restarting Felix. Just add the interface if we have
		// wireguard enabled.
		tunnelIfaces = append(tunnelIfaces, r.WireguardInterfaceName)
	}
	if ipVersion == 6 && r.WireguardEnabledV6 && len(r.WireguardInterfaceNameV6) > 0 {
		// Wireguard is assigned an IP dynamically and without restarting Felix. Just add the interface if we have
		// wireguard enabled.
		tunnelIfaces = append(tunnelIfaces, r.WireguardInterfaceNameV6)
	}

	for _, tunnel := range tunnelIfaces {
		// Add a rule to catch packets that are being sent down a tunnel from an
		// incorrect local IP address of the host and NAT them to use the tunnel IP as its
		// source.  This happens if:
		//
		// - the user explicitly binds their socket to the wrong source IP accidentally
		// - the user sends traffic to, for example, a Kubernetes service IP, which is
		//   implemented via NAT instead of routing, leading the kernel to choose the
		//   wrong source IP.
		//
		// We NAT the source of the packet to use the tunnel IP.  We assume that
		// non-local IPs have been correctly routed.  Since Calico-assigned IPs are
		// non-local (because they're down a veth), they won't get caught by the rule.
		// Other remote sources will only reach the tunnel if they're being NATted
		// already (for example, a Kubernetes "NodePort").  The kernel will then
		// choose the correct source on its own.
		rules = append(rules, generictables.Rule{
			Match: r.NewMatch().
				// Only match packets going out the tunnel.
				OutInterface(tunnel).
				// Match packets that don't have the correct source address.  This
				// matches local addresses (i.e. ones assigned to this host)
				// limiting the match to the output interface (which we matched
				// above as the tunnel).  Avoiding embedding the IP address lets
				// us use a static rule, which is easier to manage.
				NotSrcAddrType(generictables.AddrTypeLocal, true).
				// Only match if the IP is also some local IP on the box.  This
				// prevents us from matching packets from workloads, which are
				// remote as far as the routing table is concerned.
				SrcAddrType(generictables.AddrTypeLocal, false),
			Action: r.Masq(""),
		})
	}
	return []*generictables.Chain{{
		Name:  ChainNATPostrouting,
		Rules: rules,
	}}
}

func (r *DefaultRuleRenderer) StaticNATOutputChains(ipVersion uint8) []*generictables.Chain {
	rules := []generictables.Rule{
		{
			Match:  r.NewMatch(),
			Action: r.Jump(ChainFIPDnat),
		},
	}

	return []*generictables.Chain{{
		Name:  ChainNATOutput,
		Rules: rules,
	}}
}

func (r *DefaultRuleRenderer) StaticMangleTableChains(ipVersion uint8) (chains []*generictables.Chain) {
	if ipVersion == 4 && r.EgressIPEnabled {
		var rules []generictables.Rule

		// Prerouting chain for egress ip
		// Restore ConnMark for pod traffic.
		rules = append(rules,
			generictables.Rule{
				Match:   r.NewMatch().SourceIPSet(r.IPSetConfigV4.NameForMainIPSet(IPSetIDAllPools)),
				Action:  r.RestoreConnMark(r.MarkEgress),
				Comment: []string{"Restore connmark for pod traffic"},
			},
		)

		// When external network is enabled, packets from EGW to the external network is marked with 0x80000.
		// The mark must be restored for the return traffic, if the packet is from external and destined to
		// EGW pod.
		rules = append(rules,
			generictables.Rule{
				Match: r.NewMatch().
					DestIPSet(r.IPSetConfigV4.NameForMainIPSet(IPSetIDAllPools)),
				Action:  r.RestoreConnMark(r.MarkEgress),
				Comment: []string{"Restore connmark for external traffic to EGW"},
			},
		)

		chains = append(chains, &generictables.Chain{Name: ChainManglePreroutingEgress, Rules: rules})

		// Postrouting chain for egress ip
		// Fill checksum for packet leaving egress.calico interface and going into tunnel device.
		tunnelDeviceName := "None"
		if r.VXLANEnabled {
			tunnelDeviceName = "vxlan.calico"
		} else if r.IPIPEnabled {
			tunnelDeviceName = "tunl0"
		}

		if tunnelDeviceName != "None" {
			chains = append(chains, &generictables.Chain{
				Name: ChainManglePostroutingEgress,
				Rules: []generictables.Rule{{
					Match:  r.NewMatch().MarkSingleBitSet(r.MarkEgress).OutInterface(tunnelDeviceName),
					Action: r.Checksum(),
				}},
			})
		}

		chains = append(chains, &generictables.Chain{
			Name: ChainManglePreroutingEgressInbound,
			Rules: []generictables.Rule{
				// mark returning egress traffic for RPF purposes
				{
					Match: r.NewMatch().InInterface("egress.calico"),
					Action: r.SetMaskedMark(
						r.MarkEgress,
						r.MarkEgress,
					),
					Comment: []string{"Set mark for returning egress packet"},
				},
			},
		})
	}

	if r.TPROXYModeEnabled() {
		mark := r.MarkProxy

		// We match in this chain if the packet is either on an established
		// connection that is proxied and marked accordingly or not.
		tproxyEstablRules := []generictables.Rule{
			{
				Comment: []string{"Clean upstream mark, not needed anymore"},
				Match:   r.NewMatch(),
				Action:  r.ClearMark(r.TPROXYUpstreamConnMark),
			},
			{
				Comment: []string{"Restore proxy mark from connection if not set"},
				Match:   r.NewMatch().MarkClear(mark),
				Action:  r.RestoreConnMark(mark),
			},
			{
				Comment: []string{"Accept packets destined to proxy on existing connection"},
				Match:   r.NewMatch().MarkMatchesWithMask(mark, mark),
				Action:  r.Allow(), // No further processing to match TPROXY behavior.
			},
		}

		chains = append(chains, &generictables.Chain{Name: ChainManglePreroutingTProxyEstabl, Rules: tproxyEstablRules})

		tproxyRules := []generictables.Rule{
			{
				Comment: []string{"Mark the connection so that subsequent packets go to proxy"},
				Action:  r.SetConnmark(mark, mark),
			},
			{
				Comment: []string{"Divert the TCP connection to proxy"},
				Match:   r.NewMatch().Protocol("tcp"),
				Action:  r.TProxy(mark, mark, uint16(r.TPROXYPort)),
			},
			{
				Comment: []string{"Unmark non-proxied"},
				Action:  r.SetConnmark(0, mark),
			},
		}

		chains = append(chains, &generictables.Chain{Name: ChainManglePreroutingTProxySvc, Rules: tproxyRules})

		nameForIPSet := func(ipsetID string) string {
			if ipVersion == 4 {
				return r.IPSetConfigV4.NameForMainIPSet(ipsetID)
			} else {
				return r.IPSetConfigV6.NameForMainIPSet(ipsetID)
			}
		}

		chains = append(chains, &generictables.Chain{
			Name: ChainManglePreroutingTProxySelect,
			Rules: []generictables.Rule{
				{
					Comment: []string{"Proxy selected services"},
					Match:   r.NewMatch().DestIPPortSet(nameForIPSet(tproxydefs.ServiceIPsIPSet)),
					Action:  r.Jump(ChainManglePreroutingTProxySvc),
				},
				{
					Comment: []string{"Proxy selected pods"},
					Match: r.NewMatch().
						Protocol("tcp").
						DestIPSet(nameForIPSet(tproxydefs.ApplicationLayerPolicyIPSet)),
					Action: r.Jump(ChainManglePreroutingTProxySvc),
				},
				{
					Comment: []string{"Proxy selected nodeports"},
					Match: r.NewMatch().
						Protocol("tcp").
						DestAddrType(generictables.AddrTypeLocal).
						// We use a single port ipset for both V4 and V6
						DestPortSet(r.IPSetConfigV4.NameForMainIPSet(tproxydefs.NodePortsIPSet)),
					Action: r.Jump(ChainManglePreroutingTProxyNP),
				},
			},
		})

		tproxyRules = nil

		if r.KubernetesProvider == config.ProviderEKS && r.EKSPrimaryENI != "" {
			tproxyRules = []generictables.Rule{{
				Comment: []string{"Set the EKS nodeport mark that we bypass"},
				Match: r.NewMatch().
					InInterface(r.EKSPrimaryENI).
					DestAddrTypeLimitIfaceIn(generictables.AddrTypeLocal),
				Action: r.SetConnmark(0x80, 0x80),
			}}
		}

		tproxyRules = append(tproxyRules,
			generictables.Rule{
				Comment: []string{"Divert the TCP connection to proxy"},
				Match:   r.NewMatch().Protocol("tcp").DestAddrType(generictables.AddrTypeLocal),
				Action:  r.TProxy(mark, mark, uint16(r.TPROXYPort+1)),
			},
			generictables.Rule{
				Comment: []string{"Divert the TCP connection to proxy"},
				Match:   r.NewMatch().Protocol("udp").DestAddrType(generictables.AddrTypeLocal),
				Action:  r.TProxy(mark, mark, uint16(r.TPROXYPort+1)),
			},
		)

		chains = append(chains, &generictables.Chain{Name: ChainManglePreroutingTProxyNP, Rules: tproxyRules})

		upMark := r.TPROXYUpstreamConnMark

		rules := []generictables.Rule{
			{
				// Proxied connections for regular services do not have
				// local source nor destination. This is how we can easily
				// identify the upstream part and mark it.
				Comment: []string{"Mark any non-local connection as local for return"},
				Action:  r.SetConnmark(mark, mark),
			},
			{
				Comment: []string{"Save tproxy upstream mark in conntrack if set"},
				// XXX use the same mark in conntrack for now
				Match:  r.NewMatch().MarkMatchesWithMask(upMark, upMark),
				Action: r.SetConnmark(upMark, upMark),
			},
			{
				// Proxied connections that are pod-to-self need to be masqueraded
				Comment: []string{"MASQ proxied pod-service-self"},
				Match:   r.NewMatch().SourceDestSet(nameForIPSet(tproxydefs.PodSelf)),
				Action:  r.SetMaskedMark(r.KubeMasqueradeMark, r.KubeMasqueradeMark),
			},
		}

		if r.KubernetesProvider == config.ProviderEKS {
			rules = append(rules, generictables.Rule{
				Comment: []string{"Restore EKS nodeport routing mark"},
				Action:  r.RestoreConnMark(0x80),
			})
		}

		chains = append(chains, &generictables.Chain{
			Name:  ChainMangleOutputTProxy,
			Rules: rules,
		})

		rules = []generictables.Rule{
			{
				Comment: []string{"Restore tproxy upstream mark in conntrack if not set"},
				// XXX use the same mark in conntrack for now
				Match:  r.NewMatch().MarkClear(upMark),
				Action: r.RestoreConnMark(upMark),
			},
			{
				// If it is upstream and from local address, it means it is
				// retuning traffic from local host and we need to turn it back
				// to the proxy on the local host.
				Comment: []string{"If upstream and from local address, accept it"},
				Match:   r.NewMatch().MarkMatchesWithMask(upMark, upMark).ConntrackState("RELATED,ESTABLISHED"),
				Action:  r.Jump(ChainManglePreroutingTProxyEstabl),
			},
		}

		chains = append(chains, &generictables.Chain{
			Name:  ChainMangleOutputTProxyHostNet,
			Rules: rules,
		})
	}

	chains = append(chains,
		r.failsafeInChain("mangle", ipVersion),
		r.failsafeOutChain("mangle", ipVersion),
		r.StaticManglePreroutingChain(ipVersion),
		r.StaticManglePostroutingChain(ipVersion),
		r.StaticMangleOutputChain(ipVersion),
	)

	return chains
}

func (r *DefaultRuleRenderer) StaticManglePreroutingChain(ipVersion uint8) *generictables.Chain {
	rules := []generictables.Rule{}

	// First check if the connection is being proxied.
	if r.TPROXYModeEnabled() {
		rules = append(rules,
			generictables.Rule{
				Comment: []string{"Check if should be proxied when established"},
				Match:   r.NewMatch().ConntrackState("RELATED,ESTABLISHED"),
				Action:  r.Jump(ChainManglePreroutingTProxyEstabl),
			},
		)
	}

	// ACCEPT or RETURN immediately if packet matches an existing connection.  Note that we also
	// have a rule like this at the start of each pre-endpoint chain; the functional difference
	// with placing this rule here is that it will also apply to packets that may be unrelated
	// to Calico (i.e. not to or from Calico workloads, and not via Calico host endpoints).  We
	// think this is appropriate in the mangle table here - whereas we don't have a rule like
	// this in the filter table - because the mangle table is generally not used (except by us)
	// for dropping packets, so it is very unlikely that we would be circumventing someone
	// else's rule to drop a packet.  (And in that case, the user can configure
	// IptablesMangleAllowAction to be RETURN.)
	rules = append(rules,
		generictables.Rule{
			Match:  r.NewMatch().ConntrackState("RELATED,ESTABLISHED"),
			Action: r.mangleAllowAction,
		},
	)

	// Or if we've already accepted this packet in the raw table.
	rules = append(rules,
		generictables.Rule{
			Match:  r.NewMatch().MarkSingleBitSet(r.MarkAccept),
			Action: r.mangleAllowAction,
		},
	)

	// Now dispatch to host endpoint chain for the incoming interface.
	rules = append(rules,
		generictables.Rule{
			Action: r.Jump(ChainDispatchFromHostEndpoint),
		},
		// Following that...  If the packet was explicitly allowed by a pre-DNAT policy, it
		// will have MarkAccept set.  If the packet was denied, it will have been dropped
		// already.  If the incoming interface isn't one that we're policing, or the packet
		// isn't governed by any pre-DNAT policy on that interface, it will fall through to
		// here without any Calico bits set.

		// In the MarkAccept case, we ACCEPT or RETURN according to
		// IptablesMangleAllowAction.
		generictables.Rule{
			Match:   r.NewMatch().MarkSingleBitSet(r.MarkAccept),
			Action:  r.mangleAllowAction,
			Comment: []string{"Host endpoint policy accepted packet."},
		},
	)

	if r.TPROXYModeEnabled() {
		rules = append(rules,
			generictables.Rule{
				Comment: []string{"Check if it is a new connection to be proxied"},
				Action:  r.Jump(ChainManglePreroutingTProxySelect),
			},
		)
	}

	return &generictables.Chain{
		Name:  ChainManglePrerouting,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) StaticMangleOutputChain(ipVersion uint8) *generictables.Chain {
	rules := []generictables.Rule{}

	if r.TPROXYModeEnabled() {
		rules = append(rules,
			generictables.Rule{
				Comment: []string{"Process non-local connections as proxied"},
				Match:   r.NewMatch().NotSrcAddrType(generictables.AddrTypeLocal, false),
				Action:  r.Jump(ChainMangleOutputTProxy),
			},
			generictables.Rule{
				Comment: []string{"Check local connections for host networked workloads"},
				Match:   r.NewMatch().SrcAddrType(generictables.AddrTypeLocal, false),
				Action:  r.Jump(ChainMangleOutputTProxyHostNet),
			},
		)
	}

	return &generictables.Chain{
		Name:  ChainMangleOutput,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) StaticManglePostroutingChain(ipVersion uint8) *generictables.Chain {
	rules := []generictables.Rule{}

	if r.IstioAmbientModeEnabled {
		var meshIPSet string
		if ipVersion == 4 {
			meshIPSet = r.IPSetConfigV4.NameForMainIPSet(IPSetIDAllIstioWEPs)
		} else {
			meshIPSet = r.IPSetConfigV6.NameForMainIPSet(IPSetIDAllIstioWEPs)
		}
		for _, ifacePrefix := range r.WorkloadIfacePrefixes {
			rules = append(rules,
				generictables.Rule{
					Match: r.NewMatch().
						Protocol("tcp").
						ConntrackState("NEW").
						OutInterface(ifacePrefix + r.wildcard).
						DestIPSet(meshIPSet).
						SourceIPSet(meshIPSet),
					Action: r.DSCP(r.IstioDSCPMark),
				})
		}
	}

	// Note, we use RETURN as the Allow action in this chain, rather than ACCEPT because the
	// mangle table is typically used, if at all, for packet manipulations that might need to
	// apply to our allowed traffic.

	if !r.BPFEnabled {
		ipConf := r.ipSetConfig(ipVersion)
		allIPsSetName := ipConf.NameForMainIPSet(IPSetIDAllPools)
		localHostSetName := ipConf.NameForMainIPSet(IPSetIDThisHostIPs)
		dscpSetName := ipConf.NameForMainIPSet(IPSetIDDSCPEndpoints)
		rules = append(
			rules, generictables.Rule{
				Match: r.NewMatch().
					SourceIPSet(dscpSetName).
					NotDestIPSet(allIPsSetName).
					NotDestIPSet(localHostSetName),
				Action:  r.Jump(ChainEgressDSCP),
				Comment: []string{"set dscp for traffic leaving cluster."},
			},
		)
	}

	// Allow immediately if MarkAccept is set.  Our filter-FORWARD chain sets this for
	// any packets that reach the end of that chain.  The principle is that we don't want to
	// apply normal host endpoint policy to forwarded traffic.
	rules = append(rules, generictables.Rule{
		Match:  r.NewMatch().MarkSingleBitSet(r.MarkAccept),
		Action: r.Return(),
	})

	// Similarly, avoid applying normal host endpoint policy to IPVS-forwarded traffic.
	// IPVS-forwarded traffic is identified by having a non-zero endpoint ID in the
	// MarkEndpoint bits.  Note: we only need this check for when net.ipv4.vs.conntrack
	// is enabled.  When net.ipv4.vs.conntrack is disabled (which is the default),
	// IPVS-forwarded traffic will fail the ConntrackState("DNAT") match below, and so would
	// avoid normal host endpoint policy anyway.  But it doesn't hurt to have this additional
	// check even when not strictly needed.
	if r.KubeIPVSSupportEnabled {
		rules = append(rules,
			generictables.Rule{
				Match:  r.NewMatch().MarkNotClear(r.MarkEndpoint),
				Action: r.Return(),
			},
		)
	}

	// At this point we know that the packet is not forwarded, so it must be originated by a
	// host-based process or host-networked pod.

	// The similar sequence in filterOutputChain has rules here to allow IPIP and VXLAN traffic.
	// We don't need those rules here because the encapsulated traffic won't match `--ctstate
	// DNAT` and so we won't try applying HEP policy to it anyway.

	// The similar sequence in filterOutputChain has rules here to detect traffic to local
	// workloads, and to return early in that case.  We don't need those rules here because
	// ChainDispatchToHostEndpoint also checks for traffic to a local workload, and avoids
	// applying any host endpoint policy in that case.  Search for "Skip egress WHEP" in
	// dispatch.go, to see that.

	// Apply host endpoint policy to non-forwarded traffic that has been DNAT'd.  We do this
	// here, rather than in filter-OUTPUT, because Linux is weird: when a host-originated packet
	// is DNAT'd (typically in nat-OUTPUT), its destination IP is changed immediately, but Linux
	// does not recalculate the outgoing interface (OIF) until AFTER the filter-OUTPUT chain.
	// The OIF has been recalculated by the time we hit THIS chain (mangle-POSTROUTING), so we
	// can reliably apply host endpoint policy here.

	// Matching on conntrack status varies by table type.
	dnatMatch := r.NewMatch()
	if m, ok := dnatMatch.(nftables.NFTMatchCriteria); ok {
		dnatMatch = m.ConntrackStatus("DNAT")
	} else {
		dnatMatch = dnatMatch.ConntrackState("DNAT")
	}

	rules = append(rules,
		generictables.Rule{
			Action: r.ClearMark(r.allCalicoMarkBits()),
		},
		generictables.Rule{
			Match:  dnatMatch,
			Action: r.Jump(ChainDispatchToHostEndpoint),
		},
		generictables.Rule{
			Match:   r.NewMatch().MarkSingleBitSet(r.MarkAccept),
			Action:  r.Return(),
			Comment: []string{"Host endpoint policy accepted packet."},
		},
	)

	return &generictables.Chain{
		Name:  ChainManglePostrouting,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) StaticRawTableChains(ipVersion uint8) []*generictables.Chain {
	return []*generictables.Chain{
		r.failsafeInChain("raw", ipVersion),
		r.failsafeOutChain("raw", ipVersion),
		r.StaticRawPreroutingChain(ipVersion, nil),
		r.WireguardIncomingMarkChain(),
		r.StaticRawOutputChain(0, ipVersion, nil),

		// Include the DNS log chain; depending on configuration it may not get
		// used but the iptables layer will filter it out if it's not needed.
		r.dnsLogChain(),
	}
}

func (r *DefaultRuleRenderer) StaticBPFModeRawChains(ipVersion uint8,
	wgEncryptHost, bypassHostConntrack bool,
) []*generictables.Chain {
	var rawRules []generictables.Rule

	if ((r.WireguardEnabled && len(r.WireguardInterfaceName) > 0) || (r.WireguardEnabledV6 && len(r.WireguardInterfaceNameV6) > 0)) && wgEncryptHost {
		// Set a mark on packets coming from any interface except for lo, wireguard, or pod veths to ensure the RPF
		// check allows it.
		log.Debug("Adding Wireguard iptables rule chain")
		rawRules = append(rawRules, generictables.Rule{
			Match:  nil,
			Action: r.Jump(ChainSetWireguardIncomingMark),
		})
	}

	rawRules = append(rawRules,
		generictables.Rule{
			// Return, i.e. no-op, if bypass mark is not set.
			Match:   r.NewMatch().MarkMatchesWithMask(tcdefs.MarkSeenBypassXDP, 0xffffffff),
			Action:  r.GoTo(ChainRawBPFUntrackedPolicy),
			Comment: []string{"Jump to target for packets with Bypass mark"},
		},
		generictables.Rule{
			Match:   r.NewMatch().DestAddrType(generictables.AddrTypeLocal),
			Action:  r.SetMaskedMark(tcdefs.MarkSeenSkipFIB, tcdefs.MarkSeenSkipFIB),
			Comment: []string{"Mark traffic towards the host - it is TRACKed"},
		},
	)

	if bypassHostConntrack {
		rawRules = append(rawRules,
			generictables.Rule{
				Match:   r.NewMatch().NotDestAddrType(generictables.AddrTypeLocal),
				Action:  r.GoTo(ChainRawUntrackedFlows),
				Comment: []string{"Check if forwarded traffic needs to be TRACKed"},
			},
		)
	}

	rawPreroutingChain := &generictables.Chain{
		Name:  ChainRawPrerouting,
		Rules: rawRules,
	}

	// BPF Untracked Flow Rules:
	var bpfUntrackedFlowRules []generictables.Rule
	if bypassHostConntrack {
		// Iterate all BPF interfaces forced to track packets and append rule.
		for _, interfaceName := range r.BPFForceTrackPacketsFromIfaces {
			if len(interfaceName) > 0 {
				bpfUntrackedFlowRules = append(bpfUntrackedFlowRules,
					generictables.Rule{
						Match:   r.NewMatch().InInterface(interfaceName),
						Action:  r.Return(),
						Comment: []string{"Track interface " + interfaceName},
					},
				)
			}
		}

		switch ipVersion {
		case 4:
			bpfUntrackedFlowRules = append(bpfUntrackedFlowRules,
				generictables.Rule{
					Match:   r.NewMatch().DestNet("169.254.0.0/16"),
					Action:  r.Return(),
					Comment: []string{"link-local"},
				},
			)
		case 6:
			bpfUntrackedFlowRules = append(bpfUntrackedFlowRules,
				generictables.Rule{
					Match:   r.NewMatch().DestNet("fe80::/10"),
					Action:  r.Return(),
					Comment: []string{"link-local"},
				},
			)
		}

		bpfUntrackedFlowRules = append(bpfUntrackedFlowRules,
			generictables.Rule{
				Match:   r.NewMatch().MarkMatchesWithMask(tcdefs.MarkSeenSkipFIB, tcdefs.MarkSeenSkipFIB),
				Action:  r.Return(),
				Comment: []string{"MarkSeenSkipFIB Mark"},
			},
			generictables.Rule{
				Match:   r.NewMatch().MarkMatchesWithMask(tcdefs.MarkSeenFallThrough, tcdefs.MarkSeenFallThroughMask),
				Action:  r.Return(),
				Comment: []string{"MarkSeenFallThrough Mark"},
			},
			generictables.Rule{
				Match:   r.NewMatch().MarkMatchesWithMask(tcdefs.MarkSeenMASQ, tcdefs.MarkSeenMASQMask),
				Action:  r.Return(),
				Comment: []string{"MarkSeenMASQ Mark"},
			},
			generictables.Rule{
				Match:   r.NewMatch().MarkMatchesWithMask(tcdefs.MarkSeenNATOutgoing, tcdefs.MarkSeenNATOutgoingMask),
				Action:  r.Return(),
				Comment: []string{"MarkSeenNATOutgoing Mark"},
			},
			generictables.Rule{
				Action: r.NoTrack(),
			},
		)
	}
	bpfUntrackedFlowChain := &generictables.Chain{
		Name:  ChainRawUntrackedFlows,
		Rules: bpfUntrackedFlowRules,
	}

	xdpUntrackedPoliciesChain := &generictables.Chain{
		Name: ChainRawBPFUntrackedPolicy,
		Rules: []generictables.Rule{
			// At this point we know bypass mark is set, which means that the packet has
			// been explicitly allowed by untracked ingress policy (XDP).  We should
			// clear the mark so as not to affect any FROM_HOST processing.  There
			// shouldn't be any FROM_HOST processing, because untracked policy is only
			// intended for traffic to/from the host.  But if the traffic is in fact
			// forwarded and goes to or through another endpoint, it's better to enforce
			// that endpoint's policy than to accidentally skip it because of the BYPASS
			// mark.  Note that we can clear the mark without stomping on anyone else's
			// logic because no one else's iptables should have had a chance to execute
			// yet.
			{
				Action: r.SetMaskedMark(0, tcdefs.MarksMask),
			},
			// Now ensure that the packet is not tracked.
			{
				Action: r.NoTrack(),
			},
		},
	}

	chains := []*generictables.Chain{
		rawPreroutingChain,
		xdpUntrackedPoliciesChain,
		bpfUntrackedFlowChain,
		r.failsafeOutChain("raw", ipVersion),
		r.WireguardIncomingMarkChain(),
	}

	chains = append(chains, r.StaticRawOutputChain(tcdefs.MarkSeenBypass, ipVersion, nil))

	// Include the DNS log chain; depending on configuration it may not get
	// used but the iptables layer will filter it out if it's not needed.
	chains = append(chains, r.dnsLogChain())

	return chains
}

func (r *DefaultRuleRenderer) StaticRawPreroutingChain(ipVersion uint8, nodeLocalDNSAddrs []config.ServerPort) *generictables.Chain {
	rules := []generictables.Rule{}

	// For safety, clear all our mark bits before we start.  (We could be in append mode and
	// another process' rules could have left the mark bit set.)
	rules = append(rules, generictables.Rule{Match: r.NewMatch(), Action: r.ClearMark(r.allCalicoMarkBits())})

	if len(nodeLocalDNSAddrs) > 0 {
		log.Debug("Adding nodelocaldns iptables rule to cali-PREROUTING")
		rules = append(rules, r.nodeLocalDNSPreRoutingRules(nodeLocalDNSAddrs)...)
	}

	// Set a mark on encapsulated packets coming from WireGuard to ensure the RPF check allows it
	if ((r.WireguardEnabled && len(r.WireguardInterfaceName) > 0) || (r.WireguardEnabledV6 && len(r.WireguardInterfaceNameV6) > 0)) && r.WireguardEncryptHostTraffic {
		log.Debug("Adding Wireguard iptables rule")
		rules = append(rules, generictables.Rule{
			Match:  r.NewMatch(),
			Action: r.Jump(ChainSetWireguardIncomingMark),
		})
	}

	// Ensure VXLAN UDP Flows are not tracked in conntrack.
	// VXLAN uses different source ports in each direction so
	// tracking results in unreplied flows.
	if (ipVersion == 4 && r.VXLANEnabled) || (ipVersion == 6 && r.VXLANEnabledV6) {
		log.Debug("Adding VXLAN NOTRACK iptables rule to PREROUTING chain")
		rules = append(rules, generictables.Rule{
			Match:  r.NewMatch().Protocol("udp").DestPort(uint16(r.VXLANPort)),
			Action: r.NoTrack(),
		})
	}

	// Set a mark on the packet if it's from a workload interface.
	markFromWorkload := r.MarkScratch0
	for _, ifacePrefix := range r.WorkloadIfacePrefixes {
		rules = append(rules, generictables.Rule{
			Match:  r.NewMatch().InInterface(ifacePrefix + r.wildcard),
			Action: r.SetMark(markFromWorkload),
		})
	}

	if ipVersion == 4 && r.MarkIPsec != 0 {
		rules = append(rules, generictables.Rule{
			Match:  r.NewMatch().MarkSingleBitSet(markFromWorkload),
			Action: r.SetMark(r.MarkIPsec),
		})
	}

	if ipVersion == 4 {
		// Apply strict RPF check to packets from workload interfaces (except for egress
		// gateways).  This prevents workloads from spoofing their IPs.  Note:
		// non-privileged containers can't usually spoof but privileged containers and VMs
		// can.
		rules = append(rules, generictables.Rule{
			Match:  r.NewMatch().MarkSingleBitSet(markFromWorkload),
			Action: r.Jump(ChainFromWorkloadDispatch),
		})
	} else {
		// Send workload traffic to a specific chain to skip the rpf check for some workloads
		rules = append(rules,
			generictables.Rule{
				Match:  r.NewMatch().MarkMatchesWithMask(markFromWorkload, markFromWorkload),
				Action: r.Jump(ChainRpfSkip),
			})

		// Apply strict RPF check to packets from workload interfaces.  This prevents
		// workloads from spoofing their IPs.  Note: non-privileged containers can't usually
		// spoof but privileged containers and VMs can.
		//
		rules = append(rules,
			r.RPFilter(ipVersion, markFromWorkload, markFromWorkload, r.OpenStackSpecialCasesEnabled)...)
	}

	rules = append(rules,
		// Send non-workload traffic to the untracked policy chains.
		generictables.Rule{
			Match:  r.NewMatch().MarkClear(markFromWorkload),
			Action: r.Jump(ChainDispatchFromHostEndpoint),
		},
		// Then, if the packet was marked as allowed, accept it.  Packets also return here
		// without the mark bit set if the interface wasn't one that we're policing.  We
		// let those packets fall through to the user's policy.
		generictables.Rule{
			Match:  r.NewMatch().MarkSingleBitSet(r.MarkAccept),
			Action: r.Allow(),
		},
	)

	return &generictables.Chain{
		Name:  ChainRawPrerouting,
		Rules: rules,
	}
}

// RPFilter returns rules that implement RPF
func (r *DefaultRuleRenderer) RPFilter(ipVersion uint8, mark, mask uint32, openStackSpecialCasesEnabled bool) []generictables.Rule {
	rules := make([]generictables.Rule, 0, 2)

	// For OpenStack, allow DHCP v4 packets with source 0.0.0.0.  These must be allowed before
	// checking against the iptables rp_filter module, because the rp_filter module in some
	// kernel versions does not allow for DHCP with source 0.0.0.0 (whereas the rp_filter sysctl
	// setting _did_).
	//
	// Initial DHCP requests (DHCPDISCOVER) have source 0.0.0.0, and so will be allowed through
	// by the specific rule just following.  Later DHCP requests (DHCPREQUEST) may have source
	// 0.0.0.0, or the client's actual IP (as discovered through the DHCP process).  The 0.0.0.0
	// case will again be allowed by the following specific rule; the actual IP case should be
	// allowed by the general RPF check.  (Ref: https://www.ietf.org/rfc/rfc2131.txt page 37)
	//
	// Note: in DHCPv6, the initial request is sent with a link-local IPv6 address, which should
	// pass RPF, hence no special case is needed for DHCPv6.
	//
	// Here we are only focussing on anti-spoofing, and note that we ACCEPT a correct packet for
	// the current raw table, but don't mark it (with our Accept bit) as automatically accepted
	// for later tables.  Hence - for the policy level - we still have an OpenStack DHCP special
	// case again in filterWorkloadToHostChain.
	if openStackSpecialCasesEnabled && ipVersion == 4 {
		log.Info("Add OpenStack special-case rule for DHCP with source 0.0.0.0")
		rules = append(rules,
			generictables.Rule{
				Match: r.NewMatch().
					Protocol("udp").
					SourceNet("0.0.0.0").
					SourcePorts(68).
					DestPorts(67),
				Action: r.Allow(),
			},
		)
	}

	baseMatch := r.NewMatch()
	if mark == 0 {
		// No mark to match; we're in a context where we already know we're coming from a
		// workload interface.
	} else {
		// Match on mark to check we're coming from a workload interface.
		baseMatch = baseMatch.MarkMatchesWithMask(mark, mask)
	}
	rules = append(rules, r.DropRules(baseMatch.RPFCheckFailed())...)

	return rules
}

func (r *DefaultRuleRenderer) allCalicoMarkBits() uint32 {
	return r.MarkAccept |
		r.MarkPass |
		r.MarkScratch0 |
		r.MarkScratch1 |
		r.MarkIPsec |
		r.MarkDNSPolicy
}

func (r *DefaultRuleRenderer) WireguardIncomingMarkChain() *generictables.Chain {
	rules := []generictables.Rule{
		{
			Match:  r.NewMatch().InInterface("lo"),
			Action: r.Return(),
		},
		{
			Match:  r.NewMatch().InInterface(r.WireguardInterfaceName),
			Action: r.Return(),
		},
		{
			Match:  r.NewMatch().InInterface(r.WireguardInterfaceNameV6),
			Action: r.Return(),
		},
	}

	for _, ifacePrefix := range r.WorkloadIfacePrefixes {
		rules = append(rules, generictables.Rule{
			Match:  r.NewMatch().InInterface(fmt.Sprintf("%s%s", ifacePrefix, r.wildcard)),
			Action: r.Return(),
		})
	}

	rules = append(rules, generictables.Rule{Match: nil, Action: r.SetMark(r.WireguardMark)})

	return &generictables.Chain{
		Name:  ChainSetWireguardIncomingMark,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) nodeLocalDNSPreRoutingRules(nodeLocalDNSAddrs []config.ServerPort) []generictables.Rule {
	rules := []generictables.Rule{}

	for _, server := range nodeLocalDNSAddrs {
		dnsLocalIPRule := []generictables.Rule{
			{
				Match: r.NewMatch().Protocol("udp").
					DestPorts(server.Port).
					DestNet(server.IP),
				Action: r.Jump(
					ChainDNSLog,
				),
			},
			{
				Match: r.NewMatch().Protocol("tcp").
					DestPorts(server.Port).
					DestNet(server.IP),
				Action: r.Jump(
					ChainDNSLog,
				),
			},
		}

		rules = append(rules, dnsLocalIPRule...)
	}

	return rules
}

func (r *DefaultRuleRenderer) dnsLogChain() *generictables.Chain {
	rules := []generictables.Rule{
		{
			Action: r.Nflog(
				NFLOGDomainGroup,
				DNSActionPrefix,
				// Don't truncate the DNS packet when copying it to Felix.
				-1,
			),
		},
	}
	if r.MarkSkipDNSPolicyNfqueue != 0 {
		rules = append(rules, generictables.Rule{
			Action: r.SetMaskedMark(
				r.MarkSkipDNSPolicyNfqueue,
				r.MarkSkipDNSPolicyNfqueue,
			),
		})
	}
	return &generictables.Chain{
		Name:  ChainDNSLog,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) StaticRawOutputChain(tcBypassMark uint32, ipVersion uint8, nodeLocalDNSAddrs []config.ServerPort) *generictables.Chain {
	rules := []generictables.Rule{
		// For safety, clear all our mark bits before we start.  (We could be in
		// append mode and another process' rules could have left the mark bit set.)
		{Action: r.ClearMark(r.allCalicoMarkBits())},
		// Then, jump to the untracked policy chains.
		{Action: r.Jump(ChainDispatchToHostEndpoint)},
		// Then, if the packet was marked as allowed, accept it.  Packets also
		// return here without the mark bit set if the interface wasn't one that
		// we're policing.
	}

	if len(nodeLocalDNSAddrs) > 0 {
		log.Debug("Adding nodelocaldns iptables rule to cali-OUTPUT")
		rules = append(rules, r.nodeLocalDNSOutputRules(nodeLocalDNSAddrs)...)
	}

	// Ensure VXLAN UDP Flows are not tracked in conntrack.
	if (ipVersion == 4 && r.VXLANEnabled) || (ipVersion == 6 && r.VXLANEnabledV6) {
		log.Debug("Adding VXLAN NOTRACK iptables rule")
		rules = append(rules, generictables.Rule{
			Match:  r.NewMatch().Protocol("udp").DestPort(uint16(r.VXLANPort)),
			Action: r.NoTrack(),
		})
	}

	if tcBypassMark == 0 {
		rules = append(rules, []generictables.Rule{
			{
				Match:  r.NewMatch().MarkSingleBitSet(r.MarkAccept),
				Action: r.Allow(),
			},
		}...)
	} else {
		rules = append(rules, []generictables.Rule{
			{
				Match:  r.NewMatch().MarkSingleBitSet(r.MarkAccept),
				Action: r.SetMaskedMark(tcBypassMark, 0xffffffff),
			},
			{
				Match:  r.NewMatch().MarkMatchesWithMask(tcBypassMark, 0xffffffff),
				Action: r.Allow(),
			},
		}...)
	}

	return &generictables.Chain{
		Name:  ChainRawOutput,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) nodeLocalDNSOutputRules(nodeLocalDNSAddrs []config.ServerPort) []generictables.Rule {
	rules := []generictables.Rule{}
	for _, server := range nodeLocalDNSAddrs {
		dnsLocalIPRule := []generictables.Rule{
			{
				Match: r.NewMatch().Protocol("udp").
					SourcePorts(server.Port).
					SourceNet(server.IP),
				Action: r.Jump(
					ChainDNSLog,
				),
			},
			{
				Match: r.NewMatch().Protocol("tcp").
					SourcePorts(server.Port).
					SourceNet(server.IP),
				Action: r.Jump(
					ChainDNSLog,
				),
			},
		}

		rules = append(rules, dnsLocalIPRule...)
	}

	return rules
}

// DropRules combines the matchCritera and comments given in the function parameters to the drop rules calculated when
// the DefaultRenderer was constructed.
//
// If the original drop rules have MatchCriteria the matchCriteria is combined with the existing MatchCritera on the
// rule.
func (r *DefaultRuleRenderer) DropRules(matchCriteria generictables.MatchCriteria, comments ...string) []generictables.Rule {
	rules := []generictables.Rule{}

	for _, rule := range r.dropRules {
		if matchCriteria != nil {
			rule.Match = r.CombineMatches(rule.Match, matchCriteria)
		}
		rule.Comment = comments
		rules = append(rules, rule)
	}

	return rules
}

// NfqueueRuleDelayDeniedPacket combines the matchCritera and comments given in the function parameters to the delay-denied packet
// nfqueue rule calculated when the DefaultRenderer was constructed.
func (r *DefaultRuleRenderer) NfqueueRuleDelayDeniedPacket(matchCriteria generictables.MatchCriteria, comments ...string) *generictables.Rule {
	if r.nfqueueRuleDelayDeniedPacket != nil {
		nfqueueRule := *r.nfqueueRuleDelayDeniedPacket

		if matchCriteria != nil {
			nfqueueRule.Match = r.CombineMatches(nfqueueRule.Match, matchCriteria)
		}
		nfqueueRule.Comment = comments

		return &nfqueueRule
	}

	return nil
}
