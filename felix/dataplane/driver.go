// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.
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

//go:build !windows

package dataplane

import (
	"context"
	"math/bits"
	"net"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/vishvananda/netlink"
	coreV1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/clock"

	"github.com/projectcalico/calico/felix/aws"
	"github.com/projectcalico/calico/felix/bpf"
	bpfconntrack "github.com/projectcalico/calico/felix/bpf/conntrack/timeouts"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/capture"
	"github.com/projectcalico/calico/felix/collector"
	"github.com/projectcalico/calico/felix/config"
	extdataplane "github.com/projectcalico/calico/felix/dataplane/external"
	"github.com/projectcalico/calico/felix/dataplane/inactive"
	intdataplane "github.com/projectcalico/calico/felix/dataplane/linux"
	"github.com/projectcalico/calico/felix/idalloc"
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/markbits"
	"github.com/projectcalico/calico/felix/nftables"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/wireguard"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
)

func StartDataplaneDriver(
	configParams *config.Config,
	healthAggregator *health.HealthAggregator,
	collector collector.Collector,
	configChangedRestartCallback func(),
	fatalErrorCallback func(error),
	childExitedRestartCallback func(),
	ipamClient ipam.Interface,
	k8sClientSet *kubernetes.Clientset,
	lc *calc.LookupsCache,
) (DataplaneDriver, *exec.Cmd, chan *sync.WaitGroup) {
	if !configParams.IsLeader() {
		// Return an inactive dataplane, since we're not the leader.
		log.Info("Not the leader, using an inactive dataplane")
		return &inactive.InactiveDataplane{}, nil, make(chan *sync.WaitGroup)
	}

	if configParams.UseInternalDataplaneDriver {
		log.Info("Using internal (linux) dataplane driver.")
		// If kube ipvs interface is present, enable ipvs support.  In BPF mode, we bypass kube-proxy so IPVS
		// is irrelevant.
		kubeIPVSSupportEnabled := false
		if ifacemonitor.IsInterfacePresent(intdataplane.KubeIPVSInterface) {
			if configParams.BPFEnabled {
				log.Info("kube-proxy IPVS device found but we're in BPF mode, ignoring.")
			} else {
				kubeIPVSSupportEnabled = true
				log.Info("Kube-proxy in ipvs mode, enabling felix kube-proxy ipvs support.")
			}
		}
		if configChangedRestartCallback == nil || fatalErrorCallback == nil {
			log.Panic("Starting dataplane with nil callback func.")
		}

		allowedMarkBits := configParams.MarkMask()
		if configParams.BPFEnabled {
			// In BPF mode, the BPF programs use mark bits that are not configurable.  Make sure that those
			// bits are covered by our allowed mask.
			if allowedMarkBits&tcdefs.MarksMask != tcdefs.MarksMask {
				log.WithFields(
					log.Fields{
						"Name":            "felix-iptables",
						"MarkMask":        allowedMarkBits,
						"RequiredBPFBits": tcdefs.MarksMask,
					}).Panic("IptablesMarkMask/NftablesMarkMask doesn't cover bits that are used (unconditionally) by eBPF mode.")
			}
			allowedMarkBits ^= allowedMarkBits & tcdefs.MarksMask
			log.WithField("updatedBits", allowedMarkBits).Info(
				"Removed BPF program bits from available mark bits.")
		}

		markBitsManager := markbits.NewMarkBitsManager(allowedMarkBits, "felix-iptables")

		// Allocate mark bits; only the accept, scratch-0 and Wireguard bits are used in BPF mode so we
		// avoid allocating the others to minimize the number of bits in use.

		// The accept bit is a long-lived bit used to communicate between chains.
		var markAccept, markPass, markScratch0, markScratch1, markWireguard, markEndpointNonCaliEndpoint uint32
		markAccept, _ = markBitsManager.NextSingleBitMark()

		// The pass bit is used to communicate from a policy chain up to the endpoint chain.
		markPass, _ = markBitsManager.NextSingleBitMark()

		markDrop, _ := markBitsManager.NextSingleBitMark()
		var markIPsec, markEgressIP uint32
		if configParams.IPSecEnabled() {
			log.Info("IPsec enabled, allocating a mark bit")
			markIPsec, _ = markBitsManager.NextSingleBitMark()
			if markIPsec == 0 {
				log.WithFields(log.Fields{
					"Name":     "felix-iptables",
					"MarkMask": configParams.MarkMask,
				}).Panic("Failed to allocate a mark bit for IPsec, not enough mark bits available.")
			}
		}

		// Egress mark is hard-coded in BPF mode - because then it needs to
		// interop between the BPF C code and Felix golang code - but dynamically
		// allocated in iptables mode.
		if configParams.BPFEnabled {
			markEgressIP = tcdefs.MarkEgress
		} else if configParams.EgressIPCheckEnabled() {
			log.Info("Egress IP enabled, allocating a mark bit")
			markEgressIP, _ = markBitsManager.NextSingleBitMark()
			if markEgressIP == 0 {
				log.WithFields(log.Fields{
					"Name":     "felix-iptables",
					"MarkMask": configParams.MarkMask,
				}).Panic("Failed to allocate a mark bit for Egress IP, not enough mark bits available.")
			}
		}

		// Scratch bits are short-lived bits used for calculating multi-rule results.
		markScratch0, _ = markBitsManager.NextSingleBitMark()
		markScratch1, _ = markBitsManager.NextSingleBitMark()

		if configParams.WireguardEnabled || configParams.WireguardEnabledV6 {
			log.Info("Wireguard enabled, allocating a mark bit")
			markWireguard, _ = markBitsManager.NextSingleBitMark()
			if markWireguard == 0 {
				log.WithFields(
					log.Fields{
						"Name":     "felix-iptables",
						"MarkMask": allowedMarkBits,
					}).Panic("Failed to allocate a mark bit for wireguard, not enough mark bits available.")
			}
		}

		var markProxy, k8sMasqMark uint32

		k8sMasqMark = 1 << configParams.KubeMasqueradeBit

		if configParams.TPROXYModeEnabled() {
			log.Infof("TPROXYMode %s, allocating a mark bit", configParams.TPROXYMode)
			markProxy, _ = markBitsManager.NextSingleBitMark()
			if markProxy == 0 {
				log.WithFields(log.Fields{
					"Name":     "felix-iptables",
					"MarkMask": allowedMarkBits,
				}).Panic("Failed to allocate a mark bit for proxy, not enough mark bits available.")
			}
		}

		if markAccept == 0 || markScratch0 == 0 || markPass == 0 || markScratch1 == 0 {
			log.WithFields(
				log.Fields{
					"Name":     "felix-iptables",
					"MarkMask": allowedMarkBits,
				}).Panic("Not enough mark bits available.")
		}

		var markDNSPolicy, markSkipDNSPolicyNfqueue uint32
		// If this is in BPF mode don't even try to allocate DNS policy bits. The markDNSPolicy bit is used as a flag
		// to enable the DNS policy enhancements and we don't want to somehow have the markDNSPolicy bit set without
		// the markSkipDNSPolicyNfqueue.
		if !configParams.BPFEnabled {
			markDNSPolicy, _ = markBitsManager.NextSingleBitMark()
			markSkipDNSPolicyNfqueue, _ = markBitsManager.NextSingleBitMark()
		}

		// Mark bits for endpoint mark. Currently Felix takes the rest bits from mask available for use.
		markEndpointMark, allocated := markBitsManager.NextBlockBitsMark(markBitsManager.AvailableMarkBitCount())
		if kubeIPVSSupportEnabled {
			if allocated == 0 {
				log.WithFields(
					log.Fields{
						"Name":     "felix-iptables",
						"MarkMask": allowedMarkBits,
					}).Panic("Not enough mark bits available for endpoint mark.")
			}
			// Take lowest bit position (position 1) from endpoint mark mask reserved for non-calico endpoint.
			markEndpointNonCaliEndpoint = uint32(1) << uint(bits.TrailingZeros32(markEndpointMark))
		}
		log.WithFields(log.Fields{
			"acceptMark":           markAccept,
			"passMark":             markPass,
			"dropMark":             markDrop,
			"scratch0Mark":         markScratch0,
			"scratch1Mark":         markScratch1,
			"endpointMark":         markEndpointMark,
			"endpointMarkNonCali":  markEndpointNonCaliEndpoint,
			"wireguardMark":        markWireguard,
			"ipsecMark":            markIPsec,
			"egressMark":           markEgressIP,
			"dnsPolicyMark":        markDNSPolicy,
			"skipDNSPolicyNfqueue": markSkipDNSPolicyNfqueue,
		}).Info("Calculated iptables mark bits")

		// Create a routing table manager. There are certain components that should take specific indices in the range
		// to simplify table tidy-up.
		reservedTables := []idalloc.IndexRange{{Min: 253, Max: 255}}
		routeTableIndexAllocator := idalloc.NewIndexAllocator(configParams.RouteTableIndices(), reservedTables)

		// Always allocate the wireguard table index (even when not enabled). This ensures we can tidy up entries
		// if wireguard is disabled after being previously enabled.
		var wireguardEnabled bool
		var wireguardTableIndex int
		if idx, err := routeTableIndexAllocator.GrabIndex(); err == nil {
			log.Debugf("Assigned IPv4 wireguard table index: %d", idx)
			wireguardEnabled = configParams.WireguardEnabled
			wireguardTableIndex = idx
		} else {
			log.WithError(err).Warning("Unable to assign table index for IPv4 wireguard")
		}

		var wireguardEnabledV6 bool
		var wireguardTableIndexV6 int
		if idx, err := routeTableIndexAllocator.GrabIndex(); err == nil {
			log.Debugf("Assigned IPv6 wireguard table index: %d", idx)
			wireguardEnabledV6 = configParams.WireguardEnabledV6
			wireguardTableIndexV6 = idx
		} else {
			log.WithError(err).Warning("Unable to assign table index for IPv6 wireguard")
		}

		// Extract node labels from the hosts such they could be referenced later
		// e.g. Topology Aware Hints.
		felixHostname := configParams.FelixHostname

		var felixNodeZone string
		if k8sClientSet != nil {

			// Code defensively here as k8sClientSet may be nil for certain FV tests e.g. OpenStack
			felixNode, err := k8sClientSet.CoreV1().Nodes().Get(context.Background(), felixHostname, v1.GetOptions{})
			if err != nil {
				log.WithFields(
					log.Fields{
						"FelixHostname": felixHostname,
					}).Info("Unable to extract node labels from Felix host")
			}

			felixNodeZone = felixNode.Labels[coreV1.LabelTopologyZone]
		}

		dpConfig := intdataplane.Config{
			Hostname:           felixHostname,
			NodeZone:           felixNodeZone,
			FloatingIPsEnabled: strings.EqualFold(configParams.FloatingIPs, string(apiv3.FloatingIPsEnabled)),
			IfaceMonitorConfig: ifacemonitor.Config{
				InterfaceExcludes: configParams.InterfaceExclude,
				ResyncInterval:    configParams.InterfaceRefreshInterval,
				NetlinkTimeout:    configParams.NetlinkTimeoutSecs,
			},
			RulesConfig: rules.Config{
				FlowLogsEnabled:       configParams.FlowLogsEnabled(),
				NFTables:              configParams.NFTablesMode == "Enabled",
				WorkloadIfacePrefixes: configParams.InterfacePrefixes(),

				IPSetConfigV4: ipsets.NewIPVersionConfig(
					ipsets.IPFamilyV4,
					rules.IPSetNamePrefix,
					rules.AllHistoricIPSetNamePrefixes,
					rules.LegacyV4IPSetNames,
				),
				IPSetConfigV6: ipsets.NewIPVersionConfig(
					ipsets.IPFamilyV6,
					rules.IPSetNamePrefix,
					rules.AllHistoricIPSetNamePrefixes,
					nil,
				),

				KubeNodePortRanges:     configParams.KubeNodePortRanges,
				KubeIPVSSupportEnabled: kubeIPVSSupportEnabled,
				KubernetesProvider:     configParams.KubernetesProvider(),

				OpenStackSpecialCasesEnabled: configParams.OpenstackActive(),
				OpenStackMetadataIP:          net.ParseIP(configParams.MetadataAddr),
				OpenStackMetadataPort:        uint16(configParams.MetadataPort),

				DNSPolicyMode:         apiv3.DNSPolicyMode(configParams.DNSPolicyMode),
				NFTablesDNSPolicyMode: apiv3.NFTablesDNSPolicyMode(configParams.NFTablesDNSPolicyMode),
				DNSPolicyNfqueueID:    int64(configParams.DNSPolicyNfqueueID),
				DNSPacketsNfqueueID:   int64(configParams.DNSPacketsNfqueueID),

				MarkAccept:               markAccept,
				MarkPass:                 markPass,
				MarkDrop:                 markDrop,
				MarkIPsec:                markIPsec,
				MarkEgress:               markEgressIP,
				MarkScratch0:             markScratch0,
				MarkScratch1:             markScratch1,
				MarkEndpoint:             markEndpointMark,
				MarkNonCaliEndpoint:      markEndpointNonCaliEndpoint,
				MarkDNSPolicy:            markDNSPolicy,
				MarkSkipDNSPolicyNfqueue: markSkipDNSPolicyNfqueue,

				VXLANEnabled:   configParams.Encapsulation.VXLANEnabled,
				VXLANEnabledV6: configParams.Encapsulation.VXLANEnabledV6,
				VXLANPort:      configParams.VXLANPort,
				VXLANVNI:       configParams.VXLANVNI,

				IPIPEnabled:            configParams.Encapsulation.IPIPEnabled,
				FelixConfigIPIPEnabled: configParams.IpInIpEnabled,
				IPIPTunnelAddress:      configParams.IpInIpTunnelAddr,
				VXLANTunnelAddress:     configParams.IPv4VXLANTunnelAddr,
				VXLANTunnelAddressV6:   configParams.IPv6VXLANTunnelAddr,

				IPSecEnabled: configParams.IPSecEnabled(),

				EgressIPEnabled:   configParams.EgressIPCheckEnabled(),
				EgressIPVXLANPort: configParams.EgressIPVXLANPort,
				EgressIPVXLANVNI:  configParams.EgressIPVXLANVNI,
				EgressIPInterface: "egress.calico",

				AllowVXLANPacketsFromWorkloads: configParams.AllowVXLANPacketsFromWorkloads,
				AllowIPIPPacketsFromWorkloads:  configParams.AllowIPIPPacketsFromWorkloads,

				WireguardEnabled:            configParams.WireguardEnabled,
				WireguardEnabledV6:          configParams.WireguardEnabledV6,
				WireguardInterfaceName:      configParams.WireguardInterfaceName,
				WireguardInterfaceNameV6:    configParams.WireguardInterfaceNameV6,
				WireguardMark:               markWireguard,
				WireguardListeningPort:      configParams.WireguardListeningPort,
				WireguardListeningPortV6:    configParams.WireguardListeningPortV6,
				WireguardEncryptHostTraffic: configParams.WireguardHostEncryptionEnabled,
				RouteSource:                 configParams.RouteSource,

				LogPrefix:                 configParams.LogPrefix,
				IncludeDropActionInPrefix: configParams.LogDropActionOverride,
				ActionOnDrop:              configParams.DropActionOverride,
				EndpointToHostAction:      configParams.DefaultEndpointToHostAction,
				FilterAllowAction:         configParams.IptablesFilterAllowAction,
				MangleAllowAction:         configParams.IptablesMangleAllowAction,
				FilterDenyAction:          configParams.IptablesFilterDenyAction,

				FailsafeInboundHostPorts:  configParams.FailsafeInboundHostPorts,
				FailsafeOutboundHostPorts: configParams.FailsafeOutboundHostPorts,

				DisableConntrackInvalid: configParams.DisableConntrackInvalidCheck,

				NATPortRange:                       configParams.NATPortRange,
				IptablesNATOutgoingInterfaceFilter: configParams.IptablesNATOutgoingInterfaceFilter,
				DNSTrustedServers:                  configParams.DNSTrustedServers,
				NATOutgoingAddress:                 configParams.NATOutgoingAddress,
				NATOutgoingExclusions:              configParams.NATOutgoingExclusions,
				BPFEnabled:                         configParams.BPFEnabled,
				BPFLogLevel:                        configParams.BPFLogLevel,
				BPFForceTrackPacketsFromIfaces:     replaceWildcards(configParams.NFTablesMode == "Enabled", configParams.BPFForceTrackPacketsFromIfaces),
				ServiceLoopPrevention:              configParams.ServiceLoopPrevention,

				TPROXYMode:             configParams.TPROXYMode,
				TPROXYPort:             configParams.TPROXYPort,
				TPROXYUpstreamConnMark: configParams.TPROXYUpstreamConnMark,
				MarkProxy:              markProxy,
				KubeMasqueradeMark:     k8sMasqMark,
			},

			Wireguard: wireguard.Config{
				Enabled:             wireguardEnabled,
				EnabledV6:           wireguardEnabledV6,
				ListeningPort:       configParams.WireguardListeningPort,
				ListeningPortV6:     configParams.WireguardListeningPortV6,
				FirewallMark:        int(markWireguard),
				RoutingRulePriority: configParams.WireguardRoutingRulePriority,
				RoutingTableIndex:   wireguardTableIndex,
				RoutingTableIndexV6: wireguardTableIndexV6,
				InterfaceName:       configParams.WireguardInterfaceName,
				InterfaceNameV6:     configParams.WireguardInterfaceNameV6,
				MTU:                 configParams.WireguardMTU,
				MTUV6:               configParams.WireguardMTUV6,
				RouteSource:         configParams.RouteSource,
				EncryptHostTraffic:  configParams.WireguardHostEncryptionEnabled,
				PersistentKeepAlive: configParams.WireguardPersistentKeepAlive,
				ThreadedNAPI:        configParams.WireguardThreadingEnabled,
				RouteSyncDisabled:   configParams.RouteSyncDisabled,
			},

			IPIPMTU:                        configParams.IpInIpMtu,
			VXLANMTU:                       configParams.VXLANMTU,
			VXLANMTUV6:                     configParams.VXLANMTUV6,
			VXLANPort:                      configParams.VXLANPort,
			IptablesBackend:                configParams.IptablesBackend,
			TableRefreshInterval:           configParams.TableRefreshInterval(),
			RouteSyncDisabled:              configParams.RouteSyncDisabled,
			RouteRefreshInterval:           configParams.RouteRefreshInterval,
			DeviceRouteSourceAddress:       configParams.DeviceRouteSourceAddress,
			DeviceRouteSourceAddressIPv6:   configParams.DeviceRouteSourceAddressIPv6,
			DeviceRouteProtocol:            netlink.RouteProtocol(configParams.DeviceRouteProtocol),
			RemoveExternalRoutes:           configParams.RemoveExternalRoutes,
			ProgramClusterRoutes:           configParams.ProgramClusterRoutesEnabled(),
			IPForwarding:                   configParams.IPForwarding,
			IPSetsRefreshInterval:          configParams.IpsetsRefreshInterval,
			IptablesPostWriteCheckInterval: configParams.IptablesPostWriteCheckIntervalSecs,
			IptablesInsertMode:             configParams.ChainInsertMode,
			IptablesLockProbeInterval:      configParams.IptablesLockProbeIntervalMillis,
			MaxIPSetSize:                   configParams.MaxIpsetSize,
			IPv6Enabled:                    configParams.Ipv6Support,
			BPFIpv6Enabled:                 configParams.Ipv6Support && configParams.BPFEnabled,
			BPFHostConntrackBypass:         configParams.BPFHostConntrackBypass,
			StatusReportingInterval:        configParams.ReportingIntervalSecs,
			XDPRefreshInterval:             configParams.XDPRefreshInterval,

			NetlinkTimeout: configParams.NetlinkTimeoutSecs,

			NodeIP:                     configParams.NodeIP,
			IPSecPSK:                   configParams.GetPSKFromFile(),
			IPSecAllowUnsecuredTraffic: configParams.IPSecAllowUnsecuredTraffic,
			IPSecIKEProposal:           configParams.IPSecIKEAlgorithm,
			IPSecESPProposal:           configParams.IPSecESPAlgorithm,
			IPSecLogLevel:              configParams.IPSecLogLevel,
			IPSecRekeyTime:             configParams.IPSecRekeyTime,
			IPSecPolicyRefreshInterval: configParams.IPSecPolicyRefreshInterval,

			EgressIPEnabled:               configParams.EgressIPCheckEnabled(),
			EgressIPVXLANPort:             configParams.EgressIPVXLANPort,
			EgressIPRoutingRulePriority:   configParams.EgressIPRoutingRulePriority,
			EgressGatewayPollInterval:     configParams.EgressGatewayPollInterval,
			EgressGatewayPollFailureCount: configParams.EgressGatewayPollFailureCount,
			EgressIPHostIfacePattern:      configParams.EgressIPHostIfacePattern,

			ExternalNetworkEnabled:             configParams.ExternalNetworkCheckEnabled(),
			ExternalNetworkRoutingRulePriority: configParams.ExternalNetworkRoutingRulePriority,

			ConfigChangedRestartCallback: configChangedRestartCallback,
			FatalErrorRestartCallback:    fatalErrorCallback,
			ChildExitedRestartCallback:   childExitedRestartCallback,

			PostInSyncCallback: func() {
				// The initial resync uses a lot of scratch space so now is
				// a good time to force a GC and return any RAM that we can.
				debug.FreeOSMemory()

				if configParams.DebugMemoryProfilePath == "" {
					return
				}
				logutils.DumpHeapMemoryProfile(configParams.DebugMemoryProfilePath)
			},
			HealthAggregator:                 healthAggregator,
			WatchdogTimeout:                  configParams.DataplaneWatchdogTimeout,
			DebugConsoleEnabled:              configParams.DebugConsoleEnabled,
			DebugSimulateDataplaneHangAfter:  configParams.DebugSimulateDataplaneHangAfter,
			DebugUseShortPollIntervals:       configParams.DebugUseShortPollIntervals,
			DebugSimulateDataplaneApplyDelay: configParams.DebugSimulateDataplaneApplyDelay,

			FelixHostname:              configParams.FelixHostname,
			ExternalNodesCidrs:         configParams.ExternalNodesCIDRList,
			SidecarAccelerationEnabled: configParams.SidecarAccelerationEnabled,

			BPFEnabled:                         configParams.BPFEnabled,
			BPFPolicyDebugEnabled:              configParams.BPFPolicyDebugEnabled,
			BPFDisableUnprivileged:             configParams.BPFDisableUnprivileged,
			BPFJITHardening:                    configParams.BPFJITHardening,
			BPFConnTimeLBEnabled:               configParams.BPFConnectTimeLoadBalancingEnabled,
			BPFConnTimeLB:                      configParams.BPFConnectTimeLoadBalancing,
			BPFHostNetworkedNAT:                configParams.BPFHostNetworkedNATWithoutCTLB,
			BPFKubeProxyIptablesCleanupEnabled: configParams.BPFKubeProxyIptablesCleanupEnabled,
			BPFLogLevel:                        configParams.BPFLogLevel,
			BPFConntrackLogLevel:               configParams.BPFConntrackLogLevel,
			BPFLogFilters:                      configParams.BPFLogFilters,
			BPFCTLBLogFilter:                   configParams.BPFCTLBLogFilter,
			BPFExtToServiceConnmark:            configParams.BPFExtToServiceConnmark,
			BPFDataIfacePattern:                configParams.BPFDataIfacePattern,
			BPFL3IfacePattern:                  configParams.BPFL3IfacePattern,
			BPFCgroupV2:                        configParams.DebugBPFCgroupV2,
			KubeProxyMinSyncPeriod:             configParams.BPFKubeProxyMinSyncPeriod,
			KubeProxyHealtzPort:                configParams.BPFKubeProxyHealthzPort,
			BPFPSNATPorts:                      configParams.BPFPSNATPorts,
			BPFMapSizeRoute:                    configParams.BPFMapSizeRoute,
			BPFMapSizeNATFrontend:              configParams.BPFMapSizeNATFrontend,
			BPFMapSizeNATBackend:               configParams.BPFMapSizeNATBackend,
			BPFMapSizeNATAffinity:              configParams.BPFMapSizeNATAffinity,
			BPFMapSizeConntrack:                configParams.BPFMapSizeConntrack,
			BPFMapSizeConntrackScaling:         configParams.BPFMapSizeConntrackScaling,
			BPFMapSizePerCPUConntrack:          configParams.BPFMapSizePerCPUConntrack,
			BPFMapSizeConntrackCleanupQueue:    configParams.BPFMapSizeConntrackCleanupQueue,
			BPFMapSizeIPSets:                   configParams.BPFMapSizeIPSets,
			BPFMapSizeIfState:                  configParams.BPFMapSizeIfState,
			BPFMapSizeMaglev:                   configParams.BPFMapSizeMaglev(),
			BPFMaglevLUTSize:                   configParams.BPFLUTSizeMaglev(),
			BPFEnforceRPF:                      configParams.BPFEnforceRPF,
			BPFDisableGROForIfaces:             configParams.BPFDisableGROForIfaces,
			BPFExportBufferSizeMB:              configParams.BPFExportBufferSizeMB,
			XDPEnabled:                         configParams.XDPEnabled,
			XDPAllowGeneric:                    configParams.GenericXDPEnabled,
			BPFConntrackTimeouts:               bpfconntrack.GetTimeouts(configParams.BPFConntrackTimeouts),
			BPFConntrackCleanupMode:            apiv3.BPFConntrackMode(configParams.BPFConntrackCleanupMode),
			RouteTableManager:                  routeTableIndexAllocator,
			MTUIfacePattern:                    configParams.MTUIfacePattern,
			BPFExcludeCIDRsFromNAT:             configParams.BPFExcludeCIDRsFromNAT,
			FlowLogsCollectProcessInfo:         configParams.FlowLogsCollectProcessInfo,
			FlowLogsCollectProcessPath:         configParams.FlowLogsCollectProcessPath,
			FlowLogsCollectTcpStats:            configParams.FlowLogsCollectTcpStats,
			FlowLogsFileIncludeService:         configParams.FlowLogsFileIncludeService,
			FlowLogsFileDomainsLimit:           configParams.FlowLogsFileDomainsLimit,
			NfNetlinkBufSize:                   configParams.NfNetlinkBufSize,
			BPFRedirectToPeer:                  configParams.BPFRedirectToPeer,
			BPFAttachType:                      configParams.GetBPFAttachType(),
			BPFProfiling:                       configParams.BPFProfiling,
			ServiceLoopPrevention:              configParams.ServiceLoopPrevention,

			IPAMClient: ipamClient,

			FeatureDetectOverrides: configParams.FeatureDetectOverride,
			FeatureGates:           configParams.FeatureGates,

			RouteSource: configParams.RouteSource,

			KubernetesProvider: configParams.KubernetesProvider(),

			RequireMTUFile: configParams.RequireMTUFile,

			DNSCacheFile:              configParams.GetDNSCacheFile(),
			DNSCacheSaveInterval:      configParams.DNSCacheSaveInterval,
			DNSCacheEpoch:             configParams.DNSCacheEpoch,
			DNSExtraTTL:               configParams.GetDNSExtraTTL(),
			DNSLogsLatency:            configParams.DNSLogsLatency,
			EnableDestDomainsByClient: configParams.FlowLogsDestDomainsByClient,

			AWSSecondaryIPSupport:             configParams.AWSSecondaryIPSupport,
			AWSRequestTimeout:                 configParams.AWSRequestTimeout,
			AWSSecondaryIPRoutingRulePriority: configParams.AWSSecondaryIPRoutingRulePriority,

			PacketCapture: capture.Config{
				Directory:       configParams.CaptureDir,
				MaxSizeBytes:    configParams.CaptureMaxSizeBytes,
				RotationSeconds: configParams.CaptureRotationSeconds,
				MaxFiles:        configParams.CaptureMaxFiles,
			},

			Collector:       collector,
			LookupsCache:    lc,
			FlowLogsEnabled: configParams.FlowLogsEnabled(),

			BPFDNSPolicyMode:                 apiv3.BPFDNSPolicyMode(configParams.BPFDNSPolicyMode),
			DNSPolicyNfqueueID:               configParams.DNSPolicyNfqueueID,
			DNSPolicyNfqueueSize:             configParams.DNSPolicyNfqueueSize,
			DNSPacketsNfqueueID:              configParams.DNSPacketsNfqueueID,
			DNSPacketsNfqueueSize:            configParams.DNSPacketsNfqueueSize,
			DNSPacketsNfqueueMaxHoldDuration: configParams.DNSPacketsNfqueueMaxHoldDuration,
			DebugDNSResponseDelay:            configParams.DebugDNSResponseDelay,
			DebugDNSDoNotWriteIPSets:         configParams.DebugDNSDoNotWriteIPSets,
		}
		if k8sClientSet != nil {
			dpConfig.KubeClientSet = k8sClientSet
		}

		if configParams.BPFExternalServiceMode == "dsr" {
			dpConfig.BPFNodePortDSREnabled = true
			dpConfig.BPFDSROptoutCIDRs = configParams.BPFDSROptoutCIDRs
		}

		stopChan := make(chan *sync.WaitGroup, 1)
		intDP := intdataplane.NewIntDataplaneDriver(dpConfig, stopChan)
		intDP.Start()

		// Set source-destination-check on AWS EC2 instance.
		check := apiv3.AWSSrcDstCheckOption(configParams.AWSSrcDstCheck)
		if check != apiv3.AWSSrcDstCheckOptionDoNothing {
			c := &clock.RealClock{}
			updater := aws.NewEC2SrcDstCheckUpdater()
			go aws.WaitForEC2SrcDstCheckUpdate(check, healthAggregator, updater, c)
		}

		return intDP, nil, stopChan
	} else {
		log.WithField("driver", configParams.DataplaneDriver).Info(
			"Using external dataplane driver.")

		dpConn, cmd := extdataplane.StartExtDataplaneDriver(configParams.DataplaneDriver)
		return dpConn, cmd, nil
	}
}

func SupportsBPF() error {
	return bpf.SupportsBPFDataplane()
}

func ConfigurePrometheusMetrics(configParams *config.Config) {
	if configParams.PrometheusGoMetricsEnabled && configParams.PrometheusProcessMetricsEnabled {
		log.Info("Including Golang and Process metrics")
	} else {
		if !configParams.PrometheusGoMetricsEnabled {
			log.Info("Discarding Golang metrics")
			prometheus.Unregister(collectors.NewGoCollector())
		}
		if !configParams.PrometheusProcessMetricsEnabled {
			log.Info("Discarding process metrics")
			prometheus.Unregister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
		}
	}

	if configParams.PrometheusWireGuardMetricsEnabled && (configParams.WireguardEnabled || configParams.WireguardEnabledV6) {
		log.Info("Including Wireguard metrics")
		prometheus.MustRegister(wireguard.MustNewWireguardMetrics())
	} else {
		log.Info("Discarding WireGuard metrics")
		prometheus.Unregister(wireguard.MustNewWireguardMetrics())
	}
}

func replaceWildcards(nftEnabled bool, s []string) []string {
	for i, v := range s {
		s[i] = replaceWildcard(nftEnabled, v)
	}
	return s
}

func replaceWildcard(nftEnabled bool, s string) string {
	// Need to replace the "+" wildcard with "*" for nftables.
	if nftEnabled && strings.HasSuffix(s, iptables.Wildcard) {
		return s[:len(s)-1] + nftables.Wildcard
	}
	return s
}
