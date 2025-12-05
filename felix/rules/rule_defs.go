// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.
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
	"net"
	"reflect"
	"strings"

	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/nftables"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
)

const (
	// ChainNamePrefix is a prefix used for all our iptables chain names.  We include a '-' at
	// the end to reduce clashes with other apps.  Our OpenStack DHCP agent uses prefix
	// 'calico-dhcp-', for example.
	ChainNamePrefix = "cali-"

	// IPSetNamePrefix: similarly for IP sets, we use the following prefix; the IP sets layer
	// adds its own "-" so it isn't included here.
	IPSetNamePrefix = ipsets.IPSetNamePrefix

	ChainFilterInput   = ChainNamePrefix + "INPUT"
	ChainFilterForward = ChainNamePrefix + "FORWARD"
	ChainFilterOutput  = ChainNamePrefix + "OUTPUT"

	ChainRawPrerouting         = ChainNamePrefix + "PREROUTING"
	ChainRawOutput             = ChainNamePrefix + "OUTPUT"
	ChainRawUntrackedFlows     = ChainNamePrefix + "untracked-flows"
	ChainRawBPFUntrackedPolicy = ChainNamePrefix + "untracked-policy"

	ChainFailsafeIn  = ChainNamePrefix + "failsafe-in"
	ChainFailsafeOut = ChainNamePrefix + "failsafe-out"

	ChainNATPrerouting       = ChainNamePrefix + "PREROUTING"
	ChainNATPreroutingEgress = ChainNamePrefix + "egress"
	ChainNATPostrouting      = ChainNamePrefix + "POSTROUTING"
	ChainNATOutput           = ChainNamePrefix + "OUTPUT"
	ChainNATOutgoing         = ChainNamePrefix + "nat-outgoing"

	ChainManglePrerouting              = ChainNamePrefix + "PREROUTING"
	ChainManglePostrouting             = ChainNamePrefix + "POSTROUTING"
	ChainManglePreroutingEgress        = ChainNamePrefix + "pre-egress"
	ChainManglePreroutingEgressInbound = ChainNamePrefix + "pre-egress-in"
	ChainManglePostroutingEgress       = ChainNamePrefix + "post-egress"
	ChainManglePreroutingTProxySvc     = ChainNamePrefix + "pre-tproxy-svc"
	ChainManglePreroutingTProxyNP      = ChainNamePrefix + "pre-tproxy-np"
	ChainManglePreroutingTProxyEstabl  = ChainNamePrefix + "pre-tproxy-establ"
	ChainManglePreroutingTProxySelect  = ChainNamePrefix + "pre-tproxy-selec"
	ChainMangleOutput                  = ChainNamePrefix + "OUTPUT"
	ChainMangleOutputTProxy            = ChainNamePrefix + "out-mangle-tproxy"
	ChainMangleOutputTProxyHostNet     = ChainNamePrefix + "out-mangle-tproxy-host"

	ChainEgressDSCP      = ChainNamePrefix + "egress-dscp"
	IPSetIDDSCPEndpoints = "dscp-src-net"

	IPSetIDAllPools             = "all-ipam-pools"
	IPSetIDNATOutgoingMasqPools = "masq-ipam-pools"

	IPSetIDAllHostNets        = "all-hosts-net"
	IPSetIDAllVXLANSourceNets = "all-vxlan-net"
	IPSetIDThisHostIPs        = "this-host"
	IPSetIDAllTunnelNets      = "all-tunnel-net"
	IPSetIDAllEGWHealthPorts  = "egw-health-ports"

	ChainFIPDnat = ChainNamePrefix + "fip-dnat"
	ChainFIPSnat = ChainNamePrefix + "fip-snat"

	ChainCIDRBlock = ChainNamePrefix + "cidr-block"

	PolicyInboundPfx   PolicyChainNamePrefix  = ChainNamePrefix + "pi-"
	PolicyOutboundPfx  PolicyChainNamePrefix  = ChainNamePrefix + "po-"
	ProfileInboundPfx  ProfileChainNamePrefix = ChainNamePrefix + "pri-"
	ProfileOutboundPfx ProfileChainNamePrefix = ChainNamePrefix + "pro-"

	PolicyGroupInboundPrefix  string = ChainNamePrefix + "gi-"
	PolicyGroupOutboundPrefix string = ChainNamePrefix + "go-"

	ChainWorkloadToHost       = ChainNamePrefix + "wl-to-host"
	ChainFromWorkloadDispatch = ChainNamePrefix + "from-wl-dispatch"
	ChainToWorkloadDispatch   = ChainNamePrefix + "to-wl-dispatch"

	NftablesToWorkloadDispatchMap   = ChainNamePrefix + "to-wl-dispatch"
	NftablesFromWorkloadDispatchMap = ChainNamePrefix + "from-wl-dispatch"

	ChainDispatchToHostEndpoint          = ChainNamePrefix + "to-host-endpoint"
	ChainDispatchFromHostEndpoint        = ChainNamePrefix + "from-host-endpoint"
	ChainDispatchToHostEndpointForward   = ChainNamePrefix + "to-hep-forward"
	ChainDispatchFromHostEndPointForward = ChainNamePrefix + "from-hep-forward"
	ChainDispatchSetEndPointMark         = ChainNamePrefix + "set-endpoint-mark"
	ChainDispatchFromEndPointMark        = ChainNamePrefix + "from-endpoint-mark"

	ChainForwardCheck        = ChainNamePrefix + "forward-check"
	ChainForwardEndpointMark = ChainNamePrefix + "forward-endpoint-mark"

	ChainSetWireguardIncomingMark = ChainNamePrefix + "wireguard-incoming-mark"

	ChainRpfSkip = ChainNamePrefix + "rpf-skip"

	ChainDNSLog = ChainNamePrefix + "log-dns"

	WorkloadToEndpointPfx   = ChainNamePrefix + "tw-"
	WorkloadPfxSpecialAllow = "ALLOW"
	WorkloadFromEndpointPfx = ChainNamePrefix + "fw-"

	SetEndPointMarkPfx = ChainNamePrefix + "sm-"

	HostToEndpointPfx          = ChainNamePrefix + "th-"
	HostFromEndpointPfx        = ChainNamePrefix + "fh-"
	HostToEndpointForwardPfx   = ChainNamePrefix + "thfw-"
	HostFromEndpointForwardPfx = ChainNamePrefix + "fhfw-"

	RPFChain = ChainNamePrefix + "rpf"

	RuleHashPrefix = "cali:"

	// NFLOGPrefixMaxLength is NFLOG max prefix length which is 64 characters.
	// Ref: http://ipset.netfilter.org/iptables-extensions.man.html#lbDI
	NFLOGPrefixMaxLength = 64

	// NFLOG groups. 1 for inbound and 2 for outbound.  3 for
	// snooping DNS response for domain information.
	NFLOGInboundGroup  uint16 = 1
	NFLOGOutboundGroup uint16 = 2
	NFLOGDomainGroup   uint16 = 3

	// Windows Hns rule delimeter between prefix string, rule name and sequence number.
	WindowsHnsRuleNameDelimeter = "---"

	// HistoricNATRuleInsertRegex is a regex pattern to match to match
	// special-case rules inserted by old versions of felix.  Specifically,
	// Python felix used to insert a masquerade rule directly into the
	// POSTROUTING chain.
	//
	// Note: this regex depends on the output format of iptables-save so,
	// where possible, it's best to match only on part of the rule that
	// we're sure can't change (such as the ipset name in the masquerade
	// rule).
	HistoricInsertedNATRuleRegex = `-A POSTROUTING .* felix-masq-ipam-pools .*|` +
		`-A POSTROUTING -o tunl0 -m addrtype ! --src-type LOCAL --limit-iface-out -m addrtype --src-type LOCAL -j MASQUERADE`

	KubeProxyInsertRuleRegex = `-j KUBE-[a-zA-Z0-9-]*SERVICES|-j KUBE-FORWARD`

	ChainFilterInputTProxy  = ChainNamePrefix + "input-filter-tproxy"
	ChainFilterOutputTProxy = ChainNamePrefix + "output-filter-tproxy"
)

type PolicyDirection string

const (
	PolicyDirectionInbound  PolicyDirection = "inbound"  // AKA ingress
	PolicyDirectionOutbound PolicyDirection = "outbound" // AKA egress
)

type RuleAction byte

const (
	// We define these with specific byte values as we write this value directly into the NFLOG
	// prefix.
	RuleActionAllow RuleAction = 'A'
	RuleActionDeny  RuleAction = 'D'
	// Pass onto the next tier
	RuleActionPass RuleAction = 'P'
)

func (r RuleAction) String() string {
	switch r {
	case RuleActionAllow:
		return "Allow"
	case RuleActionDeny:
		return "Deny"
	case RuleActionPass:
		return "Pass"
	}
	return ""
}

type RuleDir byte

const (
	// We define these with specific byte values as we write this value directly into the NFLOG
	// prefix.
	RuleDirIngress RuleDir = 'I'
	RuleDirEgress  RuleDir = 'E'
)

func (r RuleDir) String() string {
	switch r {
	case RuleDirIngress:
		return "Ingress"
	case RuleDirEgress:
		return "Egress"
	}
	return ""
}

type RuleOwnerType byte

const (
	// We define these with specific byte values as we write this value directly into the NFLOG
	// prefix.
	RuleOwnerTypePolicy  RuleOwnerType = 'P'
	RuleOwnerTypeProfile RuleOwnerType = 'R'
)

func (r RuleOwnerType) String() string {
	switch r {
	case RuleOwnerTypePolicy:
		return "Policy"
	case RuleOwnerTypeProfile:
		return "Profile"
	}
	return ""
}

// Typedefs to prevent accidentally passing the wrong prefix to the Policy/ProfileChainName()
type (
	PolicyChainNamePrefix  string
	ProfileChainNamePrefix string
)

var (
	// AllHistoricChainNamePrefixes lists all the prefixes that we've used for chains.  Keeping
	// track of the old names lets us clean them up.
	AllHistoricChainNamePrefixes = []string{
		// Current.
		"cali-",

		// Early RCs of Felix 2.1 used "cali" as the prefix for some chains rather than
		// "cali-".  This led to name clashes with the DHCP agent, which uses "calico-" as
		// its prefix.  We need to explicitly list these exceptions.
		"califw-",
		"calitw-",
		"califh-",
		"calith-",
		"calipi-",
		"calipo-",

		// Pre Felix v2.1.
		"felix-",
	}
	// AllHistoricIPSetNamePrefixes, similarly contains all the prefixes we've ever used for IP
	// sets.
	AllHistoricIPSetNamePrefixes = []string{"felix-", "cali"}
	// LegacyV4IPSetNames contains some extra IP set names that were used in older versions of
	// Felix and don't fit our versioned pattern.
	LegacyV4IPSetNames = []string{"felix-masq-ipam-pools", "felix-all-ipam-pools"}

	// Rule previxes used by kube-proxy.  Note: we exclude the so-called utility chains KUBE-MARK-MASQ and co because
	// they are jointly owned by kube-proxy and kubelet.
	KubeProxyChainPrefixes = []string{
		"KUBE-FORWARD",
		"KUBE-SERVICES",
		"KUBE-EXTERNAL-SERVICES",
		"KUBE-NODEPORTS",
		"KUBE-SVC-",
		"KUBE-SEP-",
		"KUBE-FW-",
		"KUBE-XLB-",
	}
)

type RuleRenderer interface {
	StaticFilterTableChains(ipVersion uint8) []*generictables.Chain
	StaticNATTableChains(ipVersion uint8) []*generictables.Chain
	StaticNATPostroutingChains(ipVersion uint8) []*generictables.Chain
	StaticRawTableChains(ipVersion uint8) []*generictables.Chain
	StaticBPFModeRawChains(ipVersion uint8, wgEncryptHost, disableConntrack bool) []*generictables.Chain
	StaticMangleTableChains(ipVersion uint8) []*generictables.Chain
	StaticFilterForwardAppendRules() []generictables.Rule

	StaticRawOutputChain(tcBypassMark uint32, ipVersion uint8, nodelocaldnsBroadcastedIPs []config.ServerPort) *generictables.Chain
	StaticRawPreroutingChain(ipVersion uint8, nodelocaldnsBroadcastedIPs []config.ServerPort) *generictables.Chain

	DispatchMappings(map[types.WorkloadEndpointID]*proto.WorkloadEndpoint) (map[string][]string, map[string][]string)
	WorkloadRPFDispatchMappings(map[types.WorkloadEndpointID]*proto.WorkloadEndpoint) (map[string][]string, map[string][]string)
	WorkloadDispatchChains(map[types.WorkloadEndpointID]*proto.WorkloadEndpoint) []*generictables.Chain
	WorkloadRPFDispatchChains(ipVersion uint8, gatewayInterfaceNames []string) []*generictables.Chain
	WorkloadEndpointToIptablesChains(
		ifaceName string,
		epMarkMapper EndpointMarkMapper,
		adminUp bool,
		tiers []TierPolicyGroups,
		profileIDs []string,
		qosControls *proto.QoSControls,
		isEgressGateway bool,
		egwHealthPort uint16,
		ipVersion uint8,
	) []*generictables.Chain

	WorkloadInterfaceAllowChains(endpoints map[types.WorkloadEndpointID]*proto.WorkloadEndpoint) []*generictables.Chain

	EndpointMarkDispatchChains(
		epMarkMapper EndpointMarkMapper,
		wlEndpoints map[types.WorkloadEndpointID]*proto.WorkloadEndpoint,
		hepEndpoints map[string]types.HostEndpointID,
	) []*generictables.Chain

	HostDispatchChains(map[string]types.HostEndpointID, string, bool) []*generictables.Chain
	FromHostDispatchChains(map[string]types.HostEndpointID, string) []*generictables.Chain
	ToHostDispatchChains(map[string]types.HostEndpointID, string) []*generictables.Chain
	HostEndpointToFilterChains(
		ifaceName string,
		tiers []TierPolicyGroups,
		forwardTiers []TierPolicyGroups,
		epMarkMapper EndpointMarkMapper,
		profileIDs []string,
	) []*generictables.Chain
	HostEndpointToMangleEgressChains(
		ifaceName string,
		tiers []TierPolicyGroups,
		profileIDs []string,
	) []*generictables.Chain
	HostEndpointToRawEgressChain(
		ifaceName string,
		untrackedTiers []TierPolicyGroups,
	) *generictables.Chain
	HostEndpointToRawChains(
		ifaceName string,
		untrackedTiers []TierPolicyGroups,
	) []*generictables.Chain
	HostEndpointToMangleIngressChains(
		ifaceName string,
		preDNATTiers []TierPolicyGroups,
	) []*generictables.Chain

	PolicyToIptablesChains(policyID *types.PolicyID, policy *proto.Policy, ipVersion uint8) []*generictables.Chain
	ProfileToIptablesChains(profileID *types.ProfileID, policy *proto.Profile, ipVersion uint8) (inbound, outbound *generictables.Chain)
	ProtoRuleToIptablesRules(pRule *proto.Rule, ipVersion uint8, owner RuleOwnerType, dir RuleDir, idx int, name string, untracked bool) []generictables.Rule
	PolicyGroupToIptablesChains(group *PolicyGroup) []*generictables.Chain

	NATOutgoingChain(active bool, ipVersion uint8) *generictables.Chain

	EgressDSCPChain(policies []*DSCPRule) *generictables.Chain

	DNATsToIptablesChains(dnats map[string]string) []*generictables.Chain
	SNATsToIptablesChains(snats map[string]string) []*generictables.Chain
	BlockedCIDRsToIptablesChains(cidrs []string, ipVersion uint8) []*generictables.Chain

	RPFilter(ipVersion uint8, mark, mask uint32, openStackSpecialCasesEnabled bool) []generictables.Rule

	WireguardIncomingMarkChain() *generictables.Chain

	IptablesFilterDenyAction() generictables.Action

	FilterInputChainAllowWG(ipVersion uint8, c Config, allowAction generictables.Action) []generictables.Rule
	ICMPv6Filter(action generictables.Action) []generictables.Rule
	SetIPSetIDGetter(idGetter IPSetIDGetter, ipVersion uint8)
}

type IPSetIDGetter interface {
	GetNoAlloc(string) uint64
}

type DefaultRuleRenderer struct {
	generictables.ActionFactory

	Config

	dropRules          []generictables.Rule
	inputAcceptActions []generictables.Action
	filterAllowAction  generictables.Action
	mangleAllowAction  generictables.Action
	blockCIDRAction    generictables.Action
	FilterDenyAction   generictables.Action

	NewMatch       func() generictables.MatchCriteria
	CombineMatches func(m1, m2 generictables.MatchCriteria) generictables.MatchCriteria

	// wildcard is the symbol to use for wildcard matches.
	wildcard string

	// maxNameLength is the maximum length of a chain name.
	maxNameLength int

	nfqueueRuleDelayDeniedPacket *generictables.Rule

	// The idallocators are used for getting the ipset ID from ipset name
	// used in bpf ipsets. This is used for DNS policy inline in iptables.
	IPSetIDGetterV4 IPSetIDGetter
	IPSetIDGetterV6 IPSetIDGetter
}

func (r *DefaultRuleRenderer) IptablesFilterDenyAction() generictables.Action {
	return r.FilterDenyAction
}

func (r *DefaultRuleRenderer) SetIPSetIDGetter(idGetter IPSetIDGetter, ipVersion uint8) {
	switch ipVersion {
	case 4:
		r.IPSetIDGetterV4 = idGetter
	case 6:
		r.IPSetIDGetterV6 = idGetter
	default:
		log.WithField("version", ipVersion).Panic("Unknown IP version")
	}
}

func (r *DefaultRuleRenderer) ipSetConfig(ipVersion uint8) *ipsets.IPVersionConfig {
	switch ipVersion {
	case 4:
		return r.IPSetConfigV4
	case 6:
		return r.IPSetConfigV6
	default:
		log.WithField("version", ipVersion).Panic("Unknown IP version")
		return nil
	}
}

type Config struct {
	IPSetConfigV4 *ipsets.IPVersionConfig
	IPSetConfigV6 *ipsets.IPVersionConfig

	WorkloadIfacePrefixes []string

	DNSPolicyMode         apiv3.DNSPolicyMode
	NFTablesDNSPolicyMode apiv3.NFTablesDNSPolicyMode
	DNSPolicyNfqueueID    int64
	DNSPacketsNfqueueID   int64

	MarkAccept   uint32
	MarkPass     uint32
	MarkDrop     uint32
	MarkIPsec    uint32
	MarkEgress   uint32
	MarkScratch0 uint32
	MarkScratch1 uint32
	MarkEndpoint uint32
	// MarkNonCaliEndpoint is an endpoint mark which is reserved
	// to mark non-calico (workload or host) endpoint.
	MarkNonCaliEndpoint uint32

	// MarkProxy marks packets that are to/from proxy.
	MarkProxy uint32

	// MarkDNSPolicy marks packets that have been evaluated by a DNS policy rule.
	MarkDNSPolicy uint32

	// MarkSkipDNSPolicyNfqueue marks a packet that should not be added to nfqueue again.
	MarkSkipDNSPolicyNfqueue uint32

	KubeNodePortRanges     []numorstring.Port
	KubeIPVSSupportEnabled bool
	KubeMasqueradeMark     uint32
	KubernetesProvider     config.Provider

	OpenStackMetadataIP          net.IP
	OpenStackMetadataPort        uint16
	OpenStackSpecialCasesEnabled bool

	VXLANEnabled   bool
	VXLANEnabledV6 bool
	VXLANPort      int
	VXLANVNI       int

	IPIPEnabled            bool
	FelixConfigIPIPEnabled *bool
	// IPIPTunnelAddress is an address chosen from an IPAM pool, used as a source address
	// by the host when sending traffic to a workload over IPIP.
	IPIPTunnelAddress net.IP
	// Same for VXLAN.
	VXLANTunnelAddress   net.IP
	VXLANTunnelAddressV6 net.IP

	AllowVXLANPacketsFromWorkloads bool
	AllowIPIPPacketsFromWorkloads  bool

	WireguardEnabled            bool
	WireguardEnabledV6          bool
	WireguardInterfaceName      string
	WireguardInterfaceNameV6    string
	WireguardMark               uint32
	WireguardListeningPort      int
	WireguardListeningPortV6    int
	WireguardEncryptHostTraffic bool
	RouteSource                 string

	LogPrefix                 string
	IncludeDropActionInPrefix bool
	EndpointToHostAction      string
	ActionOnDrop              string
	FilterAllowAction         string
	MangleAllowAction         string
	FilterDenyAction          string

	FailsafeInboundHostPorts  []config.ProtoPort
	FailsafeOutboundHostPorts []config.ProtoPort

	DisableConntrackInvalid bool

	NATPortRange                       numorstring.Port
	IptablesNATOutgoingInterfaceFilter string

	NATOutgoingAddress             net.IP
	NATOutgoingExclusions          string
	BPFEnabled                     bool
	BPFLogLevel                    string
	BPFForceTrackPacketsFromIfaces []string

	ServiceLoopPrevention string

	NFTables        bool
	FlowLogsEnabled bool

	EnableNflogSize bool
	IPSecEnabled    bool

	EgressIPEnabled   bool
	EgressIPVXLANPort int
	EgressIPVXLANVNI  int
	EgressIPInterface string

	EKSPrimaryENI string

	DNSTrustedServers []config.ServerPort

	TPROXYMode             string
	TPROXYPort             int
	TPROXYUpstreamConnMark uint32
}

var unusedBitsInBPFMode = map[string]bool{
	"MarkPass":                 true,
	"MarkScratch1":             true,
	"MarkEndpoint":             true,
	"MarkNonCaliEndpoint":      true,
	"MarkDNSPolicy":            true,
	"MarkSkipDNSPolicyNfqueue": true,
}

func (c *Config) validate() {
	// Scan for unset iptables mark bits.  We use reflection so that we have a hope of catching
	// newly-added fields.
	myValue := reflect.ValueOf(c).Elem()
	myType := myValue.Type()
	found := 0
	usedBits := uint32(0)
	for i := 0; i < myValue.NumField(); i++ {
		fieldName := myType.Field(i).Name
		if fieldName == "MarkNonCaliEndpoint" ||
			fieldName == "MarkIPsec" ||
			fieldName == "MarkEgress" {
			// These mark bits are only used when needed (by IPVS, IPsec and Egress IP support, respectively) so we allow them to
			// be zero.
			continue
		}
		// Not set if Proxy is not enabled
		if fieldName == "MarkProxy" && !c.TPROXYModeEnabled() {
			continue
		}
		if strings.HasPrefix(fieldName, "Mark") && fieldName != "MarkNonCaliEndpoint" {
			if c.BPFEnabled && unusedBitsInBPFMode[fieldName] {
				log.WithField("field", fieldName).Debug("Ignoring unused field in BPF mode.")
				continue
			}
			bits := myValue.Field(i).Interface().(uint32)
			if bits == 0 {
				log.WithField("field", fieldName).Panic(
					"MarkXXX field not set.")
			}
			if usedBits&bits > 0 {
				log.WithField("field", fieldName).Panic(
					"MarkXXX field overlapped with another's bits.")
			}
			usedBits |= bits
			found++
		}
	}
	if found == 0 {
		// Check the reflection found something we were expecting.
		log.Panic("Didn't find any MarkXXX fields.")
	}

	if c.MarkDNSPolicy != 0x0 && c.DNSPolicyNfqueueID == 0 {
		log.WithField("field", "DNSPolicyNfqueueID").Panic("Must not be 0 when the MarkDNSPolicy is set.")
	}
}

func NewRenderer(config Config) RuleRenderer {
	log.WithField("config", config).Info("Creating rule renderer.")
	config.validate()

	actions := iptables.Actions()
	var reject generictables.Action = iptables.RejectAction{}
	var accept generictables.Action = iptables.AcceptAction{}
	var drop generictables.Action = iptables.DropAction{}
	var ret generictables.Action = iptables.ReturnAction{}

	if config.NFTables {
		actions = nftables.Actions()
		reject = nftables.RejectAction{}
		accept = nftables.AcceptAction{}
		drop = nftables.DropAction{}
		ret = nftables.ReturnAction{}
	}

	newMatchFn := func() generictables.MatchCriteria {
		if config.NFTables {
			return nftables.Match()
		}
		return iptables.Match()
	}
	combineMatches := iptables.Combine
	if config.NFTables {
		combineMatches = nftables.Combine
	}

	// First, what should we do when packets are not accepted.
	var iptablesFilterDenyAction generictables.Action
	switch config.FilterDenyAction {
	case "REJECT":
		log.Info("packets that are not passed by any policy or profile will be rejected.")
		iptablesFilterDenyAction = reject
	default:
		log.Info("packets that are not passed by any policy or profile will be dropped.")
		iptablesFilterDenyAction = drop
	}

	// Convert configured actions to rule slices.
	// First, what should we actually do when we'd normally drop a packet?  For
	// sandbox mode, we support allowing the packet instead, or logging it.
	var dropRules []generictables.Rule
	var nfqueueRuleDelayDeniedPacket *generictables.Rule
	if strings.HasPrefix(config.ActionOnDrop, "LOG") {
		log.Warnf("Action on drop includes LOG.  All dropped packets will be logged. %s", config.LogPrefix)
		logPrefix := "calico-drop"
		if config.IncludeDropActionInPrefix {
			logPrefix = logPrefix + " " + config.ActionOnDrop
		}

		dropRules = append(dropRules, generictables.Rule{
			Match:  newMatchFn(),
			Action: actions.Log(logPrefix),
		})
	}

	if strings.HasSuffix(config.ActionOnDrop, "ACCEPT") {
		log.Warn("Action on drop set to ACCEPT.  Calico security is disabled!")
		dropRules = append(dropRules, generictables.Rule{
			Match:  newMatchFn(),
			Action: actions.Allow(),
		})
	} else {
		if config.IsDNSPolicyModeDelayDeniedPacket() && config.MarkDNSPolicy != 0x0 {
			nfqueueRuleDelayDeniedPacket = &generictables.Rule{
				Match: newMatchFn().
					MarkSingleBitSet(config.MarkDNSPolicy).
					NotMarkMatchesWithMask(config.MarkSkipDNSPolicyNfqueue, config.MarkSkipDNSPolicyNfqueue),
				Action: actions.Nfqueue(config.DNSPolicyNfqueueID),
			}
		}
		dropRules = append(dropRules, generictables.Rule{
			Match:  newMatchFn(),
			Action: iptablesFilterDenyAction,
		})
	}

	// Second, what should we do with packets that come from workloads to the host itself.
	var inputAcceptActions []generictables.Action
	switch config.EndpointToHostAction {
	case "DROP":
		log.Info("Workload to host packets will be dropped.")
		for _, rule := range dropRules {
			inputAcceptActions = append(inputAcceptActions, rule.Action)
		}
	case "REJECT":
		log.Info("Workload to host packets will be rejected.")
		inputAcceptActions = []generictables.Action{reject}
	case "ACCEPT":
		log.Info("Workload to host packets will be accepted.")
		inputAcceptActions = []generictables.Action{accept}
	default:
		log.Info("Workload to host packets will be returned to INPUT chain.")
		inputAcceptActions = []generictables.Action{ret}
	}

	// What should we do with packets that are accepted in the forwarding chain
	var filterAllowAction, mangleAllowAction generictables.Action
	switch config.FilterAllowAction {
	case "RETURN":
		log.Info("filter table allowed packets will be returned to FORWARD chain.")
		filterAllowAction = ret
	default:
		log.Info("filter table allowed packets will be accepted immediately.")
		filterAllowAction = accept
	}
	switch config.MangleAllowAction {
	case "RETURN":
		log.Info("mangle table allowed packets will be returned to PREROUTING chain.")
		mangleAllowAction = ret
	default:
		log.Info("mangle table allowed packets will be accepted immediately.")
		mangleAllowAction = accept
	}

	// How should we block CIDRs for loop prevention?
	var blockCIDRAction generictables.Action
	switch config.ServiceLoopPrevention {
	case "Drop":
		log.Info("Packets to unknown service IPs will be dropped")
		blockCIDRAction = drop
	case "Reject":
		log.Info("Packets to unknown service IPs will be rejected")
		blockCIDRAction = reject
	default:
		log.Info("Packets to unknown service IPs will be allowed to loop")
	}

	maxNameLength := iptables.MaxChainNameLength
	wildcard := iptables.Wildcard
	if config.NFTables {
		wildcard = nftables.Wildcard
		maxNameLength = nftables.MaxChainNameLength
	}

	return &DefaultRuleRenderer{
		Config:                       config,
		ActionFactory:                actions,
		NewMatch:                     newMatchFn,
		dropRules:                    dropRules,
		nfqueueRuleDelayDeniedPacket: nfqueueRuleDelayDeniedPacket,
		inputAcceptActions:           inputAcceptActions,
		filterAllowAction:            filterAllowAction,
		mangleAllowAction:            mangleAllowAction,
		blockCIDRAction:              blockCIDRAction,
		FilterDenyAction:             iptablesFilterDenyAction,
		wildcard:                     wildcard,
		maxNameLength:                maxNameLength,
		CombineMatches:               combineMatches,
	}
}

func (c *Config) TPROXYModeEnabled() bool {
	return c.TPROXYMode == "Enabled" || c.TPROXYMode == "EnabledAllServices"
}

func (c *Config) IsDNSPolicyModeDelayDNSResponse() bool {
	if c.BPFEnabled {
		return false
	}
	if c.NFTables {
		return c.NFTablesDNSPolicyMode == apiv3.NFTablesDNSPolicyModeDelayDNSResponse
	}
	return c.DNSPolicyMode == apiv3.DNSPolicyModeDelayDNSResponse
}

func (c *Config) IsDNSPolicyModeDelayDeniedPacket() bool {
	if c.BPFEnabled {
		return false
	}
	if c.NFTables {
		return c.NFTablesDNSPolicyMode == apiv3.NFTablesDNSPolicyModeDelayDeniedPacket
	}
	return c.DNSPolicyMode == apiv3.DNSPolicyModeDelayDeniedPacket
}

func (c *Config) IsDNSPolicyModeNoDelay() bool {
	if c.BPFEnabled {
		return false
	}
	if c.NFTables {
		return c.NFTablesDNSPolicyMode == apiv3.NFTablesDNSPolicyModeNoDelay
	}
	return c.DNSPolicyMode == apiv3.DNSPolicyModeNoDelay
}

func (c *Config) IsDNSPolicyModeInline() bool {
	if c.NFTables || c.BPFEnabled {
		return false
	}
	return c.DNSPolicyMode == apiv3.DNSPolicyModeInline
}
