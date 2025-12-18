// Copyright (c) 2016-2024 Tigera, Inc. All rights reserved.

package calc_test

import (
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	kapiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/dataplane/mock"
	"github.com/projectcalico/calico/felix/proto"
	felixtypes "github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	. "github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	calinet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// Pre-defined datastore states.  Each State object wraps up the complete state
// of the datastore as well as the expected state of the dataplane.  The state
// of the dataplane *should* depend only on the current datastore state, not on
// the path taken to get there.  Therefore, it's always a valid test to move
// from any state to any other state (by feeding in the corresponding
// datastore updates) and then assert that the dataplane matches the resulting
// state.

var hostEp1WithPolicyAndTier = withPolicyAndTier.withKVUpdates(
	KVPair{Key: hostEpWithNameKey, Value: &hostEpWithName},
).withIPSet(allSelectorId, []string{
	"10.0.0.1/32", // ep1
	"fc00:fe11::1/128",
	"10.0.0.2/32", // ep1 and ep2
	"fc00:fe11::2/128",
}).withIPSet(bEqBSelectorId, []string{
	"10.0.0.1/32",
	"fc00:fe11::1/128",
	"10.0.0.2/32",
	"fc00:fe11::2/128",
}).withActivePolicies(
	felixtypes.PolicyID{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
).withActiveProfiles(
	felixtypes.ProfileID{Name: "prof-1"},
	felixtypes.ProfileID{Name: "prof-2"},
	felixtypes.ProfileID{Name: "prof-missing"},
).withEndpoint(
	hostEpWithNameId,
	[]mock.TierInfo{
		{
			Name:            "tier-1",
			IngressPolicies: []felixtypes.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
			EgressPolicies:  []felixtypes.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
		},
	},
).withName("host ep1, policy")

var hostEp2WithPolicyAndTier = withPolicyAndTier.withKVUpdates(
	KVPair{Key: hostEp2NoNameKey, Value: &hostEp2NoName},
).withIPSet(allSelectorId, []string{
	"10.0.0.2/32", // ep1 and ep2
	"fc00:fe11::2/128",
	"10.0.0.3/32", // ep2
	"fc00:fe11::3/128",
}).withIPSet(bEqBSelectorId, []string{}).withActivePolicies(
	felixtypes.PolicyID{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
).withActiveProfiles(
	felixtypes.ProfileID{Name: "prof-2"},
	felixtypes.ProfileID{Name: "prof-3"},
).withEndpoint(
	hostEpNoNameId,
	[]mock.TierInfo{
		{
			Name:            "tier-1",
			IngressPolicies: []felixtypes.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
			EgressPolicies:  []felixtypes.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
		},
	},
).withName("host ep2, policy")

// local endpoint key for captures
var localWlEpCaptureKey1 = WorkloadEndpointKey{
	Hostname: localHostname, OrchestratorID: "orch", WorkloadID: "wl1-capture", EndpointID: "ep1",
}

// local endpoint key for captures
var localWlEpCaptureKey2 = WorkloadEndpointKey{
	Hostname: localHostname, OrchestratorID: "orch", WorkloadID: "wl2-capture", EndpointID: "ep2",
}

// local endpoint ids for captures
var (
	localWlEp1CaptureId = "orch/wl1-capture/ep1"
	localWlEp2CaptureId = "orch/wl2-capture/ep2"
)

// packet capture that select two local endpoints
var withCaptureSelectAll = withLocalEndpointsForCapture.withKVUpdates(
	KVPair{Key: CaptureAllKey, Value: CaptureAllValue},
).withCapturesUpdates(felixtypes.PacketCaptureUpdate{
	Id: &proto.PacketCaptureID{
		Name:      CaptureAllValue.Name,
		Namespace: CaptureAllValue.Namespace,
	},
	Endpoint: &proto.WorkloadEndpointID{
		WorkloadId:     localWlEpCaptureKey1.WorkloadID,
		OrchestratorId: localWlEpCaptureKey1.OrchestratorID,
		EndpointId:     localWlEpCaptureKey1.EndpointID,
	},
},
	felixtypes.PacketCaptureUpdate{
		Id: &proto.PacketCaptureID{
			Name:      CaptureAllValue.Name,
			Namespace: CaptureAllValue.Namespace,
		},
		Endpoint: &proto.WorkloadEndpointID{
			WorkloadId:     localWlEpCaptureKey2.WorkloadID,
			OrchestratorId: localWlEpCaptureKey2.OrchestratorID,
			EndpointId:     localWlEpCaptureKey2.EndpointID,
		},
	},
).withName("with capture all()")

// local endpoints update for capture
var withLocalEndpointsForCapture = initialisedStore.withKVUpdates(
	KVPair{Key: localWlEpCaptureKey1, Value: &localWlEp1OnlyLabels},
	KVPair{Key: localWlEpCaptureKey2, Value: &localWlEp2OnlyLabels},
).withRoutes(
	// Routes for the local WEPs.
	routelocalWlTenDotOne,
	routelocalWlTenDotTwo,
	routelocalWlV6ColonOne,
	routelocalWlV6ColonTwo,
).withEndpoint(localWlEp1CaptureId, []mock.TierInfo{}).withEndpoint(localWlEp2CaptureId, []mock.TierInfo{}).withName("with local endpoints for capture")

// packet capture that select a single local endpoints
var withCaptureSelectA = withLocalEndpointsForCapture.withKVUpdates(
	KVPair{Key: CaptureSelectionKey, Value: CaptureSelectAValue},
).withCapturesUpdates(felixtypes.PacketCaptureUpdate{
	Id: &proto.PacketCaptureID{
		Name:      CaptureSelectAValue.Name,
		Namespace: CaptureSelectAValue.Namespace,
	},
	Endpoint: &proto.WorkloadEndpointID{
		WorkloadId:     localWlEpCaptureKey1.WorkloadID,
		OrchestratorId: localWlEpCaptureKey1.OrchestratorID,
		EndpointId:     localWlEpCaptureKey1.EndpointID,
	},
},
).withName("with capture select label")

// two packet captures that select twice a local endpoints
var withCaptureSelectTwice = withLocalEndpointsForCapture.withKVUpdates(
	KVPair{Key: CaptureSelectionKey, Value: CaptureSelectAValue},
	KVPair{Key: CaptureAllKey, Value: CaptureAllValue},
).withCapturesUpdates(felixtypes.PacketCaptureUpdate{
	Id: &proto.PacketCaptureID{
		Name:      CaptureSelectAValue.Name,
		Namespace: CaptureSelectAValue.Namespace,
	},
	Endpoint: &proto.WorkloadEndpointID{
		WorkloadId:     localWlEpCaptureKey1.WorkloadID,
		OrchestratorId: localWlEpCaptureKey1.OrchestratorID,
		EndpointId:     localWlEpCaptureKey1.EndpointID,
	},
},
	felixtypes.PacketCaptureUpdate{
		Id: &proto.PacketCaptureID{
			Name:      CaptureAllValue.Name,
			Namespace: CaptureAllValue.Namespace,
		},
		Endpoint: &proto.WorkloadEndpointID{
			WorkloadId:     localWlEpCaptureKey1.WorkloadID,
			OrchestratorId: localWlEpCaptureKey1.OrchestratorID,
			EndpointId:     localWlEpCaptureKey1.EndpointID,
		},
	},
	felixtypes.PacketCaptureUpdate{
		Id: &proto.PacketCaptureID{
			Name:      CaptureAllValue.Name,
			Namespace: CaptureAllValue.Namespace,
		},
		Endpoint: &proto.WorkloadEndpointID{
			WorkloadId:     localWlEpCaptureKey2.WorkloadID,
			OrchestratorId: localWlEpCaptureKey2.OrchestratorID,
			EndpointId:     localWlEpCaptureKey2.EndpointID,
		},
	},
).withName("with capture select an endpoint twice")

// One local endpoint with a host IP, should generate an IPsec binding for each IP of the endpoint.
var localEp1WithNode = localEp1WithPolicy.withKVUpdates(
	KVPair{Key: HostIPKey{Hostname: localHostname}, Value: calinet.ParseIP("192.168.0.1")},
).withIPSecBinding(
	"192.168.0.1", "10.0.0.1",
).withIPSecBinding(
	"192.168.0.1", "10.0.0.2",
).withRoutes(
	felixtypes.RouteUpdate{
		Types:       proto.RouteType_LOCAL_HOST,
		IpPoolType:  proto.IPPoolType_NONE,
		Dst:         "192.168.0.1/32",
		DstNodeName: "localhostname",
		DstNodeIp:   "192.168.0.1",
	},
	// Routes for the local WEPs.
	routelocalWlTenDotOneWithNodeIP,
	routelocalWlTenDotTwoWithNodeIP,
	routelocalWlV6ColonOne,
	routelocalWlV6ColonTwo,
).withName("Local endpoint 1 with a host IP")

var localEp1WithNodeDiffIP = localEp1WithPolicy.withKVUpdates(
	KVPair{Key: HostIPKey{Hostname: localHostname}, Value: calinet.ParseIP("192.168.0.2")},
).withIPSecBinding(
	"192.168.0.2", "10.0.0.1",
).withIPSecBinding(
	"192.168.0.2", "10.0.0.2",
).withRoutes(
	felixtypes.RouteUpdate{
		Types:       proto.RouteType_LOCAL_HOST,
		IpPoolType:  proto.IPPoolType_NONE,
		Dst:         "192.168.0.2/32",
		DstNodeName: "localhostname",
		DstNodeIp:   "192.168.0.2",
	},
	// Routes for the local WEPs.
	routelocalWlTenDotOneWithNodeIPTwo,
	routelocalWlTenDotTwoWithNodeIPTwo,
	routelocalWlV6ColonOne,
	routelocalWlV6ColonTwo,
).withName("Local endpoint 1 with a (different) host IP")

// Two nodes sharing an IP but only one of them has endpoints so the other will get ignored.
var localEp1WithNodesSharingIP = localEp1WithPolicy.withKVUpdates(
	KVPair{Key: HostIPKey{Hostname: localHostname}, Value: calinet.ParseIP("192.168.0.1")},
	KVPair{Key: HostIPKey{Hostname: remoteHostname}, Value: calinet.ParseIP("192.168.0.1")},
).withIPSecBinding(
	"192.168.0.1", "10.0.0.1",
).withIPSecBinding(
	"192.168.0.1", "10.0.0.2",
).withRoutes(
	felixtypes.RouteUpdate{
		Types:       proto.RouteType_LOCAL_HOST,
		IpPoolType:  proto.IPPoolType_NONE,
		Dst:         "192.168.0.1/32",
		DstNodeName: "localhostname",
		DstNodeIp:   "192.168.0.1",
	},
	// Routes for the local WEPs.
	routelocalWlTenDotOneWithNodeIP,
	routelocalWlTenDotTwoWithNodeIP,
	routelocalWlV6ColonOne,
	routelocalWlV6ColonTwo,
).withName("Local endpoint 1 with pair of hosts sharing IP")

var localEp1With3NodesSharingIP = localEp1WithPolicy.withKVUpdates(
	KVPair{Key: HostIPKey{Hostname: localHostname}, Value: calinet.ParseIP("192.168.0.1")},
	KVPair{Key: HostIPKey{Hostname: remoteHostname}, Value: calinet.ParseIP("192.168.0.1")},
	KVPair{Key: HostIPKey{Hostname: remoteHostname2}, Value: calinet.ParseIP("192.168.0.1")},
).withIPSecBinding(
	"192.168.0.1", "10.0.0.1",
).withIPSecBinding(
	"192.168.0.1", "10.0.0.2",
).withRoutes(
	felixtypes.RouteUpdate{
		Types:       proto.RouteType_LOCAL_HOST,
		IpPoolType:  proto.IPPoolType_NONE,
		Dst:         "192.168.0.1/32",
		DstNodeName: "localhostname",
		DstNodeIp:   "192.168.0.1",
	},
	// Routes for the local WEPs.
	routelocalWlTenDotOneWithNodeIP,
	routelocalWlTenDotTwoWithNodeIP,
	routelocalWlV6ColonOne,
	routelocalWlV6ColonTwo,
).withName("Local endpoint 1 with triple of hosts sharing IP")

var commRemoteWlEp1 = WorkloadEndpoint{
	State:      "active",
	Name:       "cali1",
	Mac:        mustParseMac("01:02:03:04:05:06"),
	ProfileIDs: []string{"prof-1"},
	IPv4Nets: []calinet.IPNet{
		mustParseNet("10.0.1.1/32"),
		mustParseNet("10.0.1.2/32"),
	},
}

var commRemoteWlEp2 = WorkloadEndpoint{
	State:      "active",
	Name:       "cali1",
	Mac:        mustParseMac("01:02:03:04:05:06"),
	ProfileIDs: []string{"prof-1"},
	IPv4Nets: []calinet.IPNet{mustParseNet("10.0.1.1/32"), // shared
		mustParseNet("10.0.2.2/32")},
}

// Adding an endpoint to the remote host marks it as active, so we now have a conflict between active hosts and
// we remove the IPsec bindings.
var localEp1With3NodesSharingIPAndRemoteEp = localEp1With3NodesSharingIP.withKVUpdates(
	KVPair{Key: remoteWlEpKey1, Value: &commRemoteWlEp1},
).withIPSet(allSelectorId, []string{
	"10.0.0.1/32", // ep1
	"fc00:fe11::1/128",
	"10.0.0.2/32", // ep1 and ep2
	"fc00:fe11::2/128",
	"10.0.1.1/32", // remote ep1
	"10.0.1.2/32", // remote ep1
}).withoutIPSecBinding(
	"192.168.0.1", "10.0.0.1",
).withoutIPSecBinding(
	"192.168.0.1", "10.0.0.2",
).withIPSecBlacklist(
	"10.0.0.1",
	"10.0.0.2",
	"10.0.1.1",
	"10.0.1.2",
).withRemoteEndpoint(
	calc.CalculateRemoteEndpoint(remoteWlEpKey1, &commRemoteWlEp1),
).withName("Local endpoint 1 with triple of hosts sharing IP and a remote endpoint")

var localEp1With3NodesSharingIPAndRemoteEps = localEp1With3NodesSharingIPAndRemoteEp.withKVUpdates(
	KVPair{Key: remoteWlEpKey2, Value: &commRemoteWlEp2},
).withIPSet(allSelectorId, []string{
	"10.0.0.1/32", // ep1
	"fc00:fe11::1/128",
	"10.0.0.2/32", // ep1 and ep2
	"fc00:fe11::2/128",
	"10.0.1.1/32", // remote ep1
	"10.0.1.2/32", // remote ep1
	"10.0.2.2/32", // remote ep2
}).withIPSecBlacklist(
	"10.0.2.2",
).withRemoteEndpoint(
	calc.CalculateRemoteEndpoint(remoteWlEpKey2, &commRemoteWlEp2),
).withName("Local endpoint 1 with triple of hosts sharing IP and a remote endpoints on both remote hosts")

var localAndRemoteEndpointsWithMissingRemoteNode = localEp1WithNode.withKVUpdates(
	KVPair{Key: remoteWlEpKey1, Value: &commRemoteWlEp1},
).withIPSet(allSelectorId, []string{
	"10.0.0.1/32", // ep1
	"fc00:fe11::1/128",
	"10.0.0.2/32", // ep1 and ep2
	"fc00:fe11::2/128",
	"10.0.1.1/32", // remote ep1
	"10.0.1.2/32", // remote ep1
}).withIPSecBlacklist(
	"10.0.1.1",
	"10.0.1.2",
).withRemoteEndpoint(
	calc.CalculateRemoteEndpoint(remoteWlEpKey1, &commRemoteWlEp1),
).withName("Local endpoint 1 with remote endpoint but missing remote node")

// Different local endpoint with a host IP, should generate an IPsec binding for each IP of the endpoint.
var localEp2WithNode = localEp2WithPolicy.withKVUpdates(
	KVPair{Key: HostIPKey{Hostname: localHostname}, Value: calinet.ParseIP("192.168.0.1")},
).withIPSecBinding(
	"192.168.0.1", "10.0.0.2",
).withIPSecBinding(
	"192.168.0.1", "10.0.0.3",
).withRoutes(
	felixtypes.RouteUpdate{
		Types:       proto.RouteType_LOCAL_HOST,
		IpPoolType:  proto.IPPoolType_NONE,
		Dst:         "192.168.0.1/32",
		DstNodeName: "localhostname",
		DstNodeIp:   "192.168.0.1",
	},
	// Routes for the local WEPs.
	routelocalWlTenDotTwoWithNodeIP,
	routelocalWlTenDotThreeWithNodeIP,
	routelocalWlV6ColonTwo,
	routelocalWlV6ColonThree,
).withName("Local endpoint 2 with a host IP")

// Endpoint 2 using endpoint 1's key (so we can simulate changing an endpoint's IPs.
var localEp2AsEp1WithNode = localEp2WithNode.withKVUpdates(
	KVPair{Key: localWlEpKey2},
	KVPair{Key: localWlEpKey1, Value: &localWlEp2},
).withIPSecBinding(
	"192.168.0.1", "10.0.0.2",
).withIPSecBinding(
	"192.168.0.1", "10.0.0.3",
).withEndpoint(
	localWlEp1Id,
	[]mock.TierInfo{
		{
			Name:            "default",
			IngressPolicies: []felixtypes.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
			EgressPolicies:  []felixtypes.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
		},
	},
).withEndpoint(localWlEp2Id, nil).withName("Local endpoint 2 (using key for ep 1) with a host IP")

var localWlEpKey3 = WorkloadEndpointKey{
	Hostname:       localHostname,
	OrchestratorID: "orch",
	WorkloadID:     "wl3",
	EndpointID:     "ep3",
}

var localWlEp3 = WorkloadEndpoint{
	State: "active",
	Name:  "cali3",
	IPv4Nets: []calinet.IPNet{
		mustParseNet("10.0.0.2/32"), // Shared with all endpoints
		mustParseNet("10.0.0.4/32"), // unique to this endpoint
	},
}

const localWlEp3Id = "orch/wl3/ep3"

// A node, with two local endpoints that share an IP.
var localEp1And2WithNode = localEpsWithPolicy.withKVUpdates(
	KVPair{Key: HostIPKey{Hostname: localHostname}, Value: calinet.ParseIP("192.168.0.1")},
).withIPSecBinding(
	"192.168.0.1", "10.0.0.1",
).withIPSecBinding(
	"192.168.0.1", "10.0.0.3",
).withIPSecBlacklist(
	"10.0.0.2",
).withRoutes(
	felixtypes.RouteUpdate{
		Types:       proto.RouteType_LOCAL_HOST,
		IpPoolType:  proto.IPPoolType_NONE,
		Dst:         "192.168.0.1/32",
		DstNodeName: "localhostname",
		DstNodeIp:   "192.168.0.1",
	},
	// Routes for the local WEPs.
	routelocalWlTenDotOneWithNodeIP,
	routelocalWlTenDotTwoWithNodeIP,
	routelocalWlTenDotThreeWithNodeIP,
	routelocalWlV6ColonOne,
	routelocalWlV6ColonTwo,
	routelocalWlV6ColonThree,
).withName("Local endpoints 1 and 2 sharing an IP with a host IP defined")

// Endpoint 1, 2 and 3 sharing an IP with a node too.
var threeEndpointsSharingIPWithNode = localEpsWithPolicy.withKVUpdates(
	KVPair{Key: HostIPKey{Hostname: localHostname}, Value: calinet.ParseIP("192.168.0.1")},
	KVPair{Key: localWlEpKey1, Value: &localWlEp1},
	KVPair{Key: localWlEpKey2, Value: &localWlEp2},
	KVPair{Key: localWlEpKey3, Value: &localWlEp3},
).withIPSecBinding(
	"192.168.0.1", "10.0.0.1",
).withIPSecBinding(
	"192.168.0.1", "10.0.0.3",
).withIPSecBinding(
	"192.168.0.1", "10.0.0.4",
).withIPSet(allSelectorId, []string{
	"10.0.0.1/32", // ep1
	"fc00:fe11::1/128",
	"10.0.0.2/32", // ep1, ep2 and ep3
	"fc00:fe11::2/128",
	"10.0.0.3/32", // ep2
	"fc00:fe11::3/128",
	"10.0.0.4/32", // ep3
}).withEndpoint(
	localWlEp3Id,
	[]mock.TierInfo{},
).withIPSecBlacklist(
	"10.0.0.2",
).withRoutes(
	felixtypes.RouteUpdate{
		Types:       proto.RouteType_LOCAL_HOST,
		IpPoolType:  proto.IPPoolType_NONE,
		Dst:         "192.168.0.1/32",
		DstNodeName: "localhostname",
		DstNodeIp:   "192.168.0.1",
	},
	// Routes for the local WEPs.
	routelocalWlTenDotOneWithNodeIP,
	routelocalWlTenDotTwoWithNodeIP,
	routelocalWlTenDotThreeWithNodeIP,
	routelocalWlTenDotFourWithNodeIP,
	routelocalWlV6ColonOne,
	routelocalWlV6ColonTwo,
	routelocalWlV6ColonThree,
).withName("3 endpoints sharing an IP with a host IP defined")

var threeEndpointsSharingIPWithDulicateNodeIP = localEpsWithPolicy.withKVUpdates(
	KVPair{Key: HostIPKey{Hostname: localHostname}, Value: calinet.ParseIP("192.168.0.1")},
	KVPair{Key: HostIPKey{Hostname: remoteHostname}, Value: calinet.ParseIP("192.168.0.1")},
	KVPair{Key: localWlEpKey1, Value: &localWlEp1},
	KVPair{Key: localWlEpKey2, Value: &localWlEp2},
	KVPair{Key: localWlEpKey3, Value: &localWlEp3},
).withIPSecBinding(
	"192.168.0.1", "10.0.0.1",
).withIPSecBinding(
	"192.168.0.1", "10.0.0.3",
).withIPSecBinding(
	"192.168.0.1", "10.0.0.4",
).withIPSet(allSelectorId, []string{
	"10.0.0.1/32", // ep1
	"fc00:fe11::1/128",
	"10.0.0.2/32", // ep1, ep2 and ep3
	"fc00:fe11::2/128",
	"10.0.0.3/32", // ep2
	"fc00:fe11::3/128",
	"10.0.0.4/32", // ep3
}).withEndpoint(
	localWlEp3Id,
	[]mock.TierInfo{},
).withIPSecBlacklist(
	"10.0.0.2",
).withRoutes(
	felixtypes.RouteUpdate{
		Types:       proto.RouteType_LOCAL_HOST,
		IpPoolType:  proto.IPPoolType_NONE,
		Dst:         "192.168.0.1/32",
		DstNodeName: "localhostname",
		DstNodeIp:   "192.168.0.1",
	},
	// Routes for the local WEPs.
	routelocalWlTenDotOneWithNodeIP,
	routelocalWlTenDotTwoWithNodeIP,
	routelocalWlTenDotThreeWithNodeIP,
	routelocalWlTenDotFourWithNodeIP,
	routelocalWlV6ColonOne,
	routelocalWlV6ColonTwo,
	routelocalWlV6ColonThree,
).withName("3 endpoints sharing an IP with a duplicate host IP defined")

var remoteWlEpKey3 = WorkloadEndpointKey{
	Hostname:       remoteHostname,
	OrchestratorID: "orch",
	WorkloadID:     "wl3",
	EndpointID:     "ep3",
}

var remoteWlEp1 = WorkloadEndpoint{
	State:    "active",
	Name:     "cali1",
	Mac:      mustParseMac("01:02:03:04:05:06"),
	IPv4Nets: []calinet.IPNet{mustParseNet("10.1.0.1/32"), mustParseNet("10.1.0.2/32")},
	IPv6Nets: []calinet.IPNet{mustParseNet("fe80:fe11::1/128"), mustParseNet("fe80:fe11::2/128")},
	Labels: uniquelabels.Make(map[string]string{
		"id": "rem-ep-1",
		"x":  "x",
		"y":  "y",
	}),
}

var remoteWlEp1NoIpv6 = WorkloadEndpoint{
	State: "active",
	Name:  "cali1",
	Mac:   mustParseMac("01:02:03:04:05:06"),
	IPv4Nets: []calinet.IPNet{
		mustParseNet("10.1.0.1/32"),
		mustParseNet("10.1.0.2/32"),
	},
	Labels: uniquelabels.Make(map[string]string{
		"id": "rem-ep-1",
		"x":  "x",
		"y":  "y",
	}),
}

var remoteWlEp1UpdatedLabels = WorkloadEndpoint{
	State: "active",
	Name:  "cali1",
	Mac:   mustParseMac("01:02:03:04:05:06"),
	IPv4Nets: []calinet.IPNet{
		mustParseNet("10.1.0.1/32"),
		mustParseNet("10.1.0.2/32"),
	},
	IPv6Nets: []calinet.IPNet{
		mustParseNet("fe80:fe11::1/128"),
		mustParseNet("fe80:fe11::2/128"),
	},
	Labels: uniquelabels.Make(map[string]string{
		"id": "rem-ep-1",
		"x":  "x",
		"y":  "y",
		"z":  "z",
	}),
}

var remoteWlEp3 = WorkloadEndpoint{
	State: "active",
	Name:  "cali2",
	Mac:   mustParseMac("02:03:04:05:06:07"),
	IPv4Nets: []calinet.IPNet{
		mustParseNet("10.2.0.1/32"),
		mustParseNet("10.2.0.2/32"),
	},
	IPv6Nets: []calinet.IPNet{
		mustParseNet("fe80:fe22::1/128"),
		mustParseNet("fe80:fe22::2/128"),
	},
	Labels: uniquelabels.Make(map[string]string{
		"id": "rem-ep-2",
		"x":  "x",
		"y":  "y",
	}),
}

var remoteWlEp1WithPolicyAndTier = withPolicyAndTier.withKVUpdates(
	KVPair{Key: remoteWlEpKey1, Value: &remoteWlEp1},
).withRemoteEndpoint(
	calc.CalculateRemoteEndpoint(remoteWlEpKey1, &remoteWlEp1),
).withName("1 remote endpoint")

// localEpAndRemoteEpWithPolicyAndTier contains one local and one remote endpoint.
// It should give us a local state corresponding to the local endpoint and
// record the remote endpoint as well.
var localEpAndRemoteEpWithPolicyAndTier = withPolicyAndTier.withKVUpdates(
	// Two local endpoints with overlapping IPs.
	KVPair{Key: localWlEpKey1, Value: &localWlEp1},
	KVPair{Key: remoteWlEpKey3, Value: &remoteWlEp3},
).withIPSet(allSelectorId, []string{
	"10.0.0.1/32", // local ep
	"fc00:fe11::1/128",
	"10.0.0.2/32",
	"fc00:fe11::2/128",
	"10.2.0.1/32", // remote ep
	"fe80:fe22::1/128",
	"10.2.0.2/32",
	"fe80:fe22::2/128",
}).withIPSet(bEqBSelectorId, []string{
	"10.0.0.1/32",
	"fc00:fe11::1/128",
	"10.0.0.2/32",
	"fc00:fe11::2/128",
}).withActivePolicies(
	felixtypes.PolicyID{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
).withActiveProfiles(
	felixtypes.ProfileID{Name: "prof-1"},
	felixtypes.ProfileID{Name: "prof-2"},
	felixtypes.ProfileID{Name: "prof-missing"},
).withEndpoint(
	localWlEp1Id,
	[]mock.TierInfo{
		{
			Name:            "tier-1",
			IngressPolicies: []felixtypes.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
			EgressPolicies:  []felixtypes.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
		},
	},
).withRemoteEndpoint(
	calc.CalculateRemoteEndpoint(remoteWlEpKey3, &remoteWlEp3),
).withRoutes(
	// Routes for the local WEPs.
	routelocalWlTenDotOne,
	routelocalWlTenDotTwo,
	routelocalWlV6ColonOne,
	routelocalWlV6ColonTwo,
).withName("1 local and 1 remote")

var remoteEpsWithPolicyAndTier = withPolicyAndTier.withKVUpdates(
	KVPair{Key: remoteWlEpKey1, Value: &remoteWlEp1},
	KVPair{Key: remoteWlEpKey3, Value: &remoteWlEp3},
).withRemoteEndpoint(
	calc.CalculateRemoteEndpoint(remoteWlEpKey1, &remoteWlEp1),
).withRemoteEndpoint(
	calc.CalculateRemoteEndpoint(remoteWlEpKey3, &remoteWlEp3),
).withName("2 remote endpoints")

var commercialTests = []StateList{
	// Empty should be empty!
	{},
	// Add one endpoint then remove it and add another with overlapping IP.
	{localEp1WithPolicyAndTier, localEp2WithPolicyAndTier},

	// Add one endpoint then another with an overlapping IP, then remove
	// first.
	{localEp1WithPolicyAndTier, localEpsWithPolicyAndTier, localEp2WithPolicyAndTier},

	// Add both endpoints, then return to empty, then add them both back.
	{localEpsWithPolicyAndTier, initialisedStore, localEpsWithPolicyAndTier},

	// Add a profile and a couple of endpoints.  Then update the profile to
	// use different tags and selectors.
	{localEpsWithProfile, localEpsWithUpdatedProfile},

	// Tests of policy ordering.  Each state has one tier but we shuffle
	// the order of the policies within it.
	{
		commLocalEp1WithOneTierPolicy123,
		commLocalEp1WithOneTierPolicy321,
		commLocalEp1WithOneTierPolicyAlpha,
	},

	// Test mutating the profile list of some endpoints.
	{localEpsWithNonMatchingProfile, localEpsWithProfile},

	// And tier ordering.
	{
		localEp1WithTiers123,
		localEp1WithTiers321,
		localEp1WithTiersAlpha,
		localEp1WithTiersAlpha2,
		localEp1WithTiers321,
		localEp1WithTiersAlpha3,
	},

	// String together some complex updates with profiles and policies
	// coming and going.
	{
		localEpsWithProfile,
		commLocalEp1WithOneTierPolicy123,
		localEp1WithTiers321,
		localEpsWithNonMatchingProfile,
		localEpsWithPolicyAndTier,
		localEpsWithUpdatedProfile,
		localEpsWithNonMatchingProfile,
		localEpsWithUpdatedProfileNegatedTags,
		localEp1WithPolicyAndTier,
		localEp1WithTiersAlpha2,
		localEpsWithProfile,
	},

	// Host endpoint tests.
	{hostEp1WithPolicyAndTier, hostEp2WithPolicyAndTier},

	// IPsec basic tests.
	{localEp1WithNode},
	{localEp2WithNode},
	{localEp2AsEp1WithNode},

	// IPsec mutation tests (changing IPs etc)
	{localEp1WithNode, localEp2WithNode}, // Remove one endpoint, add in the other.
	{
		localEp1WithNode,      // Start with a local endpoint.
		localEp2AsEp1WithNode, // Switch the endpoint's spec, changing its IPs.
		localEp2WithNode,      // Delete and re-add as a different endpoint.
	},
	{
		localEp1WithNode,       // Start with a local endpoint.
		localEp1WithNodeDiffIP, // Change its node's IP.
		localEp2AsEp1WithNode,  // Change node IP and endpoint IP.
		localEp2WithNode,       // Delete and re-add as a different endpoint.
	},
	{
		localEp1WithNode,
		localEp2AsEp1WithNode,  // As above but change the IP first.
		localEp1WithNodeDiffIP, // then change the node and IP.
		localEp2WithNode,
	},

	// IPSec ambiguous binding tests: nodes sharing IPs but remote nodes have no enpdoints.
	{localEp1WithNodesSharingIP},
	{localEp1WithNode, localEp1WithNodesSharingIP, localEp1WithNode, localEp1WithNodesSharingIP},
	{localEp1WithNode, localEp1With3NodesSharingIP, localEp1WithNode},

	// IPsec ambiguous binding tests: endpoints sharing IPs.
	{localEp1And2WithNode},
	{localEp1WithNode, localEp1And2WithNode, localEp1WithNode},
	{localEp1WithNode, localEp1And2WithNode, localEp2WithNode},
	{localEp1And2WithNode, localEp1WithNodesSharingIP, localEp1WithNode},
	{localEp1And2WithNode, localEp1WithNodesSharingIP, localEp2WithNode},
	{threeEndpointsSharingIPWithNode},
	{threeEndpointsSharingIPWithNode, localEp1And2WithNode, localEp1WithNode},
	{threeEndpointsSharingIPWithDulicateNodeIP, threeEndpointsSharingIPWithNode, localEp1And2WithNode},
	{threeEndpointsSharingIPWithDulicateNodeIP, localEp1WithNodesSharingIP, localEp1And2WithNode},
	{localEp1With3NodesSharingIPAndRemoteEp},
	{localEp1With3NodesSharingIP, localEp1With3NodesSharingIPAndRemoteEp, localEp1WithNode},
	{
		localEp1WithNode, // Start with a local endpoint with some bindings.
		localAndRemoteEndpointsWithMissingRemoteNode, // Add remote endpoint but no remote node.  Shouldn't change.
		localEp1With3NodesSharingIPAndRemoteEp,       // Add in remote nodes, bindings now ambiguous.
		localEp1WithNode,                             // Remote the remote nodes again, bindings go back to local endpoint.
	},
	{localEp1With3NodesSharingIPAndRemoteEps, localEp1With3NodesSharingIPAndRemoteEp, localEp1WithNode},

	// IPsec deletion tests (removing host IPs).
	{localEp1WithNode, localEp1WithPolicy},
	{localEp2WithNode, localEp2WithPolicy},

	// Remote endpoint tests.
	{
		remoteWlEp1WithPolicyAndTier,
		localEpAndRemoteEpWithPolicyAndTier,
		remoteEpsWithPolicyAndTier,
	},

	// DNS Policy unit tests.
	{withDNSPolicy, withDNSPolicyNoDupe, withDNSPolicy2, withDNSPolicy3},

	// Select all local endpoints for capture
	{withCaptureSelectAll},

	// Select a single local endpoints for capture
	{withCaptureSelectA},

	// Select an endpoint twice
	{withCaptureSelectTwice},

	// Select all states
	{withCaptureSelectAll, withCaptureSelectA, withCaptureSelectTwice},

	// The following tests are validating IP conflict resolution in cross-cluster overlay scenarios. The majority of the
	// cases involve VXLAN as the encapsulation method.
	// Cross-cluster VXLAN: scenarios involving clusters with the same pool CIDR and block size.
	{
		// All tests in this scenario are based on a disjoint local VXLAN pool (pool 1).
		remoteClusterVXLANBlocksBase,

		// Remaining states deal with pool 2.
		// Add local VXLAN pool.
		remoteClusterVXLANLocalOnly,

		// Add a remote VXLAN pool and block with identical CIDRs. Expect the remote routes do not flush.
		remoteClusterVXLANLocalOverlapsWithRemoteA,

		// Remove the local pool and block. Expect the remote routes now flush.
		// This state validates the standard configuration of local and remote disjoint VXLAN pools.
		remoteClusterVXLANRemoteAOnly,

		// Add another remote VXLAN pool and block with identical CIDRs. Expect the new remote routes do not flush.
		remoteClusterVXLANRemoteAOverlapsWithRemoteB,
	},
	// Same scenario as above, with clusters in WEP mode.
	{
		// All tests in this scenario are based on a disjoint local VXLAN pool (pool 1).
		remoteClusterVXLANWEPsBase,

		// Remaining states deal with pool 2.
		// Add local VXLAN pool.
		remoteClusterVXLANWEPsLocalOnly,

		// Add a remote VXLAN pool and WEP with identical CIDRs. Expect the remote routes do not flush.
		remoteClusterVXLANWEPsLocalOverlapsWithRemoteA,

		// Remove the local pool and WEP. Expect the remote routes now flush.
		// This state validates the standard configuration of local and remote disjoint VXLAN pools.
		remoteClusterVXLANWEPsRemoteAOnly,

		// Add another remote VXLAN pool and WEP with identical CIDRs. Expect the new remote routes do not flush.
		remoteClusterVXLANWEPsRemoteAOverlapsWithRemoteB,
	},

	// Cross-cluster CIDR overlap handling: remote pool containing local pool scenarios.
	{
		remoteClusterPoolWithLargerBlockSizeContainsLocalPoolWithBlocks,
		remoteClusterPoolWithLargerBlockSizeContainsLocalPoolWithTunnels,
		remoteClusterPoolContainsLocalPoolWithOverlappedBlocks,
	},
	{
		remoteClusterPoolAndBlocksContainLocalPoolWithBlocks,
		overlappedRemoteAndLocalClusterPoolContainsRemoteBlock,
	},

	// Cross-cluster CIDR overlap handling: local pool containing remote pool scenarios.
	// Same scenario as above, with remote and local flipped.
	{
		localClusterPoolWithLargerBlockSizeContainsRemotePoolWithBlocks,
		localClusterPoolWithLargerBlockSizeContainsRemotePoolWithTunnels,
		localClusterPoolContainsRemotePoolWithOverlappedBlocks,
	},
	{
		localClusterPoolAndBlocksContainRemotePoolWithBlocks,
		overlappedRemoteAndLocalClusterPoolContainsLocalBlock,
	},

	// Cross-cluster CIDR overlap handling: remote pool containing remote pool scenarios.
	// Same scenario as above, with two remote clusters.
	{
		remoteClusterAPoolWithLargerBlockSizeContainsRemoteBPoolWithBlocks,
		remoteClusterAPoolWithLargerBlockSizeContainsRemoteBPoolWithTunnels,
		remoteClusterAPoolContainsRemoteBPoolWithOverlappedBlocks,
		remoteClusterAPoolWithOverlappedBlocks,
		remoteClusterBPoolContainsRemoteAPoolWithOverlappedBlocks,
	},
	{
		remoteClusterAPoolAndBlocksContainRemoteBPoolWithBlock,
		remoteOverlappedPoolsContainRemoteABlock,
		remoteOverlappedPoolsContainRemoteBBlock,
	},

	// Cross-cluster CIDR overlap handling: when no IP pool is present to resolve conflict, all CIDRs flush.
	{
		remoteClusterBlockEnclosesLocalBlock,
		remoteClusterBlockEnclosesLocalWEP,
		remoteClusterBlockEnclosesRemoteBlock,
	},

	// Cross-cluster CIDR overlap handling: orphans that enclose before any pool will flush.
	{
		localClusterOrphanBlockContainsRemotePoolAndBlock,

		// Test the inverse of the above state by providing a parent pool to local block,
		// and enclosing the pool with another remote orphan.
		remoteClusterOrphanBlockContainsLocalPoolAndBlock,
	},

	// Cross-cluster CIDR overlap handling: orphans underneath pools from other clusters do not flush.
	{
		remoteClusterPoolAndBlockContainLocalOrphanBlock,

		// Test the inverse of the above state by providing a parent pool to local block,
		// and having the block enclose a remote orphan.
		localClusterPoolAndBlockContainRemoteOrphanBlock,
	},

	// The following cross-cluster tests are Wireguard specific. The majority of IP conflict handling in cross-cluster
	// scenarios has already been handled by the VXLAN tests, so we need not re-implement them for Wireguard:
	// * Block conflicts: The Block inputs into the calc graph are the same between VXLAN/Wireguard modes, so we have coverage via VXLAN tests.
	// * WEP conflicts: The WorkloadEndpoint inputs into the calc graph are the same between VXLAN/Wireguard modes, so we have coverage via VXLAN tests.
	// * Singular tunnel conflicts: The handling of VTEP IP conflict is identical to the handling of WG tunnel IP conflicts, so we have coverage via VXLAN tests.
	//
	// Where Wireguard differs is the fact that multiple tunnel IPs and multiple tunnel types can reside on a single host
	// if Wireguard is enabled on top of VXLAN. The following cases validate IP conflict handling scenarios with multiple
	// tunnel IPs and types on a host.
	{
		multipleTunnelEndpointsOverlapBetweenLocalAndRemoteA,
	},

	{
		multipleTunnelEndpointsOverlapIndirectlyBetweenLocalAndRemoteA,
	},

	{
		multipleTunnelEndpointsOverlapWithoutPoolsBetweenLocalAndRemoteA,
	},

	{
		multipleTunnelEndpointsOverlapAcrossTypesWithoutPoolsBetweenLocalAndRemoteA,
	},

	{
		multipleTunnelEndpointsDisjointWithoutPoolsBetweenLocalAndRemoteA,
	},

	// Istio tests - verify that the all-istio-weps IPSet is populated correctly
	{
		istioWithAmbientPod,
		istioWithMixedPods,
		istioSelectorEdgeCases,
	},

	// TODO(smc): Test config calculation
	// TODO(smc): Test mutation of endpoints
	// TODO(smc): Test mutation of host endpoints
	// TODO(smc): Test validation
	// TODO(smc): Test rule conversions
}

var _ = Describe("COMMERCIAL: Calculation graph state sequencing tests:", func() {
	describeSyncTests(commercialTests)
})

var _ = Describe("COMMERCIAL: Async calculation graph state sequencing tests:", func() {
	describeAsyncTests(commercialTests)
})

// Egress IP.
var (
	nowTime         = time.Now()
	inSixtySecsTime = nowTime.Add(time.Second * 60)

	namespaceSelector = "projectcalico.org/name == 'egress'"
	egressSelector    = "egress-provider == 'true'"
	egressSelectorSim = "egress-provider in {'true', 'not-sure'}"

	egwpSelector1 = "egress-provider == 'true'"
	egwpSelector2 = "egress-provider == 'not-sure'"
	egwpSelector3 = "egress-provider in {'true', 'not-sure'}"

	egressProfileSelector = calc.PreprocessEgressSelector(&v3.EgressSpec{
		Selector: egressSelector,
	}, "egress")
	egwpCombinedSelector1 = calc.PreprocessEgressSelector(&v3.EgressSpec{
		Selector:          egwpSelector1,
		NamespaceSelector: namespaceSelector,
	}, "")
	egwpCombinedSelector2 = calc.PreprocessEgressSelector(&v3.EgressSpec{
		Selector:          egwpSelector2,
		NamespaceSelector: namespaceSelector,
	}, "")
	egwpCombinedSelector3 = calc.PreprocessEgressSelector(&v3.EgressSpec{
		Selector:          egwpSelector3,
		NamespaceSelector: namespaceSelector,
	}, "")

	nsNoSelector = kapiv1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "egress",
			UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
		},
		Spec: kapiv1.NamespaceSpec{},
	}

	ns = kapiv1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "egress",
			Annotations: map[string]string{
				"egress.projectcalico.org/selector": egressSelector,
			},
			UID: types.UID("30316465-6365-4463-ad63-3564622d3638"),
		},
		Spec: kapiv1.NamespaceSpec{},
	}

	nsWithEGWP = kapiv1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "egress",
			Annotations: map[string]string{
				"egress.projectcalico.org/egressGatewayPolicy": "egw-policy1",
				"egress.projectcalico.org/namespaceSelector":   namespaceSelector,
				"egress.projectcalico.org/selector":            egressSelector,
			},
			UID: types.UID("30316465-6365-4463-ad63-3564622d3638"),
		},
		Spec: kapiv1.NamespaceSpec{},
	}

	gatewayKey = WorkloadEndpointKey{
		Hostname:       remoteHostname,
		WorkloadID:     "gw1",
		EndpointID:     "ep1",
		OrchestratorID: "orch",
	}
	gatewayKeyLocal = WorkloadEndpointKey{
		Hostname:       localHostname,
		WorkloadID:     "gw1",
		EndpointID:     "ep1",
		OrchestratorID: "orch",
	}
	gatewayKeyLocal2 = WorkloadEndpointKey{
		Hostname:       localHostname,
		WorkloadID:     "gw2",
		EndpointID:     "ep1",
		OrchestratorID: "orch",
	}
	gatewayKey3 = WorkloadEndpointKey{
		Hostname:       remoteHostname,
		WorkloadID:     "gw3",
		EndpointID:     "ep1",
		OrchestratorID: "orch",
	}
	gatewayEndpoint = &WorkloadEndpoint{
		Name:     "gw1",
		IPv4Nets: []calinet.IPNet{mustParseNet("137.0.0.1/32")},
		Labels: uniquelabels.Make(map[string]string{
			"egress-provider":             "true",
			"projectcalico.org/namespace": "egress",
		}),
		ProfileIDs: []string{"egress"},
	}
	gatewayEndpoint2 = &WorkloadEndpoint{
		Name:     "gw2",
		IPv4Nets: []calinet.IPNet{mustParseNet("137.0.0.2/32")},
		Labels: uniquelabels.Make(map[string]string{
			"egress-provider":             "true",
			"projectcalico.org/namespace": "egress",
		}),
		ProfileIDs: []string{"egress"},
	}
	gatewayEndpoint3 = &WorkloadEndpoint{
		Name:     "gw3",
		IPv4Nets: []calinet.IPNet{mustParseNet("137.0.0.10/32")},
		Labels: uniquelabels.Make(map[string]string{
			"egress-provider":             "not-sure",
			"projectcalico.org/namespace": "egress",
		}),
		ProfileIDs: []string{"egress"},
	}
	egressGatewayPolicy1    = "egw-policy1"
	egressGatewayPolicyKey1 = ResourceKey{Name: "egw-policy1", Kind: v3.KindEgressGatewayPolicy}
	preferenceNone          = v3.GatewayPreferenceNone
	egressGatewayPolicyVal1 = &v3.EgressGatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "egw-policy1",
			UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
		},
		Spec: v3.EgressGatewayPolicySpec{
			Rules: []v3.EgressGatewayRule{
				{
					Gateway: &v3.EgressSpec{
						Selector:          egwpSelector1,
						NamespaceSelector: namespaceSelector,
					},
					GatewayPreference: &preferenceNone,
				},
				{
					Destination: &v3.EgressGatewayPolicyDestinationSpec{
						CIDR: "10.0.0.0/8",
					},
					Gateway: &v3.EgressSpec{
						Selector:          egwpSelector2,
						NamespaceSelector: namespaceSelector,
					},
					GatewayPreference: &preferenceNone,
				},
				{
					Destination: &v3.EgressGatewayPolicyDestinationSpec{
						CIDR: "11.0.0.0/8",
					},
					GatewayPreference: &preferenceNone,
				},
			},
		},
	}
	egressGatewayPolicyVal2 = &v3.EgressGatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "egw-policy1",
			UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
		},
		Spec: v3.EgressGatewayPolicySpec{
			Rules: []v3.EgressGatewayRule{
				{
					Gateway: &v3.EgressSpec{
						Selector:          egwpSelector2,
						NamespaceSelector: namespaceSelector,
					},
					GatewayPreference: &preferenceNone,
				},
				{
					Destination: &v3.EgressGatewayPolicyDestinationSpec{
						CIDR: "10.0.0.0/8",
					},
					Gateway: &v3.EgressSpec{
						Selector:          egwpSelector1,
						NamespaceSelector: namespaceSelector,
					},
					GatewayPreference: &preferenceNone,
				},
				{
					Destination: &v3.EgressGatewayPolicyDestinationSpec{
						CIDR: "13.0.0.0/8",
					},
					Gateway: &v3.EgressSpec{
						Selector:          egwpSelector3,
						NamespaceSelector: namespaceSelector,
					},
					GatewayPreference: &preferenceNone,
				},
				{
					Destination: &v3.EgressGatewayPolicyDestinationSpec{
						CIDR: "11.0.0.0/8",
					},
					GatewayPreference: &preferenceNone,
				},
				{
					Destination: &v3.EgressGatewayPolicyDestinationSpec{
						CIDR: "12.0.0.0/8",
					},
					GatewayPreference: &preferenceNone,
				},
			},
		},
	}

	endpointWithOwnEgressGatewayID = WorkloadEndpointKey{
		Hostname:       localHostname,
		WorkloadID:     "wep1o",
		EndpointID:     "ep1",
		OrchestratorID: "orch",
	}
	endpointWithOwnEgressGateway = initialisedStore.withKVUpdates(
		KVPair{
			Key: endpointWithOwnEgressGatewayID,
			Value: &WorkloadEndpoint{
				Name:           "wep1o",
				EgressSelector: egressSelector,
			},
		},
		KVPair{
			Key:   gatewayKey,
			Value: gatewayEndpoint,
		},
	).withRemoteEndpoint(
		calc.CalculateRemoteEndpoint(gatewayKey, gatewayEndpoint),
	).withEndpoint(
		"orch/wep1o/ep1",
		[]mock.TierInfo{},
	).withEndpointEgressData(
		"orch/wep1o/ep1",
		calc.EPCompDataKindEgressGateway,
		&calc.ComputedEgressEP{
			Rules: []calc.EpEgressData{
				{IpSetID: egressSelectorID(egressSelector)},
			},
		},
	).withIPSet(egressSelectorID(egressSelector), []string{
		egressActiveMemberStr("137.0.0.1/32", gatewayKey.Hostname),
	},
	).withName("endpointWithOwnEgressGateway")

	endpointWithNoneExistingEgressGatewayPolicy = initialisedStore.withKVUpdates(
		KVPair{
			Key: endpointWithOwnEgressGatewayID,
			Value: &WorkloadEndpoint{
				Name:                "wep1o",
				EgressSelector:      egressSelector,
				EgressGatewayPolicy: egressGatewayPolicy1,
			},
		},
		KVPair{
			Key:   gatewayKey,
			Value: gatewayEndpoint,
		},
	).withRemoteEndpoint(
		calc.CalculateRemoteEndpoint(gatewayKey, gatewayEndpoint),
	).withEndpoint(
		"orch/wep1o/ep1",
		[]mock.TierInfo{},
	).withEndpointEgressData(
		"orch/wep1o/ep1",
		calc.EPCompDataKindEgressGateway,
		&calc.ComputedEgressEP{
			Rules: []calc.EpEgressData{
				{
					IpSetID: egressSelectorID("!all()"),
				},
			},
		},
	).withIPSet(egressSelectorID("!all()"), []string{}).withName("endpointWithNoneExistingEgressGatewayPolicy")

	endpointWithDefinedEgressGatewayPolicy = initialisedStore.withKVUpdates(
		KVPair{
			Key:   ResourceKey{Name: "egress", Kind: v3.KindProfile},
			Value: namespaceToProfile(&ns),
		},
		KVPair{
			Key: endpointWithOwnEgressGatewayID,
			Value: &WorkloadEndpoint{
				Name:                "wep1o",
				EgressGatewayPolicy: egressGatewayPolicy1,
				ProfileIDs:          []string{"egress"},
			},
		},
		KVPair{
			Key:   gatewayKey,
			Value: gatewayEndpoint,
		},
		KVPair{
			Key:   gatewayKey3,
			Value: gatewayEndpoint3,
		},
		KVPair{
			Key:   egressGatewayPolicyKey1,
			Value: egressGatewayPolicyVal1,
		},
	).withRemoteEndpoint(
		calc.CalculateRemoteEndpoint(gatewayKey, gatewayEndpoint),
	).withRemoteEndpoint(
		calc.CalculateRemoteEndpoint(gatewayKey3, gatewayEndpoint3),
	).withEndpoint(
		"orch/wep1o/ep1",
		[]mock.TierInfo{},
	).withEndpointEgressData(
		"orch/wep1o/ep1",
		calc.EPCompDataKindEgressGateway,
		&calc.ComputedEgressEP{
			Rules: []calc.EpEgressData{
				{
					IpSetID: egressSelectorID(egwpCombinedSelector1),
				},
				{
					CIDR:    "10.0.0.0/8",
					IpSetID: egressSelectorID(egwpCombinedSelector2),
				},
				{
					CIDR: "11.0.0.0/8",
				},
			},
		},
	).withIPSet(egressSelectorID(egwpCombinedSelector1), []string{
		egressActiveMemberStr("137.0.0.1/32", gatewayKey.Hostname),
	},
	).withIPSet(egressSelectorID(egwpCombinedSelector2), []string{
		egressActiveMemberStr("137.0.0.10/32", gatewayKey3.Hostname),
	},
	).withActiveProfiles(
		felixtypes.ProfileID{Name: "egress"},
	).withName("endpointWithDefinedEgressGatewayPolicy")

	endpointWithDifferentEgressGatewayPolicy = initialisedStore.withKVUpdates(
		KVPair{
			Key:   ResourceKey{Name: "egress", Kind: v3.KindProfile},
			Value: namespaceToProfile(&ns),
		},
		KVPair{
			Key: endpointWithOwnEgressGatewayID,
			Value: &WorkloadEndpoint{
				Name:                "wep1o",
				EgressGatewayPolicy: egressGatewayPolicy1,
				ProfileIDs:          []string{"egress"},
			},
		},
		KVPair{
			Key:   gatewayKey,
			Value: gatewayEndpoint,
		},
		KVPair{
			Key:   gatewayKey3,
			Value: gatewayEndpoint3,
		},
		KVPair{
			Key:   egressGatewayPolicyKey1,
			Value: egressGatewayPolicyVal2,
		},
	).withRemoteEndpoint(
		calc.CalculateRemoteEndpoint(gatewayKey, gatewayEndpoint),
	).withRemoteEndpoint(
		calc.CalculateRemoteEndpoint(gatewayKey3, gatewayEndpoint3),
	).withEndpoint(
		"orch/wep1o/ep1",
		[]mock.TierInfo{},
	).withEndpointEgressData(
		"orch/wep1o/ep1",
		calc.EPCompDataKindEgressGateway,
		&calc.ComputedEgressEP{
			Rules: []calc.EpEgressData{
				{
					IpSetID: egressSelectorID(egwpCombinedSelector2),
				},
				{
					CIDR:    "10.0.0.0/8",
					IpSetID: egressSelectorID(egwpCombinedSelector1),
				},
				{
					CIDR:    "13.0.0.0/8",
					IpSetID: egressSelectorID(egwpCombinedSelector3),
				},
				{
					CIDR: "11.0.0.0/8",
				},
				{
					CIDR: "12.0.0.0/8",
				},
			},
		},
	).withIPSet(egressSelectorID(egwpCombinedSelector1), []string{
		egressActiveMemberStr("137.0.0.1/32", gatewayKey.Hostname),
	},
	).withIPSet(egressSelectorID(egwpCombinedSelector2), []string{
		egressActiveMemberStr("137.0.0.10/32", gatewayKey3.Hostname),
	},
	).withIPSet(egressSelectorID(egwpCombinedSelector3), []string{
		egressActiveMemberStr("137.0.0.1/32", gatewayKey.Hostname),
		egressActiveMemberStr("137.0.0.10/32", gatewayKey3.Hostname),
	},
	).withActiveProfiles(
		felixtypes.ProfileID{Name: "egress"},
	).withName("endpointWithDifferentEgressGatewayPolicy")

	endpointWithOwnLocalEgressGateway = initialisedStore.withKVUpdates(
		KVPair{
			Key: endpointWithOwnEgressGatewayID,
			Value: &WorkloadEndpoint{
				Name:           "wep1o",
				EgressSelector: egressSelector,
				ProfileIDs:     []string{"egress"},
			},
		},
		KVPair{
			Key:   gatewayKeyLocal,
			Value: gatewayEndpoint,
		},
	).withEndpoint(
		"orch/gw1/ep1",
		[]mock.TierInfo{},
	).withEndpointEgressData(
		"orch/gw1/ep1",
		calc.EPCompDataKindEgressGateway,
		&calc.ComputedEgressEP{IsEgressGateway: true},
	).withEndpoint(
		"orch/wep1o/ep1",
		[]mock.TierInfo{},
	).withEndpointEgressData(
		"orch/wep1o/ep1",
		calc.EPCompDataKindEgressGateway,
		&calc.ComputedEgressEP{
			Rules: []calc.EpEgressData{
				{
					IpSetID: egressSelectorID(egressSelector),
				},
			},
		},
	).withIPSet(egressSelectorID(egressSelector), []string{
		egressActiveMemberStr("137.0.0.1/32", gatewayKeyLocal.Hostname),
	},
	).withRoutes(
		felixtypes.RouteUpdate{
			Types:         proto.RouteType_LOCAL_WORKLOAD,
			Dst:           "137.0.0.1/32",
			DstNodeName:   localHostname,
			LocalWorkload: true,
		},
	).withActiveProfiles(
		felixtypes.ProfileID{Name: "egress"},
	).withName("endpointWithOwnLocalEgressGateway")

	endpointWithOwnLocalEgressGatewayWithEGWPolicy = initialisedStore.withKVUpdates(
		KVPair{
			Key:   ResourceKey{Name: "egress", Kind: v3.KindProfile},
			Value: namespaceToProfile(&nsWithEGWP),
		},
		KVPair{
			Key: endpointWithOwnEgressGatewayID,
			Value: &WorkloadEndpoint{
				Name:                "wep1o",
				EgressGatewayPolicy: egressGatewayPolicy1,
				ProfileIDs:          []string{"egress"},
			},
		},
		KVPair{
			Key:   gatewayKeyLocal,
			Value: gatewayEndpoint,
		},
		KVPair{
			Key:   gatewayKey3,
			Value: gatewayEndpoint3,
		},
		KVPair{
			Key:   egressGatewayPolicyKey1,
			Value: egressGatewayPolicyVal1,
		},
	).withEndpoint(
		"orch/gw1/ep1",
		[]mock.TierInfo{},
	).withEndpointEgressData(
		"orch/gw1/ep1",
		calc.EPCompDataKindEgressGateway,
		&calc.ComputedEgressEP{IsEgressGateway: true},
	).withEndpoint(
		"orch/wep1o/ep1",
		[]mock.TierInfo{},
	).withRemoteEndpoint(
		calc.CalculateRemoteEndpoint(gatewayKey3, gatewayEndpoint3),
	).withEndpointEgressData(
		"orch/wep1o/ep1",
		calc.EPCompDataKindEgressGateway,
		&calc.ComputedEgressEP{
			Rules: []calc.EpEgressData{
				{
					IpSetID: egressSelectorID(egwpCombinedSelector1),
				},
				{
					CIDR:    "10.0.0.0/8",
					IpSetID: egressSelectorID(egwpCombinedSelector2),
				},
				{
					CIDR: "11.0.0.0/8",
				},
			},
		},
	).withIPSet(egressSelectorID(egwpCombinedSelector1), []string{
		egressActiveMemberStr("137.0.0.1/32", gatewayKeyLocal.Hostname),
	},
	).withIPSet(egressSelectorID(egwpCombinedSelector2), []string{
		egressActiveMemberStr("137.0.0.10/32", gatewayKey3.Hostname),
	},
	).withRoutes(
		felixtypes.RouteUpdate{
			Types:         proto.RouteType_LOCAL_WORKLOAD,
			Dst:           "137.0.0.1/32",
			DstNodeName:   localHostname,
			LocalWorkload: true,
		},
	).withActiveProfiles(
		felixtypes.ProfileID{Name: "egress"},
	).withName("endpointWithOwnLocalEgressGatewayWithEGWPolicy")

	endpointWithProfileEgressGatewayID = WorkloadEndpointKey{
		Hostname:       localHostname,
		WorkloadID:     "wep1p",
		EndpointID:     "ep1",
		OrchestratorID: "orch",
	}
	endpointWithProfileEgressGateway = initialisedStore.withKVUpdates(
		KVPair{
			Key:   ResourceKey{Name: "egress", Kind: v3.KindProfile},
			Value: namespaceToProfile(&ns),
		},
		KVPair{
			Key: endpointWithProfileEgressGatewayID,
			Value: &WorkloadEndpoint{
				Name:       "wep1p",
				ProfileIDs: []string{"egress"},
			},
		},
		KVPair{
			Key:   gatewayKey,
			Value: gatewayEndpoint,
		},
	).withRemoteEndpoint(
		calc.CalculateRemoteEndpoint(gatewayKey, gatewayEndpoint),
	).withEndpoint(
		"orch/wep1p/ep1",
		[]mock.TierInfo{},
	).withEndpointEgressData(
		"orch/wep1p/ep1",
		calc.EPCompDataKindEgressGateway,
		&calc.ComputedEgressEP{
			Rules: []calc.EpEgressData{
				{
					IpSetID: egressSelectorID(egressProfileSelector),
				},
			},
		},
	).withIPSet(egressSelectorID(egressProfileSelector), []string{
		egressActiveMemberStr("137.0.0.1/32", gatewayKey.Hostname),
	},
	).withActiveProfiles(
		felixtypes.ProfileID{Name: "egress"},
	).withName("endpointWithProfileEgressGateway")

	endpointWithProfileWithNoneExistingEgressGatewayPolicy = initialisedStore.withKVUpdates(
		KVPair{
			Key:   ResourceKey{Name: "egress", Kind: v3.KindProfile},
			Value: namespaceToProfile(&nsWithEGWP),
		},
		KVPair{
			Key: endpointWithProfileEgressGatewayID,
			Value: &WorkloadEndpoint{
				Name:       "wep1p",
				ProfileIDs: []string{"egress"},
			},
		},
		KVPair{
			Key:   gatewayKey,
			Value: gatewayEndpoint,
		},
	).withRemoteEndpoint(
		calc.CalculateRemoteEndpoint(gatewayKey, gatewayEndpoint),
	).withEndpoint(
		"orch/wep1p/ep1",
		[]mock.TierInfo{},
	).withEndpointEgressData(
		"orch/wep1p/ep1",
		calc.EPCompDataKindEgressGateway,
		&calc.ComputedEgressEP{
			Rules: []calc.EpEgressData{
				{
					IpSetID: egressSelectorID("!all()"),
				},
			},
		},
	).withActiveProfiles(
		felixtypes.ProfileID{Name: "egress"},
	).withIPSet(egressSelectorID("!all()"), []string{}).withName("endpointWithProfileWithNoneExistingEgressGatewayPolicy")

	endpointWithProfileWithEgressGatewayPolicy = initialisedStore.withKVUpdates(
		KVPair{
			Key:   ResourceKey{Name: "egress", Kind: v3.KindProfile},
			Value: namespaceToProfile(&nsWithEGWP),
		},
		KVPair{
			Key: endpointWithProfileEgressGatewayID,
			Value: &WorkloadEndpoint{
				Name:       "wep1p",
				ProfileIDs: []string{"egress"},
			},
		},
		KVPair{
			Key:   egressGatewayPolicyKey1,
			Value: egressGatewayPolicyVal1,
		},
		KVPair{
			Key:   gatewayKey3,
			Value: gatewayEndpoint3,
		},
		KVPair{
			Key:   gatewayKey,
			Value: gatewayEndpoint,
		},
	).withRemoteEndpoint(
		calc.CalculateRemoteEndpoint(gatewayKey3, gatewayEndpoint3),
	).withRemoteEndpoint(
		calc.CalculateRemoteEndpoint(gatewayKey, gatewayEndpoint),
	).withEndpoint(
		"orch/wep1p/ep1",
		[]mock.TierInfo{},
	).withEndpointEgressData(
		"orch/wep1p/ep1",
		calc.EPCompDataKindEgressGateway,
		&calc.ComputedEgressEP{
			Rules: []calc.EpEgressData{
				{
					IpSetID: egressSelectorID(egwpCombinedSelector1),
				},
				{
					CIDR:    "10.0.0.0/8",
					IpSetID: egressSelectorID(egwpCombinedSelector2),
				},
				{
					CIDR: "11.0.0.0/8",
				},
			},
		},
	).withIPSet(egressSelectorID(egwpCombinedSelector2), []string{
		egressActiveMemberStr("137.0.0.10/32", gatewayKey3.Hostname),
	},
	).withIPSet(egressSelectorID(egwpCombinedSelector1), []string{
		egressActiveMemberStr("137.0.0.1/32", gatewayKey.Hostname),
	},
	).withActiveProfiles(
		felixtypes.ProfileID{Name: "egress"},
	).withName("endpointWithProfileWithEgressGatewayPolicy")

	endpointWithProfileLocalEgressGateway = initialisedStore.withKVUpdates(
		KVPair{
			Key:   ResourceKey{Name: "egress", Kind: v3.KindProfile},
			Value: namespaceToProfile(&ns),
		},
		KVPair{
			Key: endpointWithProfileEgressGatewayID,
			Value: &WorkloadEndpoint{
				Name:       "wep1p",
				ProfileIDs: []string{"egress"},
			},
		},
		KVPair{
			Key:   gatewayKeyLocal,
			Value: gatewayEndpoint,
		},
	).withEndpoint(
		"orch/gw1/ep1",
		[]mock.TierInfo{},
	).withEndpointEgressData(
		"orch/gw1/ep1",
		calc.EPCompDataKindEgressGateway,
		&calc.ComputedEgressEP{IsEgressGateway: true},
	).withEndpoint(
		"orch/wep1p/ep1",
		[]mock.TierInfo{},
	).withEndpointEgressData(
		"orch/wep1p/ep1",
		calc.EPCompDataKindEgressGateway,
		&calc.ComputedEgressEP{
			Rules: []calc.EpEgressData{
				{
					IpSetID: egressSelectorID(egressProfileSelector),
				},
			},
		},
	).withIPSet(egressSelectorID(egressProfileSelector), []string{
		egressActiveMemberStr("137.0.0.1/32", gatewayKeyLocal.Hostname),
	},
	).withActiveProfiles(
		felixtypes.ProfileID{Name: "egress"},
	).withRoutes(
		felixtypes.RouteUpdate{
			Types:         proto.RouteType_LOCAL_WORKLOAD,
			Dst:           "137.0.0.1/32",
			DstNodeName:   localHostname,
			LocalWorkload: true,
		},
	).withName("endpointWithProfileLocalEgressGateway")

	endpointWithProfileLocalEgressGatewayWithEGWPolicy = initialisedStore.withKVUpdates(
		KVPair{
			Key:   egressGatewayPolicyKey1,
			Value: egressGatewayPolicyVal1,
		},
		KVPair{
			Key:   ResourceKey{Name: "egress", Kind: v3.KindProfile},
			Value: namespaceToProfile(&nsWithEGWP),
		},
		KVPair{
			Key: endpointWithProfileEgressGatewayID,
			Value: &WorkloadEndpoint{
				Name:       "wep1p",
				ProfileIDs: []string{"egress"},
			},
		},
		KVPair{
			Key:   gatewayKeyLocal,
			Value: gatewayEndpoint,
		},
		KVPair{
			Key:   gatewayKey3,
			Value: gatewayEndpoint3,
		},
	).withRemoteEndpoint(
		calc.CalculateRemoteEndpoint(gatewayKey3, gatewayEndpoint3),
	).withEndpoint(
		"orch/gw1/ep1",
		[]mock.TierInfo{},
	).withEndpointEgressData(
		"orch/gw1/ep1",
		calc.EPCompDataKindEgressGateway,
		&calc.ComputedEgressEP{IsEgressGateway: true},
	).withEndpoint(
		"orch/wep1p/ep1",
		[]mock.TierInfo{},
	).withEndpointEgressData(
		"orch/wep1p/ep1",
		calc.EPCompDataKindEgressGateway,
		&calc.ComputedEgressEP{
			Rules: []calc.EpEgressData{
				{
					IpSetID: egressSelectorID(egwpCombinedSelector1),
				},
				{
					CIDR:    "10.0.0.0/8",
					IpSetID: egressSelectorID(egwpCombinedSelector2),
				},
				{
					CIDR: "11.0.0.0/8",
				},
			},
		},
	).withIPSet(egressSelectorID(egwpCombinedSelector1), []string{
		egressActiveMemberStr("137.0.0.1/32", gatewayKeyLocal.Hostname),
	},
	).withIPSet(egressSelectorID(egwpCombinedSelector2), []string{
		egressActiveMemberStr("137.0.0.10/32", gatewayKey3.Hostname),
	},
	).withActiveProfiles(
		felixtypes.ProfileID{Name: "egress"},
	).withRoutes(
		felixtypes.RouteUpdate{
			Types:         proto.RouteType_LOCAL_WORKLOAD,
			Dst:           "137.0.0.1/32",
			DstNodeName:   localHostname,
			LocalWorkload: true,
		},
	).withName("endpointWithProfileLocalEgressGatewayWithEGWPolicy")

	endpointWithoutOwnEgressGateway = initialisedStore.withKVUpdates(
		KVPair{
			Key: endpointWithOwnEgressGatewayID,
			Value: &WorkloadEndpoint{
				Name: "wep1o",
			},
		},
		KVPair{
			Key:   gatewayKey,
			Value: gatewayEndpoint,
		},
	).withRemoteEndpoint(
		calc.CalculateRemoteEndpoint(gatewayKey, gatewayEndpoint),
	).withEndpoint(
		"orch/wep1o/ep1",
		[]mock.TierInfo{},
	).withName("endpointWithoutOwnEgressGateway")

	endpointWithoutProfileEgressGateway = initialisedStore.withKVUpdates(
		KVPair{
			Key:   ResourceKey{Name: "egress", Kind: v3.KindProfile},
			Value: namespaceToProfile(&nsNoSelector),
		},
		KVPair{
			Key: endpointWithProfileEgressGatewayID,
			Value: &WorkloadEndpoint{
				Name:       "wep1p",
				ProfileIDs: []string{"egress"},
			},
		},
		KVPair{
			Key:   gatewayKey,
			Value: gatewayEndpoint,
		},
	).withRemoteEndpoint(
		calc.CalculateRemoteEndpoint(gatewayKey, gatewayEndpoint),
	).withEndpoint(
		"orch/wep1p/ep1",
		[]mock.TierInfo{},
	).withActiveProfiles(
		felixtypes.ProfileID{Name: "egress"},
	).withName("endpointWithoutProfileEgressGateway")

	twoRemoteEpsSameEgressSelectorLocalGateway = initialisedStore.withKVUpdates(
		KVPair{
			Key: endpointWithOwnEgressGatewayID,
			Value: &WorkloadEndpoint{
				Name:           "wep1o",
				EgressSelector: egressSelector,
				ProfileIDs:     []string{"egress"},
			},
		},
		KVPair{
			Key: WorkloadEndpointKey{
				Hostname:       localHostname,
				WorkloadID:     "wep1o2",
				EndpointID:     "ep1",
				OrchestratorID: "orch",
			},
			Value: &WorkloadEndpoint{
				Name:           "wep1o2",
				EgressSelector: egressSelector,
				ProfileIDs:     []string{"egress"},
			},
		},
		KVPair{
			Key:   gatewayKeyLocal,
			Value: gatewayEndpoint,
		},
	).withEndpoint(
		"orch/wep1o/ep1",
		[]mock.TierInfo{},
	).withEndpointEgressData(
		"orch/wep1o/ep1",
		calc.EPCompDataKindEgressGateway,
		&calc.ComputedEgressEP{
			Rules: []calc.EpEgressData{
				{
					IpSetID: egressSelectorID(egressSelector),
				},
			},
		},
	).withEndpoint(
		"orch/wep1o2/ep1",
		[]mock.TierInfo{},
	).withEndpointEgressData(
		"orch/wep1o2/ep1",
		calc.EPCompDataKindEgressGateway,
		&calc.ComputedEgressEP{
			Rules: []calc.EpEgressData{
				{
					IpSetID: egressSelectorID(egressSelector),
				},
			},
		},
	).withEndpoint(
		"orch/gw1/ep1",
		[]mock.TierInfo{},
	).withEndpointEgressData(
		"orch/gw1/ep1",
		calc.EPCompDataKindEgressGateway,
		&calc.ComputedEgressEP{IsEgressGateway: true},
	).withIPSet(egressSelectorID(egressSelector), []string{
		egressActiveMemberStr("137.0.0.1/32", gatewayKeyLocal.Hostname),
	},
	).withRoutes(
		felixtypes.RouteUpdate{
			Types:         proto.RouteType_LOCAL_WORKLOAD,
			Dst:           "137.0.0.1/32",
			DstNodeName:   localHostname,
			LocalWorkload: true,
		},
	).withActiveProfiles(
		felixtypes.ProfileID{Name: "egress"},
	).withName("twoRemoteEpsSameEgressSelectorLocalGateway")

	twoRemoteEpsSameEgressGatewayPolicyLocalGateway = initialisedStore.withKVUpdates(
		KVPair{
			Key:   ResourceKey{Name: "egress", Kind: v3.KindProfile},
			Value: namespaceToProfile(&nsNoSelector),
		},
		KVPair{
			Key: endpointWithOwnEgressGatewayID,
			Value: &WorkloadEndpoint{
				Name:                "wep1o",
				ProfileIDs:          []string{"egress"},
				EgressGatewayPolicy: egressGatewayPolicy1,
			},
		},
		KVPair{
			Key: WorkloadEndpointKey{
				Hostname:       localHostname,
				WorkloadID:     "wep1o2",
				EndpointID:     "ep1",
				OrchestratorID: "orch",
			},
			Value: &WorkloadEndpoint{
				Name:                "wep1o2",
				ProfileIDs:          []string{"egress"},
				EgressGatewayPolicy: egressGatewayPolicy1,
			},
		},
		KVPair{
			Key:   gatewayKey3,
			Value: gatewayEndpoint3,
		},
		KVPair{
			Key:   egressGatewayPolicyKey1,
			Value: egressGatewayPolicyVal1,
		},
		KVPair{
			Key:   gatewayKeyLocal,
			Value: gatewayEndpoint,
		},
	).withRemoteEndpoint(
		calc.CalculateRemoteEndpoint(gatewayKey3, gatewayEndpoint3),
	).withEndpoint(
		"orch/wep1o/ep1",
		[]mock.TierInfo{},
	).withEndpointEgressData(
		"orch/wep1o/ep1",
		calc.EPCompDataKindEgressGateway,
		&calc.ComputedEgressEP{
			Rules: []calc.EpEgressData{
				{
					IpSetID: egressSelectorID(egwpCombinedSelector1),
				},
				{
					CIDR:    "10.0.0.0/8",
					IpSetID: egressSelectorID(egwpCombinedSelector2),
				},
				{
					CIDR: "11.0.0.0/8",
				},
			},
		},
	).withEndpoint(
		"orch/wep1o2/ep1",
		[]mock.TierInfo{},
	).withEndpointEgressData(
		"orch/wep1o2/ep1",
		calc.EPCompDataKindEgressGateway,
		&calc.ComputedEgressEP{
			Rules: []calc.EpEgressData{
				{
					IpSetID: egressSelectorID(egwpCombinedSelector1),
				},
				{
					CIDR:    "10.0.0.0/8",
					IpSetID: egressSelectorID(egwpCombinedSelector2),
				},
				{
					CIDR: "11.0.0.0/8",
				},
			},
		},
	).withEndpoint(
		"orch/gw1/ep1",
		[]mock.TierInfo{},
	).withEndpointEgressData(
		"orch/gw1/ep1",
		calc.EPCompDataKindEgressGateway,
		&calc.ComputedEgressEP{IsEgressGateway: true},
	).withIPSet(egressSelectorID(egwpCombinedSelector1), []string{
		egressActiveMemberStr("137.0.0.1/32", gatewayKeyLocal.Hostname),
	},
	).withIPSet(egressSelectorID(egwpCombinedSelector2), []string{
		egressActiveMemberStr("137.0.0.10/32", gatewayKey3.Hostname),
	},
	).withRoutes(
		felixtypes.RouteUpdate{
			Types:         proto.RouteType_LOCAL_WORKLOAD,
			Dst:           "137.0.0.1/32",
			DstNodeName:   localHostname,
			LocalWorkload: true,
		},
	).withActiveProfiles(
		felixtypes.ProfileID{Name: "egress"},
	).withName("twoRemoteEpsSameEgressGatewayPolicyLocalGateway")

	twoRemoteEpsSimilarEgressSelectorLocalGateway = initialisedStore.withKVUpdates(
		KVPair{
			Key: endpointWithOwnEgressGatewayID,
			Value: &WorkloadEndpoint{
				Name:           "wep1o",
				EgressSelector: egressSelectorSim,
				ProfileIDs:     []string{"egress"},
			},
		},
		KVPair{
			Key: WorkloadEndpointKey{
				Hostname:       localHostname,
				WorkloadID:     "wep1o2",
				EndpointID:     "ep1",
				OrchestratorID: "orch",
			},
			Value: &WorkloadEndpoint{
				Name:           "wep1o2",
				EgressSelector: egressSelector,
				ProfileIDs:     []string{"egress"},
			},
		},
		KVPair{
			Key:   gatewayKeyLocal,
			Value: gatewayEndpoint,
		},
	).withEndpoint(
		"orch/wep1o/ep1",
		[]mock.TierInfo{},
	).withEndpointEgressData(
		"orch/wep1o/ep1",
		calc.EPCompDataKindEgressGateway,
		&calc.ComputedEgressEP{
			Rules: []calc.EpEgressData{
				{
					IpSetID: egressSelectorID(egressSelectorSim),
				},
			},
		},
	).withEndpoint(
		"orch/wep1o2/ep1",
		[]mock.TierInfo{},
	).withEndpointEgressData(
		"orch/wep1o2/ep1",
		calc.EPCompDataKindEgressGateway,
		&calc.ComputedEgressEP{
			Rules: []calc.EpEgressData{
				{
					IpSetID: egressSelectorID(egressSelector),
				},
			},
		},
	).withEndpoint(
		"orch/gw1/ep1",
		[]mock.TierInfo{},
	).withEndpointEgressData(
		"orch/gw1/ep1",
		calc.EPCompDataKindEgressGateway,
		&calc.ComputedEgressEP{IsEgressGateway: true},
	).withIPSet(egressSelectorID(egressSelector), []string{
		egressActiveMemberStr("137.0.0.1/32", gatewayKeyLocal.Hostname),
	},
	).withIPSet(egressSelectorID(egressSelectorSim), []string{
		egressActiveMemberStr("137.0.0.1/32", gatewayKeyLocal.Hostname),
	},
	).withRoutes(
		felixtypes.RouteUpdate{
			Types:         proto.RouteType_LOCAL_WORKLOAD,
			Dst:           "137.0.0.1/32",
			DstNodeName:   localHostname,
			LocalWorkload: true,
		},
	).withActiveProfiles(
		felixtypes.ProfileID{Name: "egress"},
	).withName("twoRemoteEpsSimilarEgressSelectorLocalGateway")

	twoRemoteEpsSimilarEgressSelectorTwoLocalGateways = twoRemoteEpsSimilarEgressSelectorLocalGateway.withKVUpdates(
		KVPair{
			Key:   gatewayKeyLocal2,
			Value: gatewayEndpoint2,
		},
	).withIPSet(egressSelectorID(egressSelector), []string{
		egressActiveMemberStr("137.0.0.1/32", gatewayKeyLocal.Hostname),
		egressActiveMemberStr("137.0.0.2/32", gatewayKeyLocal2.Hostname),
	},
	).withIPSet(egressSelectorID(egressSelectorSim), []string{
		egressActiveMemberStr("137.0.0.1/32", gatewayKeyLocal.Hostname),
		egressActiveMemberStr("137.0.0.2/32", gatewayKeyLocal2.Hostname),
	},
	).withEndpoint(
		"orch/gw2/ep1",
		[]mock.TierInfo{},
	).withEndpointEgressData(
		"orch/gw2/ep1",
		calc.EPCompDataKindEgressGateway,
		&calc.ComputedEgressEP{IsEgressGateway: true},
	).withRoutes(
		felixtypes.RouteUpdate{
			Types:         proto.RouteType_LOCAL_WORKLOAD,
			Dst:           "137.0.0.1/32",
			DstNodeName:   localHostname,
			LocalWorkload: true,
		},
		felixtypes.RouteUpdate{
			Types:         proto.RouteType_LOCAL_WORKLOAD,
			Dst:           "137.0.0.2/32",
			DstNodeName:   localHostname,
			LocalWorkload: true,
		},
	).withName("twoRemoteEpsSimilarEgressSelectorTwoLocalGateways")

	activeGatewayEndpoint = &WorkloadEndpoint{
		Name:     "gw1",
		IPv4Nets: []calinet.IPNet{mustParseNet("137.0.0.1/32")},
		Labels: uniquelabels.Make(map[string]string{
			"egress-provider":             "true",
			"projectcalico.org/namespace": "egress",
		}),
	}

	activeGatewayEndpointWithPort = &WorkloadEndpoint{
		Name:     "gw1",
		IPv4Nets: []calinet.IPNet{mustParseNet("137.0.0.1/32")},
		Labels: uniquelabels.Make(map[string]string{
			"egress-provider":             "true",
			"projectcalico.org/namespace": "egress",
		}),
		Ports: []EndpointPort{
			{Name: "something", Port: 9090, Protocol: numorstring.ProtocolFromStringV1("tcp")},
			{Name: "health", Port: 8080, Protocol: numorstring.ProtocolFromStringV1("tcp")},
		},
	}

	terminatingGatewayEndpoint = &WorkloadEndpoint{
		Name:     "gw1",
		IPv4Nets: []calinet.IPNet{mustParseNet("137.0.0.1/32")},
		Labels: uniquelabels.Make(map[string]string{
			"egress-provider":             "true",
			"projectcalico.org/namespace": "egress",
		}),
		DeletionTimestamp:          inSixtySecsTime,
		DeletionGracePeriodSeconds: 60,
	}

	createEndpointWithRemoteEgressGateway = func(name string, gateway *WorkloadEndpoint, ipSetMemberStr string) State {
		return initialisedStore.withKVUpdates(
			KVPair{
				Key: endpointWithOwnEgressGatewayID,
				Value: &WorkloadEndpoint{
					Name:           "wep1o",
					EgressSelector: egressSelector,
				},
			},
			KVPair{
				Key:   gatewayKey,
				Value: gateway,
			},
		).withRemoteEndpoint(
			calc.CalculateRemoteEndpoint(gatewayKey, gateway),
		).withEndpoint(
			"orch/wep1o/ep1",
			[]mock.TierInfo{},
		).withEndpointEgressData(
			"orch/wep1o/ep1",
			calc.EPCompDataKindEgressGateway,
			&calc.ComputedEgressEP{
				Rules: []calc.EpEgressData{
					{
						IpSetID: egressSelectorID(egressSelector),
					},
				},
			},
		).withIPSet(egressSelectorID(egressSelector), []string{
			ipSetMemberStr,
		},
		).withName(name)
	}

	createEndpointWithLocalEgressGateway = func(name string, gateway *WorkloadEndpoint, ipSetMemberStr string) State {
		healthPort := uint16(0)
		// The health port is one of the entries in the IP set member string. For example:
		//    137.0.0.1/32,2025-02-03t16:27:58.366521782z,2025-02-03t16:28:58.366521782z,0,remotehostname
		if strings.Split(ipSetMemberStr, ",")[3] == "8080" {
			healthPort = 8080
		}
		return initialisedStore.withKVUpdates(
			KVPair{
				Key: endpointWithOwnEgressGatewayID,
				Value: &WorkloadEndpoint{
					Name:           "wep1o",
					EgressSelector: egressSelector,
				},
			},
			KVPair{
				Key:   gatewayKeyLocal,
				Value: gateway,
			},
		).withEndpoint(
			"orch/gw1/ep1",
			[]mock.TierInfo{},
		).withEndpointEgressData(
			"orch/gw1/ep1",
			calc.EPCompDataKindEgressGateway,
			&calc.ComputedEgressEP{
				IsEgressGateway: true,
				HealthPort:      healthPort,
			},
		).withEndpoint(
			"orch/wep1o/ep1",
			[]mock.TierInfo{},
		).withEndpointEgressData(
			"orch/wep1o/ep1",
			calc.EPCompDataKindEgressGateway,
			&calc.ComputedEgressEP{
				Rules: []calc.EpEgressData{
					{
						IpSetID: egressSelectorID(egressSelector),
					},
				},
			},
		).withIPSet(egressSelectorID(egressSelector), []string{
			ipSetMemberStr,
		},
		).withRoutes(
			felixtypes.RouteUpdate{
				Types:         proto.RouteType_LOCAL_WORKLOAD,
				Dst:           "137.0.0.1/32",
				DstNodeName:   localHostname,
				LocalWorkload: true,
			},
		).withName(name)
	}

	endpointWithRemoteActiveEgressGateway = createEndpointWithRemoteEgressGateway(
		"endpointWithRemoteActiveEgressGateway",
		activeGatewayEndpoint,
		egressActiveMemberStr("137.0.0.1/32", gatewayKey.Hostname))

	endpointWithRemoteActiveEgressGatewayWithPort = createEndpointWithRemoteEgressGateway(
		"endpointWithRemoteActiveEgressGatewayWithPort",
		activeGatewayEndpointWithPort,
		egressActiveMemberStrWithPort("137.0.0.1/32", 8080, gatewayKey.Hostname))

	endpointWithRemoteTerminatingEgressGateway = createEndpointWithRemoteEgressGateway(
		"endpointWithRemoteTerminatingEgressGateway",
		terminatingGatewayEndpoint,
		egressTerminatingMemberStr("137.0.0.1/32", nowTime, inSixtySecsTime, 0, gatewayKey.Hostname))

	endpointWithLocalActiveEgressGateway = createEndpointWithLocalEgressGateway(
		"endpointWithLocalActiveEgressGateway",
		activeGatewayEndpoint,
		egressActiveMemberStr("137.0.0.1/32", gatewayKeyLocal.Hostname))

	endpointWithLocalActiveEgressGatewayAndPort = createEndpointWithLocalEgressGateway(
		"endpointWithLocalActiveEgressGatewayAndPort",
		activeGatewayEndpointWithPort,
		egressActiveMemberStrWithPort("137.0.0.1/32", 8080, gatewayKeyLocal.Hostname))

	endpointWithLocalTerminatingEgressGateway = createEndpointWithLocalEgressGateway(
		"endpointWithLocalTerminatingEgressGateway",
		terminatingGatewayEndpoint,
		egressTerminatingMemberStr("137.0.0.1/32", nowTime, inSixtySecsTime, 0, gatewayKeyLocal.Hostname))

	createEndpointWithMaxNextHopsOnPod = func(name string, maxNextHops int) State {
		return initialisedStore.withKVUpdates(
			KVPair{
				Key: endpointWithOwnEgressGatewayID,
				Value: &WorkloadEndpoint{
					Name:              "wep1o",
					EgressSelector:    egressSelector,
					EgressMaxNextHops: maxNextHops,
				},
			},
			KVPair{
				Key:   gatewayKeyLocal,
				Value: activeGatewayEndpoint,
			},
		).withEndpoint(
			"orch/gw1/ep1",
			[]mock.TierInfo{},
		).withEndpointEgressData(
			"orch/gw1/ep1",
			calc.EPCompDataKindEgressGateway,
			&calc.ComputedEgressEP{IsEgressGateway: true},
		).withEndpoint(
			"orch/wep1o/ep1",
			[]mock.TierInfo{},
		).withEndpointEgressData(
			"orch/wep1o/ep1",
			calc.EPCompDataKindEgressGateway,
			&calc.ComputedEgressEP{
				Rules: []calc.EpEgressData{
					{
						IpSetID:     egressSelectorID(egressSelector),
						MaxNextHops: maxNextHops,
					},
				},
			},
		).withIPSet(egressSelectorID(egressSelector), []string{
			egressActiveMemberStr("137.0.0.1/32", gatewayKeyLocal.Hostname),
		},
		).withRoutes(
			felixtypes.RouteUpdate{
				Types:         proto.RouteType_LOCAL_WORKLOAD,
				Dst:           "137.0.0.1/32",
				DstNodeName:   localHostname,
				LocalWorkload: true,
			},
		).withName(name)
	}

	createEndpointWithMaxNextHopsOnNamespace = func(name string, maxNextHops int) State {
		return initialisedStore.withKVUpdates(
			KVPair{
				Key: ResourceKey{Name: "egress", Kind: v3.KindProfile},
				Value: &v3.Profile{
					ObjectMeta: metav1.ObjectMeta{
						Name: "egress",
						UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
					},
					Spec: v3.ProfileSpec{
						EgressGateway: &v3.EgressGatewaySpec{
							Gateway: &v3.EgressSpec{
								Selector:    "egress-provider == 'true'",
								MaxNextHops: maxNextHops,
							},
						},
					},
				},
			},
			KVPair{
				Key: endpointWithProfileEgressGatewayID,
				Value: &WorkloadEndpoint{
					Name:       "wep1p",
					ProfileIDs: []string{"egress"},
				},
			},
			KVPair{
				Key:   gatewayKeyLocal,
				Value: gatewayEndpoint,
			},
		).withEndpoint(
			"orch/gw1/ep1",
			[]mock.TierInfo{},
		).withEndpointEgressData(
			"orch/gw1/ep1",
			calc.EPCompDataKindEgressGateway,
			&calc.ComputedEgressEP{IsEgressGateway: true},
		).withEndpoint(
			"orch/wep1p/ep1",
			[]mock.TierInfo{},
		).withEndpointEgressData(
			"orch/wep1p/ep1",
			calc.EPCompDataKindEgressGateway,
			&calc.ComputedEgressEP{
				Rules: []calc.EpEgressData{
					{
						IpSetID:     egressSelectorID(egressProfileSelector),
						MaxNextHops: maxNextHops,
					},
				},
			},
		).withIPSet(egressSelectorID(egressProfileSelector), []string{
			egressActiveMemberStr("137.0.0.1/32", gatewayKeyLocal.Hostname),
		},
		).withActiveProfiles(
			felixtypes.ProfileID{Name: "egress"},
		).withRoutes(
			felixtypes.RouteUpdate{
				Types:         proto.RouteType_LOCAL_WORKLOAD,
				Dst:           "137.0.0.1/32",
				DstNodeName:   localHostname,
				LocalWorkload: true,
			},
		).withName(name)
	}

	endpointWithPodSelectorZeroMaxNextHops = createEndpointWithMaxNextHopsOnPod(
		"endpointWithPodSelectorThreeMaxNextHops",
		0)

	endpointWithPodSelectorThreeMaxNextHops = createEndpointWithMaxNextHopsOnPod(
		"endpointWithPodSelectorThreeMaxNextHops",
		3)

	endpointWithNamespaceSelectorZeroMaxNextHops = createEndpointWithMaxNextHopsOnNamespace(
		"endpointWithPodSelectorThreeMaxNextHops",
		0)

	endpointWithNamespaceSelectorThreeMaxNextHops = createEndpointWithMaxNextHopsOnNamespace(
		"endpointWithPodSelectorThreeMaxNextHops",
		3)
)

func egressActiveMemberStr(cidr string, hostname string) string {
	return egressTerminatingMemberStr(cidr, time.Time{}, time.Time{}, 0, hostname)
}

func egressActiveMemberStrWithPort(cidr string, port uint16, hostname string) string {
	return egressTerminatingMemberStr(cidr, time.Time{}, time.Time{}, port, hostname)
}

func egressTerminatingMemberStr(cidr string, start, finish time.Time, port uint16, hostname string) string {
	var startStr, finishStr string
	if !start.IsZero() {
		startBytes, err := start.MarshalText()
		if err != nil {
			panic(err)
		}
		finishBytes, err := finish.MarshalText()
		if err != nil {
			panic(err)
		}
		startStr = string(startBytes)
		finishStr = string(finishBytes)
	}
	return fmt.Sprintf("%s,%s,%s,%d,%s", cidr, startStr, finishStr, port, hostname)
}

func namespaceToProfile(ns *kapiv1.Namespace) *v3.Profile {
	c := conversion.NewConverter()
	kv, err := c.NamespaceToProfile(ns)
	if err != nil {
		panic(err)
	}
	profile, ok := kv.Value.(*v3.Profile)
	if !ok {
		panic(fmt.Errorf("Failed to convert namespace to profile.\nns: %v", ns))
	}
	return profile
}

// Test states for Istio functionality
var (
	// Base state with Istio enabled but no endpoints
	istioBaseState = initialisedStore.withIPSet("all-istio-weps", []string{}).withName("istio base state")

	// State with Istio ambient namespace and pod
	// Note: all-istio-weps IPSet should contain WEPs from ambient namespaces
	istioWithAmbientPod = istioBaseState.withKVUpdates(
		KVPair{Key: ResourceKey{Name: "istio-ambient", Kind: v3.KindProfile}, Value: namespaceToProfile(&istioNamespaceAmbient)},
		KVPair{Key: istioWepAmbientKey, Value: &istioWepAmbient},
	).withEndpoint(
		"orch/istio-wep-ambient/ep1",
		[]mock.TierInfo{},
	).withActiveProfiles(
		felixtypes.ProfileID{Name: "istio-ambient"},
	).withRoutes(
		felixtypes.RouteUpdate{
			Types:         proto.RouteType_LOCAL_WORKLOAD,
			Dst:           "10.10.1.1/32",
			DstNodeName:   localHostname,
			LocalWorkload: true,
		},
		felixtypes.RouteUpdate{
			Types:         proto.RouteType_LOCAL_WORKLOAD,
			Dst:           "fc00:fe10::1/128",
			DstNodeName:   localHostname,
			LocalWorkload: true,
		},
	).withIPSet("all-istio-weps", []string{
		"10.10.1.1/32",
		"fc00:fe10::1/128",
	}).withName("istio with ambient pod")

	// State with multiple pods - mixed scenarios
	// Note: all-istio-weps IPSet should contain only ambient and direct-ambient WEPs
	istioWithMixedPods = istioBaseState.withKVUpdates(
		KVPair{Key: ResourceKey{Name: "istio-ambient", Kind: v3.KindProfile}, Value: namespaceToProfile(&istioNamespaceAmbient)},
		KVPair{Key: ResourceKey{Name: "istio-none", Kind: v3.KindProfile}, Value: namespaceToProfile(&istioNamespaceNone)},
		KVPair{Key: ResourceKey{Name: "regular", Kind: v3.KindProfile}, Value: namespaceToProfile(&regularNamespace)},
		KVPair{Key: istioWepAmbientKey, Value: &istioWepAmbient},
		KVPair{Key: istioWepNoneKey, Value: &istioWepNone},
		KVPair{Key: regularWepKey, Value: &regularWep},
		KVPair{Key: istioWepDirectAmbientKey, Value: &istioWepDirectAmbient},
	).withEndpoint(
		"orch/istio-wep-ambient/ep1",
		[]mock.TierInfo{},
	).withEndpoint(
		"orch/istio-wep-none/ep1",
		[]mock.TierInfo{},
	).withEndpoint(
		"orch/regular-wep/ep1",
		[]mock.TierInfo{},
	).withEndpoint(
		"orch/istio-wep-direct-ambient/ep1",
		[]mock.TierInfo{},
	).withActiveProfiles(
		felixtypes.ProfileID{Name: "istio-ambient"},
		felixtypes.ProfileID{Name: "istio-none"},
		felixtypes.ProfileID{Name: "regular"},
	).withRoutes(
		felixtypes.RouteUpdate{
			Types:         proto.RouteType_LOCAL_WORKLOAD,
			Dst:           "10.10.1.1/32",
			DstNodeName:   localHostname,
			LocalWorkload: true,
		},
		felixtypes.RouteUpdate{
			Types:         proto.RouteType_LOCAL_WORKLOAD,
			Dst:           "fc00:fe10::1/128",
			DstNodeName:   localHostname,
			LocalWorkload: true,
		},
		felixtypes.RouteUpdate{
			Types:         proto.RouteType_LOCAL_WORKLOAD,
			Dst:           "10.10.3.1/32",
			DstNodeName:   localHostname,
			LocalWorkload: true,
		},
		felixtypes.RouteUpdate{
			Types:         proto.RouteType_LOCAL_WORKLOAD,
			Dst:           "fc00:fe10::3/128",
			DstNodeName:   localHostname,
			LocalWorkload: true,
		},
		felixtypes.RouteUpdate{
			Types:         proto.RouteType_LOCAL_WORKLOAD,
			Dst:           "10.10.4.1/32",
			DstNodeName:   localHostname,
			LocalWorkload: true,
		},
		felixtypes.RouteUpdate{
			Types:         proto.RouteType_LOCAL_WORKLOAD,
			Dst:           "fc00:fe10::4/128",
			DstNodeName:   localHostname,
			LocalWorkload: true,
		},
		felixtypes.RouteUpdate{
			Types:         proto.RouteType_LOCAL_WORKLOAD,
			Dst:           "10.10.5.1/32",
			DstNodeName:   localHostname,
			LocalWorkload: true,
		},
		felixtypes.RouteUpdate{
			Types:         proto.RouteType_LOCAL_WORKLOAD,
			Dst:           "fc00:fe10::5/128",
			DstNodeName:   localHostname,
			LocalWorkload: true,
		},
	).withIPSet("all-istio-weps", []string{
		"10.10.1.1/32",     // ambient namespace WEP
		"fc00:fe10::1/128", // ambient namespace WEP
		"10.10.5.1/32",     // direct ambient label WEP
		"fc00:fe10::5/128", // direct ambient label WEP
	}).withName("istio with mixed pods")

	// Edge case: Pod in ambient namespace but with explicit istio.io/dataplane-mode=none label
	// Original selector: Should be EXCLUDED (namespace ambient but pod has explicit none)
	// Your selector: Should be EXCLUDED (pod doesn't have ambient label)
	// This test should FAIL with your change because the pod should NOT be in the IPSet
	istioSelectorEdgeCases = istioBaseState.withKVUpdates(
		KVPair{Key: ResourceKey{Name: "istio-ambient", Kind: v3.KindProfile}, Value: namespaceToProfile(&istioNamespaceAmbient)},
		KVPair{Key: WorkloadEndpointKey{
			Hostname:       localHostname,
			OrchestratorID: "orch",
			WorkloadID:     "ambient-ns-but-pod-none",
			EndpointID:     "ep1",
		}, Value: &WorkloadEndpoint{
			State: "active",
			Name:  "ambient-ns-but-pod-none",
			IPv4Nets: []calinet.IPNet{
				mustParseNet("10.10.9.1/32"),
			},
			Labels: uniquelabels.Make(map[string]string{
				"projectcalico.org/namespace": "istio-ambient",
				v3.LabelIstioDataplaneMode:    v3.LabelIstioDataplaneModeNone, // Explicit none on pod
			}),
			ProfileIDs: []string{"istio-ambient"},
		}},
	).withEndpoint(
		"orch/ambient-ns-but-pod-none/ep1",
		[]mock.TierInfo{},
	).withActiveProfiles(
		felixtypes.ProfileID{Name: "istio-ambient"},
	).withRoutes(
		felixtypes.RouteUpdate{
			Types:         proto.RouteType_LOCAL_WORKLOAD,
			Dst:           "10.10.9.1/32",
			DstNodeName:   localHostname,
			LocalWorkload: true,
		},
	).withIPSet("all-istio-weps", []string{
		// Should be EMPTY - this pod should be excluded by both selectors
	}).withName("istio selector edge cases")
)
