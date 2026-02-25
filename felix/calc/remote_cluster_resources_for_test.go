package calc_test

import (
	"fmt"
	"math"
	"strings"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/dataplane/mock"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	internalapi "github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/encap"
	. "github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

// Values used in remote cluster testing.
var (
	local   = ""
	remoteA = "remote-a"
	remoteB = "remote-b"
)

var (
	localClusterHost   = "local-host"
	localClusterHost2  = "local-host-2"
	remoteClusterAHost = "remote-a-host"
	remoteClusterBHost = "remote-b-host"
)

var (
	localClusterHostIPAddr   = "192.168.0.1"
	localClusterHost2IPAddr  = "192.168.1.1"
	remoteClusterAHostIPAddr = "192.168.0.2"
	remoteClusterBHostIPAddr = "192.168.0.3"
)

var (
	localClusterHostMAC   = "66:05:91:0f:93:57"
	localClusterHost2MAC  = "66:67:b3:72:12:71"
	remoteClusterAHostMAC = "66:0b:75:83:64:51"
	remoteClusterBHostMAC = "66:ac:b1:ca:37:70"
)

// StateWithPool is a convenience function to help compose remote cluster testing states.
func StateWithPool(state State, cluster string, cidr string, flush bool) State {
	var kvp KVPair
	if cluster == "" {
		kvp = KVPair{
			Key: IPPoolKey{CIDR: mustParseNet(cidr)},
			Value: &IPPool{
				CIDR:      mustParseNet(cidr),
				VXLANMode: encap.Always,
			},
		}
	} else {
		kvp = KVPair{
			Key: RemoteClusterResourceKey{
				Cluster:     cluster,
				ResourceKey: ResourceKey{Kind: v3.KindIPPool, Name: cluster + "-ip-pool"},
			},
			Value: &v3.IPPool{
				TypeMeta: metav1.TypeMeta{
					Kind:       v3.KindIPPool,
					APIVersion: v3.GroupVersionCurrent,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: cluster + "-ip-pool",
				},
				Spec: v3.IPPoolSpec{
					CIDR:      cidr,
					VXLANMode: v3.VXLANModeAlways,
				},
			},
		}
	}

	routeUpdate := types.RouteUpdate{
		Types:      proto.RouteType_CIDR_INFO,
		IpPoolType: proto.IPPoolType_VXLAN,
		Dst:        cidr,
	}

	newState := state.Copy()
	newState.DatastoreState = append(newState.DatastoreState, kvp)
	if flush {
		newState.ExpectedRoutes.Add(routeUpdate)
		if cluster == "" {
			newState.ExpectedEncapsulation.VxlanEnabled = true
		}
	}

	return newState
}

// StateWithBlock is a convenience function to help compose remote cluster testing states.
func StateWithBlock(state State, cluster string, cidr string, flush bool, poolType proto.IPPoolType, host string, hostIP string, rts ...proto.RouteType) State {
	keyName := host
	if cluster != "" {
		keyName = cluster + "/" + keyName
	}
	affinity := "host:" + keyName
	var kvp KVPair
	if cluster == "" {
		kvp = KVPair{
			Key: BlockKey{CIDR: mustParseNet(cidr)},
			Value: &AllocationBlock{
				CIDR:        mustParseNet(cidr),
				Affinity:    &affinity,
				Allocations: createAllocationsArray(cidr),
				Unallocated: createUnallocatedArray(cidr),
			},
		}
	} else {
		kvp = KVPair{
			Key: RemoteClusterResourceKey{
				Cluster:     cluster,
				ResourceKey: ResourceKey{Kind: internalapi.KindIPAMBlock, Name: escapeCIDR(cidr)},
			},
			Value: &internalapi.IPAMBlock{
				TypeMeta: metav1.TypeMeta{
					Kind:       internalapi.KindIPAMBlock,
					APIVersion: v3.GroupVersionCurrent,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: escapeCIDR(cidr),
				},
				Spec: internalapi.IPAMBlockSpec{
					CIDR:        cidr,
					Affinity:    &affinity,
					Allocations: createAllocationsArray(cidr),
					Unallocated: createUnallocatedArray(cidr),
				},
			},
		}
	}

	var updateTypes proto.RouteType
	if len(rts) > 0 {
		for _, rt := range rts {
			updateTypes |= rt
		}
	} else {
		updateTypes = proto.RouteType_REMOTE_WORKLOAD
	}

	routeUpdate := types.RouteUpdate{
		Types:       updateTypes,
		IpPoolType:  poolType,
		Dst:         cidr,
		DstNodeName: keyName,
		DstNodeIp:   hostIP,
	}

	newState := state.Copy()
	newState.DatastoreState = append(newState.DatastoreState, kvp)
	if flush {
		newState.ExpectedRoutes.Add(routeUpdate)
	}

	return newState
}

// StateWithNode is a convenience function to help compose remote cluster testing states.
func StateWithNode(state State, cluster string, host string, hostIP string, vxlanTunnelIP string, wgTunnelIP string, wgPublicKey string) State {
	keyName := host
	if cluster != "" {
		keyName = cluster + "/" + host
	}
	node := &internalapi.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: host,
		},
		Spec: internalapi.NodeSpec{
			BGP: &internalapi.NodeBGPSpec{
				IPv4Address: hostIP + "/24",
			},
		},
	}

	if vxlanTunnelIP != "" {
		node.Spec.IPv4VXLANTunnelAddr = vxlanTunnelIP
	}

	if wgTunnelIP != "" {
		node.Spec.Wireguard = &internalapi.NodeWireguardSpec{
			InterfaceIPv4Address: wgTunnelIP,
		}
	}

	if wgPublicKey != "" {
		node.Status = internalapi.NodeStatus{
			WireguardPublicKey: wgPublicKey,
		}
	}

	kvp := KVPair{
		Key: ResourceKey{
			Kind: internalapi.KindNode,
			Name: keyName,
		},
		Value: node,
	}

	routeType := proto.RouteType_REMOTE_HOST
	if host == localHostname {
		routeType = proto.RouteType_LOCAL_HOST
	}

	routeUpdate := types.RouteUpdate{
		Types:       routeType,
		IpPoolType:  proto.IPPoolType_NONE,
		Dst:         hostIP + "/32",
		DstNodeName: keyName,
		DstNodeIp:   hostIP,
	}
	metadataUpdate := &proto.HostMetadataV4V6Update{
		Hostname: keyName,
		Ipv4Addr: hostIP + "/24",
	}

	newState := state.Copy()
	newState.DatastoreState = append(newState.DatastoreState, kvp)
	newState.ExpectedRoutes.Add(routeUpdate)
	newState.ExpectedHostMetadataV4V6[keyName] = metadataUpdate

	return newState
}

// StateWithWEP is a convenience function to help compose remote cluster testing states.
func StateWithWEP(state State, cluster string, ip string, flush bool, poolType proto.IPPoolType, name string, host string, hostIP string, borrowed bool, rts ...proto.RouteType) State {
	hostKeyName := host
	if cluster != "" {
		hostKeyName = cluster + "/" + host
	}
	key := WorkloadEndpointKey{Hostname: hostKeyName, OrchestratorID: "orch", WorkloadID: "wl-" + name, EndpointID: "ep-" + name}
	wep := &WorkloadEndpoint{
		State:      "active",
		Name:       name,
		Mac:        mustParseMac("01:02:03:04:05:06"),
		ProfileIDs: []string{},
		IPv4Nets:   []net.IPNet{mustParseNet(ip + "/32")},
		Labels: uniquelabels.Make(map[string]string{
			"id": "ep-" + name,
		}),
	}
	kvp := KVPair{
		Key:   key,
		Value: wep,
	}

	updTypes := proto.RouteType_REMOTE_WORKLOAD
	if host == localHostname {
		updTypes = proto.RouteType_LOCAL_WORKLOAD
	}
	if len(rts) > 0 {
		updTypes = 0
		for _, rt := range rts {
			updTypes |= rt
		}
	}

	routeUpdate := types.RouteUpdate{
		Types:         updTypes,
		IpPoolType:    poolType,
		Dst:           ip + "/32",
		DstNodeName:   hostKeyName,
		DstNodeIp:     hostIP,
		Borrowed:      borrowed,
		LocalWorkload: host == localHostname,
	}

	newState := state.Copy()

	if host == localHostname {
		newState = newState.withEndpoint(fmt.Sprintf("orch/wl-%s/ep-%s", name, name), []mock.TierInfo{})
	} else {
		// WEPs are only received by the FV calc graph for local WEPs, unless in WorkloadIPs mode.
		newState.DatastoreState = append(newState.DatastoreState, KVPair{Key: GlobalConfigKey{Name: "RouteSource"}, Value: &workloadIPs})
		epData := calc.CalculateRemoteEndpoint(key, wep)
		newState.ExpectedCachedRemoteEndpoints = append(newState.ExpectedCachedRemoteEndpoints, epData)
	}

	newState.DatastoreState = append(newState.DatastoreState, kvp)
	if flush {
		newState.ExpectedRoutes.Add(routeUpdate)
	}

	return newState
}

// StateWithVTEP is a convenience function to help compose remote cluster testing states.
func StateWithVTEP(state State, cluster string, ip string, flush bool, mac string, poolType proto.IPPoolType, host string, hostIP string, rts ...proto.RouteType) State {
	keyName := host
	if cluster != "" {
		keyName = cluster + "/" + host
	}

	kvp := KVPair{
		Key:   HostConfigKey{Name: "IPv4VXLANTunnelAddr", Hostname: keyName},
		Value: ip,
	}
	vtep := types.VXLANTunnelEndpointUpdate{
		Node:           keyName,
		Mac:            mac,
		Ipv4Addr:       ip,
		ParentDeviceIp: hostIP,
	}

	var updateTypes proto.RouteType
	if len(rts) > 0 {
		for _, rt := range rts {
			updateTypes |= rt
		}
	} else {
		updateTypes = proto.RouteType_REMOTE_TUNNEL
	}

	tunnelRouteUpdate := types.RouteUpdate{
		Types:       updateTypes,
		IpPoolType:  poolType,
		Dst:         ip + "/32",
		DstNodeName: keyName,
		DstNodeIp:   hostIP,
		TunnelType:  &proto.TunnelType{Vxlan: true},
	}

	newState := state.Copy()
	newState.DatastoreState = append(newState.DatastoreState, kvp)
	newState.ExpectedVTEPs.Add(vtep)
	if flush {
		newState.ExpectedRoutes.Add(tunnelRouteUpdate)
	}

	return newState
}

// StateWithWGEP is a convenience function to help compose remote cluster testing states.
func StateWithWGEP(state State, cluster string, ip string, flush bool, publicKey string, poolType proto.IPPoolType, host string, hostIP string, rts ...proto.RouteType) State {
	keyName := host
	if cluster != "" {
		keyName = cluster + "/" + host
	}

	interfaceIP := mustParseIP(ip)
	wgEnabledKVP := KVPair{Key: GlobalConfigKey{Name: "WireguardEnabled"}, Value: &t}
	wgKVP := KVPair{
		Key: WireguardKey{NodeName: host},
		Value: &Wireguard{
			InterfaceIPv4Addr: &interfaceIP,
			PublicKey:         publicKey,
		},
	}

	var updateTypes proto.RouteType
	if len(rts) > 0 {
		for _, rt := range rts {
			updateTypes |= rt
		}
	} else {
		updateTypes = proto.RouteType_REMOTE_TUNNEL
	}

	tunnelRouteUpdate := types.RouteUpdate{
		Types:       updateTypes,
		IpPoolType:  poolType,
		Dst:         ip + "/32",
		DstNodeName: keyName,
		DstNodeIp:   hostIP,
		TunnelType:  &proto.TunnelType{Wireguard: true},
	}

	wgEndpoint := types.WireguardEndpointUpdate{
		Hostname:          host,
		PublicKey:         publicKey,
		InterfaceIpv4Addr: ip,
	}

	newState := state.Copy()
	newState.DatastoreState = append(newState.DatastoreState, wgEnabledKVP, wgKVP)
	newState.ExpectedWireguardEndpoints.Add(wgEndpoint)
	if flush {
		newState.ExpectedRoutes.Add(tunnelRouteUpdate)
	}

	return newState
}

// Used for remote cluster testing. Adds complete VXLAN block configuration for "pool 2" to the local cluster.
func StateWithVXLANBlockForLocal(state State, shouldFlush bool) State {
	state = StateWithPool(state, local, "10.0.0.0/16", shouldFlush)
	state = StateWithBlock(state, local, "10.0.1.0/29", shouldFlush, proto.IPPoolType_VXLAN, localClusterHost, localClusterHostIPAddr)
	state = StateWithVTEP(state, local, "10.0.1.1", shouldFlush, localClusterHostMAC, proto.IPPoolType_VXLAN, localClusterHost, localClusterHostIPAddr, remoteTunnelWep...)
	state = StateWithNode(state, local, localClusterHost, localClusterHostIPAddr, "10.0.1.1", "", "")
	return state
}

// Used for remote cluster testing. Adds complete VXLAN block configuration for "pool 2" to the remote A cluster.
func StateWithVXLANBlockForRemoteA(state State, shouldFlush bool) State {
	state = StateWithPool(state, remoteA, "10.0.0.0/16", shouldFlush)
	state = StateWithBlock(state, remoteA, "10.0.1.0/29", shouldFlush, proto.IPPoolType_VXLAN, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithVTEP(state, remoteA, "10.0.1.1", shouldFlush, remoteClusterAHostMAC, proto.IPPoolType_VXLAN, remoteClusterAHost, remoteClusterAHostIPAddr, remoteTunnelWep...)
	state = StateWithNode(state, remoteA, remoteClusterAHost, remoteClusterAHostIPAddr, "10.0.1.1", "", "")
	return state
}

// Used for remote cluster testing. Adds complete VXLAN block configuration for "pool 2" to the remote B cluster.
func StateWithVXLANBlockForRemoteB(state State, shouldFlush bool) State {
	state = StateWithPool(state, remoteB, "10.0.0.0/16", shouldFlush)
	state = StateWithBlock(state, remoteB, "10.0.1.0/29", shouldFlush, proto.IPPoolType_VXLAN, remoteClusterBHost, remoteClusterBHostIPAddr)
	state = StateWithVTEP(state, remoteB, "10.0.1.1", shouldFlush, remoteClusterBHostMAC, proto.IPPoolType_VXLAN, remoteClusterBHost, remoteClusterBHostIPAddr)
	state = StateWithNode(state, remoteB, remoteClusterBHost, remoteClusterBHostIPAddr, "10.0.1.1", "", "")
	return state
}

// Used for remote cluster testing. Adds complete VXLAN WEP configuration for "pool 2" to the local cluster.
func StateWithVXLANWEPForLocal(state State, shouldFlush bool) State {
	state = StateWithPool(state, local, "10.0.0.0/16", shouldFlush)
	state = StateWithWEP(state, local, "10.0.0.5", shouldFlush, proto.IPPoolType_VXLAN, "local-wep", localClusterHost, localClusterHostIPAddr, false)
	state = StateWithVTEP(state, local, "10.0.1.1", shouldFlush, localClusterHostMAC, proto.IPPoolType_VXLAN, localClusterHost, localClusterHostIPAddr)
	state = StateWithNode(state, local, localClusterHost, localClusterHostIPAddr, "10.0.1.1", "", "")
	return state
}

// Used for remote cluster testing. Adds complete VXLAN WEP configuration for "pool 2" to the remote A cluster.
func StateWithVXLANWEPForRemoteA(state State, shouldFlush bool) State {
	state = StateWithPool(state, remoteA, "10.0.0.0/16", shouldFlush)
	state = StateWithWEP(state, remoteA, "10.0.0.5", shouldFlush, proto.IPPoolType_VXLAN, "local-wep", remoteClusterAHost, remoteClusterAHostIPAddr, false)
	state = StateWithVTEP(state, remoteA, "10.0.1.1", shouldFlush, remoteClusterAHostMAC, proto.IPPoolType_VXLAN, remoteClusterAHost, remoteClusterAHostIPAddr)
	state = StateWithNode(state, remoteA, remoteClusterAHost, remoteClusterAHostIPAddr, "10.0.1.1", "", "")
	return state
}

// Used for remote cluster testing. Adds complete VXLAN WEP configuration for "pool 2" to the remote B cluster.
func StateWithVXLANWEPForRemoteB(state State, shouldFlush bool) State {
	state = StateWithPool(state, remoteB, "10.0.0.0/16", shouldFlush)
	state = StateWithWEP(state, remoteB, "10.0.0.5", shouldFlush, proto.IPPoolType_VXLAN, "local-wep", remoteClusterBHost, remoteClusterBHostIPAddr, false)
	state = StateWithVTEP(state, remoteB, "10.0.1.1", shouldFlush, remoteClusterBHostMAC, proto.IPPoolType_VXLAN, remoteClusterBHost, remoteClusterBHostIPAddr)
	state = StateWithNode(state, remoteB, remoteClusterBHost, remoteClusterBHostIPAddr, "10.0.1.1", "", "")
	return state
}

func escapeCIDR(cidr string) string {
	return strings.ReplaceAll(strings.ReplaceAll(cidr, ".", "-"), "/", "-")
}

func createAllocationsArray(cidr string) []*int {
	prefixLength, _ := mustParseNet(cidr).Mask.Size()
	return make([]*int, int(math.Pow(2, float64(32-prefixLength))))
}

func createUnallocatedArray(cidr string) []int {
	prefixLength, _ := mustParseNet(cidr).Mask.Size()
	var unallocated []int
	for i := 0; i < int(math.Pow(2, float64(32-prefixLength))); i++ {
		unallocated = append(unallocated, i)
	}
	return unallocated
}
