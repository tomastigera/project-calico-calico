package template

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/kelseyhightower/memkv"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/confd/pkg/backends"

	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

const (
	maxFuncNameLen       = 66 // Max BIRD symbol length of 64 + 2 for bookending single quotes
	v4GlobalPeerIP1Str   = "77.0.0.1"
	v4GlobalPeerIP2Str   = "77.0.0.2"
	v4GlobalPeerIP3Str   = "77.0.0.3"
	v6GlobalPeerIP1Str   = "7700::1"
	v6GlobalPeerIP2Str   = "7700::2"
	v6GlobalPeerIP3Str   = "7700::3"
	v4ExplicitPeerIP1Str = "44.0.0.1"
	v4ExplicitPeerIP2Str = "44.0.0.2"
	v4ExplicitPeerIP3Str = "44.0.0.3"
	v6ExplicitPeerIP1Str = "4400::1"
	v6ExplicitPeerIP2Str = "4400::2"
	v6ExplicitPeerIP3Str = "4400::3"
)

func Test_bgpFilterFunctionName(t *testing.T) {
	str := "should-not-be-truncated"
	direction := "import"
	version := "4"
	output, err := BGPFilterFunctionName(str, direction, version)
	if err != nil {
		t.Errorf("Unexpected error calling BGPFilterFunctionName(%s, %s, %s): %s", str, direction, version, err)
	}
	if len(output) > maxFuncNameLen {
		t.Errorf(`BGPFilterFunctionName(%s, %s, %s) has length %d which is greater than the maximum allowed of %d`,
			str, direction, version, len(output), maxFuncNameLen)
	}

	str = "very-long-name-that-should-be-truncated-because-it-is-longer-than-the-max-bird-symbol-length-of-64-chars"
	output, err = BGPFilterFunctionName(str, direction, version)
	if err != nil {
		t.Errorf("Unexpected error calling BGPFilterFunctionName(%s, %s, %s): %s", str, direction, version, err)
	}
	if len(output) > maxFuncNameLen {
		t.Errorf(`BGPFilterFunctionName(%s, %s, %s) has length %d which is greater than the maximum allowed of %d`,
			str, direction, version, len(output), maxFuncNameLen)
	}
}

func Test_BGPFilterBIRDFuncs(t *testing.T) {
	testFilter := v3.BGPFilter{}
	testFilter.Name = "test-bgpfilter"
	testFilter.Spec = v3.BGPFilterSpec{
		ImportV4: []v3.BGPFilterRuleV4{
			{Action: "Accept", Source: "RemotePeers", Interface: "vxlan.calico", MatchOperator: "NotIn", CIDR: "55.4.0.0/16"},
			{Action: "Reject", Source: "RemotePeers", MatchOperator: "NotIn", CIDR: "55.4.0.0/16"},
			{Action: "Reject", Source: "RemotePeers", MatchOperator: "NotIn", CIDR: "55.4.0.0/16", PrefixLength: &v3.BGPFilterPrefixLengthV4{Min: int32Helper(16), Max: int32Helper(24)}},
			{Action: "Reject", Interface: "eth0", MatchOperator: "NotIn", CIDR: "55.4.0.0/16"},
			{Action: "Accept", Interface: "eth0", Source: "RemotePeers"},
			{Action: "Reject", Interface: "eth0", Source: "RemotePeers", PrefixLength: &v3.BGPFilterPrefixLengthV4{Min: int32Helper(16), Max: int32Helper(24)}},
			{Action: "Reject", MatchOperator: "Equal", CIDR: "44.4.0.0/16"},
			{Action: "Accept", Source: "RemotePeers"},
			{Action: "Reject", Interface: "extraiface"},
			{Action: "Reject"},
		},
		ExportV4: []v3.BGPFilterRuleV4{
			{Action: "Reject", Source: "RemotePeers", Interface: "vxlan.calico", MatchOperator: "NotIn", CIDR: "55.4.0.0/16"},
			{Action: "Reject", Source: "RemotePeers", MatchOperator: "NotIn", CIDR: "88.7.0.0/16"},
			{Action: "Reject", Source: "RemotePeers", MatchOperator: "NotIn", CIDR: "88.7.0.0/16", PrefixLength: &v3.BGPFilterPrefixLengthV4{Max: int32Helper(24)}},
			{Action: "Accept", Interface: "eth0", MatchOperator: "NotIn", CIDR: "55.4.0.0/16"},
			{Action: "Reject", Interface: "eth0", Source: "RemotePeers"},
			{Action: "Accept", MatchOperator: "In", CIDR: "77.7.0.0/16"},
			{Action: "Accept", Source: "RemotePeers"},
			{Action: "Accept", Interface: "extraiface"},
			{Action: "Reject"},
		},
		ImportV6: []v3.BGPFilterRuleV6{
			{Action: "Reject", Source: "RemotePeers", Interface: "vxlan.calico", MatchOperator: "NotIn", CIDR: "7000:1::0/64"},
			{Action: "Reject", Source: "RemotePeers", MatchOperator: "NotEqual", CIDR: "8000:1::0/64"},
			{Action: "Accept", Interface: "eth0", MatchOperator: "NotIn", CIDR: "6000:1::0/64"},
			{Action: "Accept", Interface: "eth0", MatchOperator: "NotIn", CIDR: "6000:1::0/64", PrefixLength: &v3.BGPFilterPrefixLengthV6{Min: int32Helper(96)}},
			{Action: "Reject", Interface: "eth0", Source: "RemotePeers"},
			{Action: "Accept", MatchOperator: "NotEqual", CIDR: "7000:1::0/64"},
			{Action: "Accept", MatchOperator: "NotEqual", CIDR: "7000:1::0/64", PrefixLength: &v3.BGPFilterPrefixLengthV6{Max: int32Helper(96)}},
			{Action: "Accept", Source: "RemotePeers"},
			{Action: "Accept", Interface: "extraiface"},
			{Action: "Reject"},
		},
		ExportV6: []v3.BGPFilterRuleV6{
			{Action: "Accept", Source: "RemotePeers", Interface: "vxlan.calico", MatchOperator: "NotIn", CIDR: "b000:1::0/64"},
			{Action: "Reject", Source: "RemotePeers", MatchOperator: "NotIn", CIDR: "a000:1::0/64"},
			{Action: "Reject", Interface: "eth0", MatchOperator: "NotIn", CIDR: "c000:1::0/64"},
			{Action: "Reject", Interface: "eth0", MatchOperator: "NotIn", CIDR: "c000:1::0/64", PrefixLength: &v3.BGPFilterPrefixLengthV6{Min: int32Helper(120), Max: int32Helper(128)}},
			{Action: "Accept", Interface: "eth0", Source: "RemotePeers"},
			{Action: "Accept", MatchOperator: "NotIn", CIDR: "9000:1::0/64"},
			{Action: "Accept", MatchOperator: "NotIn", CIDR: "9000:1::0/64", PrefixLength: &v3.BGPFilterPrefixLengthV6{Min: int32Helper(96), Max: int32Helper(120)}},
			{Action: "Accept", Source: "RemotePeers"},
			{Action: "Reject", Interface: "extraiface"},
			{Action: "Reject"},
		},
	}
	expectedBIRDCfgStrV4 := []string{
		"# v4 BGPFilter test-bgpfilter",
		"function 'bgp_test-bgpfilter_importFilterV4'() {",
		"  if ((net !~ 55.4.0.0/16)&&((defined(source))&&(source ~ [ RTS_BGP ]))&&((defined(ifname))&&(ifname ~ \"vxlan.calico\"))) then { accept; }",
		"  if ((net !~ 55.4.0.0/16)&&((defined(source))&&(source ~ [ RTS_BGP ]))) then { reject; }",
		"  if ((net !~ [ 55.4.0.0/16{16,24} ])&&((defined(source))&&(source ~ [ RTS_BGP ]))) then { reject; }",
		"  if ((net !~ 55.4.0.0/16)&&((defined(ifname))&&(ifname ~ \"eth0\"))) then { reject; }",
		"  if (((defined(source))&&(source ~ [ RTS_BGP ]))&&((defined(ifname))&&(ifname ~ \"eth0\"))) then { accept; }",
		"  if (((defined(source))&&(source ~ [ RTS_BGP ]))&&((defined(ifname))&&(ifname ~ \"eth0\"))) then { reject; }",
		"  if ((net = 44.4.0.0/16)) then { reject; }",
		"  if (((defined(source))&&(source ~ [ RTS_BGP ]))) then { accept; }",
		"  if (((defined(ifname))&&(ifname ~ \"extraiface\"))) then { reject; }",
		"  reject;",
		"}",
		"function 'bgp_test-bgpfilter_exportFilterV4'() {",
		"  if ((net !~ 55.4.0.0/16)&&((defined(source))&&(source ~ [ RTS_BGP ]))&&((defined(ifname))&&(ifname ~ \"vxlan.calico\"))) then { reject; }",
		"  if ((net !~ 88.7.0.0/16)&&((defined(source))&&(source ~ [ RTS_BGP ]))) then { reject; }",
		"  if ((net !~ [ 88.7.0.0/16{16,24} ])&&((defined(source))&&(source ~ [ RTS_BGP ]))) then { reject; }",
		"  if ((net !~ 55.4.0.0/16)&&((defined(ifname))&&(ifname ~ \"eth0\"))) then { accept; }",
		"  if (((defined(source))&&(source ~ [ RTS_BGP ]))&&((defined(ifname))&&(ifname ~ \"eth0\"))) then { reject; }",
		"  if ((net ~ 77.7.0.0/16)) then { accept; }",
		"  if (((defined(source))&&(source ~ [ RTS_BGP ]))) then { accept; }",
		"  if (((defined(ifname))&&(ifname ~ \"extraiface\"))) then { accept; }",
		"  reject;",
		"}",
	}
	expectedBIRDCfgStrV6 := []string{
		"# v6 BGPFilter test-bgpfilter",
		"function 'bgp_test-bgpfilter_importFilterV6'() {",
		"  if ((net !~ 7000:1::0/64)&&((defined(source))&&(source ~ [ RTS_BGP ]))&&((defined(ifname))&&(ifname ~ \"vxlan.calico\"))) then { reject; }",
		"  if ((net != 8000:1::0/64)&&((defined(source))&&(source ~ [ RTS_BGP ]))) then { reject; }",
		"  if ((net !~ 6000:1::0/64)&&((defined(ifname))&&(ifname ~ \"eth0\"))) then { accept; }",
		"  if ((net !~ [ 6000:1::0/64{96,128} ])&&((defined(ifname))&&(ifname ~ \"eth0\"))) then { accept; }",
		"  if (((defined(source))&&(source ~ [ RTS_BGP ]))&&((defined(ifname))&&(ifname ~ \"eth0\"))) then { reject; }",
		"  if ((net != 7000:1::0/64)) then { accept; }",
		"  if ((net != [ 7000:1::0/64{64,96} ])) then { accept; }",
		"  if (((defined(source))&&(source ~ [ RTS_BGP ]))) then { accept; }",
		"  if (((defined(ifname))&&(ifname ~ \"extraiface\"))) then { accept; }",
		"  reject;",
		"}",
		"function 'bgp_test-bgpfilter_exportFilterV6'() {",
		"  if ((net !~ b000:1::0/64)&&((defined(source))&&(source ~ [ RTS_BGP ]))&&((defined(ifname))&&(ifname ~ \"vxlan.calico\"))) then { accept; }",
		"  if ((net !~ a000:1::0/64)&&((defined(source))&&(source ~ [ RTS_BGP ]))) then { reject; }",
		"  if ((net !~ c000:1::0/64)&&((defined(ifname))&&(ifname ~ \"eth0\"))) then { reject; }",
		"  if ((net !~ [ c000:1::0/64{120,128} ])&&((defined(ifname))&&(ifname ~ \"eth0\"))) then { reject; }",
		"  if (((defined(source))&&(source ~ [ RTS_BGP ]))&&((defined(ifname))&&(ifname ~ \"eth0\"))) then { accept; }",
		"  if ((net !~ 9000:1::0/64)) then { accept; }",
		"  if ((net !~ [ 9000:1::0/64{96,120} ])) then { accept; }",
		"  if (((defined(source))&&(source ~ [ RTS_BGP ]))) then { accept; }",
		"  if (((defined(ifname))&&(ifname ~ \"extraiface\"))) then { reject; }",
		"  reject;",
		"}",
	}

	jsonFilter, err := json.Marshal(testFilter)
	if err != nil {
		t.Errorf("Error formatting BGPFilter into JSON: %s", err)
	}
	kvps := []memkv.KVPair{
		{Key: "test-bgpfilter", Value: string(jsonFilter)},
	}

	v4BIRDCfgResult, err := BGPFilterBIRDFuncs(kvps, 4)
	if err != nil {
		t.Errorf("Unexpected error while generating v4 BIRD BGPFilter functions: %s", err)
	}
	if !reflect.DeepEqual(v4BIRDCfgResult, expectedBIRDCfgStrV4) {
		t.Errorf("Generated v4 BIRD config differs from expectation:\n Generated = %s,\n Expected = %s",
			v4BIRDCfgResult, expectedBIRDCfgStrV4)
	}

	v6BIRDCfgResult, err := BGPFilterBIRDFuncs(kvps, 6)
	if err != nil {
		t.Errorf("Unexpected error while generating v6 BIRD BGPFilter functions: %s", err)
	}
	if !reflect.DeepEqual(v6BIRDCfgResult, expectedBIRDCfgStrV6) {
		t.Errorf("Generated v6 BIRD config differs from expectation:\n Generated = %s,\n Expected = %s",
			v6BIRDCfgResult, expectedBIRDCfgStrV6)
	}
}

func resultCheckerForExternalNetworkBIRDConfig(externalNetworksKVP, globalPeersKVP, explicitPeersKVP memkv.KVPairs, expected []string, t *testing.T) {
	t.Helper()
	result, err := ExternalNetworkBIRDConfig("dontcare", externalNetworksKVP, globalPeersKVP, explicitPeersKVP)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	if diff := cmp.Diff(result, expected); diff != "" {
		t.Errorf("Expected did not match result: %s", diff)
	}
}

func constructExternalNetworkKVPs(idxs []uint32, t *testing.T) memkv.KVPairs {
	var kvps memkv.KVPairs
	for i, idx := range idxs {
		testEnet := v3.ExternalNetwork{
			Spec: v3.ExternalNetworkSpec{
				RouteTableIndex: &idx,
			},
		}
		enetJSON, err := json.Marshal(testEnet)
		if err != nil {
			t.Errorf("Error marshalling ExternalNetwork into JSON: %s", err)
		}
		kvp := memkv.KVPair{
			Key:   fmt.Sprintf("test-enet-%d", i+1),
			Value: string(enetJSON),
		}
		kvps = append(kvps, kvp)
	}
	return kvps
}

func constructBGPPeerKVPs(peerIPStrs []string, enet string, port uint16, t *testing.T) memkv.KVPairs {
	var kvps memkv.KVPairs
	for _, peerIPStr := range peerIPStrs {
		peerIP := net.ParseIP(peerIPStr)
		peer := backends.BGPPeer{
			PeerIP:          *peerIP,
			ExternalNetwork: enet,
			Port:            port,
		}

		peerJSON, err := json.Marshal(peer)
		if err != nil {
			t.Errorf("Error marshalling peer into JSON: %s", err)
		}

		kvp := memkv.KVPair{
			Key:   "dontcare",
			Value: string(peerJSON),
		}
		kvps = append(kvps, kvp)
	}
	return kvps
}

func Test_ExternalNetworkBIRDConfig_NoExternalNetworks(t *testing.T) {
	expectedEmptyBIRDCfgStr := []string{
		"# No ExternalNetworks configured",
	}

	resultCheckerForExternalNetworkBIRDConfig(memkv.KVPairs{}, memkv.KVPairs{}, memkv.KVPairs{},
		expectedEmptyBIRDCfgStr, t)
}

func Test_ExternalNetworkBIRDConfig_EmptyAllPeers(t *testing.T) {
	routeTableIdxs := []uint32{7}
	externalNetworkKVPs := constructExternalNetworkKVPs(routeTableIdxs, t)

	expectedBIRDCfgStr := []string{
		"# No ExternalNetworks configured for any of this node's BGP peers",
	}

	resultCheckerForExternalNetworkBIRDConfig(externalNetworkKVPs, memkv.KVPairs{}, memkv.KVPairs{},
		expectedBIRDCfgStr, t)
}

func Test_ExternalNetworkBIRDConfig_MultiplePeersSomeWithExternalNetworksSomeWithout(t *testing.T) {
	routeTableIdx1 := uint32(7)
	routeTableIdx2 := uint32(4)
	routeTableIdxs := []uint32{routeTableIdx1, routeTableIdx2}
	externalNetworkKVPs := constructExternalNetworkKVPs(routeTableIdxs, t)

	globalPeerIPStrs1 := []string{v4GlobalPeerIP1Str, v6GlobalPeerIP1Str}
	globalPeersKVPs1 := constructBGPPeerKVPs(globalPeerIPStrs1, "NonExistentExternalNetwork", 0, t)
	globalPeerIPStrs2 := []string{v4GlobalPeerIP2Str, v6GlobalPeerIP2Str}
	globalPeersKVPs2 := constructBGPPeerKVPs(globalPeerIPStrs2, externalNetworkKVPs[0].Key, 0, t)
	globalPeerIPStrs3 := []string{v4GlobalPeerIP3Str, v6GlobalPeerIP3Str}
	globalPeersKVPs3 := constructBGPPeerKVPs(globalPeerIPStrs3, externalNetworkKVPs[1].Key, 0, t)
	globalPeersKVPs := append(globalPeersKVPs1, globalPeersKVPs2...)
	globalPeersKVPs = append(globalPeersKVPs, globalPeersKVPs3...)

	explicitPeerIPStrs1 := []string{v4ExplicitPeerIP1Str, v6ExplicitPeerIP1Str}
	explicitPeersKVPs1 := constructBGPPeerKVPs(explicitPeerIPStrs1, "", 0, t)
	explicitPeerIPStrs2 := []string{v4ExplicitPeerIP2Str, v6ExplicitPeerIP2Str}
	explicitPeersKVPs2 := constructBGPPeerKVPs(explicitPeerIPStrs2, externalNetworkKVPs[0].Key, 0, t)
	explicitPeerIPStrs3 := []string{v4ExplicitPeerIP3Str, v6ExplicitPeerIP3Str}
	explicitPeersKVPs3 := constructBGPPeerKVPs(explicitPeerIPStrs3, externalNetworkKVPs[1].Key, 0, t)
	explicitPeersKVPs := append(explicitPeersKVPs1, explicitPeersKVPs2...)
	explicitPeersKVPs = append(explicitPeersKVPs, explicitPeersKVPs3...)

	expectedBIRDCfgStr := []string{
		"# ExternalNetwork test-enet-1",
		"table 'T_test-enet-1';",
		"protocol kernel 'K_test-enet-1' from kernel_template {",
		"  device routes yes;",
		"  table 'T_test-enet-1';",
		"  kernel table 7;",
		"  export filter {",
		"    print \"route: \", net, \", from, \", \", \", proto, \", \", bgp_next_hop;",
		"    if proto = \"Global_77_0_0_2\" then accept;",
		"    if proto = \"Global_7700__2\" then accept;",
		"    if proto = \"Node_44_0_0_2\" then accept;",
		"    if proto = \"Node_4400__2\" then accept;",
		"    reject;",
		"  };",
		"}",
		"protocol pipe {",
		"  peer table 'T_test-enet-1';",
		"  export filter {",
		"    if (ifname ~ \"cali*\") then {",
		"      accept;",
		"    } else {",
		"      reject;",
		"    }",
		"  };",
		"  import filter {",
		"    reject;",
		"  };",
		"}",
		"protocol direct 'D_test-enet-1' from direct_template {",
		"  table 'T_test-enet-1';",
		"}",
		"protocol static 'S_test-enet-1' from static_template {",
		"  table 'T_test-enet-1';",
		"}",
		"# ExternalNetwork test-enet-2",
		"table 'T_test-enet-2';",
		"protocol kernel 'K_test-enet-2' from kernel_template {",
		"  device routes yes;",
		"  table 'T_test-enet-2';",
		"  kernel table 4;",
		"  export filter {",
		"    print \"route: \", net, \", from, \", \", \", proto, \", \", bgp_next_hop;",
		"    if proto = \"Global_77_0_0_3\" then accept;",
		"    if proto = \"Global_7700__3\" then accept;",
		"    if proto = \"Node_44_0_0_3\" then accept;",
		"    if proto = \"Node_4400__3\" then accept;",
		"    reject;",
		"  };",
		"}",
		"protocol pipe {",
		"  peer table 'T_test-enet-2';",
		"  export filter {",
		"    if (ifname ~ \"cali*\") then {",
		"      accept;",
		"    } else {",
		"      reject;",
		"    }",
		"  };",
		"  import filter {",
		"    reject;",
		"  };",
		"}",
		"protocol direct 'D_test-enet-2' from direct_template {",
		"  table 'T_test-enet-2';",
		"}",
		"protocol static 'S_test-enet-2' from static_template {",
		"  table 'T_test-enet-2';",
		"}",
	}

	resultCheckerForExternalNetworkBIRDConfig(externalNetworkKVPs, globalPeersKVPs, explicitPeersKVPs,
		expectedBIRDCfgStr, t)
}

func Test_ExternalNetworkBIRDConfig_PeersWithPorts(t *testing.T) {
	routeTableIdx1 := uint32(7)
	routeTableIdxs := []uint32{routeTableIdx1}
	externalNetworkKVPs := constructExternalNetworkKVPs(routeTableIdxs, t)

	globalPeerIPStrs := []string{v4GlobalPeerIP1Str, v6GlobalPeerIP1Str}
	globalPeersKVPs := constructBGPPeerKVPs(globalPeerIPStrs, externalNetworkKVPs[0].Key, 77, t)

	explicitPeerIPStrs := []string{v4ExplicitPeerIP1Str, v6ExplicitPeerIP1Str}
	explicitPeersKVPs := constructBGPPeerKVPs(explicitPeerIPStrs, externalNetworkKVPs[0].Key, 44, t)

	expectedBIRDCfgStr := []string{
		"# ExternalNetwork test-enet-1",
		"table 'T_test-enet-1';",
		"protocol kernel 'K_test-enet-1' from kernel_template {",
		"  device routes yes;",
		"  table 'T_test-enet-1';",
		"  kernel table 7;",
		"  export filter {",
		"    print \"route: \", net, \", from, \", \", \", proto, \", \", bgp_next_hop;",
		"    if proto = \"Global_77_0_0_1_port_77\" then accept;",
		"    if proto = \"Global_7700__1_port_77\" then accept;",
		"    if proto = \"Node_44_0_0_1_port_44\" then accept;",
		"    if proto = \"Node_4400__1_port_44\" then accept;",
		"    reject;",
		"  };",
		"}",
		"protocol pipe {",
		"  peer table 'T_test-enet-1';",
		"  export filter {",
		"    if (ifname ~ \"cali*\") then {",
		"      accept;",
		"    } else {",
		"      reject;",
		"    }",
		"  };",
		"  import filter {",
		"    reject;",
		"  };",
		"}",
		"protocol direct 'D_test-enet-1' from direct_template {",
		"  table 'T_test-enet-1';",
		"}",
		"protocol static 'S_test-enet-1' from static_template {",
		"  table 'T_test-enet-1';",
		"}",
	}

	resultCheckerForExternalNetworkBIRDConfig(externalNetworkKVPs, globalPeersKVPs, explicitPeersKVPs,
		expectedBIRDCfgStr, t)
}

func Test_ExternalNetworkTableName(t *testing.T) {
	str := "should-not-be-truncated"
	output, err := ExternalNetworkTableName(str)
	if err != nil {
		t.Errorf("Unexpected error calling ExternalNetworkTableName(%s): %s", str, err)
	}
	if len(output) > maxFuncNameLen {
		t.Errorf(`ExternalNetworkTableName(%s) has length %d which is greater than the maximum allowed of %d`,
			str, len(output), maxFuncNameLen)
	}
	expectedName := "'T_should-not-be-truncated'"
	if output != expectedName {
		t.Errorf("Expected %s to equal %s", output, expectedName)
	}

	str = "very-long-name-that-should-be-truncated-because-it-is-longer-than-the-max-bird-symbol-length-of-64-chars"
	output, err = ExternalNetworkTableName(str)
	if err != nil {
		t.Errorf("Unexpected error calling ExternalNetworkTableName(%s): %s", str, err)
	}
	if len(output) > maxFuncNameLen {
		t.Errorf(`ExternalNetworkTableName(%s) has length %d which is greater than the maximum allowed of %d`,
			str, len(output), maxFuncNameLen)
	}
}

func Test_ValidateHashToIpv4Method(t *testing.T) {
	expectedRouterId := "207.94.5.27"
	nodeName := "Testrobin123"
	actualRouterId, err := HashToIPv4(nodeName)
	if err != nil {
		t.Fatalf("HashToIPv4(%s) returned unexpected error: %v", nodeName, err)
	}
	if expectedRouterId != actualRouterId {
		t.Errorf("Expected %s to equal %s", expectedRouterId, actualRouterId)
	}

	expectedRouterId = "109.174.215.226"
	nodeName = "nodeTest"
	actualRouterId, err = HashToIPv4(nodeName)
	if err != nil {
		t.Fatalf("HashToIPv4(%s) returned unexpected error: %v", nodeName, err)
	}
	if expectedRouterId != actualRouterId {
		t.Errorf("Expected %s to equal %s", expectedRouterId, actualRouterId)
	}
}

func int32Helper(i int32) *int32 {
	return &i
}
