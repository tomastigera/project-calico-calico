package backends

import (
	"github.com/tigera/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

type BGPPeer struct {
	PeerIP            net.IP               `json:"ip"`
	ASNum             numorstring.ASNumber `json:"as_num,string"`
	RRClusterID       string               `json:"rr_cluster_id"`
	Extensions        map[string]string    `json:"extensions"`
	Password          *string              `json:"password"`
	SourceAddr        string               `json:"source_addr"`
	DirectlyConnected bool                 `json:"directly_connected"`
	RestartMode       string               `json:"restart_mode"`
	RestartTime       string               `json:"restart_time"`
	GatewayMode       string               `json:"gateway_mode"`
	EnableBFD         bool                 `json:"enable_bfd"`
	Port              uint16               `json:"port"`
	KeepNextHop       bool                 `json:"keep_next_hop"`
	CalicoNode        bool                 `json:"calico_node"`
	NumAllowLocalAS   int32                `json:"num_allow_local_as"`
	TTLSecurity       uint8                `json:"ttl_security"`
	ExternalNetwork   string               `json:"external_network"`
	Filters           []string             `json:"filters"`
	ReachableBy       string               `json:"reachable_by"`
	PassiveMode       bool                 `json:"passive_mode"`
	LocalBGPPeer      bool                 `json:"local_bgp_peer"`
}
