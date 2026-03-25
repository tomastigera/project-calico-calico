// Copyright (c) 2018-2024 Tigera, Inc. All rights reserved.
package fv

import (
	"context"
	"maps"

	"github.com/onsi/gomega"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/calicoctl/calicoctl/resourcemgr"
	internalapi "github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/api"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/client"
)

// noopPolicyActivityClient is a stub lsclient.PolicyActivityInterface that
// returns empty results. Used in FV tests that don't exercise Linseed.
type noopPolicyActivityClient struct{}

var _ lsclient.PolicyActivityInterface = (*noopPolicyActivityClient)(nil)

func (n *noopPolicyActivityClient) Create(_ context.Context, _ []lsv1.PolicyActivity) (*lsv1.BulkResponse, error) {
	return &lsv1.BulkResponse{}, nil
}

func (n *noopPolicyActivityClient) GetPolicyActivities(_ context.Context, _ *lsv1.PolicyActivityParams) (*lsv1.PolicyActivityResponse, error) {
	return &lsv1.PolicyActivityResponse{}, nil
}

/*
This file defines a number of WEP, HEP, GNP, NP resources that can be used to test the EP<->Policy mappings.
Summary of configuration below.  Rules not explicitly specified have an all() or empty selector.

Endpoint                     rack  server  ns  orch       pod
------------------------------------------------------------------------------
hep4_n4_unlabelled
hep3_n4                      099
wep1_n1_ns1                  001   1       1   k8s        pod1-aaa         (needs profile-rack-001)
wep1_n1_ns1_updated_profile  099   1       1   k8s        pod1-aaa         (needs profile-rack-099)
wep2_n1_ns1_filtered_out     001   1       1   k8s        pod1-abc
wep2_n1_ns1_filtered_in      001   1       1   k8s        pod1-abc
wep3_n1_ns2                  001   1       2   k8s        pod2-acd
wep4_n2_ns1                  001   2       1   openstack
hep1_n2                      001   2
wep5_n3_ns2_unlabelled                     2   cni
hep2_n3                      002   1

Policy  Rule                 rack  server  ns  numEgress numIngress tier
------------------------------------------------------------------------------
np1_t1_o1_ns1                001   1       1   1         0          1
sknp1_t1_o1_ns1              001   1       1   1         0          1
np1_t1_o1_ns1_not_rack1      001   1       1   1         0          1
        egress;0;src;!sel    !=001
        egress;0;dest;!sel   !=001
np1_t1_o1_ns1_not_rack1_src  001   1       1   1         0          1
        egress;0;src;!sel    !=001
np1_t1_o1_ns1_not_rack1_2    002   1       1   1         0          1
        egress;0;src;!sel    !=001
        egress;0;dest;!sel   !=001
np2_t1_o2_ns2                              2   1         1          1
gnp1_t1_o3                   001               1         1          1
sgnp1_t1_o3                  001               1         1          1
gnp2_t1_o3_fewer_rules                                              1
        egress;0;src;sel     001   2
        ingress;0;dest;!sel  !=002
gnp1_t1_o4_more_rules        001               2         2          1
        egress;0;src!sel     001   1
        ingress;0;dest;sel   !=001
gnp2_t1_o4                                     2         2          1
        egress;0;src;!sel    001   1
        egess;1;src;sel      001   2
        ingress;0;dest;sel   !=001
		ingress;1;dest;!sel  !=002
sgnp2_t1_o4                                    2         2          1
        egress;0;src;!sel    001   1
        egess;1;src;sel      001   2
        ingress;0;dest;sel   !=001
        ingress;1;dest;!sel  !=002
gnp2_t1_o4_rack2_only        002               2         2          1
        egress;0;src;!sel    001   1
        egress;0;dest;sel          1
        egress;1;src;sel     002
        ingress;0;dest;sel   !=001
        ingress;1;dest;!sel  !=002
gnp3_t2_o5_rack2_only        002               2         2          2
		egress;0;src         002
sgnp2_t1_o4_rack2_only       002               2         2          1
        egress;0;src;!sel    001   1
        egress;0;dest;sel          1
        egress;1;src;sel     002
        ingress;0;dest;sel   !=001
        ingress;1;dest;!sel  !=002
sgnp3_t2_o5_rack2_only       002               2         2          2
        egress;0;src         002
np1_t2_o1_ns1                001   2       1   1         1          2
np2_t2_o2_ns2                              2   1         1          2
np1_t2_o1_ns1_rack2_only     001   1       1   1         1          2
        egress;0;src;sel     002
        egress;0;dest;sel    002
        ingress;0;src;sel    002
		ingress;0;dest;sel   002
snp1_t2_o1_ns1               001   2       1   1         1          2
snp2_t2_o2_ns2                             2   1         1          2
snp1_t2_o1_ns1_rack2_only    001   1       1   1         1          2
        egress;0;src;sel     002
        egress;0;dest;sel    002
        ingress;0;src;sel    002
		ingress;0;dest;sel   002
sknp1_t2_o1_ns1_rack2_only    001   1       1   1         1          2
        egress;0;src;sel     002
        egress;0;dest;sel    002
        ingress;0;src;sel    002
        ingress;0;dest;sel   002
gnp1_t2_o3                   !has              1         1          2
gnp2_t2_o4                                     1         1          2

Profile                      rack  server
------------------------------------------------------------------------------
profile-rack-001             1
profile-rack-099             99

Node    Name
-------------------------
node4   master-node.0001
node1   rack.1-server.1
node2   rack.1-server.2
node3   rack.2-server.1

NetworkSet                   rack  server
------------------------------------------------------------------------------
globalnetset1                001   1
globalnetset2                002
namespacednetset1            001   1
namespacednetset1            002
*/

var (
	order1 = 1.0
	order2 = 2.0
	order3 = 3.0
	order4 = 4.0

	node1 = &internalapi.Node{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       internalapi.KindNode,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "rack.1-server.1",
			Labels: map[string]string{
				"rack":   "001",
				"server": "1",
			},
		},
		Spec: internalapi.NodeSpec{
			BGP: &internalapi.NodeBGPSpec{
				IPv4Address: "1.2.3.1/24",
				IPv6Address: "aabb:ccdd:ee11:2233:3344:4455:6677:8891/120",
			},
			Addresses: []internalapi.NodeAddress{
				{Address: "1.2.3.1/24"},
				{Address: "aabb:ccdd:ee11:2233:3344:4455:6677:8891/120"},
			},
		},
	}

	node2 = &internalapi.Node{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       internalapi.KindNode,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "rack.1-server.2",
			Labels: map[string]string{
				"rack":   "001",
				"server": "1",
			},
		},
		Spec: internalapi.NodeSpec{
			BGP: &internalapi.NodeBGPSpec{
				IPv4Address: "1.2.3.2/24",
				IPv6Address: "aabb:ccdd:ee11:2233:3344:4455:6677:8892/120",
			},
			Addresses: []internalapi.NodeAddress{
				{Address: "1.2.3.1/24"},
				{Address: "aabb:ccdd:ee11:2233:3344:4455:6677:8891/120"},
			},
		},
	}

	node3 = &internalapi.Node{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       internalapi.KindNode,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "rack.2-server.1",
			Labels: map[string]string{
				"rack":   "002",
				"server": "1",
			},
		},
		Spec: internalapi.NodeSpec{
			BGP: &internalapi.NodeBGPSpec{
				IPv4Address: "1.2.4.1/24",
				IPv6Address: "aabb:ccdd::88a1/120",
			},
			Addresses: []internalapi.NodeAddress{
				{Address: "1.2.3.1/24"},
				{Address: "aabb:ccdd:ee11:2233:3344:4455:6677:8891/120"},
			},
		},
	}

	node4 = &internalapi.Node{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       internalapi.KindNode,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "master-node.0001",
			Labels: map[string]string{
				"rack": "099",
			},
		},
		Spec: internalapi.NodeSpec{},
	}

	wep1_n1_ns1 = &internalapi.WorkloadEndpoint{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       internalapi.KindWorkloadEndpoint,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rack.1--server.1-k8s-pod1--aaa-eth0",
			Namespace: "namespace-1",
			Labels: map[string]string{
				"server": "1",
				"name":   "wep1_n1_ns1",
			},
		},
		Spec: internalapi.WorkloadEndpointSpec{
			Node:          "rack.1-server.1",
			Profiles:      []string{"profile-rack-001"},
			Workload:      "",
			Orchestrator:  "k8s",
			Pod:           "pod1-aaa",
			ContainerID:   "abcdefg",
			Endpoint:      "eth0",
			InterfaceName: "cali987654",
			IPNetworks:    []string{"1.2.3.4/32"},
		},
	}

	wep1_n1_ns1_updated_profile = &internalapi.WorkloadEndpoint{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       internalapi.KindWorkloadEndpoint,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rack.1--server.1-k8s-pod1--aaa-eth0",
			Namespace: "namespace-1",
			Labels: map[string]string{
				"server": "1",
				"name":   "wep1_n1_ns1",
			},
		},
		Spec: internalapi.WorkloadEndpointSpec{
			Node:          "rack.1-server.1",
			Profiles:      []string{"profile-rack-099"},
			Workload:      "",
			Orchestrator:  "k8s",
			Pod:           "pod1-aaa",
			ContainerID:   "abcdefg",
			Endpoint:      "eth0",
			InterfaceName: "cali987654",
			IPNetworks:    []string{"1.2.3.4/32"},
		},
	}

	wep2_n1_ns1_filtered_out = &internalapi.WorkloadEndpoint{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       internalapi.KindWorkloadEndpoint,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rack.1--server.1-k8s-pod1--abc-eth0",
			Namespace: "namespace-1",
			Labels: map[string]string{
				"rack":   "001",
				"server": "1",
				"name":   "wep2_n1_ns1_filtered_out",
			},
		},
		Spec: internalapi.WorkloadEndpointSpec{
			Node:          "rack.1-server.1",
			Workload:      "",
			Orchestrator:  "k8s",
			Pod:           "pod1-abc",
			ContainerID:   "abcdefg",
			Endpoint:      "eth0",
			InterfaceName: "cali9b9b9b",
			// No IPNetworks, so WEP will be filtered out.
			IPNetworks: []string{},
		},
	}

	wep2_n1_ns1_filtered_in = &internalapi.WorkloadEndpoint{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       internalapi.KindWorkloadEndpoint,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rack.1--server.1-k8s-pod1--abc-eth0",
			Namespace: "namespace-1",
			Labels: map[string]string{
				"rack":   "001",
				"server": "1",
				"name":   "wep2_n1_ns1_filtered_out",
			},
		},
		Spec: internalapi.WorkloadEndpointSpec{
			Node:          "rack.1-server.1",
			Workload:      "",
			Orchestrator:  "k8s",
			Pod:           "pod1-abc",
			ContainerID:   "abcdefg",
			Endpoint:      "eth0",
			InterfaceName: "cali9b9b9b",
			// Thie one has an IP address and will therefore be filtered in.
			IPNetworks: []string{"10.20.30.40/32"},
		},
	}

	wep3_n1_ns2 = &internalapi.WorkloadEndpoint{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       internalapi.KindWorkloadEndpoint,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rack.1--server.1-k8s-pod2--acd-eth0",
			Namespace: "namespace-2",
			Labels: map[string]string{
				"rack":   "001",
				"server": "1",
				"name":   "wep3_n1_ns2",
			},
		},
		Spec: internalapi.WorkloadEndpointSpec{
			Node:          "rack.1-server.1",
			Workload:      "",
			Orchestrator:  "k8s",
			Pod:           "pod2-acd",
			ContainerID:   "abcde00",
			Endpoint:      "eth0",
			InterfaceName: "cali123456",
			IPNetworks:    []string{"1.2.3.6/32"},
		},
	}

	wep4_n2_ns1 = &internalapi.WorkloadEndpoint{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       internalapi.KindWorkloadEndpoint,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rack.1--server.2-openstack-aabbccdd-eth01234",
			Namespace: "namespace-1",
			Labels: map[string]string{
				"rack":   "001",
				"server": "2",
				"name":   "wep4_n2_ns1",
			},
		},
		Spec: internalapi.WorkloadEndpointSpec{
			Node:          "rack.1-server.2",
			Workload:      "aabbccdd",
			Orchestrator:  "openstack",
			Pod:           "",
			ContainerID:   "",
			Endpoint:      "eth01234",
			InterfaceName: "caliabcdef",
			IPNetworks:    []string{"1.2.3.7/32"},
		},
	}

	wep5_n3_ns2_unlabelled = &internalapi.WorkloadEndpoint{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       internalapi.KindWorkloadEndpoint,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rack.2--server.1-cni-badcafe1-foobarbaz",
			Namespace: "namespace-2",
		},
		Spec: internalapi.WorkloadEndpointSpec{
			Node:          "rack.2-server.1",
			Workload:      "",
			Orchestrator:  "cni",
			Pod:           "",
			ContainerID:   "badcafe1",
			Endpoint:      "foobarbaz",
			InterfaceName: "calia1b2c3",
			IPNetworks:    []string{"1.2.3.8/32"},
		},
	}

	hep1_n2 = &apiv3.HostEndpoint{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindHostEndpoint,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "rack.1-server.2---eth1",
			Labels: map[string]string{
				"rack":   "001",
				"server": "2",
				"name":   "hep1_n2",
			},
		},
		Spec: apiv3.HostEndpointSpec{
			Node:          "rack.1-server.2",
			InterfaceName: "eth1",
			ExpectedIPs:   []string{"10.11.12.13"},
		},
	}

	hep2_n3 = &apiv3.HostEndpoint{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindHostEndpoint,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "rack.2-server.1---eth1",
			Labels: map[string]string{
				"rack":   "002",
				"server": "1",
				"name":   "hep2_n3",
			},
		},
		Spec: apiv3.HostEndpointSpec{
			Node:          "rack.2-server.1",
			InterfaceName: "eth1",
		},
	}

	hep3_n4 = &apiv3.HostEndpoint{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindHostEndpoint,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "master-main-interface",
			Labels: map[string]string{
				"rack": "099",
				"name": "hep3_n4",
			},
		},
		Spec: apiv3.HostEndpointSpec{
			Node:          "master-node.0001",
			InterfaceName: "eth0",
		},
	}

	hep4_n4_unlabelled = &apiv3.HostEndpoint{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindHostEndpoint,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "master-backup-interface",
		},
		Spec: apiv3.HostEndpointSpec{
			Node:          "master-node.0001",
			InterfaceName: "eth1",
		},
	}

	hep5_nonclusterhost = &apiv3.HostEndpoint{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindHostEndpoint,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "non-cluster-host-1-hep",
			Labels: map[string]string{
				"hostendpoint.projectcalico.org/type": "nonclusterhost",
			},
		},
		Spec: apiv3.HostEndpointSpec{
			Node:          "non-cluster-host-1",
			InterfaceName: "eth0",
			ExpectedIPs:   []string{"1.2.3.4"},
		},
	}

	tier1 = &apiv3.Tier{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindTier,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "ccc-tier1",
		},
		Spec: apiv3.TierSpec{
			Order: &order1,
		},
	}

	tier2 = &apiv3.Tier{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindTier,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "aaa-tier2",
		},
		Spec: apiv3.TierSpec{
			Order: &order2,
		},
	}

	// Create a couple of re-ordered tiers
	tier1_o2 = &apiv3.Tier{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindTier,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "ccc-tier1",
		},
		Spec: apiv3.TierSpec{
			Order: &order2,
		},
	}

	tier2_o1 = &apiv3.Tier{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindTier,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "aaa-tier2",
		},
		Spec: apiv3.TierSpec{
			Order: &order1,
		},
	}

	tier_default = &apiv3.Tier{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindTier,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: names.DefaultTierName,
		},
		Spec: apiv3.TierSpec{},
	}

	np1_t1_o1_ns1 = &apiv3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ccc-tier1.np1-t1-o1-ns1",
			Namespace: "namespace-1",
		},
		Spec: apiv3.NetworkPolicySpec{
			Tier:     "ccc-tier1",
			Selector: "rack == '001' && server == '1'",
			Order:    &order1,
			Egress: []apiv3.Rule{
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
			},
		},
	}

	np1_t1_o1_ns1_not_rack1_src = &apiv3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ccc-tier1.np1-t1-o1-ns1",
			Namespace: "namespace-1",
		},
		Spec: apiv3.NetworkPolicySpec{
			Tier:     "ccc-tier1",
			Selector: "rack == '001' && server == '1'",
			Order:    &order1,
			Egress: []apiv3.Rule{
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "rack == '001'",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
			},
		},
	}

	np1_t1_o1_ns1_not_rack1_2 = &apiv3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ccc-tier1.np1-t1-o1-ns1",
			Namespace: "namespace-1",
		},
		Spec: apiv3.NetworkPolicySpec{
			Tier:     "ccc-tier1",
			Selector: "rack == '002' && server == '1'",
			Order:    &order1,
			Egress: []apiv3.Rule{
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "rack == '001'",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "rack == '001'",
					},
				},
			},
		},
	}

	np2_t1_o2_ns2 = &apiv3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ccc-tier1.np2-t1-o2-ns1",
			Namespace: "namespace-2",
		},
		Spec: apiv3.NetworkPolicySpec{
			Tier:     "ccc-tier1",
			Selector: "all()",
			Order:    &order2,
			Egress: []apiv3.Rule{
				{
					Action: "Pass",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
			},
			Ingress: []apiv3.Rule{
				{
					Action: "Pass",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
			},
		},
	}

	gnp1_t1_o3 = &apiv3.GlobalNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindGlobalNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "ccc-tier1.gnp1-t1-o3",
		},
		Spec: apiv3.GlobalNetworkPolicySpec{
			Tier:     "ccc-tier1",
			Selector: "rack == '001'",
			Order:    &order3,
			Egress: []apiv3.Rule{
				{
					Action: "Pass",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
			},
			Ingress: []apiv3.Rule{
				{
					Action: "Pass",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
			},
		},
	}

	gnp2_t1_o4 = &apiv3.GlobalNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindGlobalNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "ccc-tier1.gnp2-t1-o4",
		},
		Spec: apiv3.GlobalNetworkPolicySpec{
			Tier:     "ccc-tier1",
			Selector: "",
			Order:    &order4,
			Egress: []apiv3.Rule{
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector:    "all()",
						NotSelector: "rack == '001' && server == '1'",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector:    "rack == '001' && server == '2'",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
			},
			Ingress: []apiv3.Rule{
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "has(rack) && rack != '001'",
						NotSelector: "",
					},
				},
				{
					Action: "Deny",
					Source: apiv3.EntityRule{
						Selector:    "all()",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "has(rack) && rack != '002'",
					},
				},
			},
		},
	}

	gnp2_t1_o4_rack2_only = &apiv3.GlobalNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindGlobalNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "ccc-tier1.gnp2-t1-o4-rack2-only",
		},
		Spec: apiv3.GlobalNetworkPolicySpec{
			Tier:     "ccc-tier1",
			Selector: "rack == '002'",
			Order:    &order4,
			Egress: []apiv3.Rule{
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "rack == '001' && server == '1'",
					},
					Destination: apiv3.EntityRule{
						Selector:    "server == '1'",
						NotSelector: "",
					},
				},
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector:    "rack == '002'",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
			},
			Ingress: []apiv3.Rule{
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "has(rack) && rack != '001'",
						NotSelector: "",
					},
				},
				{
					Action: "Deny",
					Source: apiv3.EntityRule{
						Selector:    "all()",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "has(rack) && rack != '002'",
					},
				},
			},
		},
	}

	gnp3_t2_o5_rack2_only = &apiv3.GlobalNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindGlobalNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "aaa-tier2.gnp3-t2-o5-rack2-only",
		},
		Spec: apiv3.GlobalNetworkPolicySpec{
			Tier:     "aaa-tier2",
			Selector: "rack == '002'",
			Order:    &order4,
			Egress: []apiv3.Rule{
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector: "rack == '002'",
					},
				},
			},
		},
	}

	sgnp1_t1_o3 = &apiv3.StagedGlobalNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindStagedGlobalNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "ccc-tier1.sgnp1-t1-o3",
		},
		Spec: apiv3.StagedGlobalNetworkPolicySpec{
			StagedAction: apiv3.StagedActionSet,
			Tier:         "ccc-tier1",
			Selector:     "rack == '001'",
			Order:        &order3,
			Egress: []apiv3.Rule{
				{
					Action: "Pass",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
			},
			Ingress: []apiv3.Rule{
				{
					Action: "Pass",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
			},
		},
	}

	sgnp2_t1_o4 = &apiv3.StagedGlobalNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindStagedGlobalNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "ccc-tier1.sgnp2-t1-o4",
		},
		Spec: apiv3.StagedGlobalNetworkPolicySpec{
			StagedAction: apiv3.StagedActionSet,
			Tier:         "ccc-tier1",
			Selector:     "all()",
			Order:        &order4,
			Egress: []apiv3.Rule{
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector:    "all()",
						NotSelector: "rack == '001' && server == '1'",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector:    "rack == '001' && server == '2'",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
			},
			Ingress: []apiv3.Rule{
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "has(rack) && rack != '001'",
						NotSelector: "",
					},
				},
				{
					Action: "Deny",
					Source: apiv3.EntityRule{
						Selector:    "all()",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "has(rack) && rack != '002'",
					},
				},
			},
		},
	}

	sgnp2_t1_o4_rack2_only = &apiv3.StagedGlobalNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindStagedGlobalNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "ccc-tier1.sgnp2-t1-o4-rack2-only",
		},
		Spec: apiv3.StagedGlobalNetworkPolicySpec{
			StagedAction: apiv3.StagedActionSet,
			Tier:         "ccc-tier1",
			Selector:     "rack == '002'",
			Order:        &order4,
			Egress: []apiv3.Rule{
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "rack == '001' && server == '1'",
					},
					Destination: apiv3.EntityRule{
						Selector:    "server == '1'",
						NotSelector: "",
					},
				},
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector:    "rack == '002'",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
			},
			Ingress: []apiv3.Rule{
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "has(rack) && rack != '001'",
						NotSelector: "",
					},
				},
				{
					Action: "Deny",
					Source: apiv3.EntityRule{
						Selector:    "all()",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "has(rack) && rack != '002'",
					},
				},
			},
		},
	}

	sgnp3_t2_o5_rack2_only = &apiv3.StagedGlobalNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindStagedGlobalNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "aaa-tier2.sgnp3-t2-o5-rack2-only",
		},
		Spec: apiv3.StagedGlobalNetworkPolicySpec{
			StagedAction: apiv3.StagedActionSet,
			Tier:         "aaa-tier2",
			Selector:     "rack == '002'",
			Order:        &order4,
			Egress: []apiv3.Rule{
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector: "rack == '002'",
					},
				},
			},
		},
	}

	np1_t2_o1_ns1 = &apiv3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aaa-tier2.np1-t2-o1-ns1",
			Namespace: "namespace-1",
		},
		Spec: apiv3.NetworkPolicySpec{
			Tier:     "aaa-tier2",
			Selector: "rack == '001' && server == '2'",
			Order:    &order1,
			Egress: []apiv3.Rule{
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
			},
			Ingress: []apiv3.Rule{
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
			},
		},
	}

	np2_t2_o2_ns2 = &apiv3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aaa-tier2.np2-t2-o2-ns1",
			Namespace: "namespace-2",
		},
		Spec: apiv3.NetworkPolicySpec{
			Tier:     "aaa-tier2",
			Selector: "all()",
			Order:    &order2,
			Egress: []apiv3.Rule{
				{
					Action: "Pass",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
			},
			Ingress: []apiv3.Rule{
				{
					Action: "Pass",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
			},
		},
	}

	np1_t2_o1_ns1_rack2_only = &apiv3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aaa-tier2.np1-t2-o1-ns1-rack2-only",
			Namespace: "namespace-1",
		},
		Spec: apiv3.NetworkPolicySpec{
			Tier:     "aaa-tier2",
			Selector: "rack == '001' && server == '1'",
			Order:    &order1,
			Egress: []apiv3.Rule{
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector:    "rack == '002'",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "rack == '002'",
						NotSelector: "",
					},
				},
			},
			Ingress: []apiv3.Rule{
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector:    "rack == '002'",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "rack == '002'",
						NotSelector: "",
					},
				},
			},
		},
	}

	np2_t1_o4_rack2_no_tier = &apiv3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "policy-no-tier-set",
			Namespace: "ns1",
		},
		Spec: apiv3.NetworkPolicySpec{
			Tier: "",
		},
	}

	sknp1_t2_o1_ns1_rack2_only = &apiv3.StagedKubernetesNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindStagedKubernetesNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sknp1-t2-o1-ns1-rack2-only",
			Namespace: "namespace-1",
		},
		Spec: apiv3.StagedKubernetesNetworkPolicySpec{
			StagedAction: apiv3.StagedActionSet,
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"rack": "001", "server": "1"},
			},
			PolicyTypes: []networkingv1.PolicyType{"Ingress", "Egress"},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{},
					},
					To: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"rack": "002"},
							},
						},
					},
				},
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{},
					},
					From: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"rack": "002"},
							},
						},
					},
				},
			},
		},
	}

	sknp1_t1_o1_ns1 = &apiv3.StagedKubernetesNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindStagedKubernetesNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sknp1-t1-o1-ns1",
			Namespace: "namespace-1",
		},
		Spec: apiv3.StagedKubernetesNetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"rack": "001", "server": "1"},
			},
			PolicyTypes: []networkingv1.PolicyType{"Egress"},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{},
			},
		},
	}

	snp1_t2_o1_ns1_delete = &apiv3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindStagedNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aaa-tier2.snp1-t2-o1-ns1-delete",
			Namespace: "namespace-1",
		},
		Spec: apiv3.StagedNetworkPolicySpec{
			StagedAction: apiv3.StagedActionDelete,
			Tier:         "aaa-tier2",
		},
	}

	snp1_t2_o1_ns1 = &apiv3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindStagedNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aaa-tier2.snp1-t2-o1-ns1",
			Namespace: "namespace-1",
		},
		Spec: apiv3.StagedNetworkPolicySpec{
			StagedAction: apiv3.StagedActionSet,
			Tier:         "aaa-tier2",
			Selector:     "rack == '001' && server == '2'",
			Order:        &order1,
			Egress: []apiv3.Rule{
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
			},
			Ingress: []apiv3.Rule{
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
			},
		},
	}

	snp2_t2_o2_ns2 = &apiv3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindStagedNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aaa-tier2.snp2-t2-o2-ns1",
			Namespace: "namespace-2",
		},
		Spec: apiv3.StagedNetworkPolicySpec{
			StagedAction: apiv3.StagedActionSet,
			Tier:         "aaa-tier2",
			Selector:     "all()",
			Order:        &order2,
			Egress: []apiv3.Rule{
				{
					Action: "Pass",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
			},
			Ingress: []apiv3.Rule{
				{
					Action: "Pass",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
			},
		},
	}

	snp1_t2_o1_ns1_rack2_only = &apiv3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindStagedNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aaa-tier2.snp1-t2-o1-ns1-rack2-only",
			Namespace: "namespace-1",
		},
		Spec: apiv3.StagedNetworkPolicySpec{
			StagedAction: apiv3.StagedActionSet,
			Tier:         "aaa-tier2",
			Selector:     "rack == '001' && server == '1'",
			Order:        &order1,
			Egress: []apiv3.Rule{
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector:    "rack == '002'",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "rack == '002'",
						NotSelector: "",
					},
				},
			},
			Ingress: []apiv3.Rule{
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector:    "rack == '002'",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "rack == '002'",
						NotSelector: "",
					},
				},
			},
		},
	}

	gnp1_t2_o3 = &apiv3.GlobalNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindGlobalNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "aaa-tier2.gnp1-t2-o3",
		},
		Spec: apiv3.GlobalNetworkPolicySpec{
			Tier:     "aaa-tier2",
			Selector: "!has(rack)",
			Order:    &order3,
			Egress: []apiv3.Rule{
				{
					Action: "Pass",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
			},
			Ingress: []apiv3.Rule{
				{
					Action: "Pass",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
			},
		},
	}

	gnp2_t2_o4 = &apiv3.GlobalNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindGlobalNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "aaa-tier2.gnp2-t2-o4",
		},
		Spec: apiv3.GlobalNetworkPolicySpec{
			Tier:     "aaa-tier2",
			Selector: "",
			Order:    &order4,
			Egress: []apiv3.Rule{
				{
					Action: "Deny",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
			},
			Ingress: []apiv3.Rule{
				{
					Action: "Deny",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
			},
		},
	}

	// Create a couple of adjusted policies that have different orders and different numbers of rules.
	gnp1_t1_o4_more_rules = &apiv3.GlobalNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindGlobalNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "ccc-tier1.gnp1-t1-o3",
		},
		Spec: apiv3.GlobalNetworkPolicySpec{
			Tier:     "ccc-tier1",
			Selector: "rack == '001'",
			Order:    &order4,
			Egress: []apiv3.Rule{
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector:    "all()",
						NotSelector: "rack == '001' && server == '1'",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
				{
					Action: "Pass",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
			},
			Ingress: []apiv3.Rule{
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "has(rack) && rack != '001'",
						NotSelector: "",
					},
				},
				{
					Action: "Pass",
					Source: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
			},
		},
	}

	gnp2_t1_o3_fewer_rules = &apiv3.GlobalNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindGlobalNetworkPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "ccc-tier1.gnp2-t1-o4",
		},
		Spec: apiv3.GlobalNetworkPolicySpec{
			Tier:     "ccc-tier1",
			Selector: "",
			Order:    &order3,
			Egress: []apiv3.Rule{
				{
					Action: "Allow",
					Source: apiv3.EntityRule{
						Selector:    "rack == '001' && server == '2'",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "",
					},
				},
			},
			Ingress: []apiv3.Rule{
				{
					Action: "Deny",
					Source: apiv3.EntityRule{
						Selector:    "all()",
						NotSelector: "",
					},
					Destination: apiv3.EntityRule{
						Selector:    "",
						NotSelector: "has(rack) && rack != '002'",
					},
				},
			},
		},
	}

	profile_rack_001 = &apiv3.Profile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindProfile,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "profile-rack-001",
		},
		Spec: apiv3.ProfileSpec{
			LabelsToApply: map[string]string{
				"rack": "001",
			},
		},
	}

	profile_rack_099 = &apiv3.Profile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindProfile,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "profile-rack-099",
		},
		Spec: apiv3.ProfileSpec{
			LabelsToApply: map[string]string{
				"rack": "099",
			},
		},
	}

	globalnetset1 = &apiv3.GlobalNetworkSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindGlobalNetworkSet,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "globalnetset1",
			Labels: map[string]string{
				"rack":   "001",
				"server": "1",
			},
		},
		Spec: apiv3.GlobalNetworkSetSpec{
			Nets: []string{"198.51.100.0/28"},
		},
	}

	globalnetset2 = &apiv3.GlobalNetworkSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindGlobalNetworkSet,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "globalnetset2",
			Labels: map[string]string{
				"rack": "002",
			},
		},
		Spec: apiv3.GlobalNetworkSetSpec{
			Nets: []string{"198.51.100.0/28", "199.51.100.0/24"},
		},
	}

	namespacednetset1 = &apiv3.NetworkSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindNetworkSet,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "namespacednetset1",
			Namespace: "namespace-1",
			Labels: map[string]string{
				"rack":   "001",
				"server": "1",
			},
		},
		Spec: apiv3.NetworkSetSpec{
			Nets: []string{"198.51.100.0/28"},
		},
	}

	namespacednetset2 = &apiv3.NetworkSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiv3.GroupVersionCurrent,
			Kind:       apiv3.KindNetworkSet,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "namespacednetset2",
			Namespace: "namespace-1",
			Labels: map[string]string{
				"rack": "002",
			},
		},
		Spec: apiv3.NetworkSetSpec{
			Nets: []string{"198.51.100.0/28", "199.51.100.0/24"},
		},
	}
)

// qcNode returns a client.Node from an v3.Node, v3.WorkloadEndpoint or v3.HostEndpoint.
func qcNode(r api.Resource, numHEP, numWEP int) client.Node {
	n := client.Node{
		NumWorkloadEndpoints: numWEP,
		NumHostEndpoints:     numHEP,
	}

	switch nr := r.(type) {
	case *internalapi.Node:
		n.Name = nr.Name
		if nr.Spec.BGP != nil {
			if nr.Spec.BGP.IPv4Address != "" {
				n.BGPIPAddresses = append(n.BGPIPAddresses, nr.Spec.BGP.IPv4Address)
			}
			if nr.Spec.BGP.IPv6Address != "" {
				n.BGPIPAddresses = append(n.BGPIPAddresses, nr.Spec.BGP.IPv6Address)
			}
		}

		if len(nr.Spec.Addresses) > 0 {
			for _, nodeAddress := range nr.Spec.Addresses {
				n.Addresses = append(n.Addresses, nodeAddress.Address)
			}
		}
	case *internalapi.WorkloadEndpoint:
		n.Name = nr.Spec.Node
	case *apiv3.HostEndpoint:
		n.Name = nr.Spec.Node
	}
	return n
}

// qcNode returns a client.Node from an v3.WorkloadEndpoint or v3.HostEndpoint.
func qcEndpoint(r api.Resource, numGNP, numNP int) client.Endpoint {
	e := client.Endpoint{
		Kind:                     r.GetObjectKind().GroupVersionKind().Kind,
		Name:                     r.GetObjectMeta().GetName(),
		Namespace:                r.GetObjectMeta().GetNamespace(),
		NumGlobalNetworkPolicies: numGNP,
		NumNetworkPolicies:       numNP,
	}

	switch er := r.(type) {
	case *internalapi.WorkloadEndpoint:
		// Copy labels to add implicit labels.
		labels := map[string]string{}
		maps.Copy(labels, r.GetObjectMeta().GetLabels())
		labels["projectcalico.org/namespace"] = er.Namespace
		labels["projectcalico.org/orchestrator"] = er.Spec.Orchestrator
		e.Labels = labels
		e.Node = er.Spec.Node
		e.Workload = er.Spec.Workload
		e.Orchestrator = er.Spec.Orchestrator
		e.Pod = er.Spec.Pod
		e.InterfaceName = er.Spec.InterfaceName
		e.IPNetworks = er.Spec.IPNetworks
	case *apiv3.HostEndpoint:
		e.Labels = r.GetObjectMeta().GetLabels()
		e.Node = er.Spec.Node
		e.InterfaceName = er.Spec.InterfaceName
		e.IPNetworks = er.Spec.ExpectedIPs
	}
	return e
}

// qcPolicy returns a client.Policy from an v3.NetworkPolicy or v3.GlobalNetworkPolicy.
// To keep the interface simple, it assigns the totWEP and totHEP values to all of the
// rule selectors (i.e. it assumes they simply match all).
func qcPolicy(r api.Resource, numHEP, numWEP, totHEP, totWEP int) client.Policy {
	p := client.Policy{
		Kind:                 r.GetObjectKind().GroupVersionKind().Kind,
		Name:                 r.GetObjectMeta().GetName(),
		Namespace:            r.GetObjectMeta().GetNamespace(),
		NumWorkloadEndpoints: numWEP,
		NumHostEndpoints:     numHEP,
	}

	createRulesFn := func(num int) []client.RuleInfo {
		if num == 0 {
			return nil
		}
		rules := make([]client.RuleInfo, num)
		for i := range num {
			rules[i] = client.RuleInfo{
				Source: client.RuleEntity{
					NumWorkloadEndpoints: totWEP,
					NumHostEndpoints:     totHEP,
				},
				Destination: client.RuleEntity{
					NumWorkloadEndpoints: totWEP,
					NumHostEndpoints:     totHEP,
				},
			}
		}
		return rules
	}

	switch er := r.(type) {
	case *apiv3.NetworkPolicy:
		p.Tier = er.Spec.Tier
		p.IngressRules = createRulesFn(len(er.Spec.Ingress))
		p.EgressRules = createRulesFn(len(er.Spec.Egress))
		p.Selector = &er.Spec.Selector
		p.ServiceAccountSelector = &er.Spec.ServiceAccountSelector
	case *apiv3.GlobalNetworkPolicy:
		p.Tier = er.Spec.Tier
		p.IngressRules = createRulesFn(len(er.Spec.Ingress))
		p.EgressRules = createRulesFn(len(er.Spec.Egress))
		p.Selector = &er.Spec.Selector
		p.NamespaceSelector = &er.Spec.NamespaceSelector
		p.ServiceAccountSelector = &er.Spec.ServiceAccountSelector
	case *apiv3.StagedNetworkPolicy:
		p.Tier = er.Spec.Tier
		p.IngressRules = createRulesFn(len(er.Spec.Ingress))
		p.EgressRules = createRulesFn(len(er.Spec.Egress))
		if er.Spec.StagedAction != "" {
			p.StagedAction = &er.Spec.StagedAction
		}
		p.Selector = &er.Spec.Selector
		p.ServiceAccountSelector = &er.Spec.ServiceAccountSelector
	case *apiv3.StagedKubernetesNetworkPolicy:
		p.IngressRules = createRulesFn(len(er.Spec.Ingress))
		p.EgressRules = createRulesFn(len(er.Spec.Egress))
		// The CRD schema has +kubebuilder:default=Set on StagedAction. The
		// validator's validateCRD applies CRD schema defaults to the object
		// before storing, so the server always returns "Set" when omitted.
		stagedAction := er.Spec.StagedAction
		if stagedAction == "" {
			stagedAction = apiv3.StagedActionSet
		}
		p.StagedAction = &stagedAction
		p.Selector = getStringPointer(conversion.K8sSelectorToCalico(&er.Spec.PodSelector, conversion.SelectorPod))
		p.ServiceAccountSelector = nil
	case *apiv3.StagedGlobalNetworkPolicy:
		p.Tier = er.Spec.Tier
		p.IngressRules = createRulesFn(len(er.Spec.Ingress))
		p.EgressRules = createRulesFn(len(er.Spec.Egress))
		if er.Spec.StagedAction != "" {
			p.StagedAction = &er.Spec.StagedAction
		}
		p.Selector = &er.Spec.Selector
		p.NamespaceSelector = &er.Spec.NamespaceSelector
		p.ServiceAccountSelector = &er.Spec.ServiceAccountSelector
	}

	// Default tier to "default" if not set.
	if p.Tier == "" {
		p.Tier = names.DefaultTierName
	}

	return p
}

func qcPolicyWithIdx(r api.Resource, idx, numHEP, numWEP, totHEP, totWEP int) client.Policy {
	p := qcPolicy(r, numHEP, numWEP, totHEP, totWEP)
	p.Index = idx
	return p
}

// createResources ensures the supplied set of `configure` resources is configured by either
// creating or updating as necessary and deleting any old resources from the configured map that
// are no longer required.  This allows test to churn configuration rather than simply deleting
// the entire contents of etcd before each run.
func createResources(
	client clientv3.Interface, configure []resourcemgr.ResourceObject,
	configured map[model.ResourceKey]resourcemgr.ResourceObject,
) map[model.ResourceKey]resourcemgr.ResourceObject {
	if configured == nil {
		configured = make(map[model.ResourceKey]resourcemgr.ResourceObject)
	}
	unhandled := make(map[model.ResourceKey]resourcemgr.ResourceObject)
	ctx := context.Background()

	// Construct the map of unhandled resources. We use this to easily look up which resources
	// we don't want to delete when tidying up the currently configured resources.
	for _, res := range configure {
		unhandled[resourceKey(res)] = res
	}

	// First delete any resources that are not in the unhandled set of resource.  We need to do this first
	// because deleting some resources (e.g. nodes) may delete other associated resources that we were not
	// intending to delete.  We require two iterations, the first to delete non-tiers, the second to delete
	// tiers (because they can only be deleted once the associated policies are also deleted).
	for i := range 2 {
		for key, res := range configured {
			if _, ok := unhandled[key]; ok {
				// This resource is in our unhandled map so we'll be creating or updating it
				// later - no need to delete.
				continue
			}
			if key.Kind == apiv3.KindTier && key.Name == names.DefaultTierName {
				// Skip deleting "default" tier
				continue
			}
			if i == 0 && key.Kind == apiv3.KindTier {
				// Skip tiers on the first iteration.
				continue
			}
			delete(configured, key)
			rm := resourcemgr.GetResourceManager(res)
			gomega.Expect(rm).NotTo(gomega.BeNil())
			_, err := rm.Delete(ctx, client, res)
			if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
				// Only check for no error if the error is does not indicate a missing resource.
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
			}
		}
	}

	// Apply the resources in the specified order.
	for _, res := range configure {
		res := res.DeepCopyObject().(resourcemgr.ResourceObject)
		rm := resourcemgr.GetResourceManager(res)
		gomega.Expect(rm).NotTo(gomega.BeNil())
		configured[resourceKey(res)] = res
		_, err := rm.Apply(ctx, client, res)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	}

	return configured
}

func resourceKey(res resourcemgr.ResourceObject) model.ResourceKey {
	return model.ResourceKey{
		Kind:      res.GetObjectKind().GroupVersionKind().Kind,
		Name:      res.GetObjectMeta().GetName(),
		Namespace: res.GetObjectMeta().GetNamespace(),
	}
}
