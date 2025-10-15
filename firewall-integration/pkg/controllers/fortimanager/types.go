// Copyright 2019 Tigera Inc. All rights reserved.

package fortimanager

import (
	"errors"
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"

	fortilib "github.com/projectcalico/calico/firewall-integration/pkg/fortimanager"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const TigeraComment = "Managed by Calico Enterprise"

type FortinetClient interface {
	CreateFirewallAddress(FirewallAddress) error
	UpdateFirewallAddress(FirewallAddress) error
	DeleteFirewallAddress(string) error
	GetFirewallAddress(string, string) (FirewallAddress, error)
	ListFirewallAddresses() ([]FirewallAddress, error)

	// AddressGroup APIs
	CreateAddressGroup(AddressGroup) error
	UpdateAddressGroup(AddressGroup) error
	DeleteAddressGroup(string) error
	GetAddressGroup(string) (AddressGroup, error)
	ListAddressGroups() ([]AddressGroup, error)

	// Membership APIs
	AddFirewallAddressToAddressGroup(AddressGroup, FirewallAddress) error
	RemoveFirewallAddressToAddressGroup(AddressGroup, FirewallAddress) error
}

func NewMockFortinetClient() FortinetClient {
	clusterNode := map[string]FirewallAddress{
		"karthikr-kadm-ms": FirewallAddress{
			Name: "karthikr-kadm-ms",
			IP:   net.ParseIP("10.128.0.165"),
		},
		"karthikr-kadm-node-0": FirewallAddress{
			Name: "karthikr-kadm-node-0",
			IP:   net.ParseIP("10.128.0.163"),
		},
		"karthikr-kadm-infra-0": FirewallAddress{
			Name: "karthikr-kadm-infra-0",
			IP:   net.ParseIP("10.128.0.166"),
		},
	}
	clusterAddressGroup := map[string]AddressGroup{
		"color_red": AddressGroup{
			Name:    "color_red",
			Members: set.New[string](),
		},
		"app_is_nginx": AddressGroup{
			Name:    "app_is_nginx",
			Members: set.New[string](),
		},
	}
	return &mockFortinetClient{
		clusterNode:         clusterNode,
		clusterAddressGroup: clusterAddressGroup,
	}
}

type mockFortinetClient struct {
	clusterNode         map[string]FirewallAddress
	clusterAddressGroup map[string]AddressGroup
}

func (fc *mockFortinetClient) ListFirewallAddresses() ([]FirewallAddress, error) {
	return []FirewallAddress{
		FirewallAddress{
			Name: "karthikr-kadm-node-0",
			IP:   net.ParseIP("10.128.0.163"),
		},
		FirewallAddress{
			Name: "karthikr-kadm-infra-0",
			IP:   net.ParseIP("10.128.0.166"),
		},
	}, nil
}

func (fc *mockFortinetClient) DeleteFirewallAddress(name string) error {
	return nil
}

func (fc *mockFortinetClient) GetFirewallAddress(adom string, name string) (FirewallAddress, error) {
	return fc.clusterNode[name], nil
}

func (fc *mockFortinetClient) CreateFirewallAddress(fwAddr FirewallAddress) error {
	return nil
}

func (fc *mockFortinetClient) UpdateFirewallAddress(fwAddr FirewallAddress) error {
	return nil
}

func (fc *mockFortinetClient) ListAddressGroups() ([]AddressGroup, error) {
	return []AddressGroup{
		AddressGroup{
			Name:    "color_red",
			Members: set.New[string](),
		},
		AddressGroup{
			Name:    "app_is_nginx",
			Members: set.New[string](),
		},
	}, nil
}

func (fc *mockFortinetClient) DeleteAddressGroup(name string) error {
	return nil
}

func (fc *mockFortinetClient) GetAddressGroup(name string) (AddressGroup, error) {
	return fc.clusterAddressGroup[name], nil
}

func (fc *mockFortinetClient) CreateAddressGroup(fwAddr AddressGroup) error {
	return nil
}

func (fc *mockFortinetClient) UpdateAddressGroup(fwAddr AddressGroup) error {
	return nil
}

func (fc *mockFortinetClient) AddFirewallAddressToAddressGroup(group AddressGroup, fwAddr FirewallAddress) error {
	return nil
}

func (fc *mockFortinetClient) RemoveFirewallAddressToAddressGroup(group AddressGroup, fwAddr FirewallAddress) error {
	return nil
}

type FirewallAddress struct {
	Name string
	IP   net.IP
}

type AddressGroup struct {
	Name    string
	Members set.Set[string]
}

func ConvertK8sNodeToFortinetFirewallAddress(node *v1.Node) (fortilib.RespFortiGateFWAddressData, error) {
	ip := getNodeInternalIP(node.Status.Addresses)
	if ip == nil {
		return fortilib.RespFortiGateFWAddressData{}, errors.New("could not get IP address for node")
	}
	faddr := fortilib.RespFortiGateFWAddressData{
		Name:    node.GetObjectMeta().GetName(),
		Comment: TigeraComment,
		Type:    fortilib.FortiGateIpMaskType,
		SubType: fortilib.FortiGateSdnType,
		Subnet:  ip.String(),
	}
	return faddr, nil
}

func getNodeInternalIP(addresses []v1.NodeAddress) *net.IP {
	for _, addr := range addresses {
		if addr.Type != v1.NodeInternalIP {
			continue
		}
		ip, _, err := net.ParseCIDR(fmt.Sprintf("%s/32", addr.Address))
		if err != nil {
			continue
		}
		return &ip
	}
	return nil
}

func ConvertK8sPodToFortinetFirewallAddress(pod *v1.Pod) (fortilib.RespFortiGateFWAddressData, error) {
	ip := getPodInternalIP(pod)
	if ip == nil {
		return fortilib.RespFortiGateFWAddressData{}, errors.New("could not get IP address for pod")
	}
	faddr := fortilib.RespFortiGateFWAddressData{
		Name:    pod.GetObjectMeta().GetNamespace() + "-" + pod.GetObjectMeta().GetName(),
		Comment: TigeraComment,
		Type:    fortilib.FortiGateIpMaskType,
		SubType: fortilib.FortiGateSdnType,
		Subnet:  ip.String(),
	}
	return faddr, nil
}

func getPodInternalIP(pod *v1.Pod) *net.IP {

	podIp := pod.Status.PodIP
	if podIp != "" {
		log.WithField("ip", podIp).Debug("PodIP field filled in")
	} else {
		log.Info("Pod has no IP")
		return nil
	}

	ip, _, err := net.ParseCIDR(fmt.Sprintf("%s/32", podIp))
	if err != nil {
		return nil
	}
	return &ip
}
