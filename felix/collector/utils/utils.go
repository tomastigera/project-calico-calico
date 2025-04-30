// Copyright (c) 2018-2023 Tigera, Inc. All rights reserved.

package utils

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/lib/std/uniquestr"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	net2 "github.com/projectcalico/calico/libcalico-go/lib/net"
)

const (
	UnknownEndpoint  = "<unknown>"
	FieldNotIncluded = "-"
)

func IpStrTo16Byte(ipStr string) [16]byte {
	addr := net.ParseIP(ipStr)
	return IpTo16Byte(addr)
}

func IpTo16Byte(addr net.IP) [16]byte {
	var addrB [16]byte
	copy(addrB[:], addr.To16()[:16])
	return addrB
}

// endpointName is a convenience function to return a printable name for an endpoint.
func EndpointName(key model.Key) (name string) {
	switch k := key.(type) {
	case model.WorkloadEndpointKey:
		name = workloadEndpointName(k)
	case model.HostEndpointKey:
		name = hostEndpointName(k)
	}
	return
}

func workloadEndpointName(wep model.WorkloadEndpointKey) string {
	return "WEP(" + wep.Hostname + "/" + wep.OrchestratorID + "/" + wep.WorkloadID + "/" + wep.EndpointID + ")"
}

func hostEndpointName(hep model.HostEndpointKey) string {
	return "HEP(" + hep.Hostname + "/" + hep.EndpointID + ")"
}

func AddressAndPort(domain string) (string, int) {
	parts := strings.Split(domain, ":")
	if len(parts) == 1 {
		// There is no port specified
		return parts[0], 0
	}

	if len(parts) == 2 {
		// There is a port specified
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			log.WithError(err).Error("Failed to parse port from L7 domain field")
			return "", 0
		}
		return parts[0], port
	}

	// If the domain is weird and has multiple ":" characters, then return nothing.
	return "", 0
}

// Extracts the Kubernetes service name if the address matches a Kubernetes service.
func ExtractK8sServiceNameAndNamespace(addr string) (string, string) {
	// Kubernetes service names can be in the format: <name>.<namespace>.svc.<cluster-domain>.<local>
	if parts := strings.Split(addr, "."); len(parts) > 4 && parts[len(parts)-3] == "svc" {
		return strings.Join(parts[:len(parts)-4], "."), parts[len(parts)-4]
	}

	// Kubernetes service names can be in the format: <name>.svc.<cluster-domain>.<local>
	if parts := strings.Split(addr, "."); len(parts) > 3 && parts[len(parts)-3] == "svc" {
		return strings.Join(parts[:len(parts)-3], "."), ""
	}

	// Kubernetes service names can be in the format: <name>.<namespace>
	// Note that this check does not allow subdomains in the <name>
	if parts := strings.Split(addr, "."); len(parts) == 2 {
		return parts[0], parts[1]
	}

	// Not a valid Kubernetes service name
	return "", ""
}

func MustParseIP(s string) net2.IP {
	ip := net.ParseIP(s)
	return net2.IP{IP: ip}
}

func MustParseMac(m string) *net2.MAC {
	hwAddr, err := net.ParseMAC(m)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse MAC: %v; %v", m, err))
	}
	return &net2.MAC{HardwareAddr: hwAddr}
}

func MustParseNet(n string) net2.IPNet {
	_, cidr, err := net2.ParseCIDR(n)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse CIDR %v; %v", n, err))
	}
	return *cidr
}

func IntersectAndFilterLabels(in, out uniquelabels.Map) uniquelabels.Map {
	return uniquelabels.IntersectAndFilter(in, out, func(k uniquestr.Handle, _ uniquestr.Handle) bool {
		// Skip Calico labels from the logs
		return !strings.HasPrefix(k.Value(), "projectcalico.org/")
	})
}

// There is support for both global and namespaced networkset. In case of
// namespaced networkset, aggregatedName is namespace/name format. Extract
// namespace and name from it.
func ExtractNamespaceFromNetworkSet(aggregatedName string) (string, string) {
	res := strings.Split(aggregatedName, "/")
	if (len(res)) > 1 {
		return res[0], res[1]
	}
	return FieldNotIncluded, aggregatedName
}

func FlattenLabels(labels map[string]string) []string {
	respSlice := []string{}
	for k, v := range labels {
		l := fmt.Sprintf("%v=%v", k, v)
		respSlice = append(respSlice, l)
	}
	return respSlice
}

func UnflattenLabels(labelSlice []string) map[string]string {
	resp := map[string]string{}
	for _, label := range labelSlice {
		labelKV := strings.Split(label, "=")
		if len(labelKV) != 2 {
			continue
		}
		resp[labelKV[0]] = labelKV[1]
	}
	return resp
}

var protoNames = map[int]string{
	1:   "icmp",
	6:   "tcp",
	17:  "udp",
	4:   "ipip",
	50:  "esp",
	58:  "icmp6",
	132: "sctp",
}

func ProtoToString(p int) string {
	s, ok := protoNames[p]
	if ok {
		return s
	}
	return strconv.Itoa(p)
}

func StringToProto(s string) int {
	for i, st := range protoNames {
		if s == st {
			return i
		}
	}
	p, _ := strconv.Atoi(s)
	return p
}
