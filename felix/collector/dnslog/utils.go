// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.

package dnslog

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/gopacket/gopacket/layers"

	"github.com/projectcalico/calico/felix/collector/types/endpoint"
	"github.com/projectcalico/calico/felix/collector/utils"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

func newMetaSpecFromUpdate(update Update, kind AggregationKind) (DNSMeta, DNSSpec, error) {
	if len(update.DNS.Questions) == 0 {
		return DNSMeta{}, DNSSpec{}, errors.New("no questions in DNS packet")
	}

	clientEM, err := endpoint.GetMetadata(update.ClientEP, utils.IpTo16Byte(update.ClientIP))
	if err != nil {
		return DNSMeta{}, DNSSpec{}, fmt.Errorf("could not extract metadata for client %v: %v", update.ClientEP, err)
	}
	clientLabels := endpoint.GetLabels(update.ClientEP)

	serverEM, err := endpoint.GetMetadata(update.ServerEP, utils.IpTo16Byte(update.ServerIP))
	if err != nil {
		return DNSMeta{}, DNSSpec{}, fmt.Errorf("could not extract metadata for server %v: %v", update.ServerEP, err)
	}
	serverLabels := endpoint.GetLabels(update.ServerEP)

	serverEP := v1.Endpoint{
		Type:           v1.EndpointType(serverEM.Type),
		Name:           serverEM.Name,
		AggregatedName: serverEM.AggregatedName,
		Namespace:      serverEM.Namespace,
	}
	clientEP := v1.Endpoint{
		Type:           v1.EndpointType(clientEM.Type),
		Name:           clientEM.Name,
		AggregatedName: clientEM.AggregatedName,
		Namespace:      clientEM.Namespace,
	}

	spec := newDNSSpecFromGoPacket(clientLabels, EndpointMetadataWithIP{serverEP, update.ServerIP.String()}, serverLabels, update.DNS, update.LatencyIfKnown)
	meta := newDNSMetaFromSpecAndGoPacket(aggregateEndpointMetadataWithIP(EndpointMetadataWithIP{clientEP, update.ClientIP.String()}, kind), update.DNS, spec)

	return meta, spec, nil
}

func aggregateEndpointMetadataWithIP(em EndpointMetadataWithIP, kind AggregationKind) EndpointMetadataWithIP {
	switch kind {
	case DNSPrefixNameAndIP:
		em.Name = utils.FieldNotIncluded
		em.IP = utils.FieldNotIncluded
	}
	return em
}

func newDNSSpecFromGoPacket(clientLabels DNSLabels, serverEM EndpointMetadataWithIP, serverLabels DNSLabels, dns *layers.DNS, latencyIfKnown *time.Duration) DNSSpec {
	spec := DNSSpec{
		RRSets:  make(v1.DNSRRSets),
		Servers: make(map[EndpointMetadataWithIP]DNSLabels),
		DNSStats: DNSStats{
			Count: 1,
		},
	}
	for _, rr := range append(append(dns.Answers, dns.Additionals...), dns.Authorities...) {
		spec.RRSets.Add(newDNSNameRDataFromGoPacketRR(rr))
	}
	spec.Servers[serverEM] = serverLabels
	spec.ClientLabels = clientLabels
	if latencyIfKnown != nil {
		spec.Latency.Count = 1
		spec.Latency.Max = *latencyIfKnown
		spec.Latency.Mean = *latencyIfKnown
	}
	return spec
}

func newDNSMetaFromSpecAndGoPacket(clientEM EndpointMetadataWithIP, dns *layers.DNS, spec DNSSpec) DNSMeta {
	return DNSMeta{
		ClientMeta: clientEM,
		Question: v1.DNSName{
			Name:  canonicalizeDNSName(dns.Questions[0].Name),
			Class: v1.DNSClass(dns.Questions[0].Class),
			Type:  v1.DNSType(dns.Questions[0].Type),
		},
		ResponseCode: v1.DNSResponseCode(dns.ResponseCode),
		RRSetsString: spec.RRSets.String(),
	}
}

func newDNSNameRDataFromGoPacketRR(rr layers.DNSResourceRecord) (v1.DNSName, v1.DNSRData) {
	name := v1.DNSName{
		Name:  canonicalizeDNSName(rr.Name),
		Class: v1.DNSClass(rr.Class),
		Type:  v1.DNSType(rr.Type),
	}
	rdata := v1.DNSRData{
		Raw:     rr.Data,
		Decoded: getRRDecoded(rr),
	}
	return name, rdata
}

func getRRDecoded(rr layers.DNSResourceRecord) any {
	switch rr.Type {
	case layers.DNSTypeA, layers.DNSTypeAAAA:
		return rr.IP
	case layers.DNSTypeNS:
		return string(rr.NS)
	case layers.DNSTypeCNAME:
		return string(rr.CNAME)
	case layers.DNSTypePTR:
		return string(rr.PTR)
	case layers.DNSTypeTXT:
		return rr.TXTs
	case layers.DNSTypeSOA:
		return rr.SOA
	case layers.DNSTypeSRV:
		return rr.SRV
	case layers.DNSTypeMX:
		return rr.MX
	case layers.DNSTypeDNSKEY:
		return rr.DNSKEY
	case layers.DNSTypeRRSIG:
		return rr.RRSIG
	case layers.DNSTypeSVCB:
		return rr.SVCB
	case layers.DNSTypeURI:
		return rr.URI
	default:
		return rr.Data
	}
}

func canonicalizeDNSName(name []byte) string {
	return regexp.MustCompile(`\.\.+`).ReplaceAllString(strings.ToLower(strings.Trim(string(name), ".")), ".")
}
