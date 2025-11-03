// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package testutils

import (
	"net"

	"github.com/gopacket/gopacket/layers"
)

func MakeQ(name string) layers.DNSQuestion {
	return layers.DNSQuestion{
		Name:  []byte(name),
		Type:  layers.DNSTypeA,
		Class: layers.DNSClassIN,
	}
}

func MakeA(name, ip string) layers.DNSResourceRecord {
	return layers.DNSResourceRecord{
		Name:       []byte(name),
		Type:       layers.DNSTypeA,
		Class:      layers.DNSClassIN,
		TTL:        0,
		DataLength: 4,
		Data:       []byte(ip),
		IP:         net.ParseIP(ip),
	}
}

func MakeAAAA(name, ip string) layers.DNSResourceRecord {
	return layers.DNSResourceRecord{
		Name:       []byte(name),
		Type:       layers.DNSTypeAAAA,
		Class:      layers.DNSClassIN,
		TTL:        0,
		DataLength: 16,
		Data:       []byte(ip),
		IP:         net.ParseIP(ip),
	}
}

func MakeCNAME(name, rname string) layers.DNSResourceRecord {
	return layers.DNSResourceRecord{
		Name:       []byte(name),
		Type:       layers.DNSTypeCNAME,
		Class:      layers.DNSClassIN,
		TTL:        1,
		DataLength: 4,
		IP:         nil,
		CNAME:      []byte(rname),
	}
}
