// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.

package main

import (
	"encoding/json"
	"net"

	"github.com/docopt/docopt-go"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/fv/dns"
)

const usage = `dns-server: create a dummy dns server that responds with pre-programmed ips for domains.

Usage:
  dns-server <port> <records>

Records is a json compact json string of the form '{"domainName": [{"ip": "123.123.123.123", "ttl": 1}]}'
`

func main() {
	arguments, err := docopt.ParseDoc(usage)
	if err != nil {
		println(usage)
		log.WithError(err).Fatal("failed to parse usage")
	}

	recordsStr, _ := arguments.String("<records>")
	port, _ := arguments.Int("<port>")

	records := map[string][]dns.RecordIP{}
	if err := json.Unmarshal([]byte(recordsStr), &records); err != nil {
		log.WithError(err).Fatal("failed to unmarshal records")
	}

	addr := net.UDPAddr{
		Port: port,
	}
	u, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.WithError(err).Fatal("failed to listen")
	}

	reqBytes := make([]byte, 1024)
	for {
		bytesRead, addr, err := u.ReadFrom(reqBytes)
		if err != nil {
			log.WithError(err).Fatal("failed to read the request")
		}

		clientAddr := addr

		packet := gopacket.NewPacket(reqBytes[:bytesRead], layers.LayerTypeDNS, gopacket.Default)
		dnsPacket := packet.Layer(layers.LayerTypeDNS)

		tcp, _ := dnsPacket.(*layers.DNS)

		sendDNSResponse(u, clientAddr, tcp, records)
	}
}

func sendDNSResponse(u *net.UDPConn, clientAddr net.Addr, request *layers.DNS, records map[string][]dns.RecordIP) {
	var err error

	response := request

	for _, question := range request.Questions {
		if ips, ok := records[string(question.Name)]; ok {
			for _, ip := range ips {
				a, _, _ := net.ParseCIDR(ip.IP + "/24")
				dnsAnswer := layers.DNSResourceRecord{
					Type:  layers.DNSTypeA,
					Name:  question.Name,
					IP:    a,
					TTL:   ip.TTL,
					Class: layers.DNSClassIN,
				}

				response.Answers = append(response.Answers, dnsAnswer)
			}
		}
	}

	response.QR = true
	response.ANCount = uint16(len(response.Answers))
	response.OpCode = layers.DNSOpCodeQuery
	response.AA = true
	response.ResponseCode = layers.DNSResponseCodeNoErr

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}

	err = response.SerializeTo(buf, opts)
	if err != nil {
		log.WithError(err).Fatal("failed to serialize the response")
	}

	if _, err := u.WriteTo(buf.Bytes(), clientAddr); err != nil {
		log.WithError(err).Fatal("failed to write the response")
	}
}
