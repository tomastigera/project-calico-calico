// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.

package dnslog

import (
	"net"

	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

var _ = Describe("DNS log utility functions", func() {
	Describe("canonicalizeDNSName", func() {
		Context("noop", func() {
			It("returns the input string", func() {
				in := "tigera.io"
				Expect(canonicalizeDNSName([]byte(in))).Should(Equal(in))
			})
		})
		Context("remove superfluous dots", func() {
			It("strips the dots from the left and right", func() {
				Expect(canonicalizeDNSName([]byte(".tigera.io."))).Should(Equal("tigera.io"))
			})
			It("removes extra dots", func() {
				Expect(canonicalizeDNSName([]byte("..tigera..io.."))).Should(Equal("tigera.io"))
			})
		})
		Context("normalizes characters", func() {
			It("corrects case", func() {
				Expect(canonicalizeDNSName([]byte("tIgeRa.Io"))).Should(Equal("tigera.io"))
			})
		})
	})

	Describe("getRRDecoded", func() {
		It("returns a net.IP for A", func() {
			decoded := net.ParseIP("127.0.0.1")
			v := getRRDecoded(layers.DNSResourceRecord{Type: layers.DNSTypeA, IP: decoded})
			Expect(v).Should(BeAssignableToTypeOf(net.IP{}))
			Expect(v).Should(Equal(decoded))
		})
		It("returns a net.IP for AAAA", func() {
			decoded := net.ParseIP("::1")
			v := getRRDecoded(layers.DNSResourceRecord{Type: layers.DNSTypeAAAA, IP: decoded})
			Expect(v).Should(BeAssignableToTypeOf(net.IP{}))
			Expect(v).Should(Equal(decoded))
		})
		It("returns a string for NS", func() {
			decoded := []byte("tigera.io")
			v := getRRDecoded(layers.DNSResourceRecord{Type: layers.DNSTypeNS, NS: decoded})
			Expect(v).Should(BeAssignableToTypeOf(""))
			Expect(v).Should(Equal(string(decoded)))
		})
		It("returns a string for CNAME", func() {
			decoded := []byte("tigera.io")
			v := getRRDecoded(layers.DNSResourceRecord{Type: layers.DNSTypeCNAME, CNAME: decoded})
			Expect(v).Should(BeAssignableToTypeOf(""))
			Expect(v).Should(Equal(string(decoded)))
		})
		It("returns a layers.DNSSOA for SOA", func() {
			decoded := layers.DNSSOA{
				MName: []byte("tigera.io."),
			}
			v := getRRDecoded(layers.DNSResourceRecord{Type: layers.DNSTypeSOA, SOA: decoded})
			Expect(v).Should(BeAssignableToTypeOf(layers.DNSSOA{}))
			Expect(v).Should(Equal(decoded))
		})
		It("returns a string for PTR", func() {
			decoded := []byte("tigera.io")
			v := getRRDecoded(layers.DNSResourceRecord{Type: layers.DNSTypePTR, PTR: decoded})
			Expect(v).Should(BeAssignableToTypeOf(""))
			Expect(v).Should(Equal(string(decoded)))
		})
		It("returns a layers.DNSMX for MX", func() {
			decoded := layers.DNSMX{
				Preference: 10,
			}
			v := getRRDecoded(layers.DNSResourceRecord{Type: layers.DNSTypeMX, MX: decoded})
			Expect(v).Should(BeAssignableToTypeOf(layers.DNSMX{}))
			Expect(v).Should(Equal(decoded))
		})
		It("returns a [][]byte for TXT", func() {
			decoded := [][]byte{[]byte("tigera."), []byte("io")}
			v := getRRDecoded(layers.DNSResourceRecord{Type: layers.DNSTypeTXT, TXTs: decoded})
			Expect(v).Should(BeAssignableToTypeOf([][]byte{}))
			Expect(v).Should(Equal(decoded))
		})
		It("returns a layers.DNSSRV for SRV", func() {
			decoded := layers.DNSSRV{
				Priority: 10,
			}
			v := getRRDecoded(layers.DNSResourceRecord{Type: layers.DNSTypeSRV, SRV: decoded})
			Expect(v).Should(BeAssignableToTypeOf(layers.DNSSRV{}))
			Expect(v).Should(Equal(decoded))
		})
		It("returns a layers.RRSIG for RRSIG", func() {
			decoded := layers.DNSRRSIG{
				TypeCovered: layers.DNSTypeA,
			}
			v := getRRDecoded(layers.DNSResourceRecord{Type: layers.DNSTypeRRSIG, RRSIG: decoded})
			Expect(v).Should(BeAssignableToTypeOf(layers.DNSRRSIG{}))
			Expect(v).Should(Equal(decoded))
		})
		It("returns a layers.DNSKEY for DNSKEY", func() {
			decoded := layers.DNSKEY{
				Flags: layers.DNSKEYFlagZoneKey,
			}
			v := getRRDecoded(layers.DNSResourceRecord{Type: layers.DNSTypeDNSKEY, DNSKEY: decoded})
			Expect(v).Should(BeAssignableToTypeOf(layers.DNSKEY{}))
			Expect(v).Should(Equal(decoded))
		})
		It("returns a layers.SVCB for SVCB", func() {
			decoded := layers.DNSSVCB{
				Priority: 1,
			}
			v := getRRDecoded(layers.DNSResourceRecord{Type: layers.DNSTypeSVCB, SVCB: decoded})
			Expect(v).Should(BeAssignableToTypeOf(layers.DNSSVCB{}))
			Expect(v).Should(Equal(decoded))
		})
		It("returns a layers.DNSURI for URI", func() {
			decoded := layers.DNSURI{
				Priority: 1,
			}
			v := getRRDecoded(layers.DNSResourceRecord{Type: layers.DNSTypeURI, URI: decoded})
			Expect(v).Should(BeAssignableToTypeOf(layers.DNSURI{}))
			Expect(v).Should(Equal(decoded))
		})
		It("returns a []byte for unknown", func() {
			raw := []byte("raw")
			v := getRRDecoded(layers.DNSResourceRecord{Type: 0, Data: raw})
			Expect(v).Should(BeAssignableToTypeOf([]byte{}))
			Expect(v).Should(Equal(raw))
		})
	})
})

var _ = Describe("gopacket to DNS log conversion function", func() {
	Describe("newMetaSpecFromUpdate", func() {
		var clientEP, serverEP calc.EndpointData
		var clientIP, serverIP net.IP
		BeforeEach(func() {
			clientEP = &calc.RemoteEndpointData{CommonEndpointData: calc.CalculateCommonEndpointData(model.HostEndpointKey{}, &model.HostEndpoint{})}
			serverEP = &calc.RemoteEndpointData{CommonEndpointData: calc.CalculateCommonEndpointData(model.HostEndpointKey{}, &model.HostEndpoint{})}
			clientIP = net.ParseIP("1.2.3.4")
			serverIP = net.ParseIP("8.8.8.8")
		})

		It("returns an error with no questions", func() {
			_, _, err := newMetaSpecFromUpdate(Update{ClientIP: clientIP, ServerIP: serverIP, ClientEP: clientEP, ServerEP: serverEP, DNS: &layers.DNS{}}, DNSDefault)
			Expect(err).Should(HaveOccurred())
		})

		It("all works together", func() {
			meta, spec, err := newMetaSpecFromUpdate(Update{ClientIP: clientIP, ServerIP: serverIP, ClientEP: clientEP, ServerEP: serverEP, DNS: &layers.DNS{
				Questions: []layers.DNSQuestion{{Name: []byte("tigera.io.")}},
				Answers: []layers.DNSResourceRecord{
					{Name: []byte("tigera.io."), Class: layers.DNSClassIN, Type: layers.DNSTypeA},
				},
			}}, DNSDefault)

			Expect(err).ShouldNot(HaveOccurred())
			Expect(meta.Question.Name).Should(Equal("tigera.io"))
			Expect(spec.Count).Should(BeNumerically("==", 1))
			Expect(meta.RRSetsString).Should(Equal(spec.RRSets.String()))
			Expect(meta.ClientMeta.IP).To(Equal("1.2.3.4"))
		})
	})

	Describe("newDNSSpecFromGoPacket", func() {
		var clientLabels, serverLabels DNSLabels
		var serverEM EndpointMetadataWithIP

		It("sets count to 1", func() {
			spec := newDNSSpecFromGoPacket(clientLabels, serverEM, serverLabels, &layers.DNS{}, nil)
			Expect(spec.Count).Should(BeNumerically("==", 1))
		})

		It("includes all RRs", func() {
			spec := newDNSSpecFromGoPacket(clientLabels, serverEM, serverLabels, &layers.DNS{
				Answers: []layers.DNSResourceRecord{
					{Name: []byte("www1.tigera.io."), Class: layers.DNSClassIN, Type: layers.DNSTypeA, Data: []byte("2"), IP: net.ParseIP("127.0.0.1")},
					{Name: []byte("www1.tigera.io."), Class: layers.DNSClassIN, Type: layers.DNSTypeA, Data: []byte("1"), IP: net.ParseIP("127.0.0.2")},
					{Name: []byte("www1.tigera.io."), Class: layers.DNSClassIN, Type: layers.DNSTypeA, Data: []byte("3"), IP: net.ParseIP("127.0.0.3")},
				},
				Additionals: []layers.DNSResourceRecord{
					{Name: []byte("www.tigera.io."), Class: layers.DNSClassIN, Type: layers.DNSTypeCNAME, Data: []byte("4"), CNAME: []byte("www1.tigera.io.")},
				},
				Authorities: []layers.DNSResourceRecord{
					{Name: []byte("tigera.io."), Class: layers.DNSClassIN, Type: layers.DNSTypeNS, Data: []byte("6"), NS: []byte("ns1.tigera.io.")},
					{Name: []byte("tigera.io."), Class: layers.DNSClassIN, Type: layers.DNSTypeNS, Data: []byte("5"), NS: []byte("ns2.tigera.io.")},
				},
			},
				nil)

			expected := v1.DNSRRSets{
				{Name: "www1.tigera.io", Class: v1.DNSClass(layers.DNSClassIN), Type: v1.DNSType(layers.DNSTypeA)}: {
					{Raw: []byte("1"), Decoded: net.ParseIP("127.0.0.2")},
					{Raw: []byte("2"), Decoded: net.ParseIP("127.0.0.1")},
					{Raw: []byte("3"), Decoded: net.ParseIP("127.0.0.3")},
				},
				{Name: "www.tigera.io", Class: v1.DNSClass(layers.DNSClassIN), Type: v1.DNSType(layers.DNSTypeCNAME)}: {
					{Raw: []byte("4"), Decoded: "www1.tigera.io."},
				},
				{Name: "tigera.io", Class: v1.DNSClass(layers.DNSClassIN), Type: v1.DNSType(layers.DNSTypeNS)}: {
					{Raw: []byte("5"), Decoded: "ns2.tigera.io."},
					{Raw: []byte("6"), Decoded: "ns1.tigera.io."},
				},
			}
			Expect(spec.RRSets).Should(Equal(expected))
		})

		It("initializes servers", func() {
			spec := newDNSSpecFromGoPacket(clientLabels, serverEM, serverLabels, &layers.DNS{}, nil)
			Expect(spec.Servers).ShouldNot(BeNil())
		})
	})

	Describe("newDNSMetaFromSpecAndGoPacket", func() {
		var serverEM EndpointMetadataWithIP

		It("fills in the question", func() {
			meta := newDNSMetaFromSpecAndGoPacket(serverEM, &layers.DNS{
				Questions: []layers.DNSQuestion{
					{Name: []byte("tigera.io."), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
				},
			}, DNSSpec{})

			Expect(meta.Question).Should(Equal(v1.DNSName{
				Name:  "tigera.io",
				Class: v1.DNSClass(layers.DNSClassIN),
				Type:  v1.DNSType(layers.DNSTypeA),
			}))
		})

		It("sets the rcode", func() {
			meta := newDNSMetaFromSpecAndGoPacket(serverEM, &layers.DNS{
				ResponseCode: layers.DNSResponseCodeNXDomain,
				Questions:    []layers.DNSQuestion{{}},
			}, DNSSpec{})

			Expect(meta.ResponseCode).Should(BeNumerically("==", layers.DNSResponseCodeNXDomain))
		})

		It("sets the rrset string", func() {
			spec := DNSSpec{
				RRSets: v1.DNSRRSets{
					{
						Name:  "tigera.io",
						Class: v1.DNSClass(layers.DNSClassIN),
						Type:  v1.DNSType(layers.DNSTypeA),
					}: {
						{Decoded: "127.0.0.1"},
					},
				},
			}

			meta := newDNSMetaFromSpecAndGoPacket(serverEM, &layers.DNS{
				Questions: []layers.DNSQuestion{{}},
			}, spec)

			Expect(meta.RRSetsString).Should(Equal(spec.RRSets.String()))
		})
	})

	Describe("newDNSNameRDataFromGoPacketRR", func() {
		It("returns name as expected", func() {
			name, _ := newDNSNameRDataFromGoPacketRR(layers.DNSResourceRecord{
				Name:  []byte("tigeRa.Io.."),
				Class: layers.DNSClassIN,
				Type:  layers.DNSTypeA,
			})

			Expect(name).Should(Equal(v1.DNSName{
				Name:  "tigera.io",
				Class: v1.DNSClass(layers.DNSClassIN),
				Type:  v1.DNSType(layers.DNSTypeA),
			}))
		})

		It("returns rdata as expected", func() {
			raw := []byte("1234")
			decoded := net.ParseIP("127.0.0.1")

			_, rdata := newDNSNameRDataFromGoPacketRR(layers.DNSResourceRecord{
				Type: layers.DNSTypeA,
				Data: raw,
				IP:   decoded,
			})

			Expect(rdata).Should(Equal(v1.DNSRData{
				Raw:     raw,
				Decoded: decoded,
			}))
		})
	})
})
