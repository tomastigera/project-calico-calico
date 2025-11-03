// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package ut_test

import (
	"fmt"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/dnsresolver"
	"github.com/projectcalico/calico/felix/bpf/ipsets"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/ip"
)

func testDNSParser(t *testing.T, pinPath string, iptables bool) {
	// DNS response to archive.ubuntu.com with multiple A answers. The packet
	// was obtained using tcpdump.
	pktBytes := []byte{
		26, 97, 165, 211, 168, 175, 246, 111, 42, 69, 108, 168, 8, 0, 69, 0, 0,
		234, 220, 104, 64, 0, 125, 17, 79, 45, 10, 100, 0, 10, 192, 168, 6, 87,
		0, 53, 225, 200, 0, 214, 38, 108, 205, 111, 129, 128, 0, 1, 0, 5, 0, 0,
		0, 0, 7, 97, 114, 99, 104, 105, 118, 101, 6, 117, 98, 117, 110, 116,
		117, 3, 99, 111, 109, 0, 0, 1, 0, 1, 7, 97, 114, 99, 104, 105, 118, 101,
		6, 117, 98, 117, 110, 116, 117, 3, 99, 111, 109, 0, 0, 1, 0, 1, 0, 0, 0,
		25, 0, 4, 91, 189, 91, 83, 7, 97, 114, 99, 104, 105, 118, 101, 6, 117,
		98, 117, 110, 116, 117, 3, 99, 111, 109, 0, 0, 1, 0, 1, 0, 0, 0, 25, 0,
		4, 185, 125, 190, 36, 7, 97, 114, 99, 104, 105, 118, 101, 6, 117, 98,
		117, 110, 116, 117, 3, 99, 111, 109, 0, 0, 1, 0, 1, 0, 0, 0, 25, 0, 4,
		91, 189, 91, 82, 7, 97, 114, 99, 104, 105, 118, 101, 6, 117, 98, 117,
		110, 116, 117, 3, 99, 111, 109, 0, 0, 1, 0, 1, 0, 0, 0, 25, 0, 4, 185,
		125, 190, 39, 7, 97, 114, 99, 104, 105, 118, 101, 6, 117, 98, 117, 110,
		116, 117, 3, 99, 111, 109, 0, 0, 1, 0, 1, 0, 0, 0, 25, 0, 4, 91, 189,
		91, 81,
	}

	ids := map[string]uint64{
		"1":    1,
		"2":    2,
		"3":    3,
		"123":  123,
		"1234": 1234,
		"666":  666,
	}

	tracker, err := dnsresolver.NewDomainTracker(4, func(s string) uint64 {
		return ids[s]
	})
	Expect(err).NotTo(HaveOccurred())
	defer tracker.Close()

	tracker.Add("ubuntu.com", "123")
	tracker.Add("*.ubuntu.com", "1234")
	tracker.Add("archive.ubuntu.com", "1", "2", "3")
	err = tracker.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())

	if !iptables {
		runBpfUnitTest(t, "dns_parser_test.c", func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

			pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
			fmt.Printf("pktR = %+v\n", pktR)

		})
	} else {
		res, err := bpftoolProgRun(pinPath, pktBytes, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(1))

	}

	for _, setID := range []uint64{1, 2, 3, 1234} {
		_, err := ipsMap.Get(
			ipsets.MakeBPFIPSetEntry(setID, ip.CIDRFromStringNoErr("91.189.91.81/32").(ip.V4CIDR), 0, 0).AsBytes())
		Expect(err).NotTo(HaveOccurred())
		_, err = ipsMap.Get(
			ipsets.MakeBPFIPSetEntry(setID, ip.CIDRFromStringNoErr("91.189.91.82/32").(ip.V4CIDR), 0, 0).AsBytes())
		Expect(err).NotTo(HaveOccurred())
		_, err = ipsMap.Get(
			ipsets.MakeBPFIPSetEntry(setID, ip.CIDRFromStringNoErr("91.189.91.83/32").(ip.V4CIDR), 0, 0).AsBytes())
		Expect(err).NotTo(HaveOccurred())
		_, err = ipsMap.Get(
			ipsets.MakeBPFIPSetEntry(setID, ip.CIDRFromStringNoErr("185.125.190.36/32").(ip.V4CIDR), 0, 0).AsBytes())
		Expect(err).NotTo(HaveOccurred())
		_, err = ipsMap.Get(
			ipsets.MakeBPFIPSetEntry(setID, ip.CIDRFromStringNoErr("185.125.190.39/32").(ip.V4CIDR), 0, 0).AsBytes())
		Expect(err).NotTo(HaveOccurred())
	}

	// DNS response to zpravy.idnes.cz with CNAME and A answer. The packet was
	// obtained using tcpdump.
	pktBytes = []byte{
		26, 97, 165, 211, 168, 175, 246, 111, 42, 69, 108, 168, 8, 0, 69, 0, 0,
		130, 84, 86, 64, 0, 125, 17, 215, 167, 10, 100, 0, 10, 192, 168, 6, 87,
		0, 53, 207, 225, 0, 110, 61, 11, 191, 48, 129, 128, 0, 1, 0, 2, 0, 0, 0,
		0, 6, 122, 112, 114, 97, 118, 121, 5, 105, 100, 110, 101, 115, 2, 99,
		122, 0, 0, 1, 0, 1, 6, 122, 112, 114, 97, 118, 121, 5, 105, 100, 110,
		101, 115, 2, 99, 122, 0, 0, 5, 0, 1, 0, 0, 0, 30, 0, 14, 3, 99, 49, 52,
		5, 105, 100, 110, 101, 115, 2, 99, 122, 0, 3, 99, 49, 52, 5, 105, 100,
		110, 101, 115, 2, 99, 122, 0, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 185, 17,
		117, 45}

	tracker.Add("*.idnes.cz", "666", "3")
	_ = tracker.ApplyAllChanges()

	if !iptables {
		runBpfUnitTest(t, "dns_parser_test.c", func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

			pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
			fmt.Printf("pktR = %+v\n", pktR)

		})
	} else {
		res, err := bpftoolProgRun(pinPath, pktBytes, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(1))
	}

	err = ipsMap.Iter(func(k, v []byte) maps.IteratorAction {
		fmt.Println(ipsets.IPSetEntryFromBytes(k))
		return maps.IterNone
	})
	Expect(err).NotTo(HaveOccurred())

	_, err = ipsMap.Get(
		ipsets.MakeBPFIPSetEntry(3, ip.CIDRFromStringNoErr("185.17.117.45/32").(ip.V4CIDR), 0, 0).AsBytes())
	Expect(err).NotTo(HaveOccurred())
	_, err = ipsMap.Get(
		ipsets.MakeBPFIPSetEntry(666, ip.CIDRFromStringNoErr("185.17.117.45/32").(ip.V4CIDR), 0, 0).AsBytes())
	Expect(err).NotTo(HaveOccurred())
}

func TestDNSParser(t *testing.T) {
	RegisterTestingT(t)
	testDNSParser(t, "", false)
}

func TestDNSParserMicrosoftFV(t *testing.T) {
	RegisterTestingT(t)

	// DNS response to microsoft.com from 8.8.8.8 (from FV tests)
	pktBytes := []byte{2, 66, 172, 18, 0, 4, 2, 66, 125, 90, 149, 238, 8, 0, 69,
		0, 0, 150, 89, 187, 0, 0, 59, 17, 105, 118, 8, 8, 8, 8, 172, 18, 0, 4, 0,
		53, 22, 23, 0, 130, 27, 57, 166, 145, 129, 128, 0, 1, 0, 5, 0, 0, 0, 1, 9,
		109, 105, 99, 114, 111, 115, 111, 102, 116, 3, 99, 111, 109, 0, 0, 1, 0, 1,
		192, 12, 0, 1, 0, 1, 0, 0, 2, 32, 0, 4, 20, 112, 250, 133, 192, 12, 0, 1, 0,
		1, 0, 0, 2, 32, 0, 4, 20, 231, 239, 246, 192, 12, 0, 1, 0, 1, 0, 0, 2, 32,
		0, 4, 20, 76, 201, 171, 192, 12, 0, 1, 0, 1, 0, 0, 2, 32, 0, 4, 20, 70, 246,
		20, 192, 12, 0, 1, 0, 1, 0, 0, 2, 32, 0, 4, 20, 236, 44, 162, 0, 0, 41, 2,
		0, 0, 0, 0, 0, 0, 0}

	ids := map[string]uint64{
		"545": 545,
	}

	tracker, err := dnsresolver.NewDomainTracker(4, func(s string) uint64 {
		return ids[s]
	})
	Expect(err).NotTo(HaveOccurred())
	defer tracker.Close()

	tracker.Add("microsoft.com", "545")
	err = tracker.ApplyAllChanges()
	Expect(err).NotTo(HaveOccurred())

	runBpfUnitTest(t, "dns_parser_test.c", func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
	})

	setID := uint64(545)

	_, err = ipsMap.Get(
		ipsets.MakeBPFIPSetEntry(setID, ip.CIDRFromStringNoErr("20.112.250.133/32").(ip.V4CIDR), 0, 0).AsBytes())
	Expect(err).NotTo(HaveOccurred())
	_, err = ipsMap.Get(
		ipsets.MakeBPFIPSetEntry(setID, ip.CIDRFromStringNoErr("20.231.239.246/32").(ip.V4CIDR), 0, 0).AsBytes())
	Expect(err).NotTo(HaveOccurred())
	_, err = ipsMap.Get(
		ipsets.MakeBPFIPSetEntry(setID, ip.CIDRFromStringNoErr("20.76.201.171/32").(ip.V4CIDR), 0, 0).AsBytes())
	Expect(err).NotTo(HaveOccurred())
	_, err = ipsMap.Get(
		ipsets.MakeBPFIPSetEntry(setID, ip.CIDRFromStringNoErr("20.70.246.20/32").(ip.V4CIDR), 0, 0).AsBytes())
	Expect(err).NotTo(HaveOccurred())
	_, err = ipsMap.Get(
		ipsets.MakeBPFIPSetEntry(setID, ip.CIDRFromStringNoErr("20.236.44.162/32").(ip.V4CIDR), 0, 0).AsBytes())
	Expect(err).NotTo(HaveOccurred())
}
