//go:build !windows

// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package dnsresolver

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf/maps"
)

const (
	DNSPfxKeySize   = 256 + 4
	DNSPfxValueSize = 8
)

var DNSPfxMapParams = maps.MapParameters{
	Type:       "lpm_trie",
	KeySize:    DNSPfxKeySize,
	ValueSize:  DNSPfxValueSize,
	MaxEntries: 64 * 1024,
	Name:       "cali_dns_pfx",
	Flags:      unix.BPF_F_NO_PREALLOC,
	Version:    2,
}

var DNSPfxMapParamsV6 = maps.MapParameters{
	Type:       "lpm_trie",
	KeySize:    DNSPfxKeySize,
	ValueSize:  DNSPfxValueSize,
	MaxEntries: 64 * 1024,
	Name:       "cali_dns_pfx6",
	Flags:      unix.BPF_F_NO_PREALLOC,
	Version:    2,
}

func DNSPrefixMap() maps.Map {
	return maps.NewPinnedMap(DNSPfxMapParams)
}

func DNSPrefixMapV6() maps.Map {
	return maps.NewPinnedMap(DNSPfxMapParamsV6)
}

const (
	DNSSetKeySize   = 8 + 8
	DNSSetValueSize = 4
)

var DNSSetMapParams = maps.MapParameters{
	Type:       "hash",
	KeySize:    DNSSetKeySize,
	ValueSize:  DNSSetValueSize,
	MaxEntries: 64 * 1024,
	Name:       "cali_dns_sets",
	Flags:      unix.BPF_F_NO_PREALLOC,
	Version:    2,
}

var DNSSetMapParamsV6 = maps.MapParameters{
	Type:       "hash",
	KeySize:    DNSSetKeySize,
	ValueSize:  DNSSetValueSize,
	MaxEntries: 64 * 1024,
	Name:       "cali_dns_sets6",
	Flags:      unix.BPF_F_NO_PREALLOC,
	Version:    2,
}

func DNSSetMap() maps.Map {
	return maps.NewPinnedMap(DNSSetMapParams)
}

func DNSSetMapV6() maps.Map {
	return maps.NewPinnedMap(DNSSetMapParamsV6)
}

type DNSPfxKey [DNSPfxKeySize]byte

func DNSPfxKeyFromBytes(b []byte) DNSPfxKey {
	var k DNSPfxKey
	copy(k[:], b)
	return k
}

func (k DNSPfxKey) AsBytes() []byte {
	return k[:]
}

func (k DNSPfxKey) PrefixLen() uint32 {
	return binary.LittleEndian.Uint32(k[:4]) / 8
}

func (k DNSPfxKey) Domain() string {
	l := int(binary.LittleEndian.Uint32(k[0:4]))
	l /= 8
	r := make([]byte, l)
	for i, b := range k[4 : 4+l] {
		r[l-i-1] = b
	}

	if len(r) > 0 && r[0] == '.' {
		r = append([]byte{'*'}, r...)
	}

	return string(r)
}

func (k DNSPfxKey) LPMDomain() []byte {
	l := int(binary.LittleEndian.Uint32(k[0:4]))
	l /= 8
	return k[4 : 4+l]
}

func (k DNSPfxKey) String() string {
	return fmt.Sprintf("prefix %d key \"%s\"", k.PrefixLen(), k.Domain())
}

func NewPfxKey(domain string) DNSPfxKey {
	var k DNSPfxKey

	prefixlen := 0

	if domain != "" {
		if domain[0] == '*' {
			domain = domain[1:]
		}
		prefixlen = len(domain) * 8
	}

	binary.LittleEndian.PutUint32(k[:4], uint32(prefixlen))

	bytes := []byte(domain)

	for i, b := range bytes {
		k[4+len(bytes)-i-1] = b
	}

	return k
}

type DNSPfxValue uint64

func DNSPfxValueFromBytes(b []byte) DNSPfxValue {
	return DNSPfxValue(binary.BigEndian.Uint64(b[:8]))
}

func (v DNSPfxValue) AsBytes() []byte {
	var b [8]byte

	binary.BigEndian.PutUint64(b[:8], uint64(v))

	return b[:]
}

func NewPfxValue(v uint64) DNSPfxValue {
	return DNSPfxValue(v)
}

type PfxMapMem map[DNSPfxKey]DNSPfxValue

func PfxMapMemIter(m PfxMapMem) func(k, v []byte) {
	ks := len(DNSPfxKey{})

	return func(k, v []byte) {
		var key DNSPfxKey
		copy(key[:ks], k[:ks])

		val := DNSPfxValueFromBytes(v)

		m[key] = val
	}
}

type DNSSetKey [DNSSetKeySize]byte
type DNSSetValue [DNSSetValueSize]byte

func NewDNSSetKey(ipset, domainID uint64) DNSSetKey {
	var k DNSSetKey

	binary.BigEndian.PutUint64(k[:8], ipset)
	binary.BigEndian.PutUint64(k[8:16], domainID)

	return k
}

func DNSSetKeyFromBytes(b []byte) DNSSetKey {
	var key DNSSetKey
	copy(key[:DNSSetKeySize], key[:DNSSetKeySize])

	return key
}

func (k DNSSetKey) IPSet() uint64 {
	return binary.BigEndian.Uint64(k[:8])
}

func (k DNSSetKey) DomainID() uint64 {
	return binary.BigEndian.Uint64(k[8:16])
}

func (k DNSSetKey) AsBytes() []byte {
	return k[:]
}

func (v DNSSetValue) AsBytes() []byte {
	var b [DNSSetValueSize]byte
	return b[:]
}

func DNSSetValueFromBytes(b []byte) DNSSetValue {
	var v DNSSetValue
	return v
}

var DNSSetValueVoid = [4]byte{0, 0, 0, 0}
