// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.

package types

import (
	"fmt"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
)

// RuleHit records how many times a rule was hit and how many bytes passed
// through.
type RuleHit struct {
	RuleID *calc.RuleID
	Hits   int
	Bytes  int
}

// PacketInfo is information about a packet we received from the dataplane
type PacketInfo struct {
	Tuple          tuple.Tuple
	PreDNATTuple   tuple.Tuple
	IsDNAT         bool
	Direction      rules.RuleDir
	RuleHits       []RuleHit
	InDeviceIndex  int
	OutDeviceIndex int
}

func (pkt PacketInfo) String() string {
	return fmt.Sprintf("Tuple: {%s}, PreDNATTuple: {%s}, IsDNAT: %t, Direction: %s, RuleHits: %+v",
		&pkt.Tuple, &pkt.PreDNATTuple, pkt.IsDNAT, pkt.Direction, pkt.RuleHits)
}

// PacketInfoReader is an interface for a reader that consumes information
// from dataplane and converts it to the format needed by collector.
type PacketInfoReader interface {
	Start() error
	PacketInfoChan() <-chan PacketInfo
}

// ConntrackCounters counters for ConntrackInfo
type ConntrackCounters struct {
	Packets int
	Bytes   int
}

func (c ConntrackCounters) String() string {
	return fmt.Sprintf("Packets: %d, Bytes :%d", c.Packets, c.Bytes)
}

// ConntrackInfo is information about a connection from the dataplane.
type ConntrackInfo struct {
	Tuple           tuple.Tuple
	PreDNATTuple    tuple.Tuple
	NatOutgoingPort int
	IsDNAT          bool
	Expired         bool
	Counters        ConntrackCounters
	ReplyCounters   ConntrackCounters
	IsProxy         bool
}

func (ct ConntrackInfo) String() string {
	return fmt.Sprintf("Tuple: {%s}, PreDNATTuple: {%s}, IsDNAT: %t, Expired: %t, Counters: {%s}, ReplyCounters {%s}",
		&ct.Tuple, &ct.PreDNATTuple, ct.IsDNAT, ct.Expired, ct.Counters, ct.ReplyCounters)
}

// ConntrackInfoReader is an interafce that provides information from conntrack.
type ConntrackInfoReader interface {
	Start() error
	ConntrackInfoChan() <-chan []ConntrackInfo
}

// ConntrackInfoBatchSize is a recommended batch size to be used by InfoReaders
const ConntrackInfoBatchSize = 1024

type TcpStatsData struct {
	SendCongestionWnd int
	SmoothRtt         int
	MinRtt            int
	Mss               int
	TotalRetrans      int
	LostOut           int
	UnrecoveredRTO    int
	IsDirty           bool
}

// ProcessData contains information about a process which includes its name, arguments and PID.
type ProcessData struct {
	Name      string
	Pid       int
	Arguments string
}

// TODO(doublek): Is this the right level of abstraction or should this be something for
// also pulling in things like socket stats? So a KprobeEventReader? But might not make
// sense for Windows?
// ProcessInfo is process information about a packet we received from BPF kprobes.
type ProcessInfo struct {
	Tuple        tuple.Tuple
	PreDNATTuple tuple.Tuple
	IsDNAT       bool

	ProcessData
	TcpStatsData
}

// ProcessInfoCache is an interface that provides process information.
type ProcessInfoCache interface {
	Start() error
	Stop()
	Lookup(tuple.Tuple, TrafficDirection) (ProcessInfo, bool)
	Update(tuple.Tuple, bool)
}

// EgressDomainCache interface used to perform reverse DNS queries.
type EgressDomainCache interface {
	IterWatchedDomainsForIP(clientIP string, ip [16]byte, cb func(domain string) (stop bool))
	GetTopLevelDomainsForIP(clientIP string, ip [16]byte) []string
}

// DataplaneInfoReader is an interface that provides information from the dataplane.
type DataplaneInfoReader interface {
	Start() error
	Stop()
	DataplaneInfoChan() <-chan *proto.ToDataplane
}
