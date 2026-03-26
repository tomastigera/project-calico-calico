// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

package events

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"unsafe"

	"github.com/pkg/errors"

	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/ringbuf"
	"github.com/projectcalico/calico/felix/bpf/state"
)

// Type defines the type of constants used for determining the type of an event.
type Type uint16

const (
	// TypeLostEvents is emitted by the BPF side when accumulated drop count
	// is flushed through the ring buffer.
	TypeLostEvents Type = 0
	// TypeProtoStats protocol v4 stats
	TypeProtoStats Type = 1
	// TypeDNSEvent reports information on DNS packets
	TypeDNSEvent Type = 2
	// TypePolicyVerdict is emitted when a policy program reaches a verdict
	TypePolicyVerdict Type = 3
	// TypeTcpStats reports L4 TCP socket information
	TypeTcpStats Type = 4
	// TypeProcessPath reports process exec path, arguments
	TypeProcessPath Type = 5
	// TypeDNSEventL3 is like TypeDNSEvent but from a L3 device - i.e. one whose packets begin
	// with the L3 header
	TypeDNSEventL3 Type = 6
	// TypePolicyVerdictV6 is emitted when a v6 policy program reaches a verdict
	TypePolicyVerdictV6 Type = 7

	// Address offsets (same for both IPv4 and IPv6)
	offsetSrcAddr        = 0
	offsetDstAddr        = 32
	offsetPostNATDstAddr = 48
	offsetNATTunSrcAddr  = 64

	// Connection info offsets
	offsetPolicyRC       = 84
	offsetSrcPort        = 88
	offsetDstPort        = 92
	offsetPostNATDstPort = 94
	offsetIPProto        = 96
	offsetIPSize         = 98
	offsetRulesHit       = 100
	offsetRuleIDs        = 104

	ruleIDSize           = 8
	conntrackBlockOffset = offsetRuleIDs + (state.MaxRuleIDs * ruleIDSize)

	// Conntrack device index offsets
	offsetOutDeviceIndex = conntrackBlockOffset + 28
	offsetInDeviceIndex  = conntrackBlockOffset + 32
)

func (t Type) String() string {
	return strconv.Itoa(int(t))
}

// Event represents the common denominator of all events
type Event struct {
	typ  Type
	data []byte
}

// Type returns the event type
func (e Event) Type() Type {
	return e.typ
}

// Data returns the data of the event as an unparsed byte string
func (e Event) Data() []byte {
	return e.data
}

// Source is where do we read the event from
type Source string

const (
	// SourceRingBuffer consumes events using the BPF ring buffer
	SourceRingBuffer Source = "ring-buffer"
)

type eventRaw interface {
	Data() []byte
}

// Events is an interface for consuming events
type Events interface {
	Next() (Event, error)
	Map() maps.Map
	Close() error
}

// New creates a new Events object to consume events.
func New(src Source, size int) (Events, error) {
	switch src {
	case SourceRingBuffer:
		return newRingBufferEvents(size)
	}

	return nil, fmt.Errorf("unknown events source: %s", src)
}

type ringBufferEventsReader struct {
	rb     *ringbuf.RingBuffer
	bpfMap maps.Map
}

func newRingBufferEvents(size int) (Events, error) {
	rbMap := ringbuf.Map("rb_evnt", size)
	if err := rbMap.EnsureExists(); err != nil {
		return nil, errors.Wrap(err, "failed to ensure ring buffer map exists")
	}

	dropsMap := ringbuf.DropsMap()
	if err := dropsMap.EnsureExists(); err != nil {
		return nil, errors.Wrap(err, "failed to ensure ring buffer drops map exists")
	}

	rb, err := ringbuf.New(rbMap, size)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create ring buffer reader")
	}

	return &ringBufferEventsReader{
		rb:     rb,
		bpfMap: rbMap,
	}, nil
}

func (r *ringBufferEventsReader) Next() (Event, error) {
	e, err := r.rb.Next()
	if err != nil {
		return Event{}, errors.WithMessage(err, "failed to get next event")
	}

	evt, err := parseEventData(e.Data())
	if err != nil {
		return Event{}, err
	}

	// The BPF side emits TYPE_LOST_EVENTS with a u64 count payload when
	// accumulated drops are flushed. Convert to ErrLostEvents so callers
	// (bpfEventPoller) handle it the same way as the old perf lost records.
	if evt.typ == TypeLostEvents {
		count := uint64(0)
		if len(evt.data) >= 8 {
			count = binary.LittleEndian.Uint64(evt.data[:8])
		}
		return Event{}, ErrLostEvents(count)
	}

	return evt, nil
}

func (r *ringBufferEventsReader) Close() error {
	return r.rb.Close()
}

func (r *ringBufferEventsReader) Map() maps.Map {
	return r.bpfMap
}

type eventHdr struct {
	Type uint32
	Len  uint32
}

func parseEventData(data []byte) (Event, error) {
	var hdr eventHdr
	hdrBytes := (*[unsafe.Sizeof(eventHdr{})]byte)((unsafe.Pointer)(&hdr))
	consumed := copy(hdrBytes[:], data)
	l := len(data)
	if int(hdr.Len) > l {
		return Event{}, fmt.Errorf("mismatched length %d vs data length %d", hdr.Len, l)
	}
	return Event{
		typ:  Type(hdr.Type),
		data: data[consumed:hdr.Len],
	}, nil
}

// ParseEvent reads the event header and returns a typed Event.
func ParseEvent(raw eventRaw) (Event, error) {
	return parseEventData(raw.Data())
}

// ErrLostEvents reports how many events were lost (dropped by the BPF program
// because the ring buffer was full).
type ErrLostEvents int

func (e ErrLostEvents) Error() string {
	return fmt.Sprintf("%d lost events", e)
}

func (e ErrLostEvents) Num() int {
	return int(e)
}

// ParsePolicyVerdict converts raw binary data from BPF to a PolicyVerdict Go structure.
//
// Binary Layout:
// +===============================================================================================+
// | OFFSET | SIZE | DESCRIPTION                            | GO FIELD    | STATE STRUCT FIELD     |
// +========+======+========================================+============+=========================+
// |   IPv4  ADDRESSES                                                                             |
// +--------+------+----------------------------------------+------------+-------------------------+
// |   0    |  4   | Source IP Address                      | SrcAddr    | SrcAddr                 |
// |   32   |  4   | Destination IP Address                 | DstAddr    | DstAddr                 |
// |   48   |  4   | Post-NAT Destination IP Address        | PostNATDst | PostNATDstAddr          |
// |   64   |  4   | NAT Tunnel Source IP Address           | NATTunSrc  | TunIP                   |
// +--------+------+----------------------------------------+------------+-------------------------+
// |   IPv6  ADDRESSES                                                                             |
// +--------+------+----------------------------------------+------------+-------------------------+
// |   0    |  16  | Source IP Address                      | SrcAddr    | SrcAddr-SrcAddr3        |
// |   32   |  16  | Destination IP Address                 | DstAddr    | DstAddr-DstAddr3        |
// |   48   |  16  | Post-NAT Destination IP Address        | PostNATDst | PostNATDstAddr-3        |
// |   64   |  16  | NAT Tunnel Source IP Address           | NATTunSrc  | TunIP-TunIP3            |
// +--------+------+----------------------------------------+------------+-------------------------+
// |   POLICY AND CONNECTION INFORMATION                                                           |
// +--------+------+----------------------------------------+------------+-------------------------+
// |   84   |  4   | Policy Result Code                     | PolicyRC   | PolicyRC                |
// |   88   |  2   | Source Port                            | SrcPort    | SrcPort                 |
// |   92   |  2   | Destination Port                       | DstPort    | DstPort                 |
// |   94   |  2   | Post-NAT Destination Port              | PostNATDst | PostNATDstPort          |
// |   96   |  1   | IP Protocol                            | IPProto    | IPProto                 |
// |   97   |  1   | Padding (unused)                       | -          | _ (unnamed padding)     |
// |   98   |  2   | IP Size (big-endian)                   | IPSize     | IPSize                  |
// |  100   |  4   | Number of Rules Hit                    | RulesHit   | RulesHit                |
// +--------+------+----------------------------------------+------------+-------------------------+
// |   RULE IDs AND CONNECTION TRACKING                                                            |
// +--------+------+----------------------------------------+------------+-------------------------+
// |  104   |  8*n | Rule IDs (n = RulesHit, max=MaxRuleIDs)| RuleIDs    | RuleIDs[i]              |
// +--------+------+----------------------------------------+------------+-------------------------+
// |   AFTER RULE IDs (ct = 104 + (MaxRuleIDs * 8))                                                |
// +--------+------+----------------------------------------+------------+-------------------------+
// |  ct+0  |  8   | Flags                                  | -          | Flags (uint64)          |
// |  ct+8  |  4   | Conntrack RC Flags                     | -          | ConntrackRCFlags        |
// |  ct+12 |  4   | Conntrack NAT IP                       | -          | ConntrackNATIP          |
// |  ct+16 |  4   | Conntrack NAT Source IP                | -          | ConntrackNATsIP         |
// |  ct+20 |  4   | Conntrack NAT Ports                    | -          | ConntrackNATPorts       |
// |  ct+24 |  4   | Conntrack Tunnel IP                    | -          | ConntrackTunIP          |
// |  ct+28 |  4   | Conntrack If Index Fwd                 | OutDevIdx  | ConntrackIfIndexFwd     |
// |  ct+32 |  4   | Conntrack If Index Created             | InDevIdx   | ConntrackIfIndexCtd     |
// |  ct+36 |  4   | Padding                                | -          | _ (unnamed padding)     |
// |  ct+40 |  8   | Timestamp                              | -          | TimeStamp               |
// |  ct+48 |  8   | NAT Data                               | -          | NATData                 |
// |  ct+56 |  8   | Program Start Time                     | -          | ProgStartTime           |
// |  ct+64 |  16  | Source Address Masquerade (IPv4/IPv6)  | -          | SrcAddrMasq-SrcAddrMasq3|
// +===============================================================================================+//
// Notes:
// - IP addresses are stored differently for IPv4 vs IPv6
// - Rule IDs are variable length based on RulesHit (up to MaxRuleIDs)
// - Device indices come from the ConntrackIfIndex fields in the underlying structure
func ParsePolicyVerdict(data []byte, isIPv6 bool) PolicyVerdict {
	fl := PolicyVerdict{
		PolicyRC:       state.PolicyResult(binary.LittleEndian.Uint32(data[offsetPolicyRC : offsetPolicyRC+4])),
		SrcPort:        binary.LittleEndian.Uint16(data[offsetSrcPort : offsetSrcPort+2]),
		DstPort:        binary.LittleEndian.Uint16(data[offsetDstPort : offsetDstPort+2]),
		PostNATDstPort: binary.LittleEndian.Uint16(data[offsetPostNATDstPort : offsetPostNATDstPort+2]),
		IPProto:        uint8(data[offsetIPProto]),
		IPSize:         binary.BigEndian.Uint16(data[offsetIPSize : offsetIPSize+2]),
		RulesHit:       binary.LittleEndian.Uint32(data[offsetRulesHit : offsetRulesHit+4]),
	}

	if isIPv6 {
		fl.SrcAddr = net.IP(data[offsetSrcAddr : offsetSrcAddr+16])
		fl.DstAddr = net.IP(data[offsetDstAddr : offsetDstAddr+16])
		fl.PostNATDstAddr = net.IP(data[offsetPostNATDstAddr : offsetPostNATDstAddr+16])
		fl.NATTunSrcAddr = net.IP(data[offsetNATTunSrcAddr : offsetNATTunSrcAddr+16])
	} else {
		fl.SrcAddr = net.IP(data[offsetSrcAddr : offsetSrcAddr+4])
		fl.DstAddr = net.IP(data[offsetDstAddr : offsetDstAddr+4])
		fl.PostNATDstAddr = net.IP(data[offsetPostNATDstAddr : offsetPostNATDstAddr+4])
		fl.NATTunSrcAddr = net.IP(data[offsetNATTunSrcAddr : offsetNATTunSrcAddr+4])
	}

	off := offsetRuleIDs
	for i := 0; i < int(fl.RulesHit); i++ {
		fl.RuleIDs[i] = binary.LittleEndian.Uint64(data[off : off+ruleIDSize])
		off += ruleIDSize
	}

	// Fill in OutDeviceIndex and InDeviceIndex if the data length is sufficient
	if len(data) >= offsetInDeviceIndex+4 {
		fl.OutDeviceIndex = binary.LittleEndian.Uint32(data[offsetOutDeviceIndex : offsetOutDeviceIndex+4])
		fl.InDeviceIndex = binary.LittleEndian.Uint32(data[offsetInDeviceIndex : offsetInDeviceIndex+4])
	}

	return fl
}

// PolicyVerdict describes the policy verdict event and must match the initial part of
// bpf/state.State after the space reserved for the event header.
type PolicyVerdict struct {
	SrcAddr        net.IP
	DstAddr        net.IP
	PostNATDstAddr net.IP
	NATTunSrcAddr  net.IP
	PolicyRC       state.PolicyResult
	SrcPort        uint16
	DstPort        uint16
	PostNATDstPort uint16
	IPProto        uint8
	pad8           uint8 //nolint:unused // Ignore U1000 unused
	IPSize         uint16
	RulesHit       uint32
	RuleIDs        [state.MaxRuleIDs]uint64
	InDeviceIndex  uint32
	OutDeviceIndex uint32
}

// Type return TypePolicyVerdict
func (PolicyVerdict) Type() Type {
	return TypePolicyVerdict
}
