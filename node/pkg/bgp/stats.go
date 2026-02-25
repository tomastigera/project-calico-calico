// Copyright (c) 2020 Tigera, Inc. All rights reserved.

package bgp

import "strconv"

const (
	// StatusIdle is used to parse/match the Idle status from a BGP daemon.
	StatusIdle = "Idle"
	// StatusConnect is used to parse/match the Connect status from a BGP daemon.
	StatusConnect = "Connect"
	// StatusActive is used to parse/match the Active status from a BGP daemon.
	StatusActive = "Active"
	// StatusOpenSent is used to parse/match the OpenSent status from a BGP daemon.
	StatusOpenSent = "OpenSent"
	// StatusOpenConfirm is used to parse/match the OpenConfirm status from a BGP daemon.
	StatusOpenConfirm = "OpenConfirm"
	// StatusEstablished is used to parse/match the Established status from a BGP daemon.
	StatusEstablished = "Established"
	// StatusClose is used to parse/match the Close status from a BGP daemon.
	StatusClose = "Close"
	// StatusDown is used to parse/match the Down status from a BGP daemon.
	StatusDown = "Down"
	// StatusPassive is used to parse/match the Passive status from a BGP daemon.
	StatusPassive = "Passive"
)

var (
	// PeerStatuses contains a list of all available BGP peer status values.
	PeerStatuses = []string{
		StatusIdle,
		StatusConnect,
		StatusActive,
		StatusOpenSent,
		StatusOpenConfirm,
		StatusEstablished,
		StatusClose,
		StatusDown,
		StatusPassive,
	}
)

// Peer is a struct containing details about a BGP peer from a BGP daemon.
type Peer struct {
	PeerIP   string
	PeerType string
	State    string
	Since    string
	BGPState string
	Info     string
	Details  PeerDetails
}

// PeerDetails contains metadata related to a BGP peer for given node.
type PeerDetails struct {
	RouteCounts        PeerRouteCounts
	ImportUpdateCounts PeerImportUpdateCounts
}

// PeerRouteCounts provides a summary of the number of BGP routes a given node has
// interacted with for a given peer.
type PeerRouteCounts struct {
	NumImported  uint32
	NumFiltered  uint32
	NumExported  uint32
	NumPreferred uint32
}

// PeerImportUpdateCounts provides a summary of the number of BGP routes a given node has
// interacted with for a given peer.
type PeerImportUpdateCounts struct {
	NumReceived uint32
	NumRejected uint32
	NumFiltered uint32
	NumIgnored  uint32
	NumAccepted uint32
}

// StatsType is an enum for representing type of BGP stats.
type StatsType uint8

const (
	// Peers represents type of stats containing BGP Peer information.
	Peers = StatsType(iota)
)

// String returns a human-readable representation of StatsType value.
func (s StatsType) String() string {
	names := []string{"BGP Peers"}
	i := uint8(s)
	switch {
	case i <= uint8(Peers):
		return names[i]
	default:
		return strconv.Itoa(int(i))
	}
}

// Version is an enum for representing IP version for a BGP daemon.
type Version uint8

const (
	// IPv4 represents IP version 4 for a BGP daemon.
	IPv4 = Version(iota)
	// IPv6 represents IP version 6 for a BGP daemon.
	IPv6
)

// String returns a human-readable representation of Version value.
func (s Version) String() string {
	names := []string{"IPv4", "IPv6"}
	i := uint8(s)
	switch {
	case i <= uint8(IPv6):
		return names[i]
	default:
		return strconv.Itoa(int(i))
	}
}

// Stats represents the BGP stats that are pulled from a BGP daemon.
type Stats struct {
	Type  StatsType
	IPVer Version
	Data  any
}
