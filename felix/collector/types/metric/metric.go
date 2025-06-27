// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.

package metric

import (
	"fmt"
	"net"

	"k8s.io/kubernetes/pkg/proxy"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types/boundedset"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/collector/utils"
)

type Value struct {
	DeltaPackets             int
	DeltaBytes               int
	DeltaAllowedHTTPRequests int
	DeltaDeniedHTTPRequests  int
}

// Reset will set all the counters stored to 0
func (mv *Value) Reset() {
	mv.DeltaBytes = 0
	mv.DeltaPackets = 0
	mv.DeltaAllowedHTTPRequests = 0
	mv.DeltaDeniedHTTPRequests = 0
}

// Increments adds delta values for all counters using another MetricValue
func (mv *Value) Increment(other Value) {
	mv.DeltaBytes += other.DeltaBytes
	mv.DeltaPackets += other.DeltaPackets
	mv.DeltaAllowedHTTPRequests += other.DeltaAllowedHTTPRequests
	mv.DeltaDeniedHTTPRequests += other.DeltaDeniedHTTPRequests
}

func (mv Value) String() string {
	return fmt.Sprintf("delta=%v deltaBytes=%v deltaAllowedHTTPReq=%v deltaDeniedHTTPReq=%v",
		mv.DeltaPackets, mv.DeltaBytes, mv.DeltaAllowedHTTPRequests, mv.DeltaDeniedHTTPRequests)
}

type TCPValue struct {
	DeltaTotalRetrans   int
	DeltaLostOut        int
	DeltaUnRecoveredRTO int
}

func (tm *TCPValue) Reset() {
	tm.DeltaTotalRetrans = 0
	tm.DeltaLostOut = 0
	tm.DeltaUnRecoveredRTO = 0
}

func (tm *TCPValue) Increment(other TCPValue) {
	tm.DeltaTotalRetrans += other.DeltaTotalRetrans
	tm.DeltaLostOut += other.DeltaLostOut
	tm.DeltaUnRecoveredRTO += other.DeltaUnRecoveredRTO
}

// ServiceInfo holds information of a service for a MetricUpdate
type ServiceInfo struct {
	proxy.ServicePortName
	// the preDNATPort used to query from the Service info in dstService
	PortNum int
}

type UpdateType int

const (
	UpdateTypeReport UpdateType = iota
	UpdateTypeExpire
)

const (
	UpdateTypeReportStr = "report"
	UpdateTypeExpireStr = "expire"
)

func (ut UpdateType) String() string {
	if ut == UpdateTypeReport {
		return UpdateTypeReportStr
	}
	return UpdateTypeExpireStr
}

type Update struct {
	UpdateType UpdateType

	// Tuple key
	Tuple           tuple.Tuple
	NatOutgoingPort int
	OrigSourceIPs   *boundedset.BoundedSet

	// Endpoint information.
	SrcEp      calc.EndpointData
	DstEp      calc.EndpointData
	DstService ServiceInfo

	// Top level egress Domains.
	DstDomains []string

	// isConnection is true if this update is from an active connection.
	IsConnection bool

	// Rules identification
	RuleIDs        []*calc.RuleID
	PendingRuleIDs []*calc.RuleID
	TransitRuleIDs []*calc.RuleID

	// Whether the rules IDs contains a deny rule.
	HasDenyRule bool

	// Sometimes we may need to send updates without having all the rules
	// in place. This field will help aggregators determine if they need
	// to handle this update or not. Typically this is used when we receive
	// HTTP Data updates after the connection itself has closed.
	UnknownRuleID *calc.RuleID

	// Inbound/Outbound packet/byte counts.
	InMetric         Value
	OutMetric        Value
	InTransitMetric  Value
	OutTransitMetric Value

	// Optional process info
	ProcessName string
	ProcessID   int
	ProcessArgs string

	// Optional TCP v4 socket stats
	SendCongestionWnd *int
	SmoothRtt         *int
	MinRtt            *int
	Mss               *int
	TcpMetric         TCPValue
}

func (mu Update) String() string {
	var (
		srcName, dstName string
		numOrigIPs       int
		origIPs          []net.IP
	)
	if mu.SrcEp != nil {
		srcName = utils.EndpointName(mu.SrcEp.Key())
	} else {
		srcName = utils.UnknownEndpoint
	}
	if mu.DstEp != nil {
		dstName = utils.EndpointName(mu.DstEp.Key())
	} else {
		dstName = utils.UnknownEndpoint
	}
	if mu.OrigSourceIPs != nil {
		numOrigIPs = mu.OrigSourceIPs.TotalCount()
		origIPs = mu.OrigSourceIPs.ToIPSlice()
	} else {
		numOrigIPs = 0
		origIPs = []net.IP{}
	}

	format := "MetricUpdate: type=%s tuple={%v}, srcEp={%v} dstEp={%v} isConnection={%v}, ruleID={%v}, unknownRuleID={%v} inMetric={%s} outMetric={%s} origIPs={%v} numOrigIPs={%d} processInfo={%s, %d, %s} tcpSocketStats={%d, %d, %d, %d, %d, %d, %d}"

	var sendCongestionWnd, smoothRtt, minRtt, mss, deltaTotalRetrans, deltaLostOut, deltaUnRecoveredRTO int

	if mu.SendCongestionWnd != nil && mu.SmoothRtt != nil &&
		mu.MinRtt != nil && mu.Mss != nil {
		sendCongestionWnd = *mu.SendCongestionWnd
		smoothRtt = *mu.SmoothRtt
		minRtt = *mu.MinRtt
		mss = *mu.Mss
		deltaTotalRetrans = mu.TcpMetric.DeltaTotalRetrans
		deltaLostOut = mu.TcpMetric.DeltaLostOut
		deltaUnRecoveredRTO = mu.TcpMetric.DeltaUnRecoveredRTO
	}

	return fmt.Sprintf(format,
		mu.UpdateType, &(mu.Tuple), srcName, dstName, mu.IsConnection, mu.RuleIDs, mu.UnknownRuleID,
		mu.InMetric, mu.OutMetric, origIPs, numOrigIPs, mu.ProcessName, mu.ProcessID, mu.ProcessArgs,
		sendCongestionWnd, smoothRtt, minRtt, mss, deltaTotalRetrans, deltaLostOut, deltaUnRecoveredRTO)
}

func (mu Update) GetLastRuleID() *calc.RuleID {
	if len(mu.RuleIDs) > 0 {
		return mu.RuleIDs[len(mu.RuleIDs)-1]
	} else if mu.UnknownRuleID != nil {
		return mu.UnknownRuleID
	}
	return nil
}

func (mu Update) GetLastTransitRuleID() *calc.RuleID {
	if len(mu.TransitRuleIDs) > 0 {
		return mu.TransitRuleIDs[len(mu.TransitRuleIDs)-1]
	} else if mu.UnknownRuleID != nil {
		return mu.UnknownRuleID
	}
	return nil
}
