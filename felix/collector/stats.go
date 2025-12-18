// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.

package collector

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gavv/monotime"
	"k8s.io/kubernetes/pkg/proxy"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/collector/types/boundedset"
	"github.com/projectcalico/calico/felix/collector/types/counter"
	"github.com/projectcalico/calico/felix/collector/types/metric"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/collector/utils"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

var ErrorIsNotDNAT = errors.New("tuple is not a DNAT connection")

// RuleMatch type is used to indicate whether a rule match from an nflog is newly set, unchanged from the previous
// value, or has been updated. In the latter case the existing entry should be reported and expired.
type RuleMatch byte

const (
	RuleMatchUnchanged RuleMatch = iota
	RuleMatchSet
	RuleMatchIsDifferent
)

const RuleTraceInitLen = 10

// RuleTrace represents the list of rules (i.e, a Trace) that a packet hits.
// The action of a RuleTrace object is the final action that is not a
// next-Tier/pass action.
type RuleTrace struct {
	path []*calc.RuleID

	// The reported path. This is calculated and stored when metrics are reported.
	rulesToReport []*calc.RuleID

	// Whether there are any deny rules within this set of rule hits. This will either be the final enforced deny or
	// a staged policy deny.
	hasDenyRule bool

	// Counters to store the packets and byte counts for the RuleTrace
	pktsCtr  counter.Counter
	bytesCtr counter.Counter
	dirty    bool

	// Stores the Index of the RuleID that has a RuleAction Allow or Deny.
	verdictIdx int

	// Stores the last index updated in this rule trace. It is assumed the policy hit logs arrive in order
	// for a particular traffic direction and connection.
	lastMatchIdx int

	// Optimization Note: When initializing a RuleTrace object, the pathArray
	// array is used as the backing array that has been pre-allocated. This avoids
	// one allocation when creating a RuleTrace object. More info on this here:
	// https://github.com/golang/go/wiki/Performance#memory-profiler
	// (Search for "slice array preallocation").
	pathArray [RuleTraceInitLen]*calc.RuleID
}

func (t *RuleTrace) Init() {
	t.verdictIdx = -1
	t.path = t.pathArray[:]
}

func (t *RuleTrace) String() string {
	rtParts := make([]string, 0)
	for _, tp := range t.Path() {
		rtParts = append(rtParts, fmt.Sprintf("(%s)", tp))
	}
	return fmt.Sprintf(
		"path=[%v], action=%v ctr={packets=%v bytes=%v}",
		strings.Join(rtParts, ", "), t.Action(), t.pktsCtr.Absolute(), t.bytesCtr.Absolute(),
	)
}

func (t *RuleTrace) Len() int {
	return len(t.path)
}

func (t *RuleTrace) Path() []*calc.RuleID {
	if t.rulesToReport != nil {
		return t.rulesToReport
	}
	if t.verdictIdx < 0 {
		return nil
	}

	// The reported rules have not been calculated or have changed. Calculate them now.
	t.rulesToReport = make([]*calc.RuleID, 0, t.verdictIdx)

	// Iterate through the ruleIDs gathered in the nflog path. The IDs will be ordered by staged policies and tiers.
	// e.g.   tier1.SNP1 tier1.SNP2 tier1(EOT) tier2.SNP2 tier2(EOT)
	//     or tier1.SNP1 tier1.NP1  [n/a]      tier2.NP1  [n/a]
	// Both of these represent possible outcomes for the same two tiers. There will be staged matches up to the first
	// enforced policy match, or the end-of-tier action (in which case there will be a hit for each staged policy).
	//
	// We don't add end of tier passes since they are only used for internal bookkeeping.
	t.hasDenyRule = false
	for i := 0; i <= t.verdictIdx; i++ {
		r := t.path[i]
		if r == nil || r.IsEndOfTierPass() {
			continue
		}

		endOfTierIndex := func() int {
			for j := i + 1; j <= t.verdictIdx; j++ {
				if t.path[j] != nil && t.path[j].Tier != r.Tier {
					return j - 1
				}
			}
			return t.verdictIdx
		}

		if model.KindIsStaged(r.Kind) {
			// This is a staged policy. If the rule is an implicitly applied the tier action then we only include it if the end-of-tier
			// pass action has also been hit.
			if r.IsTierDefaultActionRule() {
				finalIdx := endOfTierIndex()
				if t.path[finalIdx] == nil || !t.path[finalIdx].IsEndOfTierPass() {
					// This is an implicit drop, but there is no end of tier pass - we do not need to add this entry.
					continue
				}
			}

			// Add the report and then continue to the next entry in the path.
			t.rulesToReport = append(t.rulesToReport, r)
			if r.Action == rules.RuleActionDeny {
				t.hasDenyRule = true
			}

			continue
		}

		// This is an enforced policy, so just add the rule. There should be no more rules this tier, so jump to the end
		// of the tier (we might already be at that index, e.g. if we are processing the verdict).
		t.rulesToReport = append(t.rulesToReport, r)
		if r.Action == rules.RuleActionDeny {
			t.hasDenyRule = true
		}

		i = endOfTierIndex()
	}
	return t.rulesToReport
}

func (t *RuleTrace) HasDenyRule() bool {
	if t.rulesToReport != nil {
		// The deny rules flag is calculated as part of the rule calculation.
		_ = t.Path()
	}

	return t.hasDenyRule
}

func (t *RuleTrace) ToVerdictString() string {
	ruleID := t.VerdictRuleID()
	if ruleID == nil {
		return ""
	}
	return fmt.Sprintf("%s/%s/%d/%v", ruleID.Tier, ruleID.Name, ruleID.Index, ruleID.Action)
}

func (t *RuleTrace) ToRuleString() string {
	var parts []string
	for _, r := range t.path {
		if r != nil {
			parts = append(parts, r.Name)
		}
	}
	return "( " + strings.Join(parts, " , ") + " )"
}

func (t *RuleTrace) Action() rules.RuleAction {
	ruleID := t.VerdictRuleID()
	if ruleID == nil {
		// We don't know the verdict RuleID yet.
		return rules.RuleActionPass
	}
	return ruleID.Action
}

func (t *RuleTrace) IsDirty() bool {
	return t.dirty
}

// FoundVerdict returns true if the verdict rule has been found, that is the rule that contains
// the final allow or deny action.
func (t *RuleTrace) FoundVerdict() bool {
	return t.verdictIdx >= 0
}

// VerdictRuleID returns the RuleID that contains either ActionAllow or
// DenyAction in a RuleTrace or nil if we haven't seen either of these yet.
func (t *RuleTrace) VerdictRuleID() *calc.RuleID {
	if t.verdictIdx >= 0 {
		return t.path[t.verdictIdx]
	} else {
		return nil
	}
}

func (t *RuleTrace) ClearDirtyFlag() {
	t.dirty = false
	t.pktsCtr.ResetDelta()
	t.bytesCtr.ResetDelta()
}

func (t *RuleTrace) addRuleID(rid *calc.RuleID, matchIdx, numPkts, numBytes int) RuleMatch {
	t.maybeResizePath(matchIdx)

	ru := RuleMatchUnchanged

	// Matches should arrive in order, so if a previous match occurred that has not been repeated then
	// the match has changed.
	for i := t.lastMatchIdx + 1; i < matchIdx; i++ {
		if t.path[i] != nil {
			return RuleMatchIsDifferent
		}
	}

	if existingRuleID := t.path[matchIdx]; existingRuleID == nil {
		// Position is empty, insert and be done. Reset the rules to report just incase we are adding a new staged
		// policy hit.
		t.path[matchIdx] = rid
		t.rulesToReport = nil
		ru = RuleMatchSet
	} else if !existingRuleID.Equals(rid) {
		// Position is not empty, and does not match the new value.
		return RuleMatchIsDifferent
	}

	// Set as dirty and increment the match revision number for this tier.
	t.dirty = true

	if !model.KindIsStaged(rid.Kind) && rid.Action != rules.RuleActionPass {
		// This is a verdict action, so increment counters and set our verdict index.
		t.pktsCtr.Increase(numPkts)
		t.bytesCtr.Increase(numBytes)
		t.verdictIdx = matchIdx
	}

	// Set the last match index.
	t.lastMatchIdx = matchIdx

	return ru
}

func (t *RuleTrace) replaceRuleID(rid *calc.RuleID, matchIdx, numPkts, numBytes int) {
	// Matches should arrive in order, so if a previous match occurred that has not been repeated then
	// the match has changed.
	for i := t.lastMatchIdx + 1; i < matchIdx; i++ {
		t.path[i] = nil
	}

	// Set the match rule and increment the match revision number for this tier.
	t.path[matchIdx] = rid
	t.lastMatchIdx = matchIdx
	t.dirty = true

	// Reset the reporting path so that we recalculate it next report.
	t.rulesToReport = nil

	if !model.KindIsStaged(rid.Name) && rid.Action != rules.RuleActionPass {
		// This is a verdict action, so reset and set counters and set our verdict index.
		t.pktsCtr.ResetAndSet(numPkts)
		t.bytesCtr.ResetAndSet(numBytes)
		t.verdictIdx = matchIdx
		t.lastMatchIdx = 0
	}
}

// maybeResizePath may resize the tier array based on the index of the tier.
func (t *RuleTrace) maybeResizePath(matchIdx int) {
	if matchIdx >= t.Len() {
		// Insertion Index is beyond than current length. Grow the path slice as long
		// as necessary.
		incSize := (matchIdx / RuleTraceInitLen) * RuleTraceInitLen
		newPath := make([]*calc.RuleID, t.Len()+incSize)
		copy(newPath, t.path)
		t.path = newPath
	}
}

type tcpStatsData struct {
	// TCP stats
	sendCongestionWnd int
	smoothRtt         int
	minRtt            int
	mss               int
	totalRetrans      counter.Counter
	lostOut           counter.Counter
	unRecoveredRTO    counter.Counter
	dirty             bool
}

func (t *tcpStatsData) ClearDirtyFlag() {
	t.dirty = false
	t.totalRetrans.ResetDelta()
	t.lostOut.ResetDelta()
	t.unRecoveredRTO.ResetDelta()
}

// Data contains metadata and statistics such as rule counters and age of a
// connection(Tuple). Each Data object contains:
// - 2 RuleTrace's - Ingress and Egress - each providing information on the
// where the Policy was applied, with additional information on corresponding
// workload endpoint. The EgressRuleTrace and the IngressRuleTrace record the
// policies that this tuple can hit - egress from the workload that is the
// source of this connection and ingress into a workload that terminated this.
// - Connection based counters (e.g, for conntrack packets/bytes and HTTP requests).
type Data struct {
	Tuple tuple.Tuple

	origSourceIPs       *boundedset.BoundedSet
	OrigSourceIPsActive bool

	// Contains endpoint information corresponding to source and
	// destination endpoints. Either of these values can be nil
	// if we don't have information about the endpoint.
	SrcEp calc.EndpointData
	DstEp calc.EndpointData
	// Contains endpoint information corresponding to the node the tuple is being processed on.
	NodeEp calc.EndpointData

	// Top level destination (egress) Domains.
	DestDomains []string

	// Pre-DNAT information used to lookup the service information.
	IsDNAT      bool
	PreDNATAddr [16]byte
	PreDNATPort int

	// The source and destination service if uniquely attributable. Once reported this should not
	// change unless first expired.
	DstSvc proxy.ServicePortName

	// Indicates if this is a connection
	IsConnection bool

	// Indicates if this connection is proxied or not
	IsProxied bool

	NatOutgoingPort int

	// Connection related counters.
	conntrackPktsCtr         counter.Counter
	conntrackPktsCtrReverse  counter.Counter
	conntrackBytesCtr        counter.Counter
	conntrackBytesCtrReverse counter.Counter
	httpReqAllowedCtr        counter.Counter
	httpReqDeniedCtr         counter.Counter

	// Process information
	sourceProcessData types.ProcessData
	destProcessData   types.ProcessData

	TcpStats tcpStatsData

	// These contain the aggregated counts per tuple per rule.
	IngressRuleTrace        RuleTrace
	EgressRuleTrace         RuleTrace
	IngressTransitRuleTrace RuleTrace
	EgressTransitRuleTrace  RuleTrace

	// These contain the pending rule hits for the tuple.
	IngressPendingRuleIDs []*calc.RuleID
	EgressPendingRuleIDs  []*calc.RuleID

	updatedAt     time.Duration
	ruleUpdatedAt time.Duration

	Reported             bool
	UnreportedPacketInfo bool
	dirty                bool
	Expired              bool
}

func NewData(tuple tuple.Tuple, srcEp, dstEp, nodeEp calc.EndpointData, maxOriginalIPsSize int) *Data {
	now := monotime.Now()
	d := &Data{
		Tuple:         tuple,
		origSourceIPs: boundedset.New(maxOriginalIPsSize),
		updatedAt:     now,
		ruleUpdatedAt: now,
		dirty:         true,
		SrcEp:         srcEp,
		DstEp:         dstEp,
		NodeEp:        nodeEp,
	}
	d.IngressRuleTrace.Init()
	d.EgressRuleTrace.Init()
	d.IngressTransitRuleTrace.Init()
	d.EgressTransitRuleTrace.Init()

	return d
}

func (d *Data) String() string {
	var (
		srcName, dstName string
		dstSvcName       string
		osi              []net.IP
		osiTc            int
	)
	if d.SrcEp != nil {
		srcName = utils.EndpointName(d.SrcEp.Key())
	} else {
		srcName = utils.UnknownEndpoint
	}
	if d.DstEp != nil {
		dstName = utils.EndpointName(d.DstEp.Key())
	} else {
		dstName = utils.UnknownEndpoint
	}
	if d.DstSvc.Name != "" {
		dstSvcName = d.DstSvc.Namespace + "." + d.DstSvc.Name + "." + d.DstSvc.Port
	} else {
		dstSvcName = utils.UnknownEndpoint
	}
	if d.origSourceIPs != nil {
		osi = d.origSourceIPs.ToIPSlice()
		osiTc = d.origSourceIPs.TotalCount()
	}
	return fmt.Sprintf(
		"tuple={%v}, srcEp={%v} dstEp={%v}, dstSvc={%v}, connTrackCtr={packets=%v bytes=%v}, "+
			"connTrackCtrReverse={packets=%v bytes=%v}, httpPkts={allowed=%v, denied=%v}, updatedAt=%v ingressRuleTrace={%+v} egressRuleTrace={%+v}, ingressTransitRuleTrace={%+v}, egressTransitRuleTrace={%+v} ingressPendingRuleIDs={%v} egressPendingRuleIDs={%v},"+
			"expired=%v, reported=%v isDNAT=%v preDNATAddr=%v preDNATPort=%v isConnection=%+v "+
			"origSourceIPs={ips=%v totalCount=%v}, "+
			"sourceProcessInfo{name=%s, args=%s, pid=%d}, destProcessInfo{name=%s, args=%s, pid=%d} "+
			"TcpStats{sendCongestionwnd=%v, smoothRtt=%v, minRtt=%v, mss=%v, totalRetrans=%v, lostOut=%v, unrecoveredTO=%v}",
		&(d.Tuple), srcName, dstName, dstSvcName, d.conntrackPktsCtr.Absolute(), d.conntrackBytesCtr.Absolute(),
		d.conntrackPktsCtrReverse.Absolute(), d.conntrackBytesCtrReverse.Absolute(), d.httpReqAllowedCtr.Delta(),
		d.httpReqDeniedCtr.Delta(), d.updatedAt, d.IngressRuleTrace, d.EgressRuleTrace, d.IngressTransitRuleTrace, d.EgressTransitRuleTrace, d.IngressPendingRuleIDs, d.EgressPendingRuleIDs,
		d.Expired, d.Reported, d.IsDNAT, d.PreDNATAddr, d.PreDNATPort, d.IsConnection,
		osi, osiTc,
		d.SourceProcessData().Name, d.SourceProcessData().Arguments, d.SourceProcessData().Pid, d.DestProcessData().Name,
		d.DestProcessData().Arguments, d.DestProcessData().Pid, d.TcpStats.sendCongestionWnd, d.TcpStats.smoothRtt,
		d.TcpStats.minRtt, d.TcpStats.mss, d.TcpStats.totalRetrans.Absolute(), d.TcpStats.lostOut.Absolute(), d.TcpStats.unRecoveredRTO.Absolute())
}

func (d *Data) touch() {
	d.updatedAt = monotime.Now()
}

func (d *Data) setDirtyFlag() {
	d.dirty = true
}

func (d *Data) ClearConnDirtyFlag() {
	d.dirty = false
	d.httpReqAllowedCtr.ResetDelta()
	d.httpReqDeniedCtr.ResetDelta()
	d.conntrackPktsCtr.ResetDelta()
	d.conntrackBytesCtr.ResetDelta()
	d.conntrackPktsCtrReverse.ResetDelta()
	d.conntrackBytesCtrReverse.ResetDelta()
}

func (d *Data) IsDirty() bool {
	return d.dirty
}

func (d *Data) UpdatedAt() time.Duration {
	return d.updatedAt
}

func (d *Data) RuleUpdatedAt() time.Duration {
	return d.ruleUpdatedAt
}

func (d *Data) DurationSinceLastUpdate() time.Duration {
	return monotime.Since(d.updatedAt)
}

func (d *Data) DurationSinceLastRuleUpdate() time.Duration {
	return monotime.Since(d.ruleUpdatedAt)
}

// Returns the final action of the RuleTrace
func (d *Data) IngressAction() rules.RuleAction {
	return d.IngressRuleTrace.Action()
}

// Returns the final action of the RuleTrace
func (d *Data) EgressAction() rules.RuleAction {
	return d.EgressRuleTrace.Action()
}

// Returns the final action of the ingress Transit RuleTrace
func (d *Data) IngressTransitAction() rules.RuleAction {
	return d.IngressTransitRuleTrace.Action()
}

// Returns the final action of the egress Transit RuleTrace
func (d *Data) EgressTransitAction() rules.RuleAction {
	return d.EgressTransitRuleTrace.Action()
}

func (d *Data) ConntrackPacketsCounter() counter.Counter {
	return d.conntrackPktsCtr
}

func (d *Data) ConntrackBytesCounter() counter.Counter {
	return d.conntrackBytesCtr
}

func (d *Data) ConntrackPacketsCounterReverse() counter.Counter {
	return d.conntrackPktsCtrReverse
}

func (d *Data) ConntrackBytesCounterReverse() counter.Counter {
	return d.conntrackBytesCtrReverse
}

func (d *Data) HTTPRequestsAllowed() counter.Counter {
	return d.httpReqAllowedCtr
}

func (d *Data) HTTPRequestsDenied() counter.Counter {
	return d.httpReqDeniedCtr
}

// Set In Counters' values to packets and bytes. Use the SetConntrackCounters* methods
// when the source if packets/bytes are absolute values.
func (d *Data) SetConntrackCounters(packets int, bytes int) {
	if d.conntrackPktsCtr.Set(packets) && d.conntrackBytesCtr.Set(bytes) {
		d.setDirtyFlag()
	}
	d.IsConnection = true
	d.touch()
}

func (d *Data) setTCPCounters(totalRetrans int, lostOut int, unRecoveredRTO int) {
	d.TcpStats.lostOut.Set(lostOut)
	d.TcpStats.totalRetrans.Set(totalRetrans)
	d.TcpStats.unRecoveredRTO.Set(unRecoveredRTO)
}

// SetExpired flags the connection as expired for later cleanup.
func (d *Data) SetExpired() {
	d.Expired = true
	d.setDirtyFlag()
	d.touch()
}

// VerdictFound returns true if the verdict has been found for the local endpoints in this flow
// for both egress and ingress barring some special conditions
// Special case: For connections that went through a proxy, Ex: envoy proxy for L7 logs collection, only of the verdicts is found.
// For L7 tproxied connections, going client -> service -> proxy -> backend (both client and backend on same node),
// we get only egress verdict (true) for client -> service -> proxy, and ingress (true) for connection proxy -> backend.
// This is because the end point tuple is no longer same once proxy happens (source port is different for tproxy case).
// For such cases we make an exception in this logic
func (d *Data) VerdictFound() bool {
	// We expect at least one of the source or dest to be a local endpoint.
	srcIsLocal := d.SrcEp != nil && d.SrcEp.IsLocal()
	dstIsLocal := d.DstEp != nil && d.DstEp.IsLocal()

	if d.IsProxied {
		// This is a proxied flow, we'll see both legs but we only expect a verdict for one of them
		// so we return true if either leg has a verdict.
		return srcIsLocal && d.EgressRuleTrace.FoundVerdict() || dstIsLocal && d.IngressRuleTrace.FoundVerdict()
	} else {
		// for non local flows we don't need any verdict
		// for local flows we require egress or ingress verdicts based on the whether source or destination is local
		return (!srcIsLocal || d.EgressRuleTrace.FoundVerdict()) && (!dstIsLocal || d.IngressRuleTrace.FoundVerdict())
	}
}

// Set In Counters' values to packets and bytes. Use the SetConntrackCounters* methods
// when the source if packets/bytes are absolute values.
func (d *Data) SetConntrackCountersReverse(packets int, bytes int) {
	if d.conntrackPktsCtrReverse.Set(packets) && d.conntrackBytesCtrReverse.Set(bytes) {
		d.setDirtyFlag()
	}
	d.IsConnection = true
	d.touch()
}

// Increment the HTTP Request allowed count.
func (d *Data) IncreaseHTTPRequestAllowedCounter(delta int) {
	if delta == 0 {
		return
	}
	d.httpReqAllowedCtr.Increase(delta)
	d.setDirtyFlag()
	d.touch()
}

// Increment the HTTP Request denied count.
func (d *Data) IncreaseHTTPRequestDeniedCounter(delta int) {
	if delta == 0 {
		return
	}
	d.httpReqDeniedCtr.Increase(delta)
	d.setDirtyFlag()
	d.touch()
}

// ResetConntrackCounters resets the counters associated with the tracked connection for
// the data.
func (d *Data) ResetConntrackCounters() {
	d.IsConnection = false
	d.Expired = false
	d.conntrackPktsCtr.Reset()
	d.conntrackBytesCtr.Reset()
	d.conntrackPktsCtrReverse.Reset()
	d.conntrackBytesCtrReverse.Reset()
}

// ResetApplicationCounters resets the counters associated with application layer statistics.
func (d *Data) ResetApplicationCounters() {
	d.httpReqAllowedCtr.Reset()
	d.httpReqDeniedCtr.Reset()
}

// ResetTcpStatsCounters resets the Tcp socket stats
func (d *Data) ResetTcpStats() {
	d.TcpStats.sendCongestionWnd = 0
	d.TcpStats.minRtt = 0
	d.TcpStats.smoothRtt = 0
	d.TcpStats.mss = 0
	d.TcpStats.lostOut.Reset()
	d.TcpStats.totalRetrans.Reset()
	d.TcpStats.unRecoveredRTO.Reset()
	d.TcpStats.dirty = false
}

func (d *Data) AddRuleID(ruleID *calc.RuleID, matchIdx, numPkts, numBytes int, isTransit bool) RuleMatch {
	var ru RuleMatch
	switch ruleID.Direction {
	case rules.RuleDirIngress:
		if isTransit {
			ru = d.IngressTransitRuleTrace.addRuleID(ruleID, matchIdx, numPkts, numBytes)
		} else {
			ru = d.IngressRuleTrace.addRuleID(ruleID, matchIdx, numPkts, numBytes)
		}
	case rules.RuleDirEgress:
		if isTransit {
			ru = d.EgressTransitRuleTrace.addRuleID(ruleID, matchIdx, numPkts, numBytes)
		} else {
			ru = d.EgressRuleTrace.addRuleID(ruleID, matchIdx, numPkts, numBytes)
		}
	}

	if ru == RuleMatchSet {
		// The rule has just been set, update the last rule update time. This provides a window during which we can
		// gather any remaining rule hits.
		d.ruleUpdatedAt = monotime.Now()

		// And make sure we update the lastUpdated time so that we don't expire the flow.
		d.touch()
		d.setDirtyFlag()
	}
	return ru
}

func (d *Data) ReplaceRuleID(ruleID *calc.RuleID, matchIdx, numPkts, numBytes int, isTransit bool) {
	switch ruleID.Direction {
	case rules.RuleDirIngress:
		if isTransit {
			d.IngressTransitRuleTrace.replaceRuleID(ruleID, matchIdx, numPkts, numBytes)
		} else {
			d.IngressRuleTrace.replaceRuleID(ruleID, matchIdx, numPkts, numBytes)
		}
	case rules.RuleDirEgress:
		if isTransit {
			d.EgressTransitRuleTrace.replaceRuleID(ruleID, matchIdx, numPkts, numBytes)
		} else {
			d.EgressRuleTrace.replaceRuleID(ruleID, matchIdx, numPkts, numBytes)
		}
	}

	// The rule has just been set, update the last rule update time. This provides a window during which we can
	// gather any remaining rule hits.
	d.ruleUpdatedAt = monotime.Now()

	// And make sure we update the lastUpdated time so that we don't expire the flow.
	d.touch()
	d.setDirtyFlag()
}

func (d *Data) AddOriginalSourceIPs(bs *boundedset.BoundedSet) {
	d.origSourceIPs.Combine(bs)
	d.OrigSourceIPsActive = true
	d.IsConnection = true
	d.touch()
	d.setDirtyFlag()
}

func (d *Data) OriginalSourceIps() []net.IP {
	return d.origSourceIPs.ToIPSlice()
}

func (d *Data) IncreaseNumUniqueOriginalSourceIPs(deltaNum int) {
	d.origSourceIPs.IncreaseTotalCount(deltaNum)
	d.IsConnection = true
	d.touch()
	d.setDirtyFlag()
}

func (d *Data) NumUniqueOriginalSourceIPs() int {
	return d.origSourceIPs.TotalCount()
}

func (d *Data) SourceProcessData() types.ProcessData {
	return d.sourceProcessData
}

// SetSourceProcessData sets the process name and PID for the connection tuple.
// Returns false if a process name or PID is already related to the connection tuple
// and returns true otherwise.
func (d *Data) SetSourceProcessData(name, args string, pid int) bool {
	if len(d.sourceProcessData.Name) != 0 && d.sourceProcessData.Name != name &&
		d.sourceProcessData.Pid != 0 && d.sourceProcessData.Pid != pid {
		return false
	}
	d.sourceProcessData = types.ProcessData{
		Name:      name,
		Pid:       pid,
		Arguments: args,
	}
	d.setDirtyFlag()
	d.touch()
	return true
}

func (d *Data) DestProcessData() types.ProcessData {
	return d.destProcessData
}

// SetDestProcessData sets the process name and PID for the connection tuple.
// Returns false if a process name or PID is already related to the connection tuple
// and returns true otherwise.
func (d *Data) SetDestProcessData(name, args string, pid int) bool {
	if len(d.destProcessData.Name) != 0 && d.destProcessData.Name != name &&
		d.destProcessData.Pid != 0 && d.destProcessData.Pid != pid {
		return false
	}
	d.destProcessData = types.ProcessData{
		Name:      name,
		Pid:       pid,
		Arguments: args,
	}
	d.setDirtyFlag()
	d.touch()
	return true
}

func (d *Data) PreDNATTuple() (tuple.Tuple, error) {
	if !d.IsDNAT {
		return d.Tuple, ErrorIsNotDNAT
	}
	return tuple.Make(d.Tuple.Src, d.PreDNATAddr, d.Tuple.Proto, d.Tuple.L4Src, d.PreDNATPort), nil
}

// metricUpdateIngressConn creates a metric update for Inbound connection traffic
func (d *Data) MetricUpdateIngressConn(ut metric.UpdateType) metric.Update {
	metricDstServiceInfo := metric.ServiceInfo{
		ServicePortName: d.DstSvc,
		PortNum:         d.PreDNATPort,
	}

	metricUpdate := metric.Update{
		UpdateType:      ut,
		Tuple:           d.Tuple,
		NatOutgoingPort: d.NatOutgoingPort,
		SrcEp:           d.SrcEp,
		DstEp:           d.DstEp,
		DstService:      metricDstServiceInfo,
		RuleIDs:         d.IngressRuleTrace.Path(),
		TransitRuleIDs:  d.IngressTransitRuleTrace.Path(),
		HasDenyRule:     d.IngressRuleTrace.HasDenyRule() || d.IngressTransitRuleTrace.HasDenyRule(),
		PendingRuleIDs:  d.IngressPendingRuleIDs,
		IsConnection:    d.IsConnection,
		InMetric: metric.Value{
			DeltaPackets:             d.conntrackPktsCtr.Delta(),
			DeltaBytes:               d.conntrackBytesCtr.Delta(),
			DeltaAllowedHTTPRequests: d.httpReqAllowedCtr.Delta(),
			DeltaDeniedHTTPRequests:  d.httpReqDeniedCtr.Delta(),
		},
		OutMetric: metric.Value{
			DeltaPackets: d.conntrackPktsCtrReverse.Delta(),
			DeltaBytes:   d.conntrackBytesCtrReverse.Delta(),
		},
		ProcessName: d.DestProcessData().Name,
		ProcessID:   d.DestProcessData().Pid,
		ProcessArgs: d.DestProcessData().Arguments,
	}
	if d.TcpStats.dirty {
		metricUpdate.SendCongestionWnd = &d.TcpStats.sendCongestionWnd
		metricUpdate.SmoothRtt = &d.TcpStats.smoothRtt
		metricUpdate.MinRtt = &d.TcpStats.minRtt
		metricUpdate.Mss = &d.TcpStats.mss
		metricUpdate.TcpMetric = metric.TCPValue{
			DeltaTotalRetrans:   d.TcpStats.totalRetrans.Delta(),
			DeltaLostOut:        d.TcpStats.lostOut.Delta(),
			DeltaUnRecoveredRTO: d.TcpStats.unRecoveredRTO.Delta(),
		}
	}

	return metricUpdate
}

// MetricUpdateEgressConn creates a metric update for Outbound connection traffic
func (d *Data) MetricUpdateEgressConn(ut metric.UpdateType) metric.Update {
	metricDstServiceInfo := metric.ServiceInfo{
		ServicePortName: d.DstSvc,
		PortNum:         d.PreDNATPort,
	}

	metricUpdate := metric.Update{
		UpdateType:      ut,
		Tuple:           d.Tuple,
		NatOutgoingPort: d.NatOutgoingPort,
		SrcEp:           d.SrcEp,
		DstEp:           d.DstEp,
		DstService:      metricDstServiceInfo,
		DstDomains:      d.DestDomains,
		RuleIDs:         d.EgressRuleTrace.Path(),
		TransitRuleIDs:  d.EgressTransitRuleTrace.Path(),
		HasDenyRule:     d.EgressRuleTrace.HasDenyRule() || d.EgressTransitRuleTrace.HasDenyRule(),
		PendingRuleIDs:  d.EgressPendingRuleIDs,
		IsConnection:    d.IsConnection,
		InMetric: metric.Value{
			DeltaPackets: d.conntrackPktsCtrReverse.Delta(),
			DeltaBytes:   d.conntrackBytesCtrReverse.Delta(),
		},
		OutMetric: metric.Value{
			DeltaPackets: d.conntrackPktsCtr.Delta(),
			DeltaBytes:   d.conntrackBytesCtr.Delta(),
		},
		ProcessName: d.SourceProcessData().Name,
		ProcessID:   d.SourceProcessData().Pid,
		ProcessArgs: d.SourceProcessData().Arguments,
	}
	if d.TcpStats.dirty {
		metricUpdate.SendCongestionWnd = &d.TcpStats.sendCongestionWnd
		metricUpdate.SmoothRtt = &d.TcpStats.smoothRtt
		metricUpdate.MinRtt = &d.TcpStats.minRtt
		metricUpdate.Mss = &d.TcpStats.mss
		metricUpdate.TcpMetric = metric.TCPValue{
			DeltaTotalRetrans:   d.TcpStats.totalRetrans.Delta(),
			DeltaLostOut:        d.TcpStats.lostOut.Delta(),
			DeltaUnRecoveredRTO: d.TcpStats.unRecoveredRTO.Delta(),
		}
	}

	return metricUpdate
}

// metricUpdateIngressNoConn creates a metric update for Inbound non-connection traffic
func (d *Data) MetricUpdateIngressNoConn(ut metric.UpdateType, isTransit bool) metric.Update {
	metricDstServiceInfo := metric.ServiceInfo{
		ServicePortName: d.DstSvc,
		PortNum:         d.PreDNATPort,
	}

	metricUpdate := metric.Update{
		UpdateType:      ut,
		Tuple:           d.Tuple,
		NatOutgoingPort: d.NatOutgoingPort,
		SrcEp:           d.SrcEp,
		DstEp:           d.DstEp,
		DstService:      metricDstServiceInfo,
		RuleIDs:         d.IngressRuleTrace.Path(),
		TransitRuleIDs:  d.IngressTransitRuleTrace.Path(),
		HasDenyRule:     d.IngressRuleTrace.HasDenyRule() || d.IngressTransitRuleTrace.HasDenyRule(),
		PendingRuleIDs:  d.IngressPendingRuleIDs,
		IsConnection:    d.IsConnection,
		ProcessName:     d.DestProcessData().Name,
		ProcessID:       d.DestProcessData().Pid,
		ProcessArgs:     d.DestProcessData().Arguments,
	}
	if d.TcpStats.dirty {
		metricUpdate.SendCongestionWnd = &d.TcpStats.sendCongestionWnd
		metricUpdate.SmoothRtt = &d.TcpStats.smoothRtt
		metricUpdate.MinRtt = &d.TcpStats.minRtt
		metricUpdate.Mss = &d.TcpStats.mss
		metricUpdate.TcpMetric = metric.TCPValue{
			DeltaTotalRetrans:   d.TcpStats.totalRetrans.Delta(),
			DeltaLostOut:        d.TcpStats.lostOut.Delta(),
			DeltaUnRecoveredRTO: d.TcpStats.unRecoveredRTO.Delta(),
		}
	}

	if isTransit {
		metricUpdate.InTransitMetric = metric.Value{
			DeltaPackets: d.IngressTransitRuleTrace.pktsCtr.Delta(),
			DeltaBytes:   d.IngressTransitRuleTrace.bytesCtr.Delta(),
		}
	} else {
		metricUpdate.InMetric = metric.Value{
			DeltaPackets: d.IngressRuleTrace.pktsCtr.Delta(),
			DeltaBytes:   d.IngressRuleTrace.bytesCtr.Delta(),
		}
	}
	return metricUpdate
}

// metricUpdateEgressNoConn creates a metric update for Outbound non-connection traffic
func (d *Data) MetricUpdateEgressNoConn(ut metric.UpdateType, isTransit bool) metric.Update {
	metricDstServiceInfo := metric.ServiceInfo{
		ServicePortName: d.DstSvc,
		PortNum:         d.PreDNATPort,
	}

	metricUpdate := metric.Update{
		UpdateType:      ut,
		Tuple:           d.Tuple,
		NatOutgoingPort: d.NatOutgoingPort,
		SrcEp:           d.SrcEp,
		DstEp:           d.DstEp,
		DstService:      metricDstServiceInfo,
		DstDomains:      d.DestDomains,
		RuleIDs:         d.EgressRuleTrace.Path(),
		TransitRuleIDs:  d.EgressTransitRuleTrace.Path(),
		HasDenyRule:     d.EgressRuleTrace.HasDenyRule() || d.EgressTransitRuleTrace.HasDenyRule(),
		PendingRuleIDs:  d.EgressPendingRuleIDs,
		IsConnection:    d.IsConnection,
		ProcessName:     d.SourceProcessData().Name,
		ProcessID:       d.SourceProcessData().Pid,
		ProcessArgs:     d.SourceProcessData().Arguments,
	}
	if d.TcpStats.dirty {
		metricUpdate.SendCongestionWnd = &d.TcpStats.sendCongestionWnd
		metricUpdate.SmoothRtt = &d.TcpStats.smoothRtt
		metricUpdate.MinRtt = &d.TcpStats.minRtt
		metricUpdate.Mss = &d.TcpStats.mss
		metricUpdate.TcpMetric = metric.TCPValue{
			DeltaTotalRetrans:   d.TcpStats.totalRetrans.Delta(),
			DeltaLostOut:        d.TcpStats.lostOut.Delta(),
			DeltaUnRecoveredRTO: d.TcpStats.unRecoveredRTO.Delta(),
		}
	}

	if isTransit {
		metricUpdate.OutTransitMetric = metric.Value{
			DeltaPackets: d.EgressTransitRuleTrace.pktsCtr.Delta(),
			DeltaBytes:   d.EgressTransitRuleTrace.bytesCtr.Delta(),
		}
	} else {
		metricUpdate.OutMetric = metric.Value{
			DeltaPackets: d.EgressRuleTrace.pktsCtr.Delta(),
			DeltaBytes:   d.EgressRuleTrace.bytesCtr.Delta(),
		}
	}

	return metricUpdate
}

// metricUpdateOrigSourceIPs creates a metric update for HTTP Data (original source ips).
func (d *Data) MetricUpdateOrigSourceIPs(ut metric.UpdateType) metric.Update {
	// We send Original Source IP updates as standalone metric updates.
	// If however we can't find out the rule trace then we also include
	// an unknown rule ID that the rest of the  metric pipeline uses to
	// extract action and direction.
	var unknownRuleID *calc.RuleID
	if !d.IngressRuleTrace.FoundVerdict() {
		unknownRuleID = calc.NewRuleID(calc.UnknownStr, calc.UnknownStr, calc.UnknownStr, calc.UnknownStr, calc.RuleIDIndexUnknown, rules.RuleDirIngress, rules.RuleActionAllow)
	}

	metricDstServiceInfo := metric.ServiceInfo{
		ServicePortName: d.DstSvc,
		PortNum:         d.PreDNATPort,
	}

	mu := metric.Update{
		UpdateType:      ut,
		Tuple:           d.Tuple,
		NatOutgoingPort: d.NatOutgoingPort,
		SrcEp:           d.SrcEp,
		DstEp:           d.DstEp,
		DstService:      metricDstServiceInfo,
		OrigSourceIPs:   d.origSourceIPs.Copy(),
		RuleIDs:         d.IngressRuleTrace.Path(),
		HasDenyRule:     d.IngressRuleTrace.HasDenyRule() || d.IngressTransitRuleTrace.HasDenyRule(),
		UnknownRuleID:   unknownRuleID,
		IsConnection:    d.IsConnection,
		ProcessName:     d.DestProcessData().Name,
		ProcessID:       d.DestProcessData().Pid,
		ProcessArgs:     d.DestProcessData().Arguments,
	}
	if d.TcpStats.dirty {
		mu.SendCongestionWnd = &d.TcpStats.sendCongestionWnd
		mu.SmoothRtt = &d.TcpStats.smoothRtt
		mu.MinRtt = &d.TcpStats.minRtt
		mu.Mss = &d.TcpStats.mss
		mu.TcpMetric = metric.TCPValue{
			DeltaTotalRetrans:   d.TcpStats.totalRetrans.Delta(),
			DeltaLostOut:        d.TcpStats.lostOut.Delta(),
			DeltaUnRecoveredRTO: d.TcpStats.unRecoveredRTO.Delta(),
		}
	}
	d.origSourceIPs.Reset()
	return mu
}

func (d *Data) SetTcpSocketStats(tcpStats types.TcpStatsData) {
	d.TcpStats.sendCongestionWnd = tcpStats.SendCongestionWnd
	d.TcpStats.smoothRtt = tcpStats.SmoothRtt
	d.TcpStats.minRtt = tcpStats.MinRtt
	d.TcpStats.mss = tcpStats.Mss
	d.setTCPCounters(tcpStats.TotalRetrans, tcpStats.LostOut, tcpStats.UnrecoveredRTO)
	d.TcpStats.dirty = true
	d.setDirtyFlag()
	d.touch()
}
