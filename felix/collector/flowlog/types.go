// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.

package flowlog

import (
	"container/list"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types/boundedset"
	"github.com/projectcalico/calico/felix/collector/types/endpoint"
	"github.com/projectcalico/calico/felix/collector/types/metric"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/collector/utils"
	logutil "github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const (
	unsetIntField = -1
)

type empty struct{}

var emptyValue = empty{}

var (
	EmptyService = FlowService{"-", "-", "-", 0}
	EmptyIP      = [16]byte{}

	rlog1 = logutils.NewRateLimitedLogger()
	rlog2 = logutils.NewRateLimitedLogger()
)

type (
	Action       string
	ReporterType string
)

type FlowService struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	PortName  string `json:"port_name"`
	PortNum   int    `json:"port_num"`
}

type FlowMeta struct {
	Tuple      tuple.Tuple       `json:"tuple"`
	SrcMeta    endpoint.Metadata `json:"sourceMeta"`
	DstMeta    endpoint.Metadata `json:"destinationMeta"`
	DstService FlowService       `json:"destinationService"`
	Action     Action            `json:"action"`
	Reporter   ReporterType      `json:"flowReporter"`
}

type TCPRtt struct {
	Mean int `json:"mean"`
	Max  int `json:"max"`
}

type TCPWnd struct {
	Mean int `json:"mean"`
	Min  int `json:"min"`
}

type TCPMss struct {
	Mean int `json:"mean"`
	Min  int `json:"min"`
}

func newFlowMeta(mu metric.Update, includeService bool) (FlowMeta, error) {
	f := FlowMeta{}

	// Extract Tuple Info
	f.Tuple = mu.Tuple

	// Extract EndpointMetadata info
	srcMeta, err := endpoint.GetMetadata(mu.SrcEp, mu.Tuple.Src)
	if err != nil {
		return FlowMeta{}, fmt.Errorf("could not extract metadata for source %v", mu.SrcEp)
	}
	dstMeta, err := endpoint.GetMetadata(mu.DstEp, mu.Tuple.Dst)
	if err != nil {
		return FlowMeta{}, fmt.Errorf("could not extract metadata for destination %v", mu.DstEp)
	}

	f.SrcMeta = srcMeta
	f.DstMeta = dstMeta

	if includeService {
		f.DstService = getService(mu.DstService)
	} else {
		f.DstService = EmptyService
	}

	lastRuleID := mu.GetLastRuleID()
	lastTransitRuleID := mu.GetLastTransitRuleID()
	if lastRuleID == nil && lastTransitRuleID == nil {
		log.WithField("metric update", mu).Error("no rule id present")
		return f, fmt.Errorf("invalid metric update")
	}

	action, reporter := getActionAndReporterFromRuleID(lastRuleID, lastTransitRuleID)
	f.Action = action
	f.Reporter = reporter
	return f, nil
}

func newFlowMetaWithSourcePortAggregation(mu metric.Update, includeService bool) (FlowMeta, error) {
	f, err := newFlowMeta(mu, includeService)
	if err != nil {
		return FlowMeta{}, err
	}
	f.Tuple.L4Src = unsetIntField
	return f, nil
}

func newFlowMetaWithPrefixNameAggregation(mu metric.Update, includeService bool) (FlowMeta, error) {
	f, err := newFlowMeta(mu, includeService)
	if err != nil {
		return FlowMeta{}, err
	}
	f.Tuple.Src = EmptyIP
	f.Tuple.L4Src = unsetIntField
	f.Tuple.Dst = EmptyIP
	f.SrcMeta.Name = FieldNotIncluded
	f.DstMeta.Name = FieldNotIncluded
	return f, nil
}

func newFlowMetaWithNoDestPortsAggregation(mu metric.Update, includeService bool) (FlowMeta, error) {
	f, err := newFlowMeta(mu, includeService)
	if err != nil {
		return FlowMeta{}, err
	}
	f.Tuple.Src = EmptyIP
	f.Tuple.L4Src = unsetIntField
	f.Tuple.L4Dst = unsetIntField
	f.Tuple.Dst = EmptyIP
	f.SrcMeta.Name = FieldNotIncluded
	f.DstMeta.Name = FieldNotIncluded
	f.DstService.PortName = FieldNotIncluded
	return f, nil
}

func NewFlowMeta(mu metric.Update, kind AggregationKind, includeService bool) (FlowMeta, error) {
	switch kind {
	case FlowDefault:
		return newFlowMeta(mu, includeService)
	case FlowSourcePort:
		return newFlowMetaWithSourcePortAggregation(mu, includeService)
	case FlowPrefixName:
		return newFlowMetaWithPrefixNameAggregation(mu, includeService)
	case FlowNoDestPorts:
		return newFlowMetaWithNoDestPortsAggregation(mu, includeService)
	}
	return FlowMeta{}, fmt.Errorf("aggregation kind %v not recognized", kind)
}

type FlowSpec struct {
	FlowStatsByProcess
	flowExtrasRef
	FlowLabels
	FlowAllPolicySets
	FlowEnforcedPolicySets
	FlowPendingPolicySet
	FlowTransitPolicySet
	FlowDestDomains

	// Reset aggregated data on the next metric update to ensure we clear out obsolete labels, policies and Domains for
	// connections that are not actively part of the flow during the export interval.
	resetAggrData bool
}

func NewFlowSpec(mu *metric.Update, maxOriginalIPsSize, maxDomains int, includeProcess bool, processLimit, processArgsLimit int, displayDebugTraceLogs bool, natOutgoingPortLimit int) *FlowSpec {
	// NewFlowStatsByProcess potentially needs to update fields in mu *metric.Update hence passing it by pointer
	// TODO: reconsider/refactor the inner functions called in NewFlowStatsByProcess to avoid above scenario
	return &FlowSpec{
		FlowLabels:             NewFlowLabels(*mu),
		FlowAllPolicySets:      NewFlowAllPolicySets(*mu),
		FlowEnforcedPolicySets: NewFlowEnforcedPolicySets(*mu),
		FlowPendingPolicySet:   NewFlowPendingPolicySet(*mu),
		FlowTransitPolicySet:   NewFlowTransitPolicySet(*mu),
		FlowStatsByProcess:     NewFlowStatsByProcess(mu, includeProcess, processLimit, processArgsLimit, displayDebugTraceLogs, natOutgoingPortLimit),
		flowExtrasRef:          NewFlowExtrasRef(*mu, maxOriginalIPsSize),
		FlowDestDomains:        NewFlowDestDomains(*mu, maxDomains),
	}
}

func (f *FlowSpec) ContainsActiveRefs(mu *metric.Update) bool {
	return f.containsActiveRefs(mu)
}

func (f *FlowSpec) ToFlowLogs(fm FlowMeta, startTime, endTime time.Time, includeLabels bool, includePolicies bool) []*FlowLog {
	stats := f.toFlowProcessReportedStats()

	flogs := make([]*FlowLog, 0, len(stats))
	for _, stat := range stats {
		fl := &FlowLog{
			FlowMeta:                 fm,
			StartTime:                startTime,
			EndTime:                  endTime,
			FlowProcessReportedStats: stat,
			FlowDestDomains:          f.FlowDestDomains,
		}
		if f.originalSourceIPs != nil {
			fe := FlowExtras{
				OriginalSourceIPs:    f.originalSourceIPs.ToIPSlice(),
				NumOriginalSourceIPs: f.originalSourceIPs.TotalCount(),
			}
			fl.FlowExtras = fe
		}

		if includeLabels {
			fl.FlowLabels = f.FlowLabels
		}

		if !includePolicies {
			fl.FlowAllPolicySet = nil
			fl.FlowEnforcedPolicySet = nil
			fl.FlowPendingPolicySet = nil
			fl.FlowTransitPolicySet = nil
			flogs = append(flogs, fl)
		} else {
			if len(f.FlowAllPolicySets) > 1 {
				rlog1.WithField("FlowLog", fl).Warning("Flow was split into multiple flow logs since multiple policy sets were observed for the same flow. Possible causes: policy updates during log aggregation or NFLOG buffer overruns.")
			}
			allAndEnforcedPolicySetLengthsEqual := len(f.FlowAllPolicySets) == len(f.FlowEnforcedPolicySets)
			if !allAndEnforcedPolicySetLengthsEqual {
				rlog2.WithField("FlowLog", fl).Warning("Flow has different number of all and enforced policy sets. This should not happen. Only the all_policy traces will be included in the flow logs.")
			}
			// Create a flow log for each all_policies set, include the corresponding
			// enforced and pending.
			for i, ps := range f.FlowAllPolicySets {
				cpfl := *fl
				cpfl.FlowAllPolicySet = ps
				// The enforced policy set should always be the same length as the all policy set.
				// If they do not, then we can't guarantee that the pairings will be printed
				// correctly, so only include the all_policies.
				if allAndEnforcedPolicySetLengthsEqual {
					cpfl.FlowEnforcedPolicySet = f.FlowEnforcedPolicySets[i]
				}
				// The pending policy is calculated once per flush interval. The latest pending
				// policy will replace the previous one. The same pending policy will be depicted
				// across all flow logs.
				cpfl.FlowPendingPolicySet = FlowPolicySet(f.FlowPendingPolicySet)
				// The latest transit policy will replace the previous one. The same transit policy will
				// be depicted across all flow logs.
				cpfl.FlowTransitPolicySet = FlowPolicySet(f.FlowTransitPolicySet)
				flogs = append(flogs, &cpfl)
			}
		}

	}
	return flogs
}

func (f *FlowSpec) AggregateMetricUpdate(mu *metric.Update) {
	if f.resetAggrData {
		// Reset the aggregated data from this metric update.
		f.FlowAllPolicySets = nil
		f.FlowEnforcedPolicySets = nil
		f.FlowPendingPolicySet = nil
		f.FlowTransitPolicySet = nil
		f.SrcLabels = uniquelabels.Nil
		f.DstLabels = uniquelabels.Nil
		f.FlowDestDomains.reset()
		f.resetAggrData = false
	}
	f.aggregateFlowLabels(*mu)
	f.aggregateFlowAllPolicySets(*mu)
	f.aggregateFlowEnforcedPolicySets(*mu)
	f.aggregateFlowDestDomains(*mu)
	f.aggregateFlowExtrasRef(*mu)
	f.aggregateFlowStatsByProcess(mu)

	f.replaceFlowPendingPolicySet(*mu)
	f.replaceFlowTransitPolicySet(*mu)
}

// MergeWith merges two flow specs. This means copying the flowRefsActive that contains a reference
// to the original tuple that identifies the traffic. This help keeping the same numFlows counts while
// changing aggregation levels
func (f *FlowSpec) MergeWith(mu metric.Update, other *FlowSpec) {
	if stats, ok := f.statsByProcessName[mu.ProcessName]; ok {
		if otherStats, ok := other.statsByProcessName[mu.ProcessName]; ok {
			for tuple := range otherStats.flowsRefsActive {
				stats.flowsRefsActive.AddWithValue(tuple, mu.NatOutgoingPort)
				stats.flowsRefs.AddWithValue(tuple, mu.NatOutgoingPort)
			}
			stats.NumFlows = stats.flowsRefs.Len()
			// TODO(doublek): Merge processIDs.
		}
	}
}

// FlowSpec has FlowStats that are stats assocated with a given FlowMeta
// These stats are to be refreshed everytime the FlowData
// {FlowMeta->FlowStats} is published so as to account
// for correct no. of started flows in a given aggregation
// interval.
//
// This also resets policy and label data which will be re-populated from metric updates for the still active
// flows.
func (f *FlowSpec) Reset() {
	f.FlowStatsByProcess.reset()
	f.flowExtrasRef.reset()

	// Set the reset flag. We'll reset the aggregated data on the next metric update - that way we don't completely
	// zero out the labels and policies if there is no traffic for an export interval.
	f.resetAggrData = true
}

func (f *FlowSpec) GetActiveFlowsCount() int {
	return f.getActiveFlowsCount()
}

// GarbageCollect provides a chance to remove process names and corresponding stats that don't have
// any active flows being tracked.
// As an added optimization, we also return the remaining active flows so that we don't have to
// iterate over all the flow stats grouped by processes a second time.
func (f *FlowSpec) GarbageCollect() int {
	return f.gc()
}

type FlowLabels struct {
	SrcLabels uniquelabels.Map
	DstLabels uniquelabels.Map
}

func NewFlowLabels(mu metric.Update) FlowLabels {
	return FlowLabels{
		SrcLabels: endpoint.GetLabels(mu.SrcEp),
		DstLabels: endpoint.GetLabels(mu.DstEp),
	}
}

func (f *FlowLabels) aggregateFlowLabels(mu metric.Update) {
	srcLabels := endpoint.GetLabels(mu.SrcEp)
	dstLabels := endpoint.GetLabels(mu.DstEp)

	// The flow labels are reset on calibration, so either copy the labels or intersect them.
	if f.SrcLabels.IsNil() {
		f.SrcLabels = srcLabels
	} else {
		f.SrcLabels = utils.IntersectAndFilterLabels(srcLabels, f.SrcLabels)
	}

	if f.DstLabels.IsNil() {
		f.DstLabels = dstLabels
	} else {
		f.DstLabels = utils.IntersectAndFilterLabels(dstLabels, f.DstLabels)
	}
}

type FlowPolicySet map[string]empty

func newPolicySet(ruleIDs []*calc.RuleID, includeStaged bool) FlowPolicySet {
	fp := make(FlowPolicySet)
	if ruleIDs == nil {
		return fp
	}
	pIdx, nsp := 0, 0
	for idx, rid := range ruleIDs {
		if rid == nil {
			continue
		}
		if !includeStaged {
			if model.PolicyIsStaged(rid.Name) {
				nsp++
				continue
			}
			pIdx = idx - nsp
		} else {
			pIdx = idx
		}

		fp[fmt.Sprintf("%d|%s|%s", pIdx, rid.GetFlowLogPolicyName(), rid.IndexStr)] = emptyValue
	}
	return fp
}

type FlowPolicySets []FlowPolicySet

func NewFlowPolicySets(ruleIDs []*calc.RuleID, includeStaged bool) FlowPolicySets {
	fp := newPolicySet(ruleIDs, includeStaged)
	return FlowPolicySets{fp}
}

func (fpl *FlowPolicySets) aggregateFlowPolicySets(ruleIDs []*calc.RuleID, includeStaged bool) {
	fp := newPolicySet(ruleIDs, includeStaged)
	for _, existing := range *fpl {
		if reflect.DeepEqual(existing, fp) {
			return
		}
	}
	*fpl = append(*fpl, fp)
}

// FlowAllPolicySets keeps track of all policy traces associated with a flow.
type FlowAllPolicySets FlowPolicySets

func NewFlowAllPolicySets(mu metric.Update) FlowAllPolicySets {
	return FlowAllPolicySets(NewFlowPolicySets(mu.RuleIDs, true))
}

func (fpl *FlowAllPolicySets) aggregateFlowAllPolicySets(mu metric.Update) {
	(*FlowPolicySets)(fpl).aggregateFlowPolicySets(mu.RuleIDs, true)
}

// FlowEnforcedPolicySets keeps track of enforced policy traces associated with a flow.
type FlowEnforcedPolicySets FlowPolicySets

func NewFlowEnforcedPolicySets(mu metric.Update) FlowEnforcedPolicySets {
	return FlowEnforcedPolicySets(NewFlowPolicySets(mu.RuleIDs, false))
}

func (fpl *FlowEnforcedPolicySets) aggregateFlowEnforcedPolicySets(mu metric.Update) {
	(*FlowPolicySets)(fpl).aggregateFlowPolicySets(mu.RuleIDs, false)
}

// FlowPendingPolicySet keeps track of pending policy traces associated with a flow.
type FlowPendingPolicySet FlowPolicySet

func NewFlowPendingPolicySet(mu metric.Update) FlowPendingPolicySet {
	return FlowPendingPolicySet(newPolicySet(mu.PendingRuleIDs, true))
}

func (fpl *FlowPendingPolicySet) replaceFlowPendingPolicySet(mu metric.Update) {
	*fpl = NewFlowPendingPolicySet(mu)
}

// FlowTransitPolicySet tracks transit policy enforcement for network flows, specifically PreDNAT
// and ApplyOnForward policies enforced during packet transit through the node.
type FlowTransitPolicySet FlowPolicySet

func NewFlowTransitPolicySet(mu metric.Update) FlowTransitPolicySet {
	return FlowTransitPolicySet(newPolicySet(mu.TransitRuleIDs, true))
}

func (fpl *FlowTransitPolicySet) replaceFlowTransitPolicySet(mu metric.Update) {
	*fpl = NewFlowTransitPolicySet(mu)
}

type FlowDestDomains struct {
	maxDomains int
	Domains    map[string]empty
}

func NewFlowDestDomains(mu metric.Update, maxDomains int) FlowDestDomains {
	fp := FlowDestDomains{
		maxDomains: maxDomains,
	}
	fp.aggregateFlowDestDomains(mu)
	return fp
}

func (fp *FlowDestDomains) aggregateFlowDestDomains(mu metric.Update) {
	if len(mu.DstDomains) == 0 {
		return
	}
	if fp.Domains == nil {
		fp.Domains = make(map[string]empty)
	}
	if len(fp.Domains) >= fp.maxDomains {
		return
	}
	for _, name := range mu.DstDomains {
		fp.Domains[name] = emptyValue
		if len(fp.Domains) >= fp.maxDomains {
			return
		}
	}
}

func (fp *FlowDestDomains) reset() {
	fp.Domains = nil
}

type flowExtrasRef struct {
	originalSourceIPs *boundedset.BoundedSet
}

func NewFlowExtrasRef(mu metric.Update, maxOriginalIPsSize int) flowExtrasRef {
	var osip *boundedset.BoundedSet
	if mu.OrigSourceIPs != nil {
		osip = boundedset.NewFromSliceWithTotalCount(maxOriginalIPsSize, mu.OrigSourceIPs.ToIPSlice(), mu.OrigSourceIPs.TotalCount())
	} else {
		osip = boundedset.New(maxOriginalIPsSize)
	}
	return flowExtrasRef{originalSourceIPs: osip}
}

func (fer *flowExtrasRef) aggregateFlowExtrasRef(mu metric.Update) {
	if mu.OrigSourceIPs != nil {
		fer.originalSourceIPs.Combine(mu.OrigSourceIPs)
	}
}

func (fer *flowExtrasRef) reset() {
	if fer.originalSourceIPs != nil {
		fer.originalSourceIPs.Reset()
	}
}

// FlowExtras contains some additional useful information for flows.
type FlowExtras struct {
	OriginalSourceIPs    []net.IP `json:"originalSourceIPs"`
	NumOriginalSourceIPs int      `json:"numOriginalSourceIPs"`
}

// flowReferences are internal only stats used for computing numbers of flows
type flowReferences struct {
	// The set of unique flows that were started within the reporting interval. This is added to when a new flow
	// (i.e. one that is not currently active) is reported during the reporting interval. It is reset when the
	// flow data is reported.
	flowsStartedRefs tuple.Set
	// The set of unique flows that were completed within the reporting interval. This is added to when a flow
	// termination is reported during the reporting interval. It is reset when the flow data is reported.
	flowsCompletedRefs tuple.Set
	// The current set of active flows. The set may increase and decrease during the reporting interval.
	flowsRefsActive tuple.Set
	// The set of unique flows that have been active at any point during the reporting interval. This is added
	// to during the reporting interval, and is reset to the set of active flows when the flow data is reported.
	flowsRefs tuple.Set
}

// FlowReportedStats are the statistics we actually report out in flow logs.
type FlowReportedStats struct {
	BytesIn               int `json:"bytesIn"`
	BytesOut              int `json:"bytesOut"`
	PacketsIn             int `json:"packetsIn"`
	PacketsOut            int `json:"packetsOut"`
	TransitBytesIn        int `json:"transitBytesIn"`
	TransitBytesOut       int `json:"transitBytesOut"`
	TransitPacketsIn      int `json:"transitPacketsIn"`
	TransitPacketsOut     int `json:"transitPacketsOut"`
	HTTPRequestsAllowedIn int `json:"httpRequestsAllowedIn"`
	HTTPRequestsDeniedIn  int `json:"httpRequestsDeniedIn"`
	NumFlows              int `json:"numFlows"`
	NumFlowsStarted       int `json:"numFlowsStarted"`
	NumFlowsCompleted     int `json:"numFlowsCompleted"`
}

// FlowReportedTCPSocketStats
type FlowReportedTCPStats struct {
	Count             int    `json:"count"`
	SendCongestionWnd TCPWnd `json:"sendCongestionWnd"`
	SmoothRtt         TCPRtt `json:"smoothRtt"`
	MinRtt            TCPRtt `json:"minRtt"`
	Mss               TCPMss `json:"mss"`
	TotalRetrans      int    `json:"totalRetrans"`
	LostOut           int    `json:"lostOut"`
	UnrecoveredRTO    int    `json:"unrecoveredRTO"`
}

func (f *FlowReportedStats) Add(other FlowReportedStats) {
	f.BytesIn += other.BytesIn
	f.BytesOut += other.BytesOut
	f.PacketsIn += other.PacketsIn
	f.PacketsOut += other.PacketsOut
	f.TransitBytesIn += other.TransitBytesIn
	f.TransitBytesOut += other.TransitBytesOut
	f.TransitPacketsIn += other.TransitPacketsIn
	f.TransitPacketsOut += other.TransitPacketsOut
	f.HTTPRequestsAllowedIn += other.HTTPRequestsAllowedIn
	f.HTTPRequestsDeniedIn += other.HTTPRequestsDeniedIn
	f.NumFlows += other.NumFlows
	f.NumFlowsStarted += other.NumFlowsStarted
	f.NumFlowsCompleted += other.NumFlowsCompleted
}

func (f *FlowReportedTCPStats) Add(other FlowReportedTCPStats) {
	if f.Count == 0 {
		f.SendCongestionWnd.Min = other.SendCongestionWnd.Min
		f.SendCongestionWnd.Mean = other.SendCongestionWnd.Mean

		f.SmoothRtt.Max = other.SmoothRtt.Max
		f.SmoothRtt.Mean = other.SmoothRtt.Mean

		f.MinRtt.Max = other.MinRtt.Max
		f.MinRtt.Mean = other.MinRtt.Mean

		f.Mss.Min = other.Mss.Min
		f.Mss.Mean = other.Mss.Mean

		f.LostOut = other.LostOut
		f.TotalRetrans = other.TotalRetrans
		f.UnrecoveredRTO = other.UnrecoveredRTO
		f.Count = 1
		return
	}

	if other.SendCongestionWnd.Min < f.SendCongestionWnd.Min {
		f.SendCongestionWnd.Min = other.SendCongestionWnd.Min
	}
	f.SendCongestionWnd.Mean = ((f.SendCongestionWnd.Mean * f.Count) +
		(other.SendCongestionWnd.Mean * other.Count)) /
		(f.Count + other.Count)

	if f.SmoothRtt.Max < other.SmoothRtt.Max {
		f.SmoothRtt.Max = other.SmoothRtt.Max
	}
	f.SmoothRtt.Mean = ((f.SmoothRtt.Mean * f.Count) +
		(other.SmoothRtt.Mean * other.Count)) /
		(f.Count + other.Count)

	if f.MinRtt.Max < other.MinRtt.Max {
		f.MinRtt.Max = other.MinRtt.Max
	}
	f.MinRtt.Mean = ((f.MinRtt.Mean * f.Count) +
		(other.MinRtt.Mean * other.Count)) /
		(f.Count + other.Count)

	if other.Mss.Min < f.Mss.Min {
		f.Mss.Min = other.Mss.Min
	}
	f.Mss.Mean = ((f.Mss.Mean * f.Count) +
		(other.Mss.Mean * other.Count)) /
		(f.Count + other.Count)

	f.TotalRetrans += other.TotalRetrans
	f.LostOut += other.LostOut
	f.UnrecoveredRTO += other.UnrecoveredRTO
	f.Count += other.Count
}

// FlowStats captures stats associated with a given FlowMeta.
type FlowStats struct {
	FlowReportedStats
	FlowReportedTCPStats
	flowReferences
	processIDs  set.Set[string]
	processArgs set.Set[string]

	// Reset Process IDs  on the next metric update aggregation cycle. this ensures that we only clear
	// process ID information when we receive a new metric update.
	resetProcessIDs bool
}

func NewFlowStats(mu metric.Update) FlowStats {
	flowsRefs := tuple.NewSet()
	flowsRefs.AddWithValue(mu.Tuple, mu.NatOutgoingPort)
	flowsStartedRefs := tuple.NewSet()
	flowsCompletedRefs := tuple.NewSet()
	flowsRefsActive := tuple.NewSet()

	switch mu.UpdateType {
	case metric.UpdateTypeReport:
		flowsStartedRefs.AddWithValue(mu.Tuple, mu.NatOutgoingPort)
		flowsRefsActive.AddWithValue(mu.Tuple, mu.NatOutgoingPort)
	case metric.UpdateTypeExpire:
		flowsCompletedRefs.AddWithValue(mu.Tuple, mu.NatOutgoingPort)
	}

	pids := set.New[string]()
	pids.Add(strconv.Itoa(mu.ProcessID))

	processArgs := set.New[string]()
	if mu.ProcessArgs != "" {
		processArgs.Add(mu.ProcessArgs)
	}

	flowStats := FlowStats{
		FlowReportedStats: FlowReportedStats{
			NumFlows:              flowsRefs.Len(),
			NumFlowsStarted:       flowsStartedRefs.Len(),
			NumFlowsCompleted:     flowsCompletedRefs.Len(),
			PacketsIn:             mu.InMetric.DeltaPackets,
			BytesIn:               mu.InMetric.DeltaBytes,
			PacketsOut:            mu.OutMetric.DeltaPackets,
			BytesOut:              mu.OutMetric.DeltaBytes,
			TransitPacketsIn:      mu.InTransitMetric.DeltaPackets,
			TransitBytesIn:        mu.InTransitMetric.DeltaBytes,
			TransitPacketsOut:     mu.OutTransitMetric.DeltaPackets,
			TransitBytesOut:       mu.OutTransitMetric.DeltaBytes,
			HTTPRequestsAllowedIn: mu.InMetric.DeltaAllowedHTTPRequests,
			HTTPRequestsDeniedIn:  mu.InMetric.DeltaDeniedHTTPRequests,
		},
		flowReferences: flowReferences{
			// flowsRefs track the flows that were tracked
			// in the give interval
			flowsRefs:          flowsRefs,
			flowsStartedRefs:   flowsStartedRefs,
			flowsCompletedRefs: flowsCompletedRefs,
			// flowsRefsActive tracks the active (non-completed)
			// flows associated with the flowMeta
			flowsRefsActive: flowsRefsActive,
		},
		processIDs:  pids,
		processArgs: processArgs,
	}
	// Here we check if the metric update has a valid TCP stats.
	// If the TCP stats is not valid (example: config is disabled),
	// it is indicated by one of sendCongestionWnd, smoothRtt, minRtt, Mss
	// being nil. Hence it is enough if we compare one of the above with nil
	if mu.SendCongestionWnd != nil {
		flowStats.SendCongestionWnd = TCPWnd{Mean: *mu.SendCongestionWnd, Min: *mu.SendCongestionWnd}
		flowStats.SmoothRtt = TCPRtt{Mean: *mu.SmoothRtt, Max: *mu.SmoothRtt}
		flowStats.MinRtt = TCPRtt{Mean: *mu.MinRtt, Max: *mu.MinRtt}
		flowStats.Mss = TCPMss{Mean: *mu.Mss, Min: *mu.Mss}
		flowStats.TotalRetrans = mu.TcpMetric.DeltaTotalRetrans
		flowStats.LostOut = mu.TcpMetric.DeltaLostOut
		flowStats.UnrecoveredRTO = mu.TcpMetric.DeltaUnRecoveredRTO
		flowStats.Count = 1
	}
	return flowStats
}

func (f *FlowStats) aggregateFlowTCPStats(mu metric.Update, displayDebugTraceLogs bool) {
	logutil.Tracef(displayDebugTraceLogs, "Aggregrate TCP stats %+v with flow %+v", mu, f)
	// Here we check if the metric update has a valid TCP stats.
	// If the TCP stats is not valid (example: config is disabled),
	// it is indicated by one of sendCongestionWnd, smoothRtt, minRtt, Mss
	// being nil. Hence it is enough if we compare one of the above with nil
	if mu.SendCongestionWnd == nil {
		return
	}
	if f.Count == 0 {
		f.SendCongestionWnd.Min = *mu.SendCongestionWnd
		f.SendCongestionWnd.Mean = *mu.SendCongestionWnd
		f.Count = 1

		f.SmoothRtt.Max = *mu.SmoothRtt
		f.SmoothRtt.Mean = *mu.SmoothRtt
		f.Count = 1

		f.MinRtt.Max = *mu.MinRtt
		f.MinRtt.Mean = *mu.MinRtt
		f.Count = 1

		f.Mss.Min = *mu.Mss
		f.Mss.Mean = *mu.Mss
		f.Count = 1

		f.LostOut = mu.TcpMetric.DeltaLostOut
		f.TotalRetrans = mu.TcpMetric.DeltaTotalRetrans
		f.UnrecoveredRTO = mu.TcpMetric.DeltaUnRecoveredRTO
		return
	}
	// Calculate Mean, Min of Send congestion window
	if *mu.SendCongestionWnd < f.SendCongestionWnd.Min {
		f.SendCongestionWnd.Min = *mu.SendCongestionWnd
	}
	f.SendCongestionWnd.Mean = ((f.SendCongestionWnd.Mean * f.Count) +
		*mu.SendCongestionWnd) / (f.Count + 1)

	// Calculate Mean, Max of Smooth Rtt
	if *mu.SmoothRtt > f.SmoothRtt.Max {
		f.SmoothRtt.Max = *mu.SmoothRtt
	}
	f.SmoothRtt.Mean = ((f.SmoothRtt.Mean * f.Count) +
		*mu.SmoothRtt) / (f.Count + 1)

	// Calculate Mean, Max of Min Rtt
	if *mu.MinRtt > f.MinRtt.Max {
		f.MinRtt.Max = *mu.MinRtt
	}
	f.MinRtt.Mean = ((f.MinRtt.Mean * f.Count) +
		*mu.MinRtt) / (f.Count + 1)

	// Calculate Mean,Min of MSS
	if *mu.Mss < f.Mss.Min {
		f.Mss.Min = *mu.Mss
	}
	f.Mss.Mean = ((f.Mss.Mean * f.Count) +
		*mu.Mss) / (f.Count + 1)

	f.TotalRetrans += mu.TcpMetric.DeltaTotalRetrans
	f.LostOut += mu.TcpMetric.DeltaLostOut
	f.UnrecoveredRTO += mu.TcpMetric.DeltaUnRecoveredRTO
	f.Count += 1
}

func (f *FlowStats) aggregateFlowStats(mu metric.Update, displayDebugTraceLogs bool) {
	if f.resetProcessIDs {
		// Only clear process IDs when aggregating a new metric update and after
		// a prior export.
		f.processIDs.Clear()
		f.processArgs.Clear()
		f.resetProcessIDs = false
	}
	switch mu.UpdateType {
	case metric.UpdateTypeReport:
		// Add / update the flowStartedRefs if we either haven't seen this tuple before OR the tuple is already in the
		// flowStartRefs (we may have an updated value).
		if !f.flowsRefsActive.Contains(mu.Tuple) || f.flowsStartedRefs.Contains(mu.Tuple) {
			f.flowsStartedRefs.AddWithValue(mu.Tuple, mu.NatOutgoingPort)
		}

		f.flowsRefsActive.AddWithValue(mu.Tuple, mu.NatOutgoingPort)
	case metric.UpdateTypeExpire:
		f.flowsCompletedRefs.AddWithValue(mu.Tuple, mu.NatOutgoingPort)
		f.flowsRefsActive.Discard(mu.Tuple)
	}
	f.flowsRefs.AddWithValue(mu.Tuple, mu.NatOutgoingPort)
	f.processIDs.Add(strconv.Itoa(mu.ProcessID))
	if mu.ProcessArgs != "" {
		f.processArgs.Add(mu.ProcessArgs)
	}

	f.NumFlows = f.flowsRefs.Len()
	f.NumFlowsStarted = f.flowsStartedRefs.Len()
	f.NumFlowsCompleted = f.flowsCompletedRefs.Len()
	f.PacketsIn += mu.InMetric.DeltaPackets
	f.BytesIn += mu.InMetric.DeltaBytes
	f.PacketsOut += mu.OutMetric.DeltaPackets
	f.BytesOut += mu.OutMetric.DeltaBytes
	f.HTTPRequestsAllowedIn += mu.InMetric.DeltaAllowedHTTPRequests
	f.HTTPRequestsDeniedIn += mu.InMetric.DeltaDeniedHTTPRequests
	f.aggregateFlowTCPStats(mu, displayDebugTraceLogs)
}

func (f *FlowStats) getActiveFlowsCount() int {
	return len(f.flowsRefsActive)
}

func (f *FlowStats) reset() {
	f.flowsStartedRefs = tuple.NewSet()
	f.flowsCompletedRefs = tuple.NewSet()
	f.flowsRefs = f.flowsRefsActive.Copy()
	f.FlowReportedStats = FlowReportedStats{
		NumFlows: f.flowsRefs.Len(),
	}
	f.FlowReportedTCPStats = FlowReportedTCPStats{}
	// Signal that the process ID information should be reset prior to
	// aggregating.
	f.resetProcessIDs = true
}

// FlowStatsByProcess collects statistics organized by process names. When process information is not enabled
// this stores the stats in a single entry keyed by a "-".
// Flow logs should be constructed by calling toFlowProcessReportedStats and then flattening the resulting
// slice with FlowMeta and other FlowLog information such as policies and labels.
type FlowStatsByProcess struct {
	// statsByProcessName stores aggregated flow statistics grouped by a process name.
	statsByProcessName map[string]*FlowStats
	// processNames stores the order in which process information is tracked and aggrgated.
	// this is done so that when we export flow logs, we do so in the order they appeared.
	processNames          *list.List
	displayDebugTraceLogs bool
	includeProcess        bool
	processLimit          int
	processArgsLimit      int
	natOutgoingPortLimit  int
	// TODO(doublek): Track the most significant stats and show them as part
	// of the flows that are included in the process limit. Current processNames
	// only tracks insertion order.
}

func NewFlowStatsByProcess(mu *metric.Update, includeProcess bool, processLimit, processArgsLimit int,
	displayDebugTraceLogs bool, natOutgoingPortLimit int,
) FlowStatsByProcess {
	f := FlowStatsByProcess{
		displayDebugTraceLogs: displayDebugTraceLogs,
		statsByProcessName:    make(map[string]*FlowStats),
		processNames:          list.New(),
		includeProcess:        includeProcess,
		processLimit:          processLimit,
		processArgsLimit:      processArgsLimit,
		natOutgoingPortLimit:  natOutgoingPortLimit,
	}
	f.aggregateFlowStatsByProcess(mu)
	return f
}

func (f *FlowStatsByProcess) aggregateFlowStatsByProcess(mu *metric.Update) {
	if !f.includeProcess || mu.ProcessName == "" {
		mu.ProcessName = FieldNotIncluded
		mu.ProcessID = 0
		mu.ProcessArgs = FieldNotIncluded
	}
	if stats, ok := f.statsByProcessName[mu.ProcessName]; ok {
		logutil.Tracef(f.displayDebugTraceLogs, "Process stats found %+v for metric update %+v", stats, mu)
		stats.aggregateFlowStats(*mu, f.displayDebugTraceLogs)
		logutil.Tracef(f.displayDebugTraceLogs, "Aggregated stats %+v after processing metric update %+v", stats, mu)
		f.statsByProcessName[mu.ProcessName] = stats
	} else {
		logutil.Tracef(f.displayDebugTraceLogs, "Process stats not found for metric update %+v", mu)
		f.processNames.PushBack(mu.ProcessName)
		stats := NewFlowStats(*mu)
		f.statsByProcessName[mu.ProcessName] = &stats
	}
}

func (f *FlowStatsByProcess) getActiveFlowsCount() int {
	activeCount := 0
	for _, stats := range f.statsByProcessName {
		activeCount += stats.getActiveFlowsCount()
	}
	return activeCount
}

func (f *FlowStatsByProcess) containsActiveRefs(mu *metric.Update) bool {
	if !f.includeProcess || mu.ProcessName == "" {
		mu.ProcessName = FieldNotIncluded
	}
	if stats, ok := f.statsByProcessName[mu.ProcessName]; ok {
		return stats.flowsRefsActive.Contains(mu.Tuple)
	}
	return false
}

func (f *FlowStatsByProcess) reset() {
	for name, stats := range f.statsByProcessName {
		stats.reset()
		f.statsByProcessName[name] = stats
	}
}

// gc garbage collects any process names and corresponding stats that don't have any active flows.
// This should only be called after stats have been reported.
func (f *FlowStatsByProcess) gc() int {
	var next *list.Element
	remainingActiveFlowsCount := 0
	for e := f.processNames.Front(); e != nil; e = next {
		// Don't lose where we are since we may in-place delete
		// the element.
		next = e.Next()
		name := e.Value.(string)
		stats := f.statsByProcessName[name]
		afc := stats.getActiveFlowsCount()
		if afc == 0 {
			delete(f.statsByProcessName, name)
			f.processNames.Remove(e)
			continue
		}
		remainingActiveFlowsCount += afc
	}
	return remainingActiveFlowsCount
}

// toFlowProcessReportedStats returns atmost processLimit + 1 entry slice containing
// flow stats grouped by process information.
func (f *FlowStatsByProcess) toFlowProcessReportedStats() []FlowProcessReportedStats {
	var pArgs []string
	if !f.includeProcess {
		// If we are not configured to include process information then
		// we expect to only have a single entry with no process information
		// and all stats are already aggregated into a single value.
		reportedStats := make([]FlowProcessReportedStats, 0, 1)
		if stats, ok := f.statsByProcessName[FieldNotIncluded]; ok {
			s := FlowProcessReportedStats{
				ProcessName:          FieldNotIncluded,
				NumProcessNames:      0,
				ProcessID:            FieldNotIncluded,
				NumProcessIDs:        0,
				ProcessArgs:          []string{"-"},
				NumProcessArgs:       0,
				FlowReportedStats:    stats.FlowReportedStats,
				FlowReportedTCPStats: stats.FlowReportedTCPStats,
				NatOutgoingPorts:     f.getNatOutGoingPortsFromStats(stats),
			}
			reportedStats = append(reportedStats, s)
		} else {
			log.Warnf("No flow log status recorded %+v", f)
		}
		return reportedStats
	}

	// Only collect up to process limit stats and one additional entry for rest
	// of the aggregated stats.
	reportedStats := make([]FlowProcessReportedStats, 0, f.processLimit+1)
	numProcessNames := 0
	numPids := 0
	numProcessArgs := 0
	appendAggregatedStats := false
	aggregatedReportedStats := FlowReportedStats{}
	aggregatedReportedTCPStats := FlowReportedTCPStats{}
	var aggregatedNatOutgoingPorts []int
	var next *list.Element
	// Collect in insertion order, the first processLimit entries and then aggregate
	// the remaining statistics in a single aggregated FlowProcessReportedStats entry.
	for e := f.processNames.Front(); e != nil; e = next {
		next = e.Next()
		name := e.Value.(string)
		stats, ok := f.statsByProcessName[name]
		if !ok {
			log.Warnf("Stats not found for process name %v", name)
			f.processNames.Remove(e)
			continue
		}

		natOutGoingPorts := f.getNatOutGoingPortsFromStats(stats)

		// If we didn't receive any process data then the flow stats are
		// aggregated under a "-" which is FieldNotIncluded. All these
		// This is handled separately here so that we can set numProcessNames
		// and numProcessIDs to 0.
		if name == FieldNotIncluded {
			s := FlowProcessReportedStats{
				ProcessName:          FieldNotIncluded,
				NumProcessNames:      0,
				ProcessID:            FieldNotIncluded,
				NumProcessIDs:        0,
				ProcessArgs:          []string{"-"},
				NumProcessArgs:       0,
				FlowReportedStats:    stats.FlowReportedStats,
				FlowReportedTCPStats: stats.FlowReportedTCPStats,
				NatOutgoingPorts:     natOutGoingPorts,
			}
			reportedStats = append(reportedStats, s)
			// Continue processing in case there are other tuples that did collect
			// process information.
			continue
		}

		// Figure out how PIDs are to be included in a flow log entry.
		// If there are no PIDs then the pid is not included.
		// If there is a singe PID then the pid is added.
		// If there are multiple PIDs for a single process name then
		// the pid field is set to "*" (aggregated) and numProcessIDs is
		// set to the number of PIDs for this process name.
		numPids = stats.processIDs.Len()
		var pid string
		switch numPids {
		case 0:
			pid = FieldNotIncluded
		case 1:
			// Get the first and only PID.
			for p := range stats.processIDs.All() {
				pid = p
				break
			}
		default:
			pid = fieldAggregated
		}

		argList := func(numAllowedArgs int, stats *FlowStats) []string {
			var aList []string
			var tempStr string
			numProcessArgs = stats.processArgs.Len()
			if numProcessArgs == 0 {
				return []string{"-"}
			}
			if numPids == 1 {
				// This is a corner case. Logically there should be a
				// single argument if the numPids is 1. There could be more
				// when aggregating, reason being 1 flow has args from kprobes
				// and other flow has args read from /proc/pid/cmdline. In this
				// we just show a single arg which is longest, with numProcessArgs
				// set to 1.
				for item := range stats.processArgs.All() {
					if len(item) > len(tempStr) {
						tempStr = item
					}
				}
				numProcessArgs = 1
				return []string{tempStr}
			}
			if numProcessArgs == 1 || numAllowedArgs == 1 {
				for item := range stats.processArgs.All() {
					aList = append(aList, item)
					break
				}
			} else {
				argCount := 0
				for item := range stats.processArgs.All() {
					aList = append(aList, item)
					argCount = argCount + 1
					if argCount == numAllowedArgs {
						break
					}
				}
			}
			return aList
		}

		pArgs = argList(f.processArgsLimit, stats)
		// If we've reached the process limit, then start aggregating the remaining
		// stats so that we can add one additional entry containing this information.
		if len(reportedStats) == f.processLimit {
			numProcessNames++
			numPids += numPids
			numProcessArgs += numProcessArgs
			aggregatedReportedStats.Add(stats.FlowReportedStats)
			appendAggregatedStats = true
			aggregatedReportedTCPStats.Add(stats.FlowReportedTCPStats)

			spaceInNatOutGoingPortArray := f.natOutgoingPortLimit - len(aggregatedNatOutgoingPorts)
			if spaceInNatOutGoingPortArray > 0 {
				numIncludedPorts := len(natOutGoingPorts)
				if spaceInNatOutGoingPortArray < len(natOutGoingPorts) {
					numIncludedPorts = spaceInNatOutGoingPortArray
				}
				aggregatedNatOutgoingPorts = append(aggregatedNatOutgoingPorts, natOutGoingPorts[0:numIncludedPorts]...)
			}
		} else {
			s := FlowProcessReportedStats{
				ProcessName:          name,
				NumProcessNames:      1,
				ProcessID:            pid,
				NumProcessIDs:        numPids,
				ProcessArgs:          pArgs,
				NumProcessArgs:       numProcessArgs,
				FlowReportedStats:    stats.FlowReportedStats,
				FlowReportedTCPStats: stats.FlowReportedTCPStats,
				NatOutgoingPorts:     natOutGoingPorts,
			}
			reportedStats = append(reportedStats, s)
		}
	}
	if appendAggregatedStats {
		s := FlowProcessReportedStats{
			ProcessName:          fieldAggregated,
			NumProcessNames:      numProcessNames,
			ProcessID:            fieldAggregated,
			NumProcessIDs:        numPids,
			ProcessArgs:          pArgs,
			NumProcessArgs:       numProcessArgs,
			FlowReportedStats:    aggregatedReportedStats,
			FlowReportedTCPStats: aggregatedReportedTCPStats,
		}
		reportedStats = append(reportedStats, s)
	}
	return reportedStats
}

func (f *FlowStatsByProcess) getNatOutGoingPortsFromStats(stats *FlowStats) []int {
	var natOutGoingPorts []int

	numNatOutgoingPorts := 0
	for _, value := range stats.flowsRefsActive {
		if numNatOutgoingPorts >= f.natOutgoingPortLimit {
			break
		}

		if value != 0 {
			natOutGoingPorts = append(natOutGoingPorts, value)
			numNatOutgoingPorts++
		}
	}

	for _, value := range stats.flowsCompletedRefs {
		if numNatOutgoingPorts >= f.natOutgoingPortLimit {
			break
		}

		if value != 0 {
			natOutGoingPorts = append(natOutGoingPorts, value)
			numNatOutgoingPorts++
		}
	}

	return natOutGoingPorts
}

// FlowProcessReportedStats contains FlowReportedStats along with process information.
type FlowProcessReportedStats struct {
	ProcessName      string   `json:"processName"`
	NumProcessNames  int      `json:"numProcessNames"`
	ProcessID        string   `json:"processID"`
	NumProcessIDs    int      `json:"numProcessIDs"`
	ProcessArgs      []string `json:"processArgs"`
	NumProcessArgs   int      `json:"numProcessArgs"`
	NatOutgoingPorts []int
	FlowReportedStats
	FlowReportedTCPStats
}

// FlowLog is a record of flow data (metadata & reported stats) including
// timestamps. A FlowLog is ready to be serialized to an output format.
type FlowLog struct {
	StartTime, EndTime time.Time
	FlowMeta
	FlowLabels
	FlowDestDomains
	FlowExtras
	FlowProcessReportedStats

	FlowAllPolicySet, FlowEnforcedPolicySet, FlowPendingPolicySet, FlowTransitPolicySet FlowPolicySet
}

func (f *FlowLog) Deserialize(fl string) error {
	// Format is
	// startTime endTime srcType srcNamespace srcName srcLabels dstType dstNamespace dstName dstLabels srcIP dstIP proto srcPort dstPort numFlows numFlowsStarted numFlowsCompleted flowReporter packetsIn packetsOut bytesIn bytesOut action policies originalSourceIPs numOriginalSourceIPs destServiceNamespace dstServiceName dstServicePort processName numProcessNames processPid numProcessIds
	// Sample entry with no aggregation and no labels.
	// 1529529591 1529529892 wep policy-demo nginx-7d98456675-2mcs4 nginx-7d98456675-* - wep kube-system kube-dns-7cc87d595-pxvxb kube-dns-7cc87d595-* - 192.168.224.225 192.168.135.53 17 36486 53 1 1 1 in 1 1 73 119 allow ["0|tier|namespace/tier.policy|allow|0"] [1.0.0.1] 1 kube-system kube-dns dig 23033 0

	var srcType, dstType endpoint.Type

	parts := strings.Split(fl, " ")
	if len(parts) < 32 {
		return fmt.Errorf("log %v can't be processed", fl)
	}

	switch parts[2] {
	case "wep":
		srcType = endpoint.Wep
	case "hep":
		srcType = endpoint.Hep
	case "ns":
		srcType = endpoint.Ns
	case "net":
		srcType = endpoint.Net
	}

	f.SrcMeta = endpoint.Metadata{
		Type:           srcType,
		Namespace:      parts[3],
		Name:           parts[4],
		AggregatedName: parts[5],
	}
	f.SrcLabels = uniquelabels.Make(stringToLabels(parts[6]))
	if srcType == endpoint.Ns {
		namespace, name := utils.ExtractNamespaceFromNetworkSet(f.SrcMeta.AggregatedName)
		f.SrcMeta.Namespace = namespace
		f.SrcMeta.AggregatedName = name
	}

	switch parts[7] {
	case "wep":
		dstType = endpoint.Wep
	case "hep":
		dstType = endpoint.Hep
	case "ns":
		dstType = endpoint.Ns
	case "net":
		dstType = endpoint.Net
	}

	f.DstMeta = endpoint.Metadata{
		Type:           dstType,
		Namespace:      parts[8],
		Name:           parts[9],
		AggregatedName: parts[10],
	}
	f.DstLabels = uniquelabels.Make(stringToLabels(parts[11]))
	if dstType == endpoint.Ns {
		namespace, name := utils.ExtractNamespaceFromNetworkSet(f.DstMeta.AggregatedName)
		f.DstMeta.Namespace = namespace
		f.DstMeta.AggregatedName = name
	}

	var sip, dip [16]byte
	if parts[12] != "-" {
		sip = utils.IpStrTo16Byte(parts[12])
	}
	if parts[13] != "-" {
		dip = utils.IpStrTo16Byte(parts[13])
	}
	p, _ := strconv.Atoi(parts[14])
	sp, _ := strconv.Atoi(parts[15])
	dp, _ := strconv.Atoi(parts[16])
	f.Tuple = tuple.Make(sip, dip, p, sp, dp)

	f.NumFlows, _ = strconv.Atoi(parts[17])
	f.NumFlowsStarted, _ = strconv.Atoi(parts[18])
	f.NumFlowsCompleted, _ = strconv.Atoi(parts[19])

	switch parts[20] {
	case "src":
		f.Reporter = ReporterSrc
	case "dst":
		f.Reporter = ReporterDst
	}

	f.PacketsIn, _ = strconv.Atoi(parts[21])
	f.PacketsOut, _ = strconv.Atoi(parts[22])
	f.BytesIn, _ = strconv.Atoi(parts[23])
	f.BytesOut, _ = strconv.Atoi(parts[24])

	switch parts[25] {
	case "allow":
		f.Action = ActionAllow
	case "deny":
		f.Action = ActionDeny
	}

	// Parse policies, empty ones are just -
	if parts[26] == "-" {
		f.FlowAllPolicySet = make(FlowPolicySet)
	} else if len(parts[26]) > 1 {
		f.FlowAllPolicySet = make(FlowPolicySet)
		polParts := strings.Split(parts[26][1:len(parts[26])-1], ",")
		for _, p := range polParts {
			f.FlowAllPolicySet[p] = emptyValue
		}
	}

	// Parse original source IPs, empty ones are just -
	if parts[27] == "-" {
		f.FlowExtras = FlowExtras{}
	} else if len(parts[27]) > 1 {
		ips := []net.IP{}
		exParts := strings.Split(parts[27][1:len(parts[27])-1], ",")
		for _, ipStr := range exParts {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}
			ips = append(ips, ip)
		}
		f.FlowExtras = FlowExtras{
			OriginalSourceIPs: ips,
		}
		f.NumOriginalSourceIPs, _ = strconv.Atoi(parts[28])
	}

	svcPortNum, err := strconv.Atoi(parts[32])
	if err != nil {
		svcPortNum = 0
	}

	f.DstService = FlowService{
		Namespace: parts[29],
		Name:      parts[30],
		PortName:  parts[31],
		PortNum:   svcPortNum,
	}

	f.ProcessName = parts[33]
	f.NumProcessNames, _ = strconv.Atoi(parts[34])
	f.ProcessID = parts[35]
	f.NumProcessIDs, _ = strconv.Atoi(parts[36])
	temp, _ := strconv.Atoi(parts[37])
	f.SendCongestionWnd.Mean = temp
	temp, _ = strconv.Atoi(parts[38])
	f.SendCongestionWnd.Min = temp
	temp, _ = strconv.Atoi(parts[39])
	f.SmoothRtt.Mean = temp
	temp, _ = strconv.Atoi(parts[40])
	f.SmoothRtt.Max = temp
	temp, _ = strconv.Atoi(parts[41])
	f.MinRtt.Mean = temp
	temp, _ = strconv.Atoi(parts[42])
	f.MinRtt.Max = temp
	temp, _ = strconv.Atoi(parts[43])
	f.Mss.Mean = temp
	temp, _ = strconv.Atoi(parts[44])
	f.Mss.Min = temp
	temp, _ = strconv.Atoi(parts[45])
	f.TotalRetrans = temp
	temp, _ = strconv.Atoi(parts[46])
	f.LostOut = temp
	temp, _ = strconv.Atoi(parts[47])
	f.UnrecoveredRTO = temp

	return nil
}
