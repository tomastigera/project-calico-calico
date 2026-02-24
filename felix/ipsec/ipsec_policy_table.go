// Copyright (c) 2018,2021 Tigera, Inc. All rights reserved.

package ipsec

import (
	"fmt"
	"net"
	"reflect"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var (
	gaugeNumIPSecBindings = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_ipsec_bindings_total",
		Help: "Total number of active IPsec bindings.",
	})
	countNumIPSecErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_ipsec_errors",
		Help: "Number of IPsec update failures.",
	})
)

func init() {
	prometheus.MustRegister(gaugeNumIPSecBindings)
	prometheus.MustRegister(countNumIPSecErrors)
}

func (p *PolicyTable) xfrmPolToOurPol(xfrmPol netlink.XfrmPolicy) (sel PolicySelector, rule *PolicyRule) {
	if len(xfrmPol.Tmpls) == 0 {
		return
	}
	tmpl := xfrmPol.Tmpls[0]
	if tmpl.Reqid != p.ourReqID {
		return
	}

	sel = PolicySelector{
		TrafficSrc: ipNetPtrToCIDR(xfrmPol.Src),
		TrafficDst: ipNetPtrToCIDR(xfrmPol.Dst),
		Dir:        xfrmPol.Dir,
	}
	rule = &PolicyRule{}
	rule.Action = xfrmPol.Action
	if xfrmPol.Mark != nil {
		sel.Mark = xfrmPol.Mark.Value
		sel.MarkMask = xfrmPol.Mark.Mask
	}
	if tmpl.Src != nil && !tmpl.Src.IsUnspecified() {
		rule.TunnelSrc = ip.FromNetIP(tmpl.Src).(ip.V4Addr)
	}
	if tmpl.Src != nil && !tmpl.Dst.IsUnspecified() {
		rule.TunnelDst = ip.FromNetIP(tmpl.Dst).(ip.V4Addr)
	}

	return
}

func ipNetPtrToCIDR(ipNet *net.IPNet) (c ip.V4CIDR) {
	if ipNet == nil {
		return
	}
	if ones, _ := ipNet.Mask.Size(); ones == 0 {
		return
	}
	return ip.CIDRFromIPNet(ipNet).(ip.V4CIDR)
}

type PolicyTable struct {
	ourReqID          int
	ipsecEnabled      bool
	firstApplyTime    time.Time
	gracePhase        GracefulShutdownPhase
	useShortGraceTime bool

	resyncRequired bool

	pendingRuleUpdates map[PolicySelector]*PolicyRule
	pendingDeletions   set.Set[PolicySelector]

	selectorToRule map[PolicySelector]*PolicyRule

	nlHandleFactory func() (NetlinkXFRMIface, error)
	nlHndl          NetlinkXFRMIface

	// sleep is a shim for time.Sleep()
	sleep func(time.Duration)
	// timeNow is a shim for time.Now()
	timeNow func() time.Time
	// timeSince is a shim for time.Since()
	timeSince func(time.Time) time.Duration

	opRecorder logutils.OpRecorder
}

func NewPolicyTable(ourReqID int, ipsecEnabled bool, shortGraceTime bool, opRecorder logutils.OpRecorder) *PolicyTable {
	return NewPolicyTableWithShims(
		ourReqID,
		ipsecEnabled,
		shortGraceTime,
		newRealNetlinkHandle,
		time.Sleep,
		time.Now,
		time.Since,
		opRecorder,
	)
}

func newRealNetlinkHandle() (NetlinkXFRMIface, error) {
	return netlink.NewHandle(syscall.NETLINK_XFRM)
}

func NewPolicyTableWithShims(
	ourReqID int,
	ipsecEnabled bool,
	shortGraceTime bool,
	nlHandleFactory func() (NetlinkXFRMIface, error),
	sleep func(time.Duration),
	timeNow func() time.Time,
	timeSince func(time.Time) time.Duration,
	opRecorder logutils.OpRecorder,
) *PolicyTable {
	return &PolicyTable{
		ourReqID:           ourReqID,
		ipsecEnabled:       ipsecEnabled,
		resyncRequired:     true,
		pendingRuleUpdates: map[PolicySelector]*PolicyRule{},
		pendingDeletions:   set.New[PolicySelector](),
		selectorToRule:     map[PolicySelector]*PolicyRule{},
		nlHandleFactory:    nlHandleFactory,
		sleep:              sleep,
		timeNow:            timeNow,
		timeSince:          timeSince,
		useShortGraceTime:  shortGraceTime,
		opRecorder:         opRecorder,
	}
}

var blockRule = PolicyRule{Action: netlink.XFRM_POLICY_BLOCK}

func (p *PolicyTable) QueueResync() {
	p.resyncRequired = true
}

func (p *PolicyTable) SetRule(sel PolicySelector, rule *PolicyRule) {
	if !p.ipsecEnabled {
		log.Error("Unexpected call to SetRule() when IPsec is disabled")
		return
	}
	debug := log.GetLevel() >= log.DebugLevel
	// Clear out any pending state and then recalculate.
	p.pendingDeletions.Discard(sel)
	delete(p.pendingRuleUpdates, sel)

	if reflect.DeepEqual(p.selectorToRule[sel], rule) {
		// Rule is the same as what we think is in the dataplane already, ignore.
		if debug {
			log.WithFields(log.Fields{
				"sel":  sel,
				"rule": *rule,
			}).Debug("Ignoring no-op update to IPsec rule")
		}
		return
	}

	// Queue up the change.
	if debug {
		log.WithFields(log.Fields{
			"sel":  sel,
			"rule": *rule,
		}).Debug("Queueing update of IPsec rule")
	}
	p.pendingRuleUpdates[sel] = rule
}

func (p *PolicyTable) DeleteRule(sel PolicySelector) {
	if !p.ipsecEnabled {
		log.Error("Unexpected call to DeleteRule() when IPsec is disabled")
		return
	}
	// Clear out any pending state and then recalculate.
	p.pendingDeletions.Discard(sel)
	delete(p.pendingRuleUpdates, sel)

	debug := log.GetLevel() >= log.DebugLevel
	if _, ok := p.selectorToRule[sel]; !ok {
		// Rule was never programmed to the dataplane. Ignore.
		if debug {
			log.WithField("sel", sel).Debug("Ignoring no-op delete of IPsec rule")
		}
		return
	}

	// Queue up the change.
	if debug {
		log.WithField("sel", sel).Debug("Queueing delete of IPsec rule")
	}
	p.pendingDeletions.Add(sel)
}

func (p *PolicyTable) Apply() {
	if p.firstApplyTime.IsZero() {
		p.firstApplyTime = p.timeNow()
	}

	// Check if we're in a new phase of a graceful shutdown and if so force a resync.
	gState := p.CalculateGracefulShutdownPhase()
	if gState != p.gracePhase {
		log.WithFields(log.Fields{
			"oldPhase": p.gracePhase,
			"newPhase": gState,
		}).Info("IPsec disabled, entering new cleanup phase")
		p.resyncRequired = true
		p.gracePhase = gState
	}

	success := false
	retryDelay := 1 * time.Millisecond
	backOff := func() {
		p.sleep(retryDelay)
		retryDelay *= 2
	}
	var err error
	for attempt := range 10 {
		if attempt > 0 {
			log.Info("Retrying after an IPsec binding update failure...")
		}
		if p.resyncRequired {
			// Compare our in-memory state against the dataplane and queue up
			// modifications to fix any inconsistencies.
			log.Debug("Resyncing IPsec bindings with dataplane.")
			p.opRecorder.RecordOperation("resync-ipsec-bindings")
			var numProblems int
			numProblems, err = p.tryResync()
			if err != nil {
				log.WithError(err).Warning("Failed to resync with dataplane")
				backOff()
				continue
			}
			if numProblems > 0 {
				log.WithField("numProblems", numProblems).Info(
					"Found inconsistencies in dataplane")
			}
			p.resyncRequired = false
		}

		if err = p.tryUpdates(); err != nil {
			log.WithError(err).Warning("Failed to update IPsec bindings. Marking dataplane for resync.")
			p.resyncRequired = true
			countNumIPSecErrors.Inc()
			backOff()
			continue
		}

		success = true
		break
	}
	if !success {
		p.DumpStateToLog()
		log.WithError(err).Panic("Failed to update IPsec bindings after multiple retries.")
	}
	gaugeNumIPSecBindings.Set(float64(len(p.selectorToRule)))
}

type GracefulShutdownPhase string

const (
	GraceNone           GracefulShutdownPhase = ""
	GraceAllOptional    GracefulShutdownPhase = "all-optional"
	GraceRemoveOutbound GracefulShutdownPhase = "remove-outbound"
	GraceRemoveAll      GracefulShutdownPhase = "remove-all"
)

func (p *PolicyTable) CalculateGracefulShutdownPhase() GracefulShutdownPhase {
	if p.ipsecEnabled {
		return GraceNone
	}

	// The license polling interval is 30s by default so we give 60s of grace where we switch all our policy to
	// optional.  After the 60s, we remove all the outbound policy.
	allOptionalGraceTime := 60 * time.Second
	// Then, after another 60s we remove all the policy.
	removeOutboundGraceTime := 120 * time.Second
	if p.useShortGraceTime {
		// For FV testing, use a shorter grace period.
		allOptionalGraceTime = 5 * time.Second
		removeOutboundGraceTime = 10 * time.Second
	}

	if p.timeSince(p.firstApplyTime) < allOptionalGraceTime {
		return GraceAllOptional
	}
	if p.timeSince(p.firstApplyTime) < removeOutboundGraceTime {
		return GraceRemoveOutbound
	}
	return GraceRemoveAll
}

func (p *PolicyTable) tryResync() (numProblems int, err error) {
	log.Debug("IPsec resync: starting")
	defer log.Debug("IPsec resync: finished")

	xfrmPols, err := p.nl().XfrmPolicyList(netlink.FAMILY_V4)
	if err != nil {
		p.closeNL()
		return 1, err
	}

	var expectedState map[PolicySelector]*PolicyRule
	if p.gracePhase == GraceNone {
		// IPsec enabled, selectorToRule contains our desired state of the dataplane.
		expectedState = p.selectorToRule
	}
	actualState := map[PolicySelector]*PolicyRule{}

	// Look up the log level so we can avoid doing expensive log.WithField/Debug calls in the tight loop.
	debug := log.GetLevel() >= log.DebugLevel

	loggedDelete := false
	loggedRepair := false
	for _, xfrmPol := range xfrmPols {
		if debug {
			log.WithField("policy", xfrmPol).Debug("IPsec resync: examining dataplane policy")
		}
		sel, pol := p.xfrmPolToOurPol(xfrmPol)
		if pol == nil {
			if debug {
				log.Debug("IPsec resync: Not one of our policies")
			}
			continue // Not one of our policies
		}

		// Record the actual state of the dataplane.
		actualState[sel] = pol
		var expectedPol *PolicyRule

		// Figure out what we want the state of the dataplane to be...
		if p.gracePhase == GraceNone {
			// IPsec is enabled as normal, look up what we're expecting to be there.
			expectedPol = expectedState[sel]
			// Remove it from the old map; once we're done with this loop, the old map will contain any policies that
			// are missing from the dataplane.
			delete(expectedState, sel)
		} else {
			// We're doing a graceful shutdown.  This consists of three phases:
			// (1) GraceAllOptional: we make all policies optional.  In this stage, traffic will continue to be
			//     encrypted until the sender enters the next phase (or an SA times out, for example).
			// (2) GraceRemoveOutbound: we remove all outbound policies.  This disables sending of IPsec traffic.
			// (3) GraceRemoveAll: we remove all policies.
			makePolOptional := false
			switch p.gracePhase {
			case GraceAllOptional:
				makePolOptional = true
			case GraceRemoveOutbound:
				makePolOptional = sel.Dir != netlink.XFRM_DIR_OUT
			}
			if makePolOptional {
				polCopy := *pol
				polCopy.Optional = true
				expectedPol = &polCopy
			} /* else leave expectedPol as nil */
		}

		if pendingUpdate, ok := p.pendingRuleUpdates[sel]; ok {
			if reflect.DeepEqual(pendingUpdate, pol) {
				// We were just about to set up exactly this policy, skip the update.
				if debug {
					log.WithField("policy", xfrmPol).Debug(
						"IPsec resync: found pending policy was already in place, skipping update")
				}
				delete(p.pendingRuleUpdates, sel)
				continue
			}
			// We've already got an update queued up, which will replace the unexpected policy.
			if debug {
				log.WithField("policy", xfrmPol).Debug(
					"IPsec resync: found unexpected policy but it's already queued for update/deletion")
			}
			continue
		}

		if p.pendingDeletions.Contains(sel) {
			// We've already got a delete queued up, which will remove the policy.
			if debug {
				log.WithField("policy", xfrmPol).Debug(
					"IPsec resync: found policy in dataplane but it's already queued for deletion")
			}
			continue
		}

		if expectedPol == nil {
			// Policy exists in dataplane but not in our expected state.
			// Queue up a deletion to bring the kernel back into sync.
			if debug || !loggedDelete {
				log.WithField("selector", sel).Warn(
					"IPsec resync: queueing deletion of unexpected policy (skipping further logs of this type).")
				loggedDelete = true
			}
			numProblems++
			p.pendingDeletions.Add(sel)
			continue
		}

		if reflect.DeepEqual(expectedPol, pol) {
			// Policy in dataplane matches our expectation.
			if debug {
				log.WithField("policy", xfrmPol).Debug("IPsec resync: policy matches our state")
			}
			continue // match, nothing to do
		}

		// Queue up a repair to bring us back into sync.
		if p.gracePhase == GraceNone && (debug || !loggedRepair) {
			log.WithField("policy", xfrmPol).Warn(
				"IPsec resync: found incorrect policy in dataplane, queueing a repair " +
					"(skipping further logs of this type).")
			loggedRepair = true
		}
		numProblems++
		p.pendingRuleUpdates[sel] = expectedPol
	}

	loggedReplace := false
	for sel, pol := range expectedState {
		if _, ok := p.pendingRuleUpdates[sel]; ok {
			// We've already got an update queued up, which will replace the missing policy.
			continue
		}
		if p.pendingDeletions.Contains(sel) {
			log.WithField("sel", sel).Debug("IPsec resync: Found pending deletion had already been done")
			p.pendingDeletions.Discard(sel)
			continue
		}
		// Expected policy was missing from the dataplane, queue up a repair.
		if debug || !loggedReplace {
			log.WithFields(log.Fields{"sel": sel, "rule": pol}).Warn(
				"IPsec resync: found policy missing from dataplane, queueing a replacement " +
					"(suppressing any further logs)")
			loggedReplace = true
		}
		numProblems++
		p.pendingRuleUpdates[sel] = pol
	}

	p.selectorToRule = actualState

	return
}

func (p *PolicyTable) tryUpdates() (err error) {
	debug := log.GetLevel() >= log.DebugLevel

	if p.pendingDeletions.Len() > 0 {
		log.WithField("numUpdates", p.pendingDeletions.Len()).Info("Applying IPsec policy deletions")
	}
	var lastErr error
	for sel := range p.pendingDeletions.All() {
		xPol := netlink.XfrmPolicy{}
		sel.Populate(&xPol)
		p.selectorToRule[sel].Populate(&xPol, p.ourReqID)
		if debug {
			log.WithFields(log.Fields{"sel": sel, "policy": xPol}).Debug("Deleting rule")
		}
		err := p.nl().XfrmPolicyDel(&xPol)
		if err != nil {
			log.WithError(err).WithField("policy", xPol).Error("Failed to remove IPsec xfrm policy")
			lastErr = err
			p.closeNL()
			continue
		}
		delete(p.selectorToRule, sel)
		p.pendingDeletions.Discard(sel)
	}

	if len(p.pendingRuleUpdates) > 0 {
		log.WithField("numUpdates", len(p.pendingRuleUpdates)).Info("Applying IPsec policy updates")
	}
	for sel, rule := range p.pendingRuleUpdates {
		xPol := netlink.XfrmPolicy{}
		sel.Populate(&xPol)
		rule.Populate(&xPol, p.ourReqID)
		if debug {
			log.WithFields(log.Fields{"sel": sel, "rule": rule, "policy": xPol}).Debug(
				"Updating rule")
		}
		err := p.nl().XfrmPolicyUpdate(&xPol)
		if err != nil {
			log.WithError(err).WithField("policy", xPol).Error("Failed to update IPsec xfrm policy")
			lastErr = err
			p.closeNL()
			continue
		}
		p.selectorToRule[sel] = rule
		delete(p.pendingRuleUpdates, sel)
	}

	return lastErr
}

func (p *PolicyTable) DumpStateToLog() {
	log.Info("Dumping internal IPsec state...")
	for sel, pol := range p.selectorToRule {
		log.Infof("Expected policy: %v %v", sel, pol)
	}
	for sel, pol := range p.pendingRuleUpdates {
		log.Infof("Pending policy update: %v %v", sel, pol)
	}
	for sel := range p.pendingDeletions.All() {
		log.Infof("Pending deletion: %v", sel)
	}
	pols, err := p.nl().XfrmPolicyList(netlink.FAMILY_V4)
	if err != nil {
		log.WithError(err).Error("Failed to read XFRM policies from kernel")
		return
	}
	for _, pol := range pols {
		log.Infof("Kernel policy: %v", pol)
	}
}

func (p *PolicyTable) closeNL() {
	if p.nlHndl == nil {
		return
	}
	p.nlHndl.Delete()
	p.nlHndl = nil
}

func (p *PolicyTable) nl() NetlinkXFRMIface {
	if p.nlHndl == nil {
		var err error
		for range 3 {
			p.nlHndl, err = p.nlHandleFactory()
			if err == nil {
				break
			}
			p.sleep(100 * time.Millisecond)
		}
		if p.nlHndl == nil {
			log.WithError(err).Panic("Failed to connect to netlink")
		}
	}
	return p.nlHndl
}

type NetlinkXFRMIface interface {
	XfrmPolicyList(family int) ([]netlink.XfrmPolicy, error)
	XfrmPolicyUpdate(policy *netlink.XfrmPolicy) error
	XfrmPolicyDel(policy *netlink.XfrmPolicy) error
	Delete()
}

type PolicySelector struct {
	TrafficSrc ip.V4CIDR
	TrafficDst ip.V4CIDR
	Mark       uint32
	MarkMask   uint32
	Dir        netlink.Dir
}

func (sel PolicySelector) String() string {
	s := fmt.Sprintf("%v -> %v (%v)", sel.TrafficSrc, sel.TrafficDst, sel.Dir)
	if sel.MarkMask != 0 {
		s += fmt.Sprintf(" mask %#x/%#x", sel.Mark, sel.MarkMask)
	}
	return s
}

func (sel PolicySelector) Populate(pol *netlink.XfrmPolicy) {
	if sel.TrafficSrc.Prefix() > 0 {
		src := sel.TrafficSrc.ToIPNet()
		pol.Src = &src
	}
	if sel.TrafficDst.Prefix() > 0 {
		dst := sel.TrafficDst.ToIPNet()
		pol.Dst = &dst
	}
	if sel.MarkMask != 0 {
		pol.Mark = &netlink.XfrmMark{
			Value: sel.Mark,
			Mask:  sel.MarkMask,
		}
	}
	pol.Dir = sel.Dir
}

type PolicyRule struct {
	Action netlink.PolicyAction

	TunnelSrc ip.V4Addr
	TunnelDst ip.V4Addr

	Optional bool
}

func (r PolicyRule) String() string {
	s := r.Action.String()
	if r.Action != netlink.XFRM_POLICY_BLOCK {
		s += fmt.Sprintf(" tunnel %v -> %v", r.TunnelSrc, r.TunnelDst)
	}
	return s
}

func (r *PolicyRule) Populate(pol *netlink.XfrmPolicy, ourReqID int) {
	if r == nil {
		return
	}
	pol.Action = r.Action

	// Note: for a block action, the template doesn't get used.  However, we include it because it allows us
	// to include a ReqID, which we use to match our policies during resync.
	optional := 0
	if r.Optional {
		optional = 1
	}
	pol.Tmpls = append(pol.Tmpls, netlink.XfrmPolicyTmpl{
		Src:      r.TunnelSrc.AsNetIP(),
		Dst:      r.TunnelDst.AsNetIP(),
		Proto:    netlink.XFRM_PROTO_ESP,
		Mode:     netlink.XFRM_MODE_TUNNEL,
		Reqid:    ourReqID,
		Optional: optional,
	})
}
