// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.

package intdataplane

import (
	"bytes"
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/golang-collections/collections/stack"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	bpfipsets "github.com/projectcalico/calico/felix/bpf/ipsets"
	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/ethtool"
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routerule"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/routetable/ownershippol"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/felix/vxlanfdb"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// Egress IP manager watches EgressIPSet and WEP updates.
// One WEP defines one route rule which maps WEP IP to an egress routing table.
// One EgressIPSet defines one egress routing table which consists of ECMP routes.
// One ECMP route is associated with one vxlan L2 route (static ARP and FDB entry)
//
//	  WEP  WEP  WEP                    WEP  WEP  WEP
//	    \   |   /                        \   |   /
//	     \  |  / (Match Src FWMark)       \  |  /
//	      \ | /                            \ | /
//	Route Table (EgressIPSet)           Route Table n
//	   <Index 200>                        <Index n>
//	     default                           default
//	      / | \                              / | \
//	     /  |  \                            /  |  \
//	    /   |   \                          /   |   \
//
// L3 route GatewayIP...GatewayIP_n            GatewayIP...GatewayIP_n
//
// L2 routes  ARP/FDB...ARP/FDB                   ARP/FDB...ARP/FDB
//
// All Routing Rules are managed by a routerule instance.
// Each routing table is managed by a routetable instance for both L3 and L2 routes.
//
// Egress IP manager ensures vxlan interface is configured according to the configuration.
var (
	ErrInsufficientRouteTables  = errors.New("ran out of egress ip route tables, increased routeTableRanges required")
	ErrVxlanDeviceNotConfigured = errors.New("egress VXLAN device not configured")
	defaultCidr, _              = ip.ParseCIDROrIP("0.0.0.0/0")
)

const (
	egressHealthName = "EgressNetworkingInSync"
)

type egressIPSets interface {
	AddOrReplaceIPSet(meta ipsets.IPSetMetadata, members []string)
}

type healthAggregator interface {
	RegisterReporter(name string, reports *health.HealthReport, timeout time.Duration)
	Report(name string, report *health.HealthReport)
}

type routeTableGenerator interface {
	NewRouteTable(
		interfaceNames []string,
		ipVersion uint8,
		tableIndex int,
		netlinkTimeout time.Duration,
		deviceRouteSourceAddress net.IP,
		deviceRouteProtocol int,
		removeExternalRoutes bool,
		opRecorder logutils.OpRecorder,
		featureDetector environment.FeatureDetectorIface,
	) routetable.Interface
}

type routeTableFactory struct {
	count int
}

func (f *routeTableFactory) NewRouteTable(
	interfaceNames []string,
	ipVersion uint8,
	tableIndex int,
	netlinkTimeout time.Duration,
	deviceRouteSourceAddress net.IP,
	deviceRouteProtocol int,
	removeExternalRoutes bool,
	opRecorder logutils.OpRecorder,
	featureDetector environment.FeatureDetectorIface,
) routetable.Interface {

	f.count += 1
	return routetable.New(
		&ownershippol.ExclusiveOwnershipPolicy{
			InterfaceNames: interfaceNames,
		},
		ipVersion,
		netlinkTimeout,
		deviceRouteSourceAddress,
		netlink.RouteProtocol(deviceRouteProtocol),
		removeExternalRoutes,
		tableIndex,
		opRecorder,
		featureDetector,
	)
}

type routeRulesGenerator interface {
	NewRouteRules(
		ipVersion int,
		tableIndexSet set.Set[int],
		updateFunc, removeFunc routerule.RulesMatchFunc,
		cleanupFunc routerule.RuleFilterFunc,
		netlinkTimeout time.Duration,
		recorder logutils.OpRecorder,
	) routeRules
}

type routeRulesFactory struct {
	count int
}

func (f *routeRulesFactory) NewRouteRules(
	ipVersion int,
	tableIndexSet set.Set[int],
	updateFunc, removeFunc routerule.RulesMatchFunc,
	cleanupFunc routerule.RuleFilterFunc,
	netlinkTimeout time.Duration,
	opRecorder logutils.OpRecorder,
) routeRules {

	f.count += 1
	rr, err := routerule.New(
		ipVersion,
		tableIndexSet,
		updateFunc,
		removeFunc,
		cleanupFunc,
		netlinkTimeout,
		func() (routerule.HandleIface, error) {
			return netlink.NewHandle(syscall.NETLINK_ROUTE)
		},
		opRecorder)
	if err != nil {
		// table index has been checked by config.
		// This should not happen.
		log.Panicf("error creating routerule instance")
	}

	return rr
}

func (g gateway) String() string {
	start, err := g.maintenanceStarted.MarshalText()
	if err != nil {
		start = []byte("<invalid_start_time>")
	}
	finish, err := g.maintenanceFinished.MarshalText()
	if err != nil {
		finish = []byte("<invalid_finish_time>")
	}
	return fmt.Sprintf("gateway: [ip=%s, maintenanceStarted=%s, maintenanceFinished=%s, hostname=%s]", g.addr, string(start), string(finish), g.hostname)
}

type egressRule struct {
	used       bool
	srcIP      ip.Addr
	priority   int
	family     int
	mark       uint32
	tableIndex int
}

func newEgressRule(nlRule *netlink.Rule) (*egressRule, error) {
	if nlRule.Src == nil {
		return nil, fmt.Errorf("netlink rule has no source, can't be one of ours: %v", nlRule)
	}
	return &egressRule{
		srcIP:      ip.FromNetIP(nlRule.Src.IP),
		tableIndex: nlRule.Table,
		priority:   nlRule.Priority,
		family:     nlRule.Family,
		mark:       nlRule.Mark,
	}, nil
}

type egressRoute struct {
	nextHops    set.Set[ip.Addr]
	throwToMain bool
}

type egressTable struct {
	used   bool
	index  int
	routes map[ip.CIDR]egressRoute
}

func newEgressTable(index int) *egressTable {
	return &egressTable{
		index:  index,
		routes: make(map[ip.CIDR]egressRoute),
	}
}

type initialKernelState struct {
	// rules is a slice of egressRule
	rules []*egressRule
	// tables is a map from table index to egressTable
	tables map[int]*egressTable
}

func newInitialKernelState() *initialKernelState {
	return &initialKernelState{
		rules:  nil,
		tables: make(map[int]*egressTable),
	}
}

func (s *initialKernelState) String() string {
	var ruleStrs []string
	for _, r := range s.rules {
		ruleStrs = append(ruleStrs, fmt.Sprintf("%s: [%#v]", r.srcIP, *r))
	}
	rulesOutput := fmt.Sprintf("rules: {%s}", strings.Join(ruleStrs, ","))

	var tables []string
	for index, t := range s.tables {
		tables = append(tables, fmt.Sprintf("%d: [%#v]", index, *t))
	}
	tablesOutput := fmt.Sprintf("tables: {%s}", strings.Join(tables, ","))

	return fmt.Sprintf("initialKernelState:{%s; %s}", rulesOutput, tablesOutput)
}

type egressIPManager struct {
	routeRules routeRules

	initialKernelState *initialKernelState

	// vxlanFDB is responsible for programming L2 ARP and FDB entries for our
	// VXLAN device.
	vxlanFDB VXLANFDB

	// rrGenerator dynamically creates routeRules instance to program route rules.
	rrGenerator routeRulesGenerator

	// rtGenerator dynamically creates route tables to program L3 routes.
	rtGenerator routeTableGenerator

	// Routing table index stack for egress workloads
	tableIndexStack *stack.Stack

	// routetable is allocated on demand and associated to a table index permanently.
	// When an egress ipset is not valid anymore, we still need to remove routes from
	// the table so routetable should not be freed immediately.
	// We could have code to free the unused routetable if it is inSync. However, since
	// the total number of routetables is limited, we may just avoid the complexity.
	// Just keep it; it could be reused by another EgressIPSet.
	tableIndexToRouteTable map[int]routetable.Interface
	// Tracks next hops for all route tables in use.
	tableIndexToEgressTable map[int]*egressTable
	egwTracker              *EgressGWTracker

	activeWorkloads      map[types.WorkloadEndpointID]*proto.WorkloadEndpoint
	workloadToTableIndex map[types.WorkloadEndpointID]int

	workloadMaintenanceWindows map[types.WorkloadEndpointID]gateway

	// Pending workload endpoints updates, we store these up as OnUpdate is called, then process them
	// in CompleteDeferredWork.
	pendingWorkloadUpdates map[types.WorkloadEndpointID]*proto.WorkloadEndpoint

	// VXLAN configuration.
	vxlanDevice string
	vxlanID     int
	vxlanPort   int

	// lock protects the fields shared between the main goroutine and the VXLAN device sync goroutine.
	lock                 sync.Mutex
	nodeIP               net.IP
	vxlanDeviceLinkIndex int
	myNodeIPChangedC     chan struct{}

	// to rate-limit retries, track if the last kernel sync failed, and if our state has changed since then
	lastUpdateFailed, unblockingUpdateOccurred, firstSyncDone bool

	ipsets   egressIPSets
	nlHandle netlinkHandle
	dpConfig Config

	// represents the entire block of table indices the manager is allowed to use.
	// gets passed to routerule package when creating rules
	tableIndexSet set.Set[int]

	opRecorder      logutils.OpRecorder
	featureDetector environment.FeatureDetectorIface

	disableChecksumOffload func(ifName string) error

	// Callback function used to notify of workload pods impacted by a terminating egress gateway pod
	statusCallback func(namespace, name string, addr ip.Addr, maintenanceStarted, maintenanceFinished time.Time) error

	healthAgg healthAggregator

	hopRand *rand.Rand

	bpfIPSets egressIPSets

	pendingIfaceStateChanges map[string]*ifaceStateUpdate
	srcValidMarkPathFmt      string
	writeProcSysFunc         func(path, value string) error
}

func newEgressIPManager(
	deviceName string,
	vxlanFDB VXLANFDB,
	rtTableIndices set.Set[int],
	dpConfig Config,
	opRecorder logutils.OpRecorder,
	statusCallback func(namespace, name string, addr ip.Addr, maintenanceStarted, maintenanceFinished time.Time) error,
	healthAgg healthAggregator,
	healthReportC chan<- EGWHealthReport,
	ipsets egressIPSets,
	bpfIPSets egressIPSets,
	featureDetector environment.FeatureDetectorIface,
	writeProcSysFunc func(path, value string) error,
) *egressIPManager {
	nlHandle, err := netlink.NewHandle()
	if err != nil {
		log.WithError(err).Panic("Failed to get netlink handle.")
	}

	// Prepare table index stack for allocation.
	tableIndexStack := stack.New()
	// Prepare table index set to be passed to routeRules.
	tableIndexSet := set.New[int]()
	// Sort indices to make route table allocation deterministic.
	sorted := sortIntSet(rtTableIndices)
	for _, element := range sorted {
		tableIndexStack.Push(element)
		tableIndexSet.Add(element)
	}

	hopRandSource := rand.NewSource(time.Now().UTC().UnixNano())

	mgr := newEgressIPManagerWithShims(
		vxlanFDB,
		&routeRulesFactory{count: 0},
		&routeTableFactory{count: 0},
		tableIndexSet,
		tableIndexStack,
		deviceName,
		dpConfig,
		nlHandle,
		opRecorder,
		ethtool.EthtoolTXOff,
		statusCallback,
		healthAgg,
		rand.New(hopRandSource),
		healthReportC,
		ipsets,
		bpfIPSets,
		featureDetector,
		writeProcSysFunc,
	)
	return mgr
}

func newEgressIPManagerWithShims(
	vxlanFDB VXLANFDB,
	rrGenerator routeRulesGenerator,
	rtGenerator routeTableGenerator,
	tableIndexSet set.Set[int],
	tableIndexStack *stack.Stack,
	deviceName string,
	dpConfig Config,
	nlHandle netlinkHandle,
	opRecorder logutils.OpRecorder,
	disableChecksumOffload func(ifName string) error,
	statusCallback func(namespace, name string, addr ip.Addr, maintenanceStarted, maintenanceFinished time.Time) error,
	healthAgg healthAggregator,
	hopRandSource rand.Source,
	healthReportC chan<- EGWHealthReport,
	ipsets egressIPSets,
	bpfIPSets egressIPSets,
	featureDetector environment.FeatureDetectorIface,
	writeProcSysFunc func(path, value string) error,
) *egressIPManager {
	if writeProcSysFunc == nil {
		log.Panic("Manager has no way to write proc-sys")
	}
	mgr := egressIPManager{
		vxlanFDB:                   vxlanFDB,
		rrGenerator:                rrGenerator,
		rtGenerator:                rtGenerator,
		initialKernelState:         newInitialKernelState(),
		tableIndexSet:              tableIndexSet,
		tableIndexStack:            tableIndexStack,
		tableIndexToRouteTable:     make(map[int]routetable.Interface),
		tableIndexToEgressTable:    make(map[int]*egressTable),
		pendingWorkloadUpdates:     make(map[types.WorkloadEndpointID]*proto.WorkloadEndpoint),
		activeWorkloads:            make(map[types.WorkloadEndpointID]*proto.WorkloadEndpoint),
		workloadToTableIndex:       make(map[types.WorkloadEndpointID]int),
		workloadMaintenanceWindows: make(map[types.WorkloadEndpointID]gateway),
		egwTracker: NewEgressGWTracker(
			context.Background(),
			healthReportC,
			dpConfig.EgressGatewayPollInterval,
			dpConfig.EgressGatewayPollFailureCount,
		),
		vxlanDevice:              deviceName,
		vxlanID:                  dpConfig.RulesConfig.EgressIPVXLANVNI,
		vxlanPort:                dpConfig.RulesConfig.EgressIPVXLANPort,
		dpConfig:                 dpConfig,
		nlHandle:                 nlHandle,
		opRecorder:               opRecorder,
		disableChecksumOffload:   disableChecksumOffload,
		statusCallback:           statusCallback,
		healthAgg:                healthAgg,
		hopRand:                  rand.New(hopRandSource),
		myNodeIPChangedC:         make(chan struct{}, 1),
		ipsets:                   ipsets,
		bpfIPSets:                bpfIPSets,
		featureDetector:          featureDetector,
		pendingIfaceStateChanges: make(map[string]*ifaceStateUpdate),
		srcValidMarkPathFmt:      "/proc/sys/net/ipv4/conf/%s/src_valid_mark",
		writeProcSysFunc:         writeProcSysFunc,
	}

	if healthAgg != nil {
		healthAgg.RegisterReporter(egressHealthName, &health.HealthReport{Ready: true}, 0)
		healthAgg.Report(egressHealthName, &health.HealthReport{Ready: false})
	}

	return &mgr
}

func (m *egressIPManager) OnUpdate(msg any) {
	switch msg := msg.(type) {
	case *proto.IPSetDeltaUpdate:
		m.egwTracker.OnIPSetDeltaUpdate(msg)
	case *proto.IPSetUpdate:
		m.egwTracker.OnIPSetUpdate(msg)
	case *proto.IPSetRemove:
		m.egwTracker.OnIPSetRemove(msg)
	case *proto.WorkloadEndpointUpdate:
		log.WithField("msg", msg).Debug("workload endpoint update")
		id := types.ProtoToWorkloadEndpointID(msg.GetId())
		m.pendingWorkloadUpdates[id] = msg.Endpoint
	case *proto.WorkloadEndpointRemove:
		log.WithField("msg", msg).Debug("workload endpoint remove")
		id := types.ProtoToWorkloadEndpointID(msg.GetId())
		m.pendingWorkloadUpdates[id] = nil
	case *proto.HostMetadataUpdate:
		log.WithField("msg", msg).Debug("host meta update")
		if msg.Hostname == m.dpConfig.FelixHostname {
			log.WithField("msg", msg).Debug("Local host update")
			// The node IP is used by the background VXLAN device update thread, need to synchronise.
			m.lock.Lock()
			newNodeIP := net.ParseIP(msg.Ipv4Addr)
			if !newNodeIP.Equal(m.nodeIP) {
				log.WithField("newNodeIP", newNodeIP).Info("Node IP changed, updating")
				m.nodeIP = newNodeIP
				select {
				case m.myNodeIPChangedC <- struct{}{}:
				default:
				}
			}
			m.lock.Unlock()
		}
	case *ifaceStateUpdate:
		if len(m.dpConfig.EgressIPHostIfacePattern) > 0 {
			log.WithField("msg", msg).Debug("iface state change")
			m.pendingIfaceStateChanges[msg.Name] = msg
		}
	default:
		return
	}

	// when an update we care about is seen (when the default switch case isn't hit), we track its occurrence
	m.unblockingUpdateOccurred = true
}

// CompleteDeferredWork attempts to process all updates received by this manager.
// Will attempt a retry if the first attempt fails, and reports health based on its success
func (m *egressIPManager) CompleteDeferredWork() error {
	m.lock.Lock()
	defer func() {
		// reset flag after attempting to apply an unblocking update
		m.unblockingUpdateOccurred = false
		m.lock.Unlock()
	}()

	for name, stateChange := range m.pendingIfaceStateChanges {
	patternMatch:
		for _, pattern := range m.dpConfig.EgressIPHostIfacePattern {
			if pattern.MatchString(name) {
				log.WithField("iface", name).Info("Iface matches pattern")
				switch stateChange.State {
				case ifacemonitor.StateUp, ifacemonitor.StateDown:
					m.writeProcSys(name)
				default:
				}

				break patternMatch
			}
		}
		delete(m.pendingIfaceStateChanges, name)
	}

	// Retry completing deferred work once.
	// The VXLAN device may have come online, or
	// a routetable may have been free'd following a starvation error
	var err error
	if !m.lastUpdateFailed || m.unblockingUpdateOccurred || !m.firstSyncDone {
		for i := 0; i < 2; i += 1 {
			if err = m.completeDeferredWork(); err == nil {
				m.lastUpdateFailed = false
				break
			}
		}
	}

	// report health
	if err != nil {
		m.lastUpdateFailed = true
		log.WithError(err).Warn("Failed to configure egress networking for one or more workloads")
		m.healthAgg.Report(egressHealthName, &health.HealthReport{Ready: false})
	} else {
		m.healthAgg.Report(egressHealthName, &health.HealthReport{Ready: true})
	}

	return nil // we manage our own retries and health, so never report an error to the dp driver
}

// completeDeferredWork processes all received updates and queues kernel networking updates.
// When called for the first time, will init egressIPManager config with existing kernel data
func (m *egressIPManager) completeDeferredWork() error {
	var lastErr error
	if !m.egwTracker.Dirty() && len(m.pendingWorkloadUpdates) == 0 && m.firstSyncDone {
		log.Debug("No change since last application, nothing to do")
		return nil
	}

	// Set up the all-EGW-health-port IP set before we do anything else.  Need to make sure the set exists before
	// we return from the first completeDeferredWork call.
	if !m.firstSyncDone || m.egwTracker.Dirty() {
		// It's a little inefficient to recalculate the whole set each time, but it saves needing to do reference
		// counting to deal with corner cases such as EGWs being in multiple IP sets.
		if !m.dpConfig.BPFEnabled {
			m.ipsets.AddOrReplaceIPSet(ipsets.IPSetMetadata{
				SetID:   rules.IPSetIDAllEGWHealthPorts,
				Type:    ipsets.IPSetTypeHashIPPort,
				MaxSize: m.dpConfig.MaxIPSetSize,
			}, m.egwTracker.AllHealthPortIPSetMembers())
		} else {
			m.bpfIPSets.AddOrReplaceIPSet(
				ipsets.IPSetMetadata{SetID: bpfipsets.EgressGWHealthPortsName, Type: ipsets.IPSetTypeHashIPPort},
				m.egwTracker.AllHealthPortIPSetMembers())
		}
	}
	m.firstSyncDone = true

	if m.vxlanDeviceLinkIndex == 0 {
		// vxlan device not configured yet. Defer processing updates.
		log.Debug("Wait for Egress-IP VXLAN device to be configured")
		return ErrVxlanDeviceNotConfigured
	}

	if m.routeRules == nil {
		// Create routeRules to manage routing rules.
		// We create routerule inside CompleteDeferredWork to make sure datastore is in sync and all WEP/EgressIPSet updates
		// will be processed before routerule's apply() been called.
		m.routeRules = m.rrGenerator.NewRouteRules(
			4,
			m.tableIndexSet,
			routerule.RulesMatchSrcFWMarkTable,
			routerule.RulesMatchSrcFWMarkTable,
			nil,
			m.dpConfig.NetlinkTimeout,
			m.opRecorder,
		)
	}

	if m.egwTracker.Dirty() {
		// Work out all L2 routes updates.
		m.setL2Routes()
	}

	if m.initialKernelState != nil {
		log.Info("Reading initial kernel state.")
		// Query kernel rules and tables to see what is already in place and can be reused.
		err := m.readInitialKernelState()
		if err != nil {
			log.WithError(err).Info("Couldn't read initial kernel state.")
			// If we can't read the initial state, return now to avoid causing damage.
			return err
		}
	}

	if m.egwTracker.Dirty() {
		log.Info("Processing gateway updates.")
		err := m.processGatewayUpdates()
		if err != nil {
			log.WithError(err).Info("Couldn't process gateway updates.")
			lastErr = err
		}
	}

	log.Info("Processing workload updates.")
	err := m.processWorkloadUpdates()
	if err != nil {
		log.WithError(err).Info("Couldn't process workload updates.")
		lastErr = err
	}

	log.Info("Notifying workloads of any terminating gateways.")
	err = m.notifyWorkloadsOfEgressGatewayMaintenanceWindows()
	if err != nil {
		log.WithError(err).Info("Couldn't notify workloads of gateway termination.")
		lastErr = err
	}

	if m.initialKernelState != nil {
		log.Info("Cleaning up any unused initial kernel state.")
		// Cleanup any kernel routes and tables which were not needed for reuse.
		err = m.cleanupInitialKernelState()
		if err != nil {
			log.WithError(err).Info("Couldn't cleanup initial kernel state.")
			lastErr = err
		}
	}

	return lastErr
}

func (m *egressIPManager) readInitialKernelState() error {
	if m.routeRules == nil {
		return errors.New("cannot read rules and tables from kernel during initial read")
	}

	// Read routing rules within the egress manager table range from the kernel.
	m.routeRules.InitFromKernel()
	activeRules := m.routeRules.GetAllActiveRules()
	ruleTableIndices := set.New[int]()
	for _, rule := range activeRules {
		nlRule := rule.NetLinkRule()
		r, err := newEgressRule(nlRule)
		if err != nil {
			log.WithError(err).Warn("Found routing rule in our range that doesn't look like an egress gateway rule. Will clean it up.")
			m.routeRules.RemoveRule(rule)
			continue
		}
		m.initialKernelState.rules = append(m.initialKernelState.rules, r)
		ruleTableIndices.Add(r.tableIndex)
	}

	// Read routing tables referenced by a routing rule from the kernel.
	reservedTables := set.New[int]()
	for index := range ruleTableIndices.All() {
		t, err := m.getTableFromKernel(index)
		if err != nil {
			log.WithError(err).WithField("table", index).Error("failed to get route table targets")
			continue
		}
		if len(t.routes) > 0 {
			// Ensure table index isn't in the tableIndexStack, so it won't be used by another workload
			reservedTables.Add(index)
			m.initialKernelState.tables[t.index] = t
		}
	}
	m.removeIndicesFromTableStack(reservedTables)

	log.WithFields(log.Fields{
		"initialKernelState": m.initialKernelState,
	}).Info("Read existing route rules and tables from kernel.")
	return nil
}

func (m *egressIPManager) cleanupInitialKernelState() error {
	if m.routeRules == nil {
		return errors.New("cannot read rules and tables from kernel during initial cleanup")
	}
	defer func() {
		m.initialKernelState = nil
	}()

	// Remove unused rules.
	for _, r := range m.initialKernelState.rules {
		if !r.used {
			log.WithField("rule", *r).Info("Deleting unused route rule")
			m.deleteRouteRule(r)
		}
	}

	// Remove unused tables.
	for _, t := range m.initialKernelState.tables {
		if !t.used {
			log.WithField("table", *t).Info("Deleting unused route table")
			// This looks odd to create it then delete it, but is necessary since delete needs it to be tracked.
			m.createRouteTable(t)
			m.deleteRouteTable(t.index)
		}
	}
	return nil
}

// processGatewayUpdates handles all gateway updates. Any route tables which contain next hops for gateways which no
// longer exist are deleted and recreated with new valid hops.
func (m *egressIPManager) processGatewayUpdates() error {
	dirtySetIDs := m.egwTracker.UpdatePollersGetAndClearDirtySetIDs()

	var lastErr error
	sortedWEPIDs := m.sortedWorkloadIDs() /* sort for determinism in tests */
	for _, id := range dirtySetIDs {
		gateways, exists := m.egwTracker.GatewaysByID(id)
		if !exists {
			log.WithField("IPSetID", id).Info("Could not find gateways for IPSet, it will be removed.")
			gateways = make(gatewaysByIP)
		}
		gatewayIPs := gateways.allIPs()
		failedGateways := gateways.failedGateways()

		// Check if any existing workloads have next hops for deleted gateways.
		for _, workloadID := range sortedWEPIDs {
			workload := m.activeWorkloads[workloadID]
			index, exists := m.workloadToTableIndex[workloadID]
			if !exists {
				lastErr = fmt.Errorf("table index not found for workload with id %s", workloadID)
				continue
			}
			table, exists := m.tableIndexToEgressTable[index]
			if !exists {
				lastErr = fmt.Errorf("table not found with index %d", index)
				continue
			}

			workloadIsDirty := false
			for _, r := range workload.EgressGatewayRules {
				route, exists := table.routes[normaliseDestination(r.Destination)]
				if !exists {
					lastErr = fmt.Errorf("route not found for destination %s", r.Destination)
					continue
				}
				if route.throwToMain {
					// Throw routes do not use any gateway
					continue
				}
				// Check if this workload uses the current gateways
				if r.IpSetId != id {
					continue
				}
				log.WithFields(log.Fields{
					"ipSetID":    id,
					"gateways":   gateways,
					"workloadID": workloadID,
					"workload":   workload,
					"tableIndex": index,
					"nextHop":    route.nextHops,
				}).Info("Processing gateway update.")

				numActiveGateways := len(m.getActiveGateways(gateways, r.PreferLocalEgressGateway))
				maxNextHops := int(r.MaxNextHops)
				if maxNextHops == 0 {
					// No limit so default to using all EGWs.
					maxNextHops = numActiveGateways
				}
				numDesiredGateways := min(maxNextHops, numActiveGateways)

				workloadHasLessHopsThanDesired := route.nextHops.Len() < numDesiredGateways
				workloadHasNonExistentHop := !gatewayIPs.ContainsAll(route.nextHops)
				if r.PreferLocalEgressGateway {
					localGateways := gateways.localGateways(m.dpConfig.Hostname)
					if len(localGateways) > 0 {
						workloadHasNonExistentHop = !localGateways.allIPs().ContainsAll(route.nextHops)
					}
				}
				workloadHasFailedHop := len(failedGateways.filteredByHopIPs(route.nextHops)) > 0
				if workloadHasLessHopsThanDesired || workloadHasNonExistentHop || workloadHasFailedHop {
					log.WithFields(log.Fields{
						"ipSetID":                        id,
						"workloadIPs":                    workload.Ipv4Nets,
						"workloadID":                     workloadID,
						"tableIndex":                     index,
						"existingEGWs":                   route.nextHops,
						"workloadHasLessHopsThanDesired": workloadHasLessHopsThanDesired,
						"workloadHasNonExistentHop":      workloadHasNonExistentHop,
						"workloadHasFailedHop":           workloadHasFailedHop,
					}).Info("Processing gateway update - recreating route rules and table for workload.")
					workloadIsDirty = true
					break
				}
			}

			if workloadIsDirty {
				// Delete the old route rules and table as they contain an invalid hop.
				m.deleteWorkloadRuleAndTable(workloadID, workload)

				// Create new route rules and a route table for this workload.
				err := m.createWorkloadRuleAndTable(workloadID, workload)
				if err != nil {
					lastErr = err
					continue
				}
			}
		}
	}
	return lastErr
}

func (m *egressIPManager) sortedWorkloadIDs() []types.WorkloadEndpointID {
	var workloadIDs []types.WorkloadEndpointID
	for workloadID := range m.activeWorkloads {
		workloadIDs = append(workloadIDs, workloadID)
	}
	sort.Slice(workloadIDs, func(i, j int) bool {
		if workloadIDs[i].EndpointId != workloadIDs[j].EndpointId {
			return workloadIDs[i].EndpointId < workloadIDs[j].EndpointId
		}
		if workloadIDs[i].WorkloadId != workloadIDs[j].WorkloadId {
			return workloadIDs[i].WorkloadId < workloadIDs[j].WorkloadId
		}
		return workloadIDs[i].OrchestratorId < workloadIDs[j].OrchestratorId
	})
	return workloadIDs
}

// processWorkloadUpdates takes WorkLoadEndpoints from state and programs route rules for their CIDR's pointing to an egress route table
// dedicated to that workload. The table will contain maxNextHops ECMP routes if specified, otherwise it will contain an ECMP route
// for every member of the workload's IP set.
// To minimize the effect on existing traffic, route rules and tables discovered from the kernel on initialization will be left in place
// if possible, rather than creating new rules and tables.
func (m *egressIPManager) processWorkloadUpdates() error {
	var lastErr error
	// Handle pending workload endpoint updates.
	var ids []types.WorkloadEndpointID
	for id := range m.pendingWorkloadUpdates {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if ids[i].EndpointId != ids[j].EndpointId {
			return ids[i].EndpointId < ids[j].EndpointId
		}
		if ids[i].WorkloadId != ids[j].WorkloadId {
			return ids[i].WorkloadId < ids[j].WorkloadId
		}
		return ids[i].OrchestratorId < ids[j].OrchestratorId
	})

	existingTables := make(map[types.WorkloadEndpointID]*egressTable)
	var workloadsToUseExistingTable []types.WorkloadEndpointID
	var workloadsToUseNewTable []types.WorkloadEndpointID
	if m.initialKernelState != nil {
		log.Info("Processing workloads after restart. Will attempt to reuse existing rules and tables to preserve traffic.")
		// Look for any routing rules and tables which can be reused.
		for _, id := range ids {
			workload := m.pendingWorkloadUpdates[id]
			// EgressGatewayRules should have at least one rule
			if workload == nil || len(workload.EgressGatewayRules) == 0 {
				continue
			}
			existingTable, exists := m.reserveFromInitialState(workload, id)
			if exists {
				existingTables[id] = existingTable
				workloadsToUseExistingTable = append(workloadsToUseExistingTable, id)
				log.WithFields(log.Fields{
					"workloadID": id,
					"table":      existingTables,
				}).Info("Pre-processing workload - reserving table")
			} else {
				workloadsToUseNewTable = append(workloadsToUseNewTable, id)
			}
		}

		// Process workloads reusing existing tables first, so that workloads needing new tables can be created in such a way
		// as to even out the distribution of hops across workloads.
		for _, id := range workloadsToUseExistingTable {
			logCtx := log.WithField("workloadID", id)
			workload := m.pendingWorkloadUpdates[id]

			log.WithFields(log.Fields{
				"workloadID": id,
				"workload":   workload,
			}).Info("Processing workload create.")

			existingTable, exists := existingTables[id]
			if exists {
				logCtx.Info("Processing workload - suitable route rules pointing to a table with active gateway hops were found.")
				m.createWorkloadRuleAndTableWithIndex(id, workload, existingTable)
			}
			m.activeWorkloads[id] = workload
			delete(m.pendingWorkloadUpdates, id)
		}
	} else {
		workloadsToUseNewTable = append(workloadsToUseNewTable, ids...)
	}

	// Process workloads needing new tables last, to even out the distribution of hops across workloads.
	for _, id := range workloadsToUseNewTable {
		logCtx := log.WithField("workloadID", id)
		workload := m.pendingWorkloadUpdates[id]
		oldWorkload := m.activeWorkloads[id]

		if workload != nil && oldWorkload != nil {
			log.WithFields(log.Fields{
				"workloadID":                  id,
				"workload":                    workload,
				"workload.egressGatewayRules": workload.EgressGatewayRules,
				"oldWorkload":                 oldWorkload,
				"oldWorkload.egressGateRules": oldWorkload.EgressGatewayRules,
			}).Info("Processing workload update.")
		}

		if workload != nil && oldWorkload == nil {
			log.WithFields(log.Fields{
				"workloadID":                  id,
				"workload":                    workload,
				"workload.egressGatewayRules": workload.EgressGatewayRules,
			}).Info("Processing workload create.")
		}

		if workload == nil && oldWorkload != nil {
			log.WithFields(log.Fields{
				"workloadID":                  id,
				"oldWorkload":                 oldWorkload,
				"oldWorkload.egressGateRules": oldWorkload.EgressGatewayRules,
			}).Info("Processing workload delete.")
		}

		workloadCreated := workload != nil && oldWorkload == nil
		workloadDeleted := workload == nil && oldWorkload != nil
		workloadChanged := workload != nil && oldWorkload != nil

		oldEgressRulesWasEmpty := (oldWorkload == nil) || (len(oldWorkload.EgressGatewayRules) == 0)
		newEgressRulesIsEmpty := (workload == nil) || (len(workload.EgressGatewayRules) == 0)

		workloadDeletedWasUsingEgress := workloadDeleted && !oldEgressRulesWasEmpty
		workloadChangedToStopUsingEgress := workloadChanged && newEgressRulesIsEmpty && !oldEgressRulesWasEmpty
		workloadChangedToUseDifferentEgress := workloadChanged && !newEgressRulesIsEmpty &&
			!oldEgressRulesWasEmpty && !equalEgressPolicies(workload.EgressGatewayRules, oldWorkload.EgressGatewayRules)
		workloadChangedToUseNewAddr := workloadChanged && workloadAddrChanged(workload, oldWorkload)

		if workloadDeletedWasUsingEgress || workloadChangedToStopUsingEgress ||
			workloadChangedToUseDifferentEgress || workloadChangedToUseNewAddr {
			logCtx.Info("Processing workload - workload deleted or no longer using egress gateway.")
			m.deleteWorkloadRuleAndTable(id, oldWorkload)
			delete(m.activeWorkloads, id)
		}

		workloadCreatedUsingEgress := workloadCreated && !newEgressRulesIsEmpty
		workloadChangedToStartUsingEgress := workloadChanged && !newEgressRulesIsEmpty && oldEgressRulesWasEmpty

		if workloadCreatedUsingEgress || workloadChangedToStartUsingEgress ||
			workloadChangedToUseDifferentEgress || workloadChangedToUseNewAddr {
			logCtx.Info("Processing workload - creating new route rules and table.")
			err := m.createWorkloadRuleAndTable(id, workload)
			if err != nil {
				logCtx.WithError(err).Info("Couldn't create route table and rules for workload.")
				lastErr = err
				continue
			}
			m.activeWorkloads[id] = workload
		}

		delete(m.pendingWorkloadUpdates, id)
	}

	return lastErr
}

func workloadAddrChanged(n, o *proto.WorkloadEndpoint) bool {
	nSet := set.FromArray(n.Ipv4Nets)
	oSet := set.FromArray(o.Ipv4Nets)
	return !nSet.Equals(oSet)
}

func equalEgressPolicies(p1, p2 []*proto.EgressGatewayRule) bool {
	if len(p1) != len(p2) {
		return false
	}
	for i, p := range p1 {
		if p != p2[i] {
			return false
		}
	}
	return true
}

// Notifies all workloads of maintenance windows on egress gateway pods they're using by annotating the workload pods.
func (m *egressIPManager) notifyWorkloadsOfEgressGatewayMaintenanceWindows() error {
	// Cleanup any orphaned maintenance windows.
	for id := range m.workloadMaintenanceWindows {
		if _, exists := m.activeWorkloads[id]; !exists {
			delete(m.workloadMaintenanceWindows, id)
		}
	}
	for id, workload := range m.activeWorkloads {
		index, exists := m.workloadToTableIndex[id]
		if !exists {
			return fmt.Errorf("cannot find table for workload with id %s", id)
		}
		table, exists := m.tableIndexToEgressTable[index]
		if !exists {
			return fmt.Errorf("cannot find table with index %d", index)
		}
		allTerminatingGWs := make(gatewaysByIP)
		for _, rule := range workload.EgressGatewayRules {
			gateways, exists := m.egwTracker.GatewaysByID(rule.IpSetId)
			if !exists {
				log.Debugf("Workload with ID: %s references an empty set of gateways: %s for destination %s. Skipping.", id, rule.IpSetId, rule.Destination)
				continue
			}
			route, exists := table.routes[normaliseDestination(rule.Destination)]
			if !exists {
				log.Debugf("Cannot find route for destination %v in table with index %d - Skipping.", rule.Destination, index)
				continue
			}
			if route.throwToMain {
				// Throw routes do not use any gateway
				log.Debugf("Throw route for destination %s - Skipping.", rule.Destination)
				continue
			}
			terminatingGatewayHops := gateways.terminatingGateways().filteredByHopIPs(route.nextHops)
			allTerminatingGWs = allTerminatingGWs.mergeWithAnother(terminatingGatewayHops)
		}

		latest := allTerminatingGWs.latestTerminatingGateway()
		if latest == nil {
			continue
		}

		existing, exists := m.workloadMaintenanceWindows[id]
		if !exists {
			existing = gateway{}
		}

		namespace, name, err := parseNameAndNamespace(id.WorkloadId)
		if err != nil {
			return err
		}
		wepids := names.WorkloadEndpointIdentifiers{
			Node:         m.dpConfig.FelixHostname,
			Orchestrator: id.OrchestratorId,
			Endpoint:     id.EndpointId,
			Pod:          name,
		}
		wepName, err := wepids.CalculateWorkloadEndpointName(false)
		if err != nil {
			return err
		}

		if !latest.maintenanceStarted.IsZero() &&
			!latest.maintenanceFinished.IsZero() &&
			(latest.addr != existing.addr ||
				!latest.maintenanceStarted.Equal(existing.maintenanceStarted) ||
				!latest.maintenanceFinished.Equal(existing.maintenanceFinished)) {
			log.WithFields(log.Fields{
				"gateways":             allTerminatingGWs,
				"namespace":            namespace,
				"name":                 name,
				"latestTerminatingHop": latest.String(),
			}).Info("Notifying workload of its next hops which are terminating.")
			m.workloadMaintenanceWindows[id] = *latest
			err = m.statusCallback(
				namespace,
				wepName,
				latest.addr,
				latest.maintenanceStarted,
				latest.maintenanceFinished)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Set L2 routes for all active EgressIPSet.
func (m *egressIPManager) setL2Routes() {
	gatewayIPs := m.egwTracker.AllGatewayIPs()

	var vteps []vxlanfdb.VTEP
	for _, gatewayIP := range sortAddrSet(gatewayIPs) {
		vteps = append(vteps, vxlanfdb.VTEP{
			// remote VTEP mac is generated based on gateway pod ip.
			TunnelMAC: ipToMac(gatewayIP),
			TunnelIP:  gatewayIP,
			HostIP:    gatewayIP,
		})
	}

	log.WithField("vteps", vteps).Info("Egress IP manager updating VTEPs")
	m.vxlanFDB.SetVTEPs(vteps)
}

func sortAddrSet(in set.Set[ip.Addr]) []ip.Addr {
	s := in.Slice()
	sortAddrSlice(s)
	return s
}

func sortAddrSlice(s []ip.Addr) {
	sort.Slice(s, func(i, j int) bool {
		return bytes.Compare(s[i].AsNetIP(), s[j].AsNetIP()) < 0
	})
}

// Set L3 routes for an EgressIPSet.
func (m *egressIPManager) setL3Routes(rawTable routetable.Interface, t *egressTable) {
	var (
		vxlanRoutes                []routetable.Target
		noIfaceRoutes              []routetable.Target
		vxlanSinglePathRouteIsUsed bool
	)
	rTable := routetable.NewClassView(routetable.RouteClassEgress, rawTable)
	for dst, r := range t.routes {
		if r.throwToMain {
			route := routetable.Target{
				Type: routetable.TargetTypeThrow,
				CIDR: dst,
			}
			noIfaceRoutes = append(noIfaceRoutes, route)
		} else {
			// Sort ips to make ECMP route deterministic.
			nextHopsSlice := sortAddrSet(r.nextHops)
			var multipath []routetable.NextHop
			for _, addr := range nextHopsSlice {
				multipath = append(multipath, routetable.NextHop{
					Gw:        addr,
					IfaceName: m.vxlanDevice,
				})
			}

			if len(multipath) > 1 {
				// Set multipath L3 route.
				// Note the interface is InterfaceNone for multipath.
				route := routetable.Target{
					Type:      routetable.TargetTypeVXLAN,
					CIDR:      dst,
					MultiPath: multipath,
				}
				rTable.RouteRemove(m.vxlanDevice, dst)
				noIfaceRoutes = append(noIfaceRoutes, route)
			} else if len(multipath) == 1 {
				// If we send multipath routes with just one path, netlink will program it successfully.
				// However, we will read back a route via netlink with GW set to nexthop GW
				// and len(Multipath) set to 0. To keep route target consistent with netlink route,
				// we should not send a multipath target with just one GW.
				route := routetable.Target{
					Type: routetable.TargetTypeVXLAN,
					CIDR: dst,
					GW:   multipath[0].Gw,
				}
				vxlanSinglePathRouteIsUsed = true

				// Route table module may report warning of `file exists` on programming route for egress.vxlan device.
				// This is because route table module processes route updates organized by interface names.
				// In this case, default route for egress.calico interface could not be programmed unless
				// the default route linked with InterfaceNone been removed. After a couple of failures on processing
				// egress.calico updates, route table module will continue on processing InterfaceNone updates
				// and remove default route (see RouteRemove below).
				// Route updates for egress.vxlan will be successful at next dataplane apply().
				rTable.RouteRemove(routetable.InterfaceNone, dst)
				vxlanRoutes = append(vxlanRoutes, route)
			} else {
				// Set unreachable route.
				route := routetable.Target{
					Type: routetable.TargetTypeUnreachable,
					CIDR: dst,
				}
				rTable.RouteRemove(m.vxlanDevice, dst)
				noIfaceRoutes = append(noIfaceRoutes, route)
			}
		}
	}

	logCxt := log.WithField("table", rTable.Index())
	logCxt.Infof("Egress ip manager sending ECMP VXLAN L3 updates: %v", vxlanRoutes)
	if vxlanSinglePathRouteIsUsed {
		logCxt.Info("Egress ip manager sending single path VXLAN L3 updates," +
			" may see couple of warnings if an ECMP route was previously programmed")
	}
	rTable.SetRoutes(m.vxlanDevice, vxlanRoutes)

	logCxt.Infof("Egress ip manager sending route for interface %v: %v", routetable.InterfaceNone, noIfaceRoutes)
	rTable.SetRoutes(routetable.InterfaceNone, noIfaceRoutes)
}

func (m *egressIPManager) createWorkloadRuleAndTable(workloadID types.WorkloadEndpointID, workload *proto.WorkloadEndpoint) error {
	index, err := m.getNextTableIndex()
	if err != nil {
		return err
	}
	t := egressTable{
		index:  index,
		routes: make(map[ip.CIDR]egressRoute),
	}
	log.WithFields(log.Fields{
		"workloadID": workloadID,
		"rules":      workload.EgressGatewayRules,
	}).Info("Processing egress gateway rule.")
	for _, r := range workload.EgressGatewayRules {
		var egrRoute egressRoute
		if r.IpSetId == "" {
			egrRoute.throwToMain = true
		} else {
			gateways, exists := m.egwTracker.GatewaysByID(r.IpSetId)
			if !exists {
				gateways = make(gatewaysByIP)
			}
			activeGatewayIPs := m.getActiveGateways(gateways, r.PreferLocalEgressGateway).allIPs()
			adjustedNumHops := workloadNumHops(int(r.MaxNextHops), activeGatewayIPs.Len())

			hopIPs, err := m.determineRouteNextHops(workloadID, r.IpSetId, adjustedNumHops, r.PreferLocalEgressGateway)
			if err != nil {
				log.WithError(err).Errorf("Failed to determine next hop for gateway %s", r.IpSetId)
				continue
			}
			egrRoute.nextHops = hopIPs
		}
		t.routes[normaliseDestination(r.Destination)] = egrRoute
	}
	m.createWorkloadRuleAndTableWithIndex(workloadID, workload, &t)
	return nil
}

func (m *egressIPManager) createWorkloadRuleAndTableWithIndex(workloadID types.WorkloadEndpointID, workload *proto.WorkloadEndpoint, table *egressTable) {
	// Create new route rules and a route table for this workload.
	log.WithFields(log.Fields{
		"workloadID":  workloadID,
		"workloadIPs": workload.Ipv4Nets,
		"tableIndex":  table.index,
		"tableRoutes": table.routes,
	}).Info("Creating route rules and table for this workload.")
	m.createRouteTable(table)
	m.workloadToTableIndex[workloadID] = table.index
	for _, srcIP := range workload.Ipv4Nets {
		m.createRouteRule(ip.FromIPOrCIDRString(srcIP), table.index)
	}
}

func (m *egressIPManager) deleteWorkloadRuleAndTable(id types.WorkloadEndpointID, workload *proto.WorkloadEndpoint) {
	index, exists := m.workloadToTableIndex[id]
	if !exists {
		// This can occur if the workload has already been deleted as a result of an IPSet becoming empty, and then a
		// workload being removed in the same batch of updates.
		log.WithField("workloadID", id).Debug("Cannot delete routing table for workload, it has already been deleted.")
		return
	}
	for _, ipAddr := range workload.Ipv4Nets {
		m.deleteRouteRule(&egressRule{
			priority:   m.dpConfig.EgressIPRoutingRulePriority,
			mark:       m.dpConfig.RulesConfig.MarkEgress,
			srcIP:      ip.FromIPOrCIDRString(ipAddr),
			tableIndex: index,
		})
	}
	m.deleteRouteTable(index)
	delete(m.workloadToTableIndex, id)
}

func (m *egressIPManager) newRouteTable(tableNum int) routetable.Interface {
	return m.rtGenerator.NewRouteTable(
		[]string{m.vxlanDevice, routetable.InterfaceNone},
		4,
		tableNum,
		m.dpConfig.NetlinkTimeout,
		nil,
		int(m.dpConfig.DeviceRouteProtocol),
		true,
		m.opRecorder,
		m.featureDetector,
	)
}

func (m *egressIPManager) getNextTableIndex() (int, error) {
	if m.tableIndexStack.Len() == 0 {
		return 0, ErrInsufficientRouteTables
	}
	index := m.tableIndexStack.Pop().(int)
	log.WithField("index", index).Debug("Popped table index off the stack for table creation.")
	return index, nil
}

func (m *egressIPManager) createRouteTable(t *egressTable) {
	log.WithFields(log.Fields{
		"table": t,
	}).Debug("Creating route table.")
	table := m.newRouteTable(t.index)
	log.WithFields(log.Fields{
		"table": t,
	}).Debug("Adding L3 routes.")
	m.setL3Routes(table, t)
	m.tableIndexToRouteTable[t.index] = table
	m.tableIndexToEgressTable[t.index] = t
}

func (m *egressIPManager) deleteRouteTable(index int) {
	log.WithField("index", index).Debug("Deleting route table.")
	table, exists := m.tableIndexToRouteTable[index]
	if !exists {
		log.WithField("tableIndex", index).Debug("Cannot delete routing table, it does not exist.")
		return
	}
	for dst := range m.tableIndexToEgressTable[index].routes {
		log.WithFields(log.Fields{
			"index":       index,
			"destination": dst,
		}).Debug("Removing L3 routes.")
		table.RouteRemove(routetable.RouteClassEgress, routetable.InterfaceNone, dst)
		table.RouteRemove(routetable.RouteClassEgress, m.vxlanDevice, dst)
	}
	delete(m.tableIndexToEgressTable, index)
	// Don't remove the entry from m.tableIndexToRouteTable, it is needed in GetRouteTableSyncers()
	// so the dataplane knows which route tables to sync. If we remove it, the dataplane will not
	// be able to remove the routes.
	log.WithField("index", index).Debug("Pushing table index to the stack after table deletion.")
	m.tableIndexStack.Push(index)
}

func newRouteRule(priority int, fwMark uint32, srcIP ip.Addr, tableIndex int) *routerule.Rule {
	srcIPAddr := srcIP.AsCIDR().ToIPNet()
	return routerule.
		NewRule(4, priority).
		MatchSrcAddress(srcIPAddr).
		MatchFWMark(fwMark).
		GoToTable(tableIndex)
}

func (m *egressIPManager) createRouteRule(srcIP ip.Addr, tableIndex int) {
	log.WithFields(log.Fields{
		"srcIP":      srcIP,
		"tableIndex": tableIndex,
	}).Debug("Creating route rule.")
	rule := newRouteRule(m.dpConfig.EgressIPRoutingRulePriority,
		m.dpConfig.RulesConfig.MarkEgress,
		srcIP, tableIndex)
	m.routeRules.SetRule(rule)
}

func (m *egressIPManager) deleteRouteRule(rule *egressRule) {
	log.WithFields(log.Fields{
		"srcIP":      rule.srcIP,
		"tableIndex": rule.tableIndex,
	}).Debug("Deleting route rule.")
	m.routeRules.RemoveRule(
		newRouteRule(rule.priority, uint32(rule.mark), rule.srcIP, rule.tableIndex))
}

func (m *egressIPManager) getTableFromKernel(index int) (*egressTable, error) {
	table := m.newRouteTable(index)
	// get targets for both possible interface names
	vxlanTargets, err := table.ReadRoutesFromKernel(m.vxlanDevice)
	if err != nil {
		return nil, err
	}
	noneTargets, err := table.ReadRoutesFromKernel(routetable.InterfaceNone)
	if err != nil {
		return nil, err
	}
	eTable := newEgressTable(index)
	updateEgressTableRoutes(eTable, vxlanTargets)
	updateEgressTableRoutes(eTable, noneTargets)
	return eTable, nil
}

func updateEgressTableRoutes(eTable *egressTable, targets []routetable.Target) {
	for _, t := range targets {
		switch t.Type {
		case routetable.TargetTypeThrow:
			eTable.routes[t.CIDR] = egressRoute{
				throwToMain: true,
			}
		case routetable.TargetTypeVXLAN:
			if t.GW != nil {
				eTable.routes[t.CIDR] = egressRoute{
					nextHops: set.FromArray([]ip.Addr{t.GW}),
				}
			} else {
				hopIPs := []ip.Addr{}
				for _, hop := range t.MultiPath {
					hopIPs = append(hopIPs, hop.Gw)
				}
				eTable.routes[t.CIDR] = egressRoute{
					nextHops: set.FromArray(hopIPs),
				}
			}
		}
	}
}

func (m *egressIPManager) GetRouteTableSyncers() []routetable.SyncerInterface {
	rts := make([]routetable.SyncerInterface, 0, len(m.tableIndexToRouteTable))
	for _, t := range m.tableIndexToRouteTable {
		rts = append(rts, t.(routetable.SyncerInterface))
	}

	return rts
}

func (m *egressIPManager) GetRouteRules() []routeRules {
	if m.routeRules != nil {
		return []routeRules{m.routeRules}
	}
	return nil
}

// ipToMac defines how an egress gateway pod's MAC is generated
func ipToMac(ipAddr ip.Addr) net.HardwareAddr {
	netIP := ipAddr.AsNetIP()
	// Any MAC address that has the values 2, 3, 6, 7, A, B, E, or F
	// as the second most significant nibble are locally administered.
	hw := net.HardwareAddr(append([]byte{0xa2, 0x2a}, netIP...))
	return hw
}

func (m *egressIPManager) KeepVXLANDeviceInSync(mtu int, wait time.Duration, vxlanDeviceUpdatedC chan<- struct{}) {
	log.Info("egress ip VXLAN tunnel device thread started.")

	sleepMonitoringChans := func(maxDuration time.Duration) {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-m.myNodeIPChangedC:
			log.Debug("Sleep returning early: Node IP changed.")
		}
	}

	logNextTime := true
	var lastNodeIP net.IP
	var lastLinkIndex int
	for {
		m.lock.Lock()
		nodeIP := m.nodeIP
		m.lock.Unlock()

		err := m.configureVXLANDevice(nodeIP, mtu)
		if err != nil {
			log.WithError(err).Warn("Failed to configure egress ip VXLAN tunnel device, retrying...")
			time.Sleep(1 * time.Second)
			logNextTime = true
			goto next
		}

		// src_valid_mark must be enabled for RPF to accurately check returning egress packets coming through egress.calico
		err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/src_valid_mark", m.vxlanDevice), "1")
		if err != nil {
			log.WithError(err).Warnf("Failed to enable src_valid_mark system flag for device '%s", m.vxlanDevice)
			logNextTime = true
			goto next
		}

		m.lock.Lock()
		if !nodeIP.Equal(lastNodeIP) || lastLinkIndex != m.vxlanDeviceLinkIndex {
			log.Debug("Sending kick to main goroutine.")
			select {
			case vxlanDeviceUpdatedC <- struct{}{}:
			default:
			}
			lastNodeIP = nodeIP
			lastLinkIndex = m.vxlanDeviceLinkIndex
		}
		m.lock.Unlock()

		if logNextTime {
			log.Info("Egress ip VXLAN tunnel device configured.")
			logNextTime = false
		}
	next:
		sleepMonitoringChans(wait)
	}
}

// getParentInterface returns the parent interface for the given local NodeIP based on IP address. This link returned is nil
// if, and only if, an error occurred
func (m *egressIPManager) getParentInterface(nodeIP net.IP) (netlink.Link, error) {
	links, err := m.nlHandle.LinkList()
	if err != nil {
		return nil, err
	}
	for _, link := range links {
		addrs, err := m.nlHandle.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if addr.IP.Equal(nodeIP) {
				log.Debugf("Found parent interface: %#v", link)
				return link, nil
			}
		}
	}
	return nil, fmt.Errorf("unable to find parent interface with address %s", nodeIP.String())
}

// configureVXLANDevice ensures the VXLAN tunnel device is up and configured correctly.
func (m *egressIPManager) configureVXLANDevice(nodeIP net.IP, mtu int) error {
	logCxt := log.WithFields(log.Fields{"device": m.vxlanDevice})
	logCxt.Debug("Configuring egress ip VXLAN tunnel device")

	if nodeIP == nil {
		return fmt.Errorf("still waiting to learn this node's IP address")
	}

	parent, err := m.getParentInterface(nodeIP)
	if err != nil {
		return err
	}

	// Egress ip vxlan device does not need to have tunnel address.
	// We generate a predictable MAC here that we can reproduce here https://github.com/tigera/egress-gateway/blob/18133f0b37119b3463cd5af75539e27fec69b16b/util/net/mac.go#L20
	// in an identical manner.
	mac, err := hardwareAddrForNode(m.dpConfig.Hostname)
	if err != nil {
		return err
	}

	la := netlink.NewLinkAttrs()
	la.Name = m.vxlanDevice
	la.HardwareAddr = mac
	vxlan := &netlink.Vxlan{
		LinkAttrs:    la,
		VxlanId:      m.vxlanID,
		Port:         m.vxlanPort,
		VtepDevIndex: parent.Attrs().Index,
		SrcAddr:      nodeIP,
	}

	// Try to get the device.
	link, err := m.nlHandle.LinkByName(m.vxlanDevice)
	if err != nil {
		log.WithError(err).Info("Failed to get egress ip VXLAN tunnel device, assuming it isn't present")
		if err := m.nlHandle.LinkAdd(vxlan); err == syscall.EEXIST {
			// Device already exists - likely a race.
			log.Debug("egress ip VXLAN device already exists, likely created by someone else.")
		} else if err != nil {
			// Error other than "device exists" - return it.
			return err
		}

		// The device now exists - requery it to check that the link exists and is a vxlan device.
		link, err = m.nlHandle.LinkByName(m.vxlanDevice)
		if err != nil {
			return fmt.Errorf("can't locate created egress ip vxlan device %v", m.vxlanDevice)
		}
	}

	// At this point, we have successfully queried the existing device, or made sure it exists if it didn't
	// already. Check for mismatched configuration. If they don't match, recreate the device.
	if incompat := vxlanLinksIncompat(vxlan, link); incompat != "" {
		// Existing device doesn't match desired configuration - delete it and recreate.
		log.Warningf("%q exists with incompatible configuration: %v; recreating device", vxlan.Name, incompat)
		if err = m.nlHandle.LinkDel(link); err != nil {
			return fmt.Errorf("failed to delete interface: %v", err)
		}
		if err = m.nlHandle.LinkAdd(vxlan); err != nil {
			if err == syscall.EEXIST {
				log.Warnf("Failed to create VXLAN device. Another device with this VNI may already exist")
			}
			return fmt.Errorf("failed to create vxlan interface: %v", err)
		}
		link, err = m.nlHandle.LinkByName(vxlan.Name)
		if err != nil {
			return err
		}
	}

	// Make sure the MTU is set correctly.
	attrs := link.Attrs()
	oldMTU := attrs.MTU
	if oldMTU != mtu {
		logCxt.WithFields(log.Fields{"old": oldMTU, "new": mtu}).Info("VXLAN device MTU needs to be updated")
		if err := m.nlHandle.LinkSetMTU(link, mtu); err != nil {
			log.WithError(err).Warn("Failed to set vxlan tunnel device MTU")
		} else {
			logCxt.Info("Updated vxlan tunnel MTU")
		}
	}

	// Disable checksum offload.  Otherwise, we end up with invalid checksums when a
	// packet is encapped for egress gateway and then double-encapped for the regular
	// cluster IP-IP or VXLAN overlay.
	if err := m.disableChecksumOffload(m.vxlanDevice); err != nil {
		return fmt.Errorf("failed to disable checksum offload: %s", err)
	}

	// And the device is up.
	if err := m.nlHandle.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set interface up: %s", err)
	}

	// Save link index
	m.lock.Lock()
	defer m.lock.Unlock()
	m.vxlanDeviceLinkIndex = attrs.Index

	return nil
}

func (m *egressIPManager) determineRouteNextHops(workloadID types.WorkloadEndpointID, ipSetID string, maxNextHops int, preferLocalEGW bool) (set.Set[ip.Addr], error) {
	members, exists := m.egwTracker.GatewaysByID(ipSetID)
	if !exists {
		log.Infof("Workload with ID: %s references an empty set of gateways: %s. Setting its next hops to none.", workloadID, ipSetID)
		return set.New[ip.Addr](), nil
	}
	activeGatewayIPs := m.getActiveGateways(members, preferLocalEGW).allIPs()
	usage := usageMap(workloadID, activeGatewayIPs, m.tableIndexToEgressTable)
	var freqs []int
	for n := range usage {
		freqs = append(freqs, n)
	}
	sort.Ints(freqs)

	var hops []ip.Addr
	for _, n := range freqs {
		nHops := usage[n]
		m.hopRand.Shuffle(len(nHops), func(i, j int) { nHops[i], nHops[j] = nHops[j], nHops[i] })
		hops = append(hops, nHops...)
	}
	numHops := workloadNumHops(maxNextHops, activeGatewayIPs.Len())
	index := min(len(hops), numHops)
	return set.FromArray(hops[:index]), nil
}

// reserveFromInitialState searches the rules and tables found from the kernel, and looks for route rules for all the
// workload's IP addresses which point to a route table with the correct number of hops, which are currently not
// terminating.
func (m *egressIPManager) reserveFromInitialState(workload *proto.WorkloadEndpoint, workloadID types.WorkloadEndpointID) (*egressTable, bool) {
	state := m.initialKernelState
	if state == nil {
		return nil, false
	}

	priority := m.dpConfig.EgressIPRoutingRulePriority
	family := syscall.AF_INET
	mark := m.dpConfig.RulesConfig.MarkEgress

	log.WithFields(log.Fields{
		"srcIPs":             workload.Ipv4Nets,
		"priority":           priority,
		"family":             family,
		"mark":               mark,
		"initialKernelState": state,
		"egressGatewayRules": workload.EgressGatewayRules,
	}).Info("Looking for matching rule and table to reuse.")

	// Check for unused matching rules.
	var rulesIndex []int
	var tableIndex int
	for i, srcIP := range workload.Ipv4Nets {
		ipAddr := ip.MustParseCIDROrIP(srcIP).Addr()
		rIndex, exists := m.initialKernelRuleExists(ipAddr)
		if !exists || state.rules[rIndex].used {
			return nil, false
		}
		rule := state.rules[rIndex]
		if rule.priority != priority || rule.family != family || rule.mark != mark {
			return nil, false
		}
		if i == 0 {
			tableIndex = rule.tableIndex
		} else {
			if tableIndex != rule.tableIndex {
				// Multiple rules for the workload point to different tables.
				return nil, false
			}
		}
		rulesIndex = append(rulesIndex, rIndex)
	}

	table, exists := state.tables[tableIndex]
	if !exists || table.used {
		return nil, false
	}

	if len(workload.EgressGatewayRules) != len(table.routes) {
		return nil, false
	}

	for _, r := range workload.EgressGatewayRules {
		// Check for unused matching table.
		kernelRoutes, exists := table.routes[normaliseDestination(r.Destination)]
		if !exists {
			return nil, false
		}
		if r.IpSetId != "" {
			gateways, exists := m.egwTracker.GatewaysByID(r.IpSetId)
			if !exists {
				gateways = make(gatewaysByIP)
			}

			activeGatewayIPs := m.getActiveGateways(gateways, r.PreferLocalEgressGateway).allIPs()
			numHops := workloadNumHops(int(r.MaxNextHops), activeGatewayIPs.Len())

			if kernelRoutes.nextHops == nil {
				return nil, false
			}
			if kernelRoutes.nextHops.Len() != numHops {
				return nil, false
			}
			if !activeGatewayIPs.ContainsAll(kernelRoutes.nextHops) {
				return nil, false
			}
		} else {
			if !kernelRoutes.throwToMain {
				return nil, false
			}
		}
	}

	// Mark them as used.
	table.used = true
	for _, i := range rulesIndex {
		state.rules[i].used = true
	}

	return table, true
}

func (m *egressIPManager) initialKernelRuleExists(srcIP ip.Addr) (int, bool) {
	for i, r := range m.initialKernelState.rules {
		if r.srcIP == srcIP {
			return i, true
		}
	}
	return -1, false
}

func (m *egressIPManager) removeIndicesFromTableStack(indices set.Set[int]) {
	s := stack.New()
	// Pop items off the stack until the index to be removed has been popped.
	for {
		item := m.tableIndexStack.Pop()
		if item == nil {
			break
		}
		i := item.(int)
		if !indices.Contains(i) {
			s.Push(i)
		}
	}
	// Push all items back on, except the indices to be removed.
	for {
		item := s.Pop()
		if item == nil {
			break
		}
		i := item.(int)
		m.tableIndexStack.Push(i)
	}
}

func (m *egressIPManager) OnEGWHealthReport(msg EGWHealthReport) {
	m.egwTracker.OnEGWHealthReport(msg)
}

func (m *egressIPManager) getActiveGateways(gateways gatewaysByIP, preferNodeLocal bool) gatewaysByIP {
	activeGateways := gateways.activeGateways()
	if preferNodeLocal {
		localGateways := activeGateways.localGateways(m.dpConfig.Hostname)
		if len(localGateways) > 0 {
			return localGateways
		}
	}
	return activeGateways
}

func (m *egressIPManager) OnVXLANDeviceUpdate() {
	log.Debug("VXLAN device has been updated.")
	m.unblockingUpdateOccurred = true
}

func (m *egressIPManager) writeProcSys(linkName string) {
	log.WithField("LinkName", linkName).Info("Ensuring egress IP host iface has src_valid_mark")
	procSysPath := fmt.Sprintf(m.srcValidMarkPathFmt, linkName)
	log.WithField("path", procSysPath).Info("Writing src_valid_mark for iface")
	err := m.writeProcSysFunc(procSysPath, "1")
	if err != nil {
		log.WithError(err).Warn("Failed to write src_valid_mark for iface")
	}
}

// hardwareAddrForNode deterministically creates a unique hardware address from a hostname.
// IMPORTANT: an egress gateway pod needs to perform an identical operation when programming its own L2 routes to this node,
// as shown here https://github.com/tigera/egress-gateway/blob/18133f0b37119b3463cd5af75539e27fec69b16b/util/net/mac.go#L20 (change with caution).
func hardwareAddrForNode(hostname string) (net.HardwareAddr, error) {
	hasher := sha1.New()
	_, err := hasher.Write([]byte(hostname))
	if err != nil {
		return nil, err
	}
	sha := hasher.Sum(nil)
	hw := net.HardwareAddr(append([]byte("f"), sha[0:5]...))

	return hw, nil
}

func workloadNumHops(egressMaxNextHops int, ipSetSize int) int {
	// egressMaxNextHops set to 0 on a workload indicates it should use all hops
	if egressMaxNextHops == 0 {
		return ipSetSize
	}
	// egressMaxNextHops set to larger than the size of the IPSet could indicate a misconfiguration, or else the deployment has been scaled
	// down since the wl was created. Either way, default to the size of the IPSet.
	if egressMaxNextHops > ipSetSize {
		return ipSetSize
	}
	return egressMaxNextHops
}

// usageMap returns a map from the number of workloads using the hop to a slice of the hops
func usageMap(workloadID types.WorkloadEndpointID, gatewayIPs set.Set[ip.Addr], tableMap map[int]*egressTable) map[int][]ip.Addr {
	// calculate the number of wl pods referencing each gw pod.
	gwPodRefs := make(map[ip.Addr]int)
	for ipAddr := range gatewayIPs.All() {
		gwPodRefs[ipAddr] = 0
	}

	for _, t := range tableMap {
		for _, r := range t.routes {
			if r.throwToMain {
				// Throw routes do not use any gateway
				continue
			}
			for hop := range r.nextHops.All() {
				_, exists := gwPodRefs[hop]
				if exists {
					gwPodRefs[hop]++
				}
			}
		}
	}
	// calculate the reverse-mapping, i.e. the mapping from reference count to the gw pods with that number of refs.
	usage := make(map[int][]ip.Addr)
	for hop, n := range gwPodRefs {
		usage[n] = append(usage[n], hop)
	}

	// sort hops slices
	for n := range usage {
		sortAddrSlice(usage[n])
	}

	log.WithFields(log.Fields{
		"gatewayIPs":              gatewayIPs,
		"tableIndexToEgressTable": tableMap,
		"gwPodRefs":               gwPodRefs,
		"usage":                   usage,
	}).Infof("Calculated egress hop usage for workload with id: %s.", workloadID)

	return usage
}

func parseEGWIPSetMember(memberStr string) (*gateway, error) {
	maintenanceStarted := time.Time{}
	maintenanceFinished := time.Time{}
	var healthPort uint16
	var hostname string

	a := strings.Split(memberStr, ",")
	if len(a) == 0 || len(a) > 5 {
		return nil, fmt.Errorf("error parsing member str, expected \"cidr,maintenanceStartedTimestamp,maintenanceFinishedTimestamp,hostname\" but got: %s", memberStr)
	}

	addr := ip.MustParseCIDROrIP(a[0]).Addr()
	if len(a) == 5 {
		maintenanceStarted = parseProtoTimestamp(a[1])
		maintenanceFinished = parseProtoTimestamp(a[2])
		if healthPort64, err := strconv.ParseUint(a[3], 10, 16); err != nil {
			log.WithField("memberStr", memberStr).Warn("unable to parse port from member str, defaulting to zero value.")
		} else {
			healthPort = uint16(healthPort64)
		}
		hostname = a[4]
	}

	return &gateway{
		addr:                addr,
		maintenanceStarted:  maintenanceStarted,
		maintenanceFinished: maintenanceFinished,
		healthPort:          healthPort,
		hostname:            hostname,
	}, nil
}

func parseProtoTimestamp(in string) time.Time {
	if in == "" {
		return time.Time{}
	}
	var t time.Time
	err := t.UnmarshalText(([]byte)(in))
	if err != nil {
		log.WithField("timestamp", in).Warn("Failed to parse proto timestamp, defaulting to zero value.")
		t = time.Time{}
	}
	return t
}

func parseNameAndNamespace(wlId string) (string, string, error) {
	parts := strings.Split(wlId, "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("could not parse name and namespace from workload id: %s", wlId)
	}
	return parts[0], parts[1], nil
}

func sortIntSet(s set.Set[int]) []int {
	var sorted []int
	for item := range s.All() {
		sorted = append(sorted, item)
	}
	slices.Sort(sorted)
	return sorted
}

func normaliseDestination(d string) ip.CIDR {
	if d != "" {
		return ip.MustParseCIDROrIP(d)
	}
	return defaultCidr
}
