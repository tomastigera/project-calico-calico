// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package aws

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	aws2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/clock"

	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/logutils"
	calierrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	calinet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const (
	// MaxInterfacesPerInstance is the current maximum total number of ENIs supported by any AWS instance type.
	// We only support the first network card on an instance right now so limiting to the maximum that one network
	// card can support.
	MaxInterfacesPerInstance = 15

	// SecondaryInterfaceCap is the maximum number of Calico secondary ENIs that we support.  The only reason to
	// cap this right now is so that we can pre-allocate one routing table per possible secondary ENI.
	SecondaryInterfaceCap = MaxInterfacesPerInstance - 1
)

// ipamInterface is just the parts of the IPAM interface that we need.
type ipamInterface interface {
	AutoAssign(ctx context.Context, args ipam.AutoAssignArgs) (*ipam.IPAMAssignments, *ipam.IPAMAssignments, error)
	ReleaseIPs(ctx context.Context, ips ...ipam.ReleaseOptions) ([]calinet.IP, []ipam.ReleaseOptions, error)
	IPsByHandle(ctx context.Context, handleID string) ([]calinet.IP, error)
}

// Compile-time assert: ipamInterface should match the real interface.
var _ ipamInterface = ipam.Interface(nil)

// SecondaryIfaceProvisioner manages the AWS resources required to route certain local workload traffic
// (for example, the outbound traffic from egress gateways) over the AWS fabric with a "real" AWS IP.
//
// As an API, it accepts snapshots of the current state of the relevant local workloads via the
// OnDatastoreUpdate method.  That method queues the update to the background goroutine via a channel.
// When the AWS state has converged, the background loop sends a response back on the ResponseC() channel.
// This contains the state of the AWS interfaces attached to this host in order for the main dataplane
// goroutine to program appropriate local routes.
//
// The background goroutine's main loop:
// - Waits for a new snapshot.
// - When a new snapshot arrives, it triggers a resync against AWS.
// - On AWS or IPAM failure, it does exponential backoff.
//
// Resyncs consist of:
//   - Reading the capacity limits of our node type.
//   - Reading the current state of our instance and ENIs over the AWS API. If the node has additional
//     non-calico ENIs they are taken into account when calculating the capacity available to Calico
//   - Call the "capacityCallback" to tell other components how many IPs we can support.
//   - Analysing the datastore state to choose a single "best" AWS subnet.  We only support a single AWS
//     subnet per node to avoid having to balance IPs between multiple ENIs on different subnets.
//     (It's a misconfiguration to have multiple valid subnets but we need to tolerate it to do IP pool
//     migrations.)
//   - Comparing the set of local workload routes against the IPs that we've already assigned to ENIs.
//   - Remove any AWS IPs that are no longer needed.
//   - If there are more IPs than the existing ENIs can handle, try to allocate additional host IPs in
//     calico IPAM and then create and attach new AWS ENIs with those IPs.
//   - Allocate the new IPs to ENIs and assign them in AWS.
//   - Respond to the main thread.
//
// Since failures can occur at any stage, we check for
// - Leaked IPs
// - Created but unattached ENIs
// - etc
// and clean those up pro-actively.
//
// If the number of local workloads we need exceeds the capacity of the node for secondary ENIs then we
// make a best effort; assigning as many as possible and signaling the problem through a health report.
//
// To ensure that we can spot _our_ ENIs even if we fail to attach them, we label them with an "owned by
// Calico" tag and a second tag that contains the instance ID of this node.
type SecondaryIfaceProvisioner struct {
	mode string

	nodeName           string
	awsSubnetsFilename string
	timeout            time.Duration

	// Separate Clock shims for the two timers so the UTs can monitor/trigger the timers separately.
	backoffClock               clock.WithTicker
	recheckClock               clock.Clock
	sleepClock                 sleepClock
	recheckIntervalResetNeeded bool
	newEC2Client               func(ctx context.Context) (*EC2Client, error)

	healthAgg       HealthAggregator
	livenessEnabled bool
	opRecorder      *logutils.Summarizer
	ipamClient      ipamInterface

	// resyncNeeded is set to true if we need to do any kind of resync.
	resyncNeeded bool
	// elasticIPsHealthy tracks whether there were any problems syncing elastic IPs during the most recent resync.
	elasticIPsHealthy bool
	// orphanENIResyncNeeded is set to true if the next resync should also check for orphaned ENIs.  I.e. ones
	// that this node previously created but which never got attached.  (For example, because felix restarted.)
	orphanENIResyncNeeded bool
	// hostIPAMLeakCheckNeeded is set to true if the next resync should also check for IPs that are assigned to this
	// node but not in use for one of our ENIs.
	hostIPAMLeakCheckNeeded bool

	ec2Client           *EC2Client
	networkCapabilities *NetworkCapabilities
	awsGatewayAddr      ip.Addr
	awsSubnetCIDR       ip.CIDR
	// ourHostIPs contains the IPs that our host has assigned in IPAM for primary IPs.
	ourHostIPs set.Set[ip.Addr]

	// datastoreUpdateC carries updates from Felix's main dataplane loop to our loop.
	datastoreUpdateC chan DatastoreState
	// ds is the most recent datastore state we've received.
	ds DatastoreState

	// ResponseC is our channel back to the main dataplane loop.
	responseC        chan *LocalAWSNetworkState
	capacityCallback func(SecondaryIfaceCapacities)
}

type sleepClock interface {
	Sleep(duration time.Duration)
}

type DatastoreState struct {
	LocalAWSAddrsByDst map[ip.Addr]AddrInfo
	PoolIDsBySubnetID  map[string]set.Set[string]
}

type AddrInfo struct {
	AWSSubnetId string
	Dst         string
	ElasticIPs  []ip.Addr
}

const (
	healthNameAWSProvisioner   = "AWSENIProvisioner"
	healthNameENICapacity      = "AWSENICapacity"
	healthNameAWSInSync        = "AWSENIAddressesInSync"
	healthNameElasticIPsInSync = "AWSElasticIPsInSync"
	defaultTimeout             = 30 * time.Second

	livenessReportInterval = 30 * time.Second
	livenessTimeout        = 300 * time.Second
)

type IfaceProvOpt func(provisioner *SecondaryIfaceProvisioner)

func OptTimeout(to time.Duration) IfaceProvOpt {
	return func(provisioner *SecondaryIfaceProvisioner) {
		provisioner.timeout = to
	}
}

func OptLivenessEnabled(livenessEnabled bool) IfaceProvOpt {
	return func(provisioner *SecondaryIfaceProvisioner) {
		provisioner.livenessEnabled = livenessEnabled
	}
}

func OptCapacityCallback(cb func(SecondaryIfaceCapacities)) IfaceProvOpt {
	return func(provisioner *SecondaryIfaceProvisioner) {
		provisioner.capacityCallback = cb
	}
}

func OptClockOverrides(backoffClock clock.WithTicker, recheckClock clock.Clock, sleepClock sleepClock) IfaceProvOpt {
	return func(provisioner *SecondaryIfaceProvisioner) {
		provisioner.backoffClock = backoffClock
		provisioner.recheckClock = recheckClock
		provisioner.sleepClock = sleepClock
	}
}

func OptSubnetsFileOverride(filename string) IfaceProvOpt {
	return func(provisioner *SecondaryIfaceProvisioner) {
		provisioner.awsSubnetsFilename = filename
	}
}

func OptNewEC2ClientOverride(f func(ctx context.Context) (*EC2Client, error)) IfaceProvOpt {
	return func(provisioner *SecondaryIfaceProvisioner) {
		provisioner.newEC2Client = f
	}
}

type SecondaryIfaceCapacities struct {
	MaxCalicoSecondaryIPs int
}

func (c SecondaryIfaceCapacities) Equals(caps SecondaryIfaceCapacities) bool {
	return c == caps
}

type HealthAggregator interface {
	RegisterReporter(name string, reports *health.HealthReport, timeout time.Duration)
	Report(name string, report *health.HealthReport)
}

func NewSecondaryIfaceProvisioner(
	mode string,
	nodeName string,
	healthAgg HealthAggregator,
	ipamClient ipamInterface,
	options ...IfaceProvOpt,
) *SecondaryIfaceProvisioner {
	if mode != v3.AWSSecondaryIPEnabled && mode != v3.AWSSecondaryIPEnabledENIPerWorkload {
		logrus.WithField("mode", mode).Panic("Unknown AWS secondary IP mode.")
	}
	sip := &SecondaryIfaceProvisioner{
		mode: mode,

		healthAgg:          healthAgg,
		livenessEnabled:    true,
		ipamClient:         ipamClient,
		nodeName:           nodeName,
		awsSubnetsFilename: "/var/lib/calico/aws-subnets",
		timeout:            defaultTimeout,
		opRecorder:         logutils.NewSummarizer("AWS secondary IP reconciliation loop"),

		// Do the extra scans on first run.
		orphanENIResyncNeeded:   true,
		hostIPAMLeakCheckNeeded: true,

		datastoreUpdateC: make(chan DatastoreState, 1),
		responseC:        make(chan *LocalAWSNetworkState, 1),
		backoffClock:     clock.RealClock{},
		recheckClock:     clock.RealClock{},
		sleepClock:       clock.RealClock{},
		capacityCallback: func(c SecondaryIfaceCapacities) {
			logrus.WithField("cap", c).Debug("Capacity updated but no callback configured.")
		},
		newEC2Client: NewEC2Client,
	}

	for _, o := range options {
		o(sip)
	}

	if healthAgg != nil {
		// Readiness flag used to indicate if we've got enough ENI capacity to handle all the local workloads
		// that need it. No liveness, we reserve that for the main loop watchdog (set up below).
		healthAgg.RegisterReporter(healthNameENICapacity, &health.HealthReport{Ready: true}, 0)
		healthAgg.Report(healthNameENICapacity, &health.HealthReport{Ready: true})
		// Similarly, readiness flag to report whether we succeeded in syncing with AWS.
		healthAgg.RegisterReporter(healthNameAWSInSync, &health.HealthReport{Ready: true}, 0)
		healthAgg.Report(healthNameAWSInSync, &health.HealthReport{Ready: true})
		// Similarly, readiness flag to report whether we succeeded in syncing Elastic IPs.
		healthAgg.RegisterReporter(healthNameElasticIPsInSync, &health.HealthReport{Ready: true}, 0)
		healthAgg.Report(healthNameElasticIPsInSync, &health.HealthReport{Ready: true})
		if sip.livenessEnabled {
			// Health/liveness watchdog for our main loop.  We let this be disabled for ease of UT.
			healthAgg.RegisterReporter(
				healthNameAWSProvisioner,
				&health.HealthReport{Ready: true, Live: true},
				livenessTimeout,
			)
			healthAgg.Report(healthNameAWSProvisioner, &health.HealthReport{Ready: true, Live: true})
		}
	}

	return sip
}

func (m *SecondaryIfaceProvisioner) Start(ctx context.Context) (done chan struct{}) {
	logrus.Info("Starting AWS secondary interface provisioner.")
	done = make(chan struct{})
	go m.loopKeepingAWSInSync(ctx, done)
	return
}

// LocalAWSNetworkState contains a snapshot of the current state of this node's networking (according to the AWS API).
type LocalAWSNetworkState struct {
	PrimaryENIMAC      string
	SecondaryENIsByMAC map[string]Iface
	SubnetCIDR         ip.CIDR
	GatewayAddr        ip.Addr
}

type Iface struct {
	ID                 string
	MAC                net.HardwareAddr
	PrimaryIPv4Addr    ip.Addr
	SecondaryIPv4Addrs []ip.Addr
}

func (m *SecondaryIfaceProvisioner) loopKeepingAWSInSync(ctx context.Context, doneC chan struct{}) {
	defer close(doneC)
	logrus.Info("AWS secondary interface provisioner running in background.")

	// Response channel is masked (nil) until we're ready to send something.
	var responseC chan *LocalAWSNetworkState
	var response *LocalAWSNetworkState

	// Set ourselves up for exponential backoff after a failure.  backoffMgr.Backoff() returns the same Timer
	// on each call, so we need to stop it properly when cancelling it.
	var backoffTimer clock.Timer
	var backoffC <-chan time.Time
	backoffMgr := m.newBackoffManager()
	stopBackoffTimer := func() {
		if backoffTimer != nil {
			// New snapshot arrived, ignore the backoff since the new snapshot might resolve whatever issue
			// caused us to fail to resync.  We also must reset the timer before calling Backoff() again for
			// correct behaviour. This is the standard time.Timer.Stop() dance...
			if !backoffTimer.Stop() {
				<-backoffTimer.C()
			}
			backoffTimer = nil
			backoffC = nil
		}
	}
	defer stopBackoffTimer()

	// Create a simple backoff manager that can be used to schedule checks of the AWS API at
	// exponentially increasing intervals.  The k8s backoff machinery isn't quite suitable because
	// it doesn't provide a way to reset (and it remembers recent failures).  We just want a
	// way to queue up extra resyncs at 30s, 60s, 120s... after any given successful resync.
	const defaultRecheckInterval = 30 * time.Second
	const maxRecheckInterval = 30 * time.Minute
	recheckBackoffMgr := NewResettableBackoff(m.recheckClock, defaultRecheckInterval, maxRecheckInterval, 0.1)

	var livenessC <-chan time.Time
	if m.livenessEnabled {
		livenessTicker := m.backoffClock.NewTicker(livenessReportInterval)
		livenessC = livenessTicker.C()
	}

	for {
		// Thread safety: we receive messages _from_, and, send messages _to_ the dataplane main loop.
		// To avoid deadlock,
		// - Sends on datastoreUpdateC never block the main loop.  We ensure this by draining the capacity one
		//   channel before sending in OnDatastoreUpdate.
		// - We do our receives and sends in the same select block so that we never block a send op on a receive op
		//   or vice versa.
		thisIsARetry := false
		recheckTimerFired := false
		select {
		case <-ctx.Done():
			logrus.Info("SecondaryIfaceManager stopping, context canceled.")
			return
		case snapshot := <-m.datastoreUpdateC:
			logrus.WithField("update", snapshot).Debug("New datastore snapshot received")
			m.resyncNeeded = true
			m.ds = snapshot
		case responseC <- response:
			// Mask the response channel so we don't resend again and again.
			logrus.WithField("response", response).Debug("Sent AWS state back to main goroutine")
			responseC = nil
			continue // Don't want sending a response to trigger an early resync.
		case <-livenessC:
			m.reportMainLoopLive()
			continue // Don't want liveness to trigger early resync.
		case <-backoffC:
			// Important: nil out the timer so that stopBackoffTimer() won't try to stop it again (and deadlock).
			backoffC = nil
			backoffTimer = nil
			logrus.Warn("Retrying AWS resync after backoff.")
			thisIsARetry = true
			m.opRecorder.RecordOperation("aws-retry")
		case <-recheckBackoffMgr.C():
			// AWS sometimes returns stale data and sometimes loses writes.  Recheck at increasing intervals
			// after a successful update.
			logrus.Debug("Recheck timer fired, checking AWS state is still correct.")
			m.resyncNeeded = true
			recheckTimerFired = true
			m.opRecorder.RecordOperation("aws-recheck")
		}

		startTime := time.Now()

		// Either backoff has done its job or another update has come along.  Clear any pending backoff.
		stopBackoffTimer()

		if m.resyncNeeded {
			// Only stop the recheck timer if we're actually doing a resync.
			recheckBackoffMgr.Stop(recheckTimerFired)
			recheckTimerFired = false

			var err error
			// Track elastic IP problems separately, so we can give a distinct health report.  resync() will set this
			// to false if a problem occurs.
			m.elasticIPsHealthy = true
			response, err = m.resync()
			if m.healthAgg != nil {
				// Make sure we always report health on every loop...
				m.healthAgg.Report(healthNameAWSInSync, &health.HealthReport{Ready: err == nil})
				m.healthAgg.Report(healthNameElasticIPsInSync, &health.HealthReport{Ready: m.elasticIPsHealthy})
			}
			if err != nil {
				logrus.WithError(err).Warning("Failed to resync with AWS. Will retry after backoff.")
				backoffTimer = backoffMgr.Backoff()
				backoffC = backoffTimer.C()
				// We don't reschedule the recheck timer here since we've already got a retry backoff timer
				// queued up but we do reset the interval for next time.
				m.resetRecheckInterval("resync-failure")
			} else {
				// Success, we're now in sync.
				if thisIsARetry {
					logrus.Info("Retry successful, now in sync with AWS.")
				}
				// However, AWS can sometimes lose updates, schedule a recheck on an exponential backoff.
				if m.recheckIntervalResetNeeded {
					// We just made a change to the AWS dataplane (or hit an error), reset the time to the
					// next recheck.
					logrus.Debug("Resetting time to next AWS recheck.")
					recheckBackoffMgr.ResetInterval()
					m.recheckIntervalResetNeeded = false
				}
				recheckBackoffMgr.Reschedule(false /*we already reset the timer above*/)
			}
			if response == nil {
				// We're not ready to respond, mask the response channel.
				responseC = nil
			} else {
				responseC = m.responseC
			}
		}

		m.opRecorder.EndOfIteration(time.Since(startTime))
	}
}

func (m *SecondaryIfaceProvisioner) newBackoffManager() wait.BackoffManager {
	const (
		initBackoff   = 1 * time.Second
		maxBackoff    = 1 * time.Minute
		resetDuration = 10 * time.Minute
		backoffFactor = 2.0
		jitter        = 0.1
	)
	//nolint:staticcheck // Ignore SA1019 deprecated
	backoffMgr := wait.NewExponentialBackoffManager(initBackoff, maxBackoff, resetDuration, backoffFactor, jitter, m.backoffClock)
	return backoffMgr
}

func (m *SecondaryIfaceProvisioner) ResponseC() <-chan *LocalAWSNetworkState {
	return m.responseC
}

func (m *SecondaryIfaceProvisioner) OnDatastoreUpdate(snapshot DatastoreState) {
	// To make sure we don't block, drain any pending update from the channel.
	select {
	case <-m.datastoreUpdateC:
		// Discarded previous snapshot, channel now has capacity for new one.
	default:
		// No pending update.  We're ready to send a new one.
	}
	// Should have capacity in the channel now to send without blocking.
	m.datastoreUpdateC <- snapshot
}

func (m *SecondaryIfaceProvisioner) resync() (*LocalAWSNetworkState, error) {
	m.opRecorder.RecordOperation("aws-fabric-resync")

	// Make sure we've got an EC2 client.  All the methods below assume that we have one.
	if err := m.ensureEC2Client(); err != nil {
		return nil, err
	}

	// Load the capabilities (number of ENIs, IPs etc.) of this node (if not already loaded).
	if err := m.ensureNetworkCapabilitiesLoaded(); err != nil {
		return nil, err
	}

	// Load any IPAM entries assigned to this host.
	if err := m.ensureIPAMLoaded(); err != nil {
		return nil, err
	}

	// Collect the current state of this instance and our ENIs according to AWS.
	awsState, err := m.loadAWSENIsState()
	if err != nil {
		return nil, err
	}

	// Let the kubernetes Node updater know our capacity.
	numSecondaryIPs := m.calculateMaxCalicoSecondaryIPs(awsState)
	logrus.WithField("numIPs", numSecondaryIPs).Debug("Sending calculated AWS capacity to callback.")
	m.capacityCallback(SecondaryIfaceCapacities{
		MaxCalicoSecondaryIPs: numSecondaryIPs,
	})

	// First phase of the resync, check the existing AWS resources and clean up any that we don't need any more.
	// Fix any minor discrepancies (such as ENI settings).
	if err := m.checkFixOrReleaseExistingAWSResources(awsState); err != nil {
		return nil, err
	}

	// Figure out the AWS subnets that live in our AZ.  We can only create ENIs within these subnets.
	localSubnetsByID, err := m.loadLocalAWSSubnets()
	if err != nil {
		return nil, err
	}
	// (When the subnets change) write out a file to tell the CNI plugin which subnet it should be using.
	// Do this now before the possible early return if there's no "best" subnet below.
	if err := m.maybeUpdateAWSSubnetFile(localSubnetsByID); err != nil {
		return nil, fmt.Errorf("failed to write AWS subnets to file: %w", err)
	}

	// Match the Calico state to the AWS state and figure out what's missing and which subnet we should be using.
	allCalicoRoutesNotInAWS, bestSubnetID, err := m.matchAWSToCalicoState(awsState, localSubnetsByID)
	if err != nil {
		return nil, err
	}

	// Mop up any ENIs that belong to this host but are not actually attached to this host.  We only do this
	// on first run and if we detect a discrepancy.
	if err := m.maybeResyncOrphanENIs(awsState, bestSubnetID); err != nil {
		return nil, err
	}
	// Similarly, mop up any Calico IPAM resources we don't need. (Also start of day/after detecting problem.)
	if err := m.maybeDoIPAMLeakCheck(awsState); err != nil {
		return nil, err
	}

	if bestSubnetID == "" {
		// If there's no best subnet, that means there's no AWS-backed workloads and hence we have nothing to do.
		logrus.Debug("No AWS-backed workloads.  Returning early.")
		return &LocalAWSNetworkState{}, nil
	}

	// Given the selected subnet, filter down the routes to only those that we can support and look for routes
	// with no corresponding AWS state.
	subnetCalicoRoutesNotInAWS := filterRoutesByAWSSubnet(allCalicoRoutesNotInAWS, bestSubnetID)
	if len(subnetCalicoRoutesNotInAWS) > 0 {
		// We have some Calico addresses with no corresponding AWS resources.  Try to provision the AWS resources.
		err = m.provisionNewAWSIPs(awsState, bestSubnetID, subnetCalicoRoutesNotInAWS)
		if err != nil {
			return nil, err
		}
	}

	// If we get here, all the private IPs are in place.  Check whether any elastic IPs need to be associated.
	if err := m.checkAndAssociateElasticIPs(awsState); err != nil {
		return nil, err
	}

	return m.calculateResponse(awsState)
}

func (m *SecondaryIfaceProvisioner) ensureNetworkCapabilitiesLoaded() error {
	if m.networkCapabilities != nil {
		return nil
	}
	// Figure out what kind of instance we are and how many ENIs and IPs we can support.
	netCaps, err := m.getMyNetworkCapabilities()
	if err != nil {
		logrus.WithError(err).Error("Failed to get this node's network capabilities from the AWS API; " +
			"are AWS API permissions properly configured?")
		return err
	}
	logrus.WithField("netCaps", netCaps).Info("Retrieved my instance's network capabilities")
	// Cache off the network capabilities since this shouldn't change during the lifetime of an instance.
	m.networkCapabilities = netCaps
	return nil
}

func (m *SecondaryIfaceProvisioner) matchAWSToCalicoState(
	awsState *awsState,
	localSubnetsByID map[string]ec2types.Subnet,
) ([]AddrInfo, string, error) {
	allCalicoRoutesNotInAWS := m.findRoutesWithNoAWSAddr(awsState, localSubnetsByID)

	// We only support a single local subnet, choose one based on some heuristics.
	bestSubnetID := m.calculateBestSubnet(awsState, localSubnetsByID)
	if bestSubnetID == "" {
		logrus.Debug("No AWS subnets needed.")
		return nil, "", nil
	}

	// Record the gateway address of the best subnet.
	bestSubnet := localSubnetsByID[bestSubnetID]
	subnetCIDR, gatewayAddr, err := m.subnetCIDRAndGW(bestSubnet)
	if err != nil {
		return nil, "", err
	}
	if m.awsGatewayAddr != gatewayAddr || m.awsSubnetCIDR != subnetCIDR {
		logrus.WithFields(logrus.Fields{
			"addr":   gatewayAddr,
			"subnet": subnetCIDR,
		}).Info("Calculated new AWS subnet CIDR/gateway.")
		m.awsGatewayAddr = gatewayAddr
		m.awsSubnetCIDR = subnetCIDR
	}
	return allCalicoRoutesNotInAWS, bestSubnetID, nil
}

func (m *SecondaryIfaceProvisioner) maybeResyncOrphanENIs(resyncState *awsState, bestSubnetID string) error {
	if m.orphanENIResyncNeeded {
		// Look for and attach any AWS interfaces that belong to this node but that are not already attached.
		// We identify such interfaces by Calico-specific tags that we add to the interfaces at creation time.
		err := m.attachOrphanENIs(resyncState, bestSubnetID)
		if err != nil {
			return err
		}
		// We won't need to do this again unless we fail to attach an ENI in the future.
		m.orphanENIResyncNeeded = false
	}
	return nil
}

func (m *SecondaryIfaceProvisioner) maybeDoIPAMLeakCheck(awsState *awsState) error {
	if m.hostIPAMLeakCheckNeeded {
		// Now we've cleaned up any unneeded ENIs. Free any IPs that are assigned to us in IPAM but not in use for
		// one of our ENIs.
		err := m.freeUnusedHostCalicoIPs(awsState)
		if err != nil {
			return fmt.Errorf("failed to release unused secondary interface IP in Calico IPAM: %w", err)
		}
		// Won't need to do this again unless we hit an IPAM error.
		m.hostIPAMLeakCheckNeeded = false
	}
	return nil
}

func (m *SecondaryIfaceProvisioner) checkFixOrReleaseExistingAWSResources(awsState *awsState) error {
	// Scan for ENIs that don't have their "delete on termination" flag set and fix up.
	if err := m.ensureCalicoENIsDelOnTerminate(awsState); err != nil {
		return err
	}

	// Disassociate any elastic IPs that should no longer be there to free them up for later re-use.
	err := m.disassociateUnwantedElasticIPs(awsState)
	if err != nil {
		return err
	}

	// Scan for IPs that are present on our AWS ENIs but no longer required by Calico.
	awsIPsToRelease := m.findUnusedAWSSecondaryIPs(awsState)

	// Release any AWS IPs that are no longer required.
	err = m.unassignAWSIPs(awsIPsToRelease, awsState)
	if err != nil {
		return err
	}

	var enisToRelease set.Set[string]
	if m.mode == v3.AWSSecondaryIPEnabledENIPerWorkload {
		// Scan for ENIs with primary IPs that don't match a local workload.
		enisToRelease = m.findENIsWithNoWorkload(awsState)
	} else {
		// Scan for ENIs that are in a subnet that no longer matches an IP pool. We don't currently release
		// ENIs just because they have no associated pods.  This helps to reduce AWS API churn as pods
		// come and go: only the IP addresses need to be added/removed, not a whole ENI.
		enisToRelease, err = m.findENIsWithNoPoolOrIPAMEntry(awsState)
		if err != nil {
			return err
		}
	}

	// Release any AWS ENIs that are no longer needed.
	err = m.releaseAWSENIs(enisToRelease, awsState)
	if err != nil {
		return err
	}
	return nil
}

func (m *SecondaryIfaceProvisioner) provisionNewAWSIPs(
	awsState *awsState,
	bestSubnetID string,
	addrsToAdd []AddrInfo,
) error {
	// Figure out if we need to add any new ENIs to the host.
	logrus.WithField("numRoutes", addrsToAdd).Debug("Adding Calico IPs to AWS fabric")
	numENIsNeeded, err := m.calculateNumNewENIsNeeded(awsState, bestSubnetID)
	if err != nil {
		return err
	}

	numENIsToCreate := numENIsNeeded
	if numENIsNeeded > 0 {
		// Check if we _can_ create that many ENIs.
		numENIsPossible := awsState.CalculateUnusedENICapacity(m.networkCapabilities)
		haveENICapacity := numENIsToCreate <= numENIsPossible
		if m.healthAgg != nil {
			m.healthAgg.Report(healthNameENICapacity, &health.HealthReport{Ready: haveENICapacity})
		}
		if !haveENICapacity {
			logrus.Warnf("Need %d more AWS secondary ENIs to support local workloads but only %d are "+
				"available.  Some local workloads (typically egress gateways) will not have connectivity on "+
				"the AWS fabric.", numENIsToCreate, numENIsPossible)
			numENIsToCreate = numENIsPossible // Avoid trying to create ENIs that we know will fail.
		}
	}

	if numENIsToCreate > 0 {
		var eniPrimaryIPs []calinet.IPNet

		if m.mode == v3.AWSSecondaryIPEnabledENIPerWorkload {
			logrus.WithField("num", numENIsToCreate).Info("Allocating ENIs with workload IPs as primary IPs.")
			for i, aInfo := range addrsToAdd {
				if i >= numENIsToCreate {
					logrus.Warn("Failed to create ENIs for all Calico IPs.  Insufficient ENI IP capacity on " +
						"this node.")
					break
				}
				eniPrimaryIPs = append(eniPrimaryIPs, calinet.MustParseCIDR(aInfo.Dst))
			}
		} else {
			logrus.WithField("num", numENIsToCreate).Info("Allocating IPs for new AWS ENIs.")
			v4addrs, err := m.allocateCalicoHostIPs(numENIsToCreate, bestSubnetID)
			if err != nil {
				// Queue up a clean up of any IPs we may have leaked.
				m.hostIPAMLeakCheckNeeded = true
				return err
			}
			eniPrimaryIPs = v4addrs.IPs
			logrus.WithField("addrs", eniPrimaryIPs).Info("Allocated IPs; creating AWS ENIs...")
		}

		err = m.createAWSENIs(awsState, bestSubnetID, eniPrimaryIPs)
		if err != nil {
			// Queue up a cleanup of any IPs we may have leaked.
			m.hostIPAMLeakCheckNeeded = true
			return err
		}
	}

	if m.mode == v3.AWSSecondaryIPEnabled {
		// Tell AWS to assign the needed Calico IPs to the secondary ENIs as best we can.  (It's possible we weren't
		// able to allocate enough IPs or ENIs above.)
		logrus.Debug("In secondary-ip-per-pod mode, adding secondary IPs.")
		err = m.assignSecondaryIPsToENIs(awsState, addrsToAdd)
		if err != nil {
			return err
		}
	}
	return nil
}

// subnetsFileData contents of the aws-subnets file.  We write a JSON dict for extensibility.
// Must match the definition in the CNI plugin's utils.go.
type subnetsFileData struct {
	AWSSubnetIDs []string `json:"aws_subnet_ids"`
}

func (m *SecondaryIfaceProvisioner) maybeUpdateAWSSubnetFile(subnets map[string]ec2types.Subnet) error {
	var data subnetsFileData
	for id := range subnets {
		data.AWSSubnetIDs = append(data.AWSSubnetIDs, id)
	}
	sort.Strings(data.AWSSubnetIDs)
	encoded, err := json.Marshal(data)
	if err != nil {
		return err
	}

	// Avoid rewriting the file if it hasn't changed.  Since subnet updates are rare, this reduces the chance
	// of the CNI plugin seeing a partially-written file.  If the file is missing/partial then the CNI plugin
	// will fail to read/parse the file and bail out.  The CNI plugin only tries to read this file if the pod
	// has the aws-secondary-ip resource request so only AWS-backed pods are in danger of failing.
	oldData, err := os.ReadFile(m.awsSubnetsFilename)
	if err == nil {
		if bytes.Equal(oldData, encoded) {
			logrus.Debug("AWS subnets file already correct.")
			return nil
		}
	} else {
		logrus.WithError(err).Debug("Failed to read old aws-subnets file.  Rewriting it...")
	}

	err = os.WriteFile(m.awsSubnetsFilename, encoded, 0o644)
	if err != nil {
		return err
	}
	return nil
}

func (m *SecondaryIfaceProvisioner) calculateResponse(awsState *awsState) (*LocalAWSNetworkState, error) {
	// Index the AWS ENIs on MAC.
	ifacesByMAC := map[string]Iface{}
	for _, awsENI := range awsState.calicoOwnedENIsByID {
		iface, err := m.ec2ENIToIface(awsENI)
		if err != nil {
			logrus.WithError(err).Warn("Failed to convert AWS ENI.")
			continue
		}
		ifacesByMAC[iface.MAC.String()] = *iface
	}
	primaryENI, err := m.ec2ENIToIface(awsState.primaryENI)
	if err != nil {
		logrus.WithError(err).Error("Failed to convert primary ENI.")
		return nil, err
	}
	return &LocalAWSNetworkState{
		PrimaryENIMAC:      primaryENI.MAC.String(),
		SecondaryENIsByMAC: ifacesByMAC,
		SubnetCIDR:         m.awsSubnetCIDR,
		GatewayAddr:        m.awsGatewayAddr,
	}, nil
}

var errNoMAC = errors.New("AWS ENI missing MAC")

func (m *SecondaryIfaceProvisioner) ec2ENIToIface(awsENI *eniState) (*Iface, error) {
	if awsENI.MACAddress == "" {
		return nil, errNoMAC
	}
	hwAddr, err := net.ParseMAC(awsENI.MACAddress)
	if err != nil {
		logrus.WithError(err).Error("Failed to parse MAC address of AWS ENI.")
		return nil, fmt.Errorf("AWS ENI's MAC address was malformed: %w", err)
	}
	var primary ip.Addr
	var secondaryAddrs []ip.Addr
	for _, pa := range awsENI.IPAddresses {
		if pa.Primary {
			primary = pa.PrivateIP
		} else if m.mode == v3.AWSSecondaryIPEnabled {
			// Only record secondary IPs if they're meaningful in this mode.
			secondaryAddrs = append(secondaryAddrs, pa.PrivateIP)
		}
	}
	iface := &Iface{
		ID:                 awsENI.ID,
		MAC:                hwAddr,
		PrimaryIPv4Addr:    primary,
		SecondaryIPv4Addrs: secondaryAddrs,
	}
	return iface, nil
}

// getMyNetworkCapabilities looks up the network capabilities of this host; this includes the number of ENIs
// and IPs per ENI.
func (m *SecondaryIfaceProvisioner) getMyNetworkCapabilities() (*NetworkCapabilities, error) {
	ctx, cancel := m.newContext()
	defer cancel()
	netCaps, err := m.ec2Client.GetMyNetworkCapabilities(ctx)
	if err != nil {
		return nil, err
	}

	if netCaps.MaxNetworkInterfaces > MaxInterfacesPerInstance {
		logrus.Infof("Instance type supports %v interfaces, limiting to our interface cap (%v)",
			netCaps.MaxNetworkInterfaces, MaxInterfacesPerInstance)
		netCaps.MaxNetworkInterfaces = MaxInterfacesPerInstance
	}
	return &netCaps, nil
}

// loadAWSENIsState looks up all the ENIs attached to this host and creates an awsState to index them.
func (m *SecondaryIfaceProvisioner) loadAWSENIsState() (s *awsState, err error) {
	logrus.Debug("Loading AWS state.")

	ctx, cancel := m.newContext()
	defer cancel()
	myENIs, err := m.ec2Client.GetMyEC2NetworkInterfaces(ctx)
	if err != nil {
		return
	}

	s = newAWSState(m.networkCapabilities)
	for _, awsENI := range myENIs {
		eni := awsNetworkInterfaceToENIState(awsENI)
		if eni == nil {
			continue
		}

		if !NetworkInterfaceIsCalicoSecondary(awsENI) {
			if eni.Attachment != nil {
				s.inUseDeviceIndexes[eni.Attachment.DeviceIndex] = true
				s.attachmentIDByENIID[eni.ID] = eni.Attachment.ID
			}
			if s.primaryENI == nil || eni.Attachment != nil && eni.Attachment.DeviceIndex == 0 {
				s.primaryENI = eni
			}
			s.nonCalicoOwnedENIsByID[eni.ID] = eni
			continue
		}

		// Found one of our managed interfaces; collect its IPs.
		s.OnCalicoENIAttached(eni)
	}

	return
}

// findUnusedAWSSecondaryIPs scans the AWS state for secondary IPs that are not assigned in Calico IPAM.
func (m *SecondaryIfaceProvisioner) findUnusedAWSSecondaryIPs(awsState *awsState) set.Set[ip.Addr] {
	awsIPsToRelease := set.New[ip.Addr]()
	summary := map[string][]string{}
	for addr, eniID := range awsState.eniIDBySecondaryIP {
		release := false
		if m.mode == v3.AWSSecondaryIPEnabledENIPerWorkload {
			// ENI-per-workload mode, all secondary IPs should be removed.
			release = true
		} else if _, ok := m.ds.LocalAWSAddrsByDst[addr]; !ok {
			release = true
		}
		if release {
			awsIPsToRelease.Add(addr)
			summary[eniID] = append(summary[eniID], addr.String())
		}
	}
	if len(summary) > 0 && logrus.GetLevel() >= logrus.InfoLevel {
		for eni, addrs := range summary {
			logrus.WithFields(logrus.Fields{
				"eniID": eni,
				"addrs": strings.Join(addrs, ","),
			}).Info("Found unwanted AWS secondary IPs.")
		}
	}
	return awsIPsToRelease
}

// loadLocalAWSSubnets looks up all the AWS Subnets that are in this host's VPC and availability zone.
func (m *SecondaryIfaceProvisioner) loadLocalAWSSubnets() (map[string]ec2types.Subnet, error) {
	ctx, cancel := m.newContext()
	defer cancel()
	localSubnets, err := m.ec2Client.GetAZLocalSubnets(ctx)
	if err != nil {
		return nil, err
	}
	localSubnetsByID := map[string]ec2types.Subnet{}
	for _, s := range localSubnets {
		if s.SubnetId == nil {
			continue
		}
		localSubnetsByID[*s.SubnetId] = s
	}
	return localSubnetsByID, nil
}

// findENIsWithNoPoolOrIPAMEntry scans the awsState for secondary AWS ENIs that were created by Calico but no longer
// have an associated IP pool (or are missing their IPAM entry).
func (m *SecondaryIfaceProvisioner) findENIsWithNoPoolOrIPAMEntry(awsState *awsState) (set.Set[string], error) {
	enisToRelease := set.New[string]()
	for eniID, eni := range awsState.calicoOwnedENIsByID {
		if _, ok := m.ds.PoolIDsBySubnetID[eni.SubnetID]; !ok {
			// No longer have an IP pool for this ENI.
			logrus.WithFields(logrus.Fields{
				"eniID":  eniID,
				"subnet": eni.SubnetID,
			}).Info("AWS ENI belongs to subnet with no matching Calico IP pool, ENI should be released")
			enisToRelease.Add(eniID)
		}
		primaryIP := eni.PrimaryIP()
		if !m.ourHostIPs.Contains(primaryIP) {
			logrus.WithFields(logrus.Fields{
				"eniID":     eniID,
				"primaryIP": primaryIP,
			}).Info("AWS ENI primary IP does not have corresponding host IPAM entry, deleting the ENI.")
			enisToRelease.Add(eniID)
		}
	}
	return enisToRelease, nil
}

// findRoutesWithNoAWSAddr Scans our local Calico workload routes for routes with no corresponding AWS IP.
func (m *SecondaryIfaceProvisioner) findRoutesWithNoAWSAddr(awsState *awsState, localSubnetsByID map[string]ec2types.Subnet) []AddrInfo {
	var missingRoutes []AddrInfo
	var missingIPSummary []string
	for addr, route := range m.ds.LocalAWSAddrsByDst {
		if _, ok := localSubnetsByID[route.AWSSubnetId]; !ok {
			logrus.WithFields(logrus.Fields{
				"addr":           addr,
				"requiredSubnet": route.AWSSubnetId,
			}).Warn("Local workload needs an IP from an AWS subnet that is not accessible from this " +
				"availability zone. Unable to allocate an AWS IP for it.")
			continue
		}
		if eniID, ok := awsState.eniIDByPrimaryIP[addr]; ok {
			if m.mode != v3.AWSSecondaryIPEnabledENIPerWorkload {
				logrus.WithFields(logrus.Fields{
					"addr": addr,
					"eni":  eniID,
				}).Warn("Local workload IP clashes with host's primary IP on one of its secondary interfaces. " +
					"Workload will not be properly networked.")
			}
			continue
		}
		if eniID, ok := awsState.eniIDBySecondaryIP[addr]; ok {
			logrus.WithFields(logrus.Fields{
				"addr": addr,
				"eni":  eniID,
			}).Debug("Local workload IP is already present on one of our AWS ENIs.")
			continue
		}
		missingRoutes = append(missingRoutes, route)
		missingIPSummary = append(missingIPSummary, addr.String())
	}
	if len(missingIPSummary) > 0 {
		logrus.WithField("addrs", missingIPSummary).Info(
			"Found local workload IPs that should be added to AWS ENI(s).")
	}
	return missingRoutes
}

// unassignAWSIPs unassigns (releases) the given IPs in the AWS fabric.  It updates the free IP counters
// in the awsState (but it does not refresh the AWS ENI data itself).
func (m *SecondaryIfaceProvisioner) unassignAWSIPs(awsIPsToRelease set.Set[ip.Addr], awsState *awsState) error {
	if awsIPsToRelease.Len() == 0 {
		return nil
	}

	// About to change AWS state, queue up a recheck.
	m.resetRecheckInterval("unassign-ips")

	// Batch up the IPs by ENI; the AWS API lets us release multiple IPs from the same ENI in one shot.
	ipsToReleaseByENIID := map[string][]string{}
	for addr := range awsIPsToRelease.All() {
		eniID := awsState.eniIDBySecondaryIP[addr]
		ipsToReleaseByENIID[eniID] = append(ipsToReleaseByENIID[eniID], addr.String())
	}

	var finalErr error
	for eniID, ipsToRelease := range ipsToReleaseByENIID {
		ctx, cancel := m.newContext()
		_, err := m.ec2Client.EC2Svc.UnassignPrivateIpAddresses(ctx, &ec2.UnassignPrivateIpAddressesInput{
			NetworkInterfaceId: &eniID,
			PrivateIpAddresses: ipsToRelease,
		})
		cancel()
		if err != nil {
			logrus.WithError(err).WithField("eniID", eniID).Error("Failed to release AWS IPs.")
			finalErr = fmt.Errorf("failed to release some AWS IPs: %w", err)
		} else {
			awsState.OnSecondaryIPsRemoved(eniID, ipsToRelease)
		}
	}

	return finalErr
}

// releaseAWSENIs tries to unattach and release the given ENIs.
func (m *SecondaryIfaceProvisioner) releaseAWSENIs(enisToRelease set.Set[string], awsState *awsState) error {
	if enisToRelease.Len() == 0 {
		return nil
	}
	// About to release some ENIs, queue up a check of our IPAM handle and a general AWS recheck.
	m.hostIPAMLeakCheckNeeded = true
	m.resetRecheckInterval("release-eni")

	// Detach any ENIs that we want to delete.  They must be detached first.
	for eniID := range enisToRelease.All() {
		ctx, cancel := m.newContext()
		defer cancel()
		attachID := awsState.attachmentIDByENIID[eniID]
		_, err := m.ec2Client.EC2Svc.DetachNetworkInterface(ctx, &ec2.DetachNetworkInterfaceInput{
			AttachmentId: &attachID,
			Force:        boolPtr(true),
		})
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"eniID":    eniID,
				"attachID": attachID,
			}).Error("Failed to detach unneeded ENI")
			// Not setting finalErr here since the following deletion might solve the problem.
		}
		awsState.OnCalicoENIDetached(eniID)
		m.reportMainLoopLive()
	}

	// Initially, we just had a retry loop here.  However, it almost always takes at least 10s before we can delete
	// an ENI so (only) retrying in a loop produces spammy warnings and consumes precious AWS API quota.  Better to
	// sleep before the first attempt.  It'd be even better to queue this up in the background but it's not trivial
	// to arrange.  We'd need to keep track of to-be-deleted ENIs and make sure that we don't try to reattach them
	// as well as worrying about whether their device index can be used before the detach operation has fully
	// finished.
	m.sleepClock.Sleep(10 * time.Second)
	m.reportMainLoopLive()

	var finalErr error
	for range 5 {
		for eniID := range enisToRelease.All() {
			// Worth trying this even if detach fails.  Possible the failure was caused by it already
			// being detached.
			ctx, cancel := m.newContext()
			defer cancel()
			_, err := m.ec2Client.EC2Svc.DeleteNetworkInterface(ctx, &ec2.DeleteNetworkInterfaceInput{
				NetworkInterfaceId: &eniID,
			})
			if err != nil {
				logrus.WithField("eniID", eniID).WithError(err).Info(
					"Failed to delete unneeded ENI; may retry...")
				finalErr = err // Trigger retry/backoff unless we succeed on a retry.
			} else {
				logrus.WithField("eniID", eniID).Info("Successfully deleted ENI.")
				enisToRelease.Discard(eniID)
			}
		}
		if enisToRelease.Len() == 0 {
			logrus.Info("Successfully deleted all unwanted ENIs.")
			finalErr = nil
			break
		}
		m.sleepClock.Sleep(5 * time.Second)
	}

	if finalErr != nil {
		logrus.WithError(finalErr).Error("Failed to delete one or more unneeded ENIs even after retries; " +
			"triggering backoff.")
		m.orphanENIResyncNeeded = true
	}
	return finalErr
}

func (m *SecondaryIfaceProvisioner) reportMainLoopLive() {
	if !m.livenessEnabled {
		return
	}
	if m.healthAgg != nil {
		m.healthAgg.Report(healthNameAWSProvisioner, &health.HealthReport{Ready: true, Live: true})
	}
}

// calculateBestSubnet Tries to calculate a single "best" AWS subnet for this host.  When we're configured correctly
// there should only be one subnet in use on this host but we try to pick a sensible one if the IP pools have conflicting
// information.
func (m *SecondaryIfaceProvisioner) calculateBestSubnet(awsState *awsState, localSubnetsByID map[string]ec2types.Subnet) string {
	// Match AWS subnets against our IP pools.
	localIPPoolSubnetIDs := set.New[string]()
	for subnetID := range m.ds.PoolIDsBySubnetID {
		if _, ok := localSubnetsByID[subnetID]; ok {
			localIPPoolSubnetIDs.Add(subnetID)
		}
	}
	logrus.WithField("subnets", localIPPoolSubnetIDs).Debug("AWS Subnets with associated Calico IP pool.")

	// If the IP pools only name one then that is preferred.  If there's more than one in the IP pools but we've
	// already got a local ENI, that one is preferred.  If there's a tie, pick the one with the most routes.
	subnetScores := map[string]int{}
	for subnetID := range localIPPoolSubnetIDs.All() {
		subnetScores[subnetID] += 1000000
	}
	for subnet, eniIDs := range awsState.calicoENIIDsBySubnet {
		subnetScores[subnet] += 10000 * len(eniIDs)
	}
	for _, r := range m.ds.LocalAWSAddrsByDst {
		subnetScores[r.AWSSubnetId] += 1
	}
	var bestSubnet string
	var bestScore int
	for subnet, score := range subnetScores {
		if score > bestScore ||
			score == bestScore && subnet > bestSubnet {
			bestSubnet = subnet
			bestScore = score
		}
	}
	return bestSubnet
}

// subnetCIDRAndGW extracts the subnet's CIDR and gateway address from the given AWS subnet.
func (m *SecondaryIfaceProvisioner) subnetCIDRAndGW(subnet ec2types.Subnet) (ip.CIDR, ip.Addr, error) {
	subnetID := safeReadString(subnet.SubnetId)
	if subnet.CidrBlock == nil {
		return nil, nil, fmt.Errorf("our subnet missing its CIDR id=%s", subnetID) // AWS bug?
	}
	ourCIDR, err := ip.ParseCIDROrIP(*subnet.CidrBlock)
	if err != nil {
		return nil, nil, fmt.Errorf("our subnet had malformed CIDR %q: %w", *subnet.CidrBlock, err)
	}
	// The AWS Subnet gateway is always the ".1" address in the subnet.
	addr := ourCIDR.Addr().Add(1)
	return ourCIDR, addr, nil
}

// filterRoutesByAWSSubnet returns the subset of the given routes that belong to the given AWS subnet.
func filterRoutesByAWSSubnet(missingRoutes []AddrInfo, bestSubnet string) []AddrInfo {
	var filteredRoutes []AddrInfo
	for _, r := range missingRoutes {
		if r.AWSSubnetId != bestSubnet {
			logrus.WithFields(logrus.Fields{
				"route":        r,
				"activeSubnet": bestSubnet,
			}).Warn("Cannot program route into AWS fabric; only one AWS subnet is supported per node. All " +
				"workloads on the same node that use AWS networking (typically egress gateways) must use the " +
				"same AWS subnet.")
			continue
		}
		filteredRoutes = append(filteredRoutes, r)
	}
	return filteredRoutes
}

// attachOrphanENIs looks for any unattached Calico-created ENIs that should be attached to this host and tries
// to attach them.
func (m *SecondaryIfaceProvisioner) attachOrphanENIs(awsState *awsState, bestSubnetID string) error {
	ctx, cancel := m.newContext()
	dio, err := m.ec2Client.EC2Svc.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
		Filters: []ec2types.Filter{
			{
				// We label all our ENIs at creation time with the instance they belong to.
				Name:   stringPtr("tag:" + CalicoNetworkInterfaceTagOwningInstance),
				Values: []string{m.ec2Client.InstanceID},
			},
			{
				Name:   stringPtr("status"),
				Values: []string{"available" /* Not attached to the instance */},
			},
		},
	})
	cancel()
	if err != nil {
		return fmt.Errorf("failed to list unattached ENIs that belong to this node: %w", err)
	}

	numLeakedENIs := 0
	var lastLeakErr error
	for _, eni := range dio.NetworkInterfaces {
		// About to change AWS state, queue up a recheck.
		m.resetRecheckInterval("attach-orphan-eni")

		// Find next free device index.
		devIdx := awsState.FindFreeDeviceIdx()

		subnetID := safeReadString(eni.SubnetId)
		eniID := safeReadString(eni.NetworkInterfaceId)
		logCtx := logrus.WithFields(logrus.Fields{
			"eniID":        eniID,
			"activeSubnet": bestSubnetID,
			"eniSubnet":    subnetID,
		})
		deleteENI := false
		if subnetID != bestSubnetID {
			logCtx.Info("Found unattached ENI belonging to this node but not from our active subnet. " +
				"Deleting.")
			deleteENI = true
		} else if int(devIdx) >= m.networkCapabilities.MaxENIsForCard(0) {
			logCtx.Info("Found unattached ENI belonging to this node but node doesn't have enough " +
				"capacity to attach it. Deleting.")
			deleteENI = true
		} else if eni.PrivateIpAddress == nil {
			logrus.WithField("eniID", eniID).Warn(
				"Found unattached Calico ENI with no private IP?  Remove.")
			deleteENI = true
		} else if m.mode == v3.AWSSecondaryIPEnabled {
			primaryIP := ip.FromIPOrCIDRString(*eni.PrivateIpAddress)
			if !m.ourHostIPs.Contains(primaryIP) {
				logrus.WithField("eniID", eniID).Info(
					"Found unattached Calico ENI with no corresponding IPAM entry.  Remove.")
				deleteENI = true
			}
		} else if m.mode == v3.AWSSecondaryIPEnabledENIPerWorkload {
			primaryIP := ip.FromIPOrCIDRString(*eni.PrivateIpAddress)
			if _, ok := m.ds.LocalAWSAddrsByDst[primaryIP]; !ok {
				logrus.WithField("eniID", eniID).Info(
					"Found unattached Calico ENI that no longer matches a workload.  Remove.")
				deleteENI = true
			}
		}

		if deleteENI {
			ctx, cancel := m.newContext()
			_, err = m.ec2Client.EC2Svc.DeleteNetworkInterface(ctx, &ec2.DeleteNetworkInterfaceInput{
				NetworkInterfaceId: eni.NetworkInterfaceId,
			})
			cancel()
			if err != nil {
				logCtx.WithError(err).Error("Failed to delete unattached ENI")
				// Could bail out here but having an orphaned ENI doesn't stop us from getting _our_ state right.
				numLeakedENIs++
				lastLeakErr = err
			}
			continue
		}

		logCtx.Info("Found unattached ENI that belongs to this node; trying to attach it.")
		ctx, cancel := m.newContext()
		attOut, err := m.ec2Client.EC2Svc.AttachNetworkInterface(ctx, &ec2.AttachNetworkInterfaceInput{
			DeviceIndex:        &devIdx,
			InstanceId:         &m.ec2Client.InstanceID,
			NetworkInterfaceId: eni.NetworkInterfaceId,
			// For now, only support the first network card.  There's only one type of AWS instance with >1
			// NetworkCard.
			NetworkCardIndex: int32Ptr(0),
		})
		cancel()
		if err != nil {
			logCtx.WithError(err).Error("Failed to attach interface to host, trying to delete it.")
			ctx, cancel := m.newContext()
			_, err = m.ec2Client.EC2Svc.DeleteNetworkInterface(ctx, &ec2.DeleteNetworkInterfaceInput{
				NetworkInterfaceId: eni.NetworkInterfaceId,
			})
			cancel()
			if err != nil {
				logCtx.WithError(err).Error("Failed to delete unattached ENI (after failing to attach it)")
				numLeakedENIs++
				lastLeakErr = err
			}
			continue
		}
		ourENI := awsNetworkInterfaceToENIState(eni)
		ourENI.Attachment = &eniAttachment{
			ID:          *attOut.AttachmentId,
			DeviceIndex: devIdx,
		}
		awsState.OnCalicoENIAttached(ourENI)
		awsState.ClaimDeviceIdx(devIdx) // Mark the device index as used.
		logCtx.WithFields(logrus.Fields{
			"attachmentID": safeReadString(attOut.AttachmentId),
			"networkCard":  safeReadInt32(attOut.NetworkCardIndex),
		}).Info("Attached orphaned AWS ENI to this host.")
	}
	// Set some limit on how many ENIs we'll leak before we say "no more".
	if numLeakedENIs > m.networkCapabilities.MaxNetworkInterfaces {
		return fmt.Errorf("detected multiple ENIs that belong to this node but cannot be attached or deleted, "+
			"backing off to prevent further leaks: %w", lastLeakErr)
	}
	return nil
}

// freeUnusedHostCalicoIPs finds any IPs assign to this host for a secondary ENI that are not actually in use
// and then frees those IPs.
func (m *SecondaryIfaceProvisioner) freeUnusedHostCalicoIPs(awsState *awsState) error {
	var finalErr error
	for addr := range m.ourHostIPs.All() {
		if _, ok := awsState.eniIDByPrimaryIP[addr]; ok {
			continue
		}
		// IP is not assigned to any of our local ENIs and, if we got this far, we've already attached
		// any orphaned ENIs or deleted them.  Clean up the IP.
		logrus.WithField("addr", addr).Info(
			"Found IP assigned to this node in IPAM but not in use for an AWS ENI, freeing it.")
		ctx, cancel := m.newContext()
		_, _, err := m.ipamClient.ReleaseIPs(ctx, ipam.ReleaseOptions{Address: addr.String()})
		cancel()
		if err != nil {
			logrus.WithError(err).WithField("ip", addr).Error(
				"Failed to free host IP that we no longer need.")
			finalErr = err
			continue
		}
		m.ourHostIPs.Discard(addr) // Freed the IP so update the cache.
	}
	return finalErr
}

// calculateNumNewENIsNeeded does the maths to figure out how many ENIs we need to add given the number of
// IPs we need and the spare capacity of existing ENIs.
func (m *SecondaryIfaceProvisioner) calculateNumNewENIsNeeded(awsState *awsState, bestSubnetID string) (int, error) {
	var totalIPs int
	for _, addr := range m.ds.LocalAWSAddrsByDst {
		if addr.AWSSubnetId == bestSubnetID {
			totalIPs++
		}
	}

	var totalENIsNeeded int
	if m.mode == v3.AWSSecondaryIPEnabledENIPerWorkload {
		totalENIsNeeded = totalIPs
	} else {
		if m.networkCapabilities.MaxIPv4PerInterface <= 1 {
			logrus.Error("Instance type doesn't support secondary IPs")
			return 0, fmt.Errorf("instance type doesn't support secondary IPs")
		}
		secondaryIPsPerIface := m.networkCapabilities.MaxIPv4PerInterface - 1
		totalENIsNeeded = (totalIPs + secondaryIPsPerIface - 1) / secondaryIPsPerIface
	}

	enisAlreadyAllocated := len(awsState.calicoENIIDsBySubnet[bestSubnetID])
	numENIsNeeded := totalENIsNeeded - enisAlreadyAllocated

	return numENIsNeeded, nil
}

// allocateCalicoHostIPs allocates the given number of IPPoolAllowedUseHostSecondary IPs to this host in Calico IPAM.
func (m *SecondaryIfaceProvisioner) allocateCalicoHostIPs(numENIsNeeded int, subnetID string) (*ipam.IPAMAssignments, error) {
	ipamCtx, ipamCancel := m.newContext()

	v4addrs, _, err := m.ipamClient.AutoAssign(ipamCtx, m.ipamAssignArgs(numENIsNeeded, subnetID))
	ipamCancel()
	if err != nil {
		return nil, fmt.Errorf("failed to allocate primary IP for secondary interface: %w", err)
	}
	logrus.WithField("ips", v4addrs.IPs).Info("Allocated primary IPs for secondary interfaces")
	if len(v4addrs.IPs) < numENIsNeeded {
		logrus.WithFields(logrus.Fields{
			"needed":    numENIsNeeded,
			"allocated": len(v4addrs.IPs),
			"reasons":   v4addrs.Msgs, // Contains messages like "pool X is full"
		}).Warn("Wasn't able to allocate enough ENI primary IPs. IP pool may be full.")
	}
	for _, addr := range v4addrs.IPs {
		m.ourHostIPs.Add(ip.CIDRFromCalicoNet(addr).Addr())
	}
	return v4addrs, nil
}

// ipamAssignArgs is mainly broken out for testing.
func (m *SecondaryIfaceProvisioner) ipamAssignArgs(numENIsNeeded int, subnetID string) ipam.AutoAssignArgs {
	return ipam.AutoAssignArgs{
		Num4:     numENIsNeeded,
		HandleID: stringPtr(m.hostPrimaryIPIPAMHandle()),
		Attrs: map[string]string{
			ipam.AttributeType: ipam.AttributeTypeAWSSecondary,
			ipam.AttributeNode: m.nodeName,
		},
		Hostname:    m.nodeName,
		IntendedUse: v3.IPPoolAllowedUseHostSecondary,
		// Make sure we get an IP from the right subnet.
		AWSSubnetIDs: []string{subnetID},
	}
}

// createAWSENIs creates one AWS secondary ENI in the given subnet for each given IP address and attempts to
// attach the newly created ENI to this host.
func (m *SecondaryIfaceProvisioner) createAWSENIs(awsState *awsState, subnetID string, v4addrs []calinet.IPNet) error {
	if len(v4addrs) == 0 {
		return nil
	}

	// About to change AWS state, queue up a recheck.
	m.resetRecheckInterval("create-eni")

	// Figure out the security groups of our primary ENI, we'll copy these to the new interfaces that we create.
	secGroups := awsState.PrimaryENISecurityGroups()

	// Create the new ENIs for the IPs we were able to get.
	var finalErr error
	for _, addr := range v4addrs {
		ctx, cancel := m.newContext()
		ipStr := addr.IP.String()
		cno, err := m.ec2Client.EC2Svc.CreateNetworkInterface(ctx, &ec2.CreateNetworkInterfaceInput{
			SubnetId:         &subnetID,
			Description:      stringPtr(fmt.Sprintf("Calico secondary ENI for instance %s", m.ec2Client.InstanceID)),
			Groups:           secGroups,
			Ipv6AddressCount: int32Ptr(0),
			PrivateIpAddress: stringPtr(ipStr),
			TagSpecifications: []ec2types.TagSpecification{
				{
					ResourceType: ec2types.ResourceTypeNetworkInterface,
					Tags: []ec2types.Tag{
						{
							Key:   stringPtr(CalicoNetworkInterfaceTagUse),
							Value: stringPtr(CalicoNetworkInterfaceUseSecondary),
						},
						{
							Key:   stringPtr(CalicoNetworkInterfaceTagOwningInstance),
							Value: stringPtr(m.ec2Client.InstanceID),
						},
					},
				},
			},
		})
		cancel()
		if err != nil {
			logrus.WithError(err).Error("Failed to create interface.")
			finalErr = fmt.Errorf("failed to create ENI: %w", err)
			continue // Carry on and try the other interfaces before we give up.
		}

		// Find a free device index.
		ctx, cancel = m.newContext()
		devIdx := awsState.FindFreeDeviceIdx()
		awsState.ClaimDeviceIdx(devIdx)
		attOut, err := m.ec2Client.EC2Svc.AttachNetworkInterface(ctx, &ec2.AttachNetworkInterfaceInput{
			DeviceIndex:        &devIdx,
			InstanceId:         &m.ec2Client.InstanceID,
			NetworkInterfaceId: cno.NetworkInterface.NetworkInterfaceId,
			// For now, only support the first network card.  There's only one type of AWS instance with >1
			// NetworkCard.
			NetworkCardIndex: int32Ptr(0),
		})
		cancel()
		if err != nil {
			logrus.WithError(err).Error("Failed to attach interface to host.")
			finalErr = fmt.Errorf("failed to attach ENI to instance: %w", err)
			continue // Carry on and try the other interfaces before we give up.
		}
		logrus.WithFields(logrus.Fields{
			"attachmentID": safeReadString(attOut.AttachmentId),
			"networkCard":  safeReadInt32(attOut.NetworkCardIndex),
		}).Info("Attached ENI.")
		ourENI := awsNetworkInterfaceToENIState(*cno.NetworkInterface)
		ourENI.Attachment = &eniAttachment{
			ID:          *attOut.AttachmentId,
			DeviceIndex: devIdx,
		}
		awsState.OnCalicoENIAttached(ourENI)

		ctx, cancel = m.newContext()
		_, err = m.ec2Client.EC2Svc.ModifyNetworkInterfaceAttribute(ctx, &ec2.ModifyNetworkInterfaceAttributeInput{
			NetworkInterfaceId: cno.NetworkInterface.NetworkInterfaceId,
			Attachment: &ec2types.NetworkInterfaceAttachmentChanges{
				AttachmentId:        attOut.AttachmentId,
				DeleteOnTermination: boolPtr(true),
			},
		})
		cancel()
		if err != nil {
			logrus.WithError(err).Error("Failed to set interface delete-on-termination flag")
			finalErr = fmt.Errorf("failed to set interface delete-on-termination flag: %w", err)
			continue // Carry on and try the other interfaces before we give up.
		}
		awsState.OnENIDeleteOnTermUpdated(ourENI.ID, true)
	}

	if finalErr != nil {
		logrus.Info("Some AWS ENI operations failed; queueing a scan for orphaned ENIs/IPAM resources.")
		m.hostIPAMLeakCheckNeeded = true
		m.orphanENIResyncNeeded = true
	}

	return finalErr
}

func (m *SecondaryIfaceProvisioner) assignSecondaryIPsToENIs(awsState *awsState, filteredRoutes []AddrInfo) error {
	if len(filteredRoutes) == 0 {
		return nil
	}

	// About to change AWS state, queue up a recheck.
	m.resetRecheckInterval("assign-ips")

	remainingRoutes := filteredRoutes
	var fatalErr error
	for eniID, freeIPs := range awsState.freeIPv4CapacityByENIID {
		if len(remainingRoutes) == 0 {
			// We're done.
			break
		}
		if freeIPs == 0 {
			continue
		}
		routesToAdd := remainingRoutes
		if len(routesToAdd) > freeIPs {
			routesToAdd = routesToAdd[:freeIPs]
		}
		remainingRoutes = remainingRoutes[len(routesToAdd):]

		var ipAddrs []string
		for _, r := range routesToAdd {
			ipAddrs = append(ipAddrs, trimPrefixLen(r.Dst))
		}

		logrus.WithFields(logrus.Fields{"eni": eniID, "addrs": ipAddrs})

		ctx, cancel := m.newContext()
		_, err := m.ec2Client.EC2Svc.AssignPrivateIpAddresses(ctx, &ec2.AssignPrivateIpAddressesInput{
			NetworkInterfaceId: &eniID,
			AllowReassignment:  boolPtr(true),
			PrivateIpAddresses: ipAddrs,
		})
		cancel()
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"eniID": eniID,
				"addrs": ipAddrs,
			}).Error("Failed to assign IPs to my ENI.")
			fatalErr = fmt.Errorf("failed to assign workload IPs to secondary ENI: %w", err)
			continue // Carry on trying to assign more IPs.
		}
		logrus.WithFields(logrus.Fields{
			"eniID": eniID,
			"addrs": strings.Join(ipAddrs, ","),
		}).Info("Assigned IPs to secondary ENI.")

		awsState.OnSecondaryIPsAdded(eniID, ipAddrs)
	}

	if len(remainingRoutes) > 0 {
		logrus.Warn("Failed to assign all Calico IPs to local ENIs.  Insufficient secondary IP capacity on the available ENIs.")
	}

	if fatalErr != nil {
		return fatalErr
	}

	return nil
}

func (m *SecondaryIfaceProvisioner) hostPrimaryIPIPAMHandle() string {
	// Using the node name here for consistency with tunnel IPs.
	return fmt.Sprintf("aws-secondary-ifaces-%s", m.nodeName)
}

func (m *SecondaryIfaceProvisioner) newContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), m.timeout)
}

func (m *SecondaryIfaceProvisioner) ensureEC2Client() error {
	if m.ec2Client != nil {
		return nil
	}

	logrus.Debug("Creating EC2 client.")
	ctx, cancel := m.newContext() // Context only for creation of the client, it doesn't get stored.
	defer cancel()
	c, err := m.newEC2Client(ctx)
	if err != nil {
		return fmt.Errorf("failed to create an AWS client: %w", err)
	}
	m.ec2Client = c
	return nil
}

func (m *SecondaryIfaceProvisioner) calculateMaxCalicoSecondaryIPs(snapshot *awsState) int {
	caps := m.networkCapabilities
	maxCalicoENIs := caps.MaxNetworkInterfaces - len(snapshot.nonCalicoOwnedENIsByID)
	if m.mode == v3.AWSSecondaryIPEnabledENIPerWorkload {
		return maxCalicoENIs
	}
	maxSecondaryIPsPerENI := caps.MaxIPv4PerInterface - 1
	maxCapacity := maxCalicoENIs * maxSecondaryIPsPerENI
	return maxCapacity
}

func (m *SecondaryIfaceProvisioner) ensureCalicoENIsDelOnTerminate(snapshot *awsState) error {
	var finalErr error
	for eniID, eni := range snapshot.calicoOwnedENIsByID {
		if eni.Attachment == nil {
			logrus.WithField("eniID", eniID).Warn("ENI has no attachment specified (but it should be attached to this node).")
			finalErr = fmt.Errorf("ENI %s has no attachment (but it should be attached to this node)", eniID)
			continue // Try to deal with the other ENIs.
		}
		if !eni.Attachment.DeleteOnTermination {
			logrus.WithField("eniID", eniID).Info(
				"Calico secondary ENI doesn't have delete-on-termination flag enabled; enabling it...")
			// About to change AWS state, queue up a recheck.
			m.resetRecheckInterval("set-eni-delete-on-term")
			ctx, cancel := m.newContext()
			_, err := m.ec2Client.EC2Svc.ModifyNetworkInterfaceAttribute(ctx, &ec2.ModifyNetworkInterfaceAttributeInput{
				NetworkInterfaceId: &eni.ID,
				Attachment: &ec2types.NetworkInterfaceAttachmentChanges{
					AttachmentId:        &eni.Attachment.ID,
					DeleteOnTermination: boolPtr(true),
				},
			})
			cancel()
			if err != nil {
				logrus.WithError(err).Error("Failed to set interface delete-on-termination flag")
				finalErr = fmt.Errorf("failed to set interface delete-on-termination flag: %w", err)
				continue // Carry on and try the other interfaces before we give up.
			}
		}
	}
	return finalErr
}

func (m *SecondaryIfaceProvisioner) resetRecheckInterval(operation string) {
	logrus.WithField("reason", operation).Debug("Recheck interval reset needed")
	m.opRecorder.RecordOperation(operation)
	m.recheckIntervalResetNeeded = true
}

func (m *SecondaryIfaceProvisioner) disassociateUnwantedElasticIPs(snapshot *awsState) error {
	logrus.Debug("Scanning for unwanted elastic IPs...")
	var finalErr error
	for _, eni := range snapshot.calicoOwnedENIsByID {
		for _, privIP := range eni.IPAddresses {
			if privIP.Association == nil {
				continue
			}
			// May have associated elastic IP.
			privIPAddr := privIP.PrivateIP
			eip := privIP.Association.PublicIP
			wanted := false
			logCtx := logrus.WithFields(logrus.Fields{
				"publicAddr":  eip,
				"privateAddr": privIPAddr,
			})
			if slices.Contains(m.ds.LocalAWSAddrsByDst[privIPAddr].ElasticIPs, eip) {
				// EIP is assigned to a private IP that should have it, all good.
				logCtx.Debug("Elastic IP is associated with matching private IP.")
				wanted = true
			}
			if (m.mode == v3.AWSSecondaryIPEnabledENIPerWorkload && !privIP.Primary) ||
				(m.mode == v3.AWSSecondaryIPEnabled && privIP.Primary) {
				logCtx.Info("Found elastic IP associated with wrong type of address for the AWS secondary " +
					"IP mode. Disassociating elastic IP.")
				wanted = false
			} else if !wanted {
				logCtx.Info("Workload private IP is associated with an elastic IP that isn't one of its " +
					"permitted elastic IPs.  Disassociating elastic IP.")
			}
			if !wanted {
				// Elastic IP is assigned to an IP that it shouldn't be. free it.
				m.resetRecheckInterval("disassociate-eip")

				ctx, cancel := m.newContext()
				_, err := m.ec2Client.EC2Svc.DisassociateAddress(ctx, &ec2.DisassociateAddressInput{
					AssociationId: &privIP.Association.ID,
				})
				cancel()
				if err != nil {
					var smithyErr smithy.APIError
					if errors.As(err, &smithyErr) && smithyErr.ErrorCode() == "InvalidAssociationID.NotFound" {
						// We've seen AWS get stuck for a minute or two, claiming that an EIP is associated in
						// eni.PrivateIpAddresses but then saying it's not when we try to disassociate it.
						// Avoid triggering a resync in that case since we may not make any progress.  Better to
						// try the remainder of the operations we have queued up.
						logrus.WithError(err).Warn("Tried to disassociate Elastic IP but AWS said it was " +
							"already gone. Assuming EIP is gone.")
						// Nil out the association so that checkAndAssociateElasticIPs() will _try_ to reuse that
						// EIP if needed.
						privIP.Association = nil
					} else {
						m.elasticIPsHealthy = false
						finalErr = err
					}
				} else {
					privIP.Association = nil
				}
			}
		}
	}
	return finalErr
}

func (m *SecondaryIfaceProvisioner) checkAndAssociateElasticIPs(awsState *awsState) error {
	// Figure out which IPs already have an elastic IP attached.
	logrus.Debug("Checking if we need to associate any elastic IPs.")
	privIPToElasticIPID := map[ip.Addr]string{}
	inUseElasticIPs := set.New[ip.Addr]()
	for eniID, eni := range awsState.calicoOwnedENIsByID {
		for _, privIP := range eni.IPAddresses {
			if privIP.Association != nil {
				privIPAddr := privIP.PrivateIP
				publicIPAddr := privIP.Association.PublicIP
				eipID := privIP.Association.AllocationID
				logrus.WithFields(logrus.Fields{
					"eniID":    eniID,
					"privIP":   privIPAddr,
					"publicIP": publicIPAddr,
					"eipID":    eipID,
				}).Debug("Found existing elastic IP associated to this node.")
				inUseElasticIPs.Add(publicIPAddr)
				privIPToElasticIPID[privIPAddr] = eipID
			}
		}
	}

	// Collect all the elastic IP IDs that we _may_ want to attach.
	eipToCandidatePrivIPs := map[ip.Addr][]ip.Addr{}
	privIPsToDo := set.New[ip.Addr]()
	for _, addrInfo := range m.ds.LocalAWSAddrsByDst {
		privIPAddr := ip.MustParseCIDROrIP(addrInfo.Dst).Addr()
		if _, ok := privIPToElasticIPID[privIPAddr]; ok {
			logrus.WithField("privAddr", privIPAddr).Debug("Private IP already has elastic IP.")
			continue // This private IP already has an elastic IP attached, skip it.
		}
		for _, elasticIP := range addrInfo.ElasticIPs {
			privIPsToDo.Add(privIPAddr)
			if inUseElasticIPs.Contains(elasticIP) {
				continue // Optimisation: we know this IP is attached, we've already seen it.
			}
			logrus.WithFields(logrus.Fields{
				"privIP":    privIPAddr,
				"elasticIP": elasticIP,
			}).Debug("Candidate private IP/elastic IP combination.")
			eipToCandidatePrivIPs[elasticIP] = append(eipToCandidatePrivIPs[elasticIP], privIPAddr)
		}
	}
	if privIPsToDo.Len() == 0 {
		logrus.Debug("No new elastic IPs needed.")
		return nil
	}
	var candidateElasticIPs []string
	for elasticIP := range eipToCandidatePrivIPs {
		candidateElasticIPs = append(candidateElasticIPs, elasticIP.String())
	}

	failedPrivIPs := map[ip.Addr]error{}
	const chunkSize = 200 // AWS filter limit is 200 filters per call.
	for _, candidateEIPsChunk := range chunkStringSlice(candidateElasticIPs, chunkSize) {
		// Query AWS to find out which elastic IPs are available.
		logrus.WithField("eips", candidateEIPsChunk).Debug("Looking up elastic IPs in AWS API.")
		ctx, cancel := m.newContext()
		dao, err := m.ec2Client.EC2Svc.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{
			// Important to use a filter rather than the other fields in the DescribeAddressesInput because
			// using the other fields to match EIPs results in errors if any one of the EIPs doesn't exist.
			// We don't want a failure to get one EIP to mean that we can't look up the others.
			Filters: []ec2types.Filter{
				{
					Name:   aws2.String("public-ip"),
					Values: candidateEIPsChunk,
				},
				// Would like to include a filter to return only unassociated addresses but there doesn't seem to be one.
			},
		})
		cancel()
		if err != nil {
			return fmt.Errorf("failed to list elastic IPs: %w", err)
		}

		for _, eip := range dao.Addresses {
			eipID := safeReadString(eip.AllocationId)
			if eip.AssociationId != nil {
				logrus.WithField("eipID", eipID).Debug("Elastic IP already in use.")
				continue // Already assigned on another node.
			}
			// Got a free elastic IP, try to assign it to one of our private IPs.
			publicIP := ip.FromString(*eip.PublicIp)
			for _, privIP := range eipToCandidatePrivIPs[publicIP] {
				logCtx := logrus.WithFields(logrus.Fields{
					"privIP":   privIP,
					"eipID":    eipID,
					"publicIP": publicIP.String(),
				})
				if !privIPsToDo.Contains(privIP) {
					continue
				}
				var eniID string
				if m.mode == v3.AWSSecondaryIPEnabledENIPerWorkload {
					// In ENI-per-workload mode, only look at the primary IPs.  If we see a secondary IP it must
					// be stale data from AWS.
					eniID = awsState.eniIDByPrimaryIP[privIP]
				} else {
					// In secondary IP-per-workload mode, only look at the secondary IPs.  If we see a matching
					// primary IP it must be stale data from AWS.
					eniID = awsState.eniIDBySecondaryIP[privIP]
				}
				if eniID == "" {
					logCtx.Warn("Couldn't find ENI for private IP, did we fail to add an ENI earlier?")
					continue
				}
				logCtx = logCtx.WithField("eniID", eniID)
				// Found a free elastic IP and a private IP that can use it with no existing elastic IP.
				// Try to associate the elastic IP with the private IP...
				logCtx.Info("Attempting to associate elastic IP with private IP.")
				m.resetRecheckInterval("associate-eip")
				ctx, cancel := m.newContext()
				aao, err := m.ec2Client.EC2Svc.AssociateAddress(ctx, &ec2.AssociateAddressInput{
					AllocationId:       eip.AllocationId,
					NetworkInterfaceId: stringPtr(eniID),
					PrivateIpAddress:   stringPtr(privIP.String()),
					AllowReassociation: aws2.Bool(false), // true is the default but we don't want to steal.
				})
				cancel()
				if err != nil {
					var smithyErr smithy.APIError
					if errors.As(err, &smithyErr) && smithyErr.ErrorCode() == "Resource.AlreadyAssociated" {
						// Someone else claimed the IP already.
						logCtx.Info("IP was already claimed by someone else; will try another one if available.")
					} else {
						logCtx.WithError(err).Warning("Failed to associate elastic IP; will try another one if available.")
						failedPrivIPs[privIP] = err // Record the error for now; we'll report if the retries fail.
					}
					continue
				} else {
					delete(failedPrivIPs, privIP)
					awsState.OnElasticIPAssociated(eniID, privIP, *aao.AssociationId, *eip.AllocationId, publicIP)
				}
				privIPsToDo.Discard(privIP)
			}
		}
	}
	if len(failedPrivIPs) > 0 {
		m.elasticIPsHealthy = false
		return fmt.Errorf("errors encountered while associating some elastic IPs: %v", failedPrivIPs)
	}
	if privIPsToDo.Len() > 0 {
		logrus.WithField("privIPs", privIPsToDo).Warn(
			"Unable to assign elastic IPs to some private IPs. Required Elastic IPs are in use elsewhere. " +
				"This may resolve automatically when another node releases an Elastic IP that's no longer needed.")
		m.elasticIPsHealthy = false
		// Not returning an error here; best to wait for the slow retry.
	}
	return nil
}

// findENIsWithNoWorkload is used in ENI-per-workload mode to find ENIs that have a primary IP that doesn't match any
// workloads.
func (m *SecondaryIfaceProvisioner) findENIsWithNoWorkload(state *awsState) set.Set[string] {
	enisIDsToRelease := set.New[string]()
	for eniID, eni := range state.calicoOwnedENIsByID {
		for _, addr := range eni.IPAddresses {
			if addr.Primary {
				if _, ok := m.ds.LocalAWSAddrsByDst[addr.PrivateIP]; !ok {
					logrus.WithField("eniID", eniID).Info(
						"Found Calico ENI which no longer matches a workload.  Remove.")
					enisIDsToRelease.Add(eniID)
				}
			}
		}
	}
	return enisIDsToRelease
}

func (m *SecondaryIfaceProvisioner) ensureIPAMLoaded() error {
	if m.ourHostIPs != nil && !m.hostIPAMLeakCheckNeeded {
		return nil
	}

	logrus.Debug("Refreshing cache of host IPs from Calico IPAM.")
	m.ourHostIPs = nil // Make sure we retry after a failure.

	hostIPs := set.New[ip.Addr]()
	ctx, cancel := m.newContext()
	defer cancel()
	ourIPs, err := m.ipamClient.IPsByHandle(ctx, m.hostPrimaryIPIPAMHandle())
	if err != nil {
		if _, ok := err.(calierrors.ErrorResourceDoesNotExist); ok {
			logrus.Debug("No host IPs in IPAM.")
			m.ourHostIPs = hostIPs
			return nil
		} else {
			return fmt.Errorf("failed to look up our existing IPs: %w", err)
		}
	}

	for _, addr := range ourIPs {
		hostIPs.Add(ip.FromCalicoIP(addr))
	}
	m.ourHostIPs = hostIPs
	return nil
}

func chunkStringSlice(s []string, chunkSize int) (chunks [][]string) {
	for len(s) > 0 {
		if chunkSize >= len(s) {
			chunks = append(chunks, s)
			return
		}
		chunks = append(chunks, s[:chunkSize])
		s = s[chunkSize:]
	}
	return
}

func trimPrefixLen(cidr string) string {
	parts := strings.Split(cidr, "/")
	return parts[0]
}

func safeReadInt32(iptr *int32) string {
	if iptr == nil {
		return "<nil>"
	}
	return fmt.Sprint(*iptr)
}

func safeReadString(sptr *string) string {
	if sptr == nil {
		return "<nil>"
	}
	return *sptr
}

func boolPtr(b bool) *bool {
	return &b
}

func int32Ptr(i int32) *int32 {
	return &i
}

func stringPtr(s string) *string {
	return &s
}
